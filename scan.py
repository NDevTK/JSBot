"""JSBot 5.0 — Opinionated JavaScript security scanner.

Async pipeline: domain discovery → page crawling → JS audit.
All three stages run concurrently via asyncio.Queue.
"""
import argparse
import asyncio
import concurrent.futures
import re
import sys
from collections import namedtuple
from dataclasses import dataclass, field
from random import shuffle
from urllib.parse import urljoin, urlparse

import httpx
from bs4 import BeautifulSoup

import output
from output import log_message
from scoring import score_url
from patterns import JS_PATH_FINDER
from analysis import (
    format_javascript, structural_hash, get_sha256, get_ast_analyzer,
    check_script_safety,
    SEEN_SCRIPTS, CHECKED_JS_URLS, IGNORED_HASHES,
    CrossFileState,
)
from sourcemaps import try_fetch_sourcemap, get_original_source
from discovery import (
    discover_paths, spider_links, fetch_wayback_urls,
    ct_load_state, ct_save_state, ct_fetch_next_month,
)

# --- Dependency Availability Checks ---
try:
    from waybackpy import WaybackMachineCDXServerAPI
    WAYBACK_AVAILABLE = True
except ImportError:
    WAYBACK_AVAILABLE = False

try:
    import psycopg2
    PSYCOPG2_AVAILABLE = True
except ImportError:
    PSYCOPG2_AVAILABLE = False

# --- Global State ---
CHECKED_URLS = set()
DISCOVERED_URLS = set()

# --- Configuration ---
class Config:
    USER_AGENT = 'JSBot/5.0 (Autonomous Security Agent)'

# --- Pipeline Data Structures ---
_POISON = object()

JsWorkItem = namedtuple('JsWorkItem', [
    'js_code', 'page_url', 'script_url', 'page_tracker',
])


@dataclass
class PageTracker:
    """Coordinates cross-file analysis — counts scripts remaining for one page."""
    page_url: str
    cross_file: CrossFileState
    total: int
    remaining: int = field(init=False)
    lock: asyncio.Lock = field(default_factory=asyncio.Lock, repr=False)

    def __post_init__(self):
        self.remaining = self.total


class ProducerTracker:
    """Tracks active producers for a queue. Sends poison pills when all finish."""

    def __init__(self, queue, num_consumers):
        self._queue = queue
        self._num_consumers = num_consumers
        self._active = 0
        self._lock = asyncio.Lock()
        self._done = False

    async def register(self):
        async with self._lock:
            self._active += 1

    async def unregister(self):
        async with self._lock:
            self._active -= 1
            if self._active <= 0 and not self._done:
                self._done = True
                for _ in range(self._num_consumers):
                    await self._queue.put(_POISON)


# --- Worker Coroutines ---

async def domain_discovery_worker(domain_queue, url_queue, client, args):
    """Pulls domains from domain_queue, runs discover_paths, puts URLs into url_queue."""
    while True:
        domain = await domain_queue.get()
        if domain is _POISON:
            domain_queue.task_done()
            break
        try:
            discovered = await discover_paths(domain, client)
            for url in discovered:
                if args.min_score > 0 and score_url(url) < args.min_score:
                    continue
                url_hash = get_sha256(url)
                if url_hash not in DISCOVERED_URLS:
                    DISCOVERED_URLS.add(url_hash)
                    await url_queue.put(url)
            if discovered:
                log_message("INFO", f"Discovery for {domain}: {len(discovered)} URLs")
        except Exception as e:
            log_message("ERROR", f"Discovery failed for {domain}: {e}")
        finally:
            domain_queue.task_done()


async def page_crawl_worker(url_queue, js_queue, client, args, url_tracker):
    """Pulls URLs, fetches pages, puts scripts into js_queue, spiders back into url_queue."""
    timeout = httpx.Timeout(10.0, connect=5.0)

    while True:
        url = await url_queue.get()
        if url is _POISON:
            url_queue.task_done()
            break

        await url_tracker.register()
        try:
            hashed_url = get_sha256(url)
            if hashed_url in CHECKED_URLS:
                continue
            CHECKED_URLS.add(hashed_url)

            if args.min_score > 0 and score_url(url) < args.min_score:
                continue

            log_message("INFO", f"Crawling: {url}")
            response = await client.get(url, timeout=timeout)
            content_type = response.headers.get('content-type', '').lower()

            # Direct JS file
            if 'javascript' in content_type:
                await js_queue.put(JsWorkItem(
                    js_code=response.text,
                    page_url=url,
                    script_url=str(response.url),
                    page_tracker=None,
                ))

            # HTML content
            elif 'html' in content_type:
                analyzer = get_ast_analyzer()
                page_parser = BeautifulSoup(response.text, 'lxml')

                # Collect all scripts for this page
                script_items = []
                for script in page_parser.find_all('script'):
                    if not script.get('src'):
                        js = script.string or ""
                        if js.strip():
                            script_items.append((js, None))

                for script in page_parser.find_all('script', src=True):
                    script_url = urljoin(str(response.url), script['src'])
                    hashed_script_url = get_sha256(script_url)
                    if hashed_script_url in CHECKED_JS_URLS:
                        continue
                    CHECKED_JS_URLS.add(hashed_script_url)
                    try:
                        resp = await client.get(script_url, timeout=timeout)
                        if resp.status_code < 400 and 'javascript' in resp.headers.get('content-type', '').lower():
                            script_items.append((resp.text, script_url))
                        elif resp.status_code < 400:
                            # No content-type check for <script src> — server might not set it
                            script_items.append((resp.text, script_url))
                    except httpx.RequestError as e:
                        log_message("ERROR", f"Failed to fetch script {script_url}: {e}")

                # Build PageTracker for cross-file analysis
                tracker = None
                if analyzer and script_items:
                    cross_file = CrossFileState()
                    tracker = PageTracker(
                        page_url=url,
                        cross_file=cross_file,
                        total=len(script_items),
                    )

                # Enqueue each script
                for js_code, script_url in script_items:
                    await js_queue.put(JsWorkItem(
                        js_code=js_code,
                        page_url=url,
                        script_url=script_url,
                        page_tracker=tracker,
                    ))

                # Discover JS paths referenced in HTML
                for match in re.finditer(JS_PATH_FINDER, response.text):
                    path = match.group(1)
                    if path.startswith('//'):
                        path = f"https:{path}"
                    js_url = urljoin(str(response.url), path)
                    hashed = get_sha256(js_url)
                    if hashed in CHECKED_JS_URLS:
                        continue
                    CHECKED_JS_URLS.add(hashed)
                    try:
                        js_resp = await client.get(js_url, timeout=timeout)
                        if js_resp.status_code < 400:
                            await js_queue.put(JsWorkItem(
                                js_code=js_resp.text,
                                page_url=url,
                                script_url=js_url,
                                page_tracker=None,
                            ))
                    except httpx.RequestError:
                        pass

                # Spider: feed links back into url_queue
                if args.spider:
                    parsed_url = urlparse(url)
                    base_domain = '.'.join((parsed_url.hostname or '').split('.')[-2:])
                    new_links = spider_links(response.text, response.url, base_domain)
                    for link in new_links:
                        link_hash = get_sha256(link)
                        if link_hash not in DISCOVERED_URLS and link_hash not in CHECKED_URLS:
                            DISCOVERED_URLS.add(link_hash)
                            await url_queue.put(link)

            else:
                log_message("INFO", f"Skipping non-HTML/JS content at {url}")

        except httpx.RequestError as e:
            log_message("ERROR", f"HTTP request failed for {url}: {e}")
        except Exception as e:
            log_message("ERROR", f"Unexpected error for {url}: {e}")
        finally:
            await url_tracker.unregister()
            url_queue.task_done()


async def js_audit_worker(js_queue, client, args, executor):
    """Pulls JS from js_queue, runs analysis (heavy work in ThreadPoolExecutor)."""
    loop = asyncio.get_event_loop()
    fetch_timeout = httpx.Timeout(10.0, connect=5.0)

    while True:
        item = await js_queue.get()
        if item is _POISON:
            js_queue.task_done()
            break

        try:
            js_code = item.js_code
            if not js_code or not js_code.strip():
                # Still need to decrement PageTracker for empty scripts
                await _decrement_page_tracker(item.page_tracker, executor, loop)
                continue

            js_code = format_javascript(js_code)
            raw_hash = get_sha256(js_code)
            struct_hash = structural_hash(js_code)

            # Dedup (on event loop thread — safe)
            skip_analysis = False
            if raw_hash in IGNORED_HASHES:
                skip_analysis = True
            elif raw_hash in SEEN_SCRIPTS or struct_hash in SEEN_SCRIPTS:
                skip_analysis = True
            else:
                SEEN_SCRIPTS.add(raw_hash)
                SEEN_SCRIPTS.add(struct_hash)

            if not skip_analysis:
                # Heavy sync work → thread pool
                await loop.run_in_executor(
                    executor,
                    check_script_safety, js_code, raw_hash, item.page_url, item.script_url,
                )

                # Source map (async fetch, sync re-analysis)
                if (not getattr(args, 'no_sourcemaps', False)
                        and item.script_url and item.script_url != "inline"):
                    try:
                        sourcemap = await try_fetch_sourcemap(item.script_url, js_code, client)
                        if sourcemap:
                            original = get_original_source(sourcemap)
                            if original and len(original) > 50:
                                original_hash = get_sha256(original)
                                if original_hash not in SEEN_SCRIPTS:
                                    SEEN_SCRIPTS.add(original_hash)
                                    log_message("INFO", f"Re-analyzing source map for {item.script_url}")
                                    await loop.run_in_executor(
                                        executor,
                                        check_script_safety, original, original_hash,
                                        item.page_url, item.script_url + " (source map)",
                                    )
                    except Exception as e:
                        log_message("ERROR", f"Source map failed for {item.script_url}: {e}")

                # Save to disk
                if args.save:
                    try:
                        with open(f"{raw_hash}.js", 'w', encoding='utf-8') as f:
                            f.write(f"// Source: {item.page_url}\n"
                                    f"// Script URL: {item.script_url or 'inline'}\n\n{js_code}")
                    except IOError as e:
                        log_message("ERROR", f"Failed to save script {raw_hash}: {e}")

                # Discover JS paths referenced inside JS code
                for match in re.finditer(JS_PATH_FINDER, js_code):
                    path = match.group(1)
                    if path.startswith('//'):
                        path = f"https:{path}"
                    script_url = urljoin(item.page_url, path)
                    hashed_url = get_sha256(script_url)
                    if hashed_url in CHECKED_JS_URLS:
                        continue
                    CHECKED_JS_URLS.add(hashed_url)
                    log_message("INFO", f"Discovered JS via regex: {script_url}")
                    try:
                        resp = await client.get(script_url, timeout=fetch_timeout)
                        if resp.status_code < 400:
                            await js_queue.put(JsWorkItem(
                                js_code=resp.text,
                                page_url=item.page_url,
                                script_url=script_url,
                                page_tracker=None,
                            ))
                    except httpx.RequestError:
                        pass

            # Cross-file tracking (always, even for deduped scripts)
            if item.page_tracker is not None:
                pt = item.page_tracker
                pt.cross_file.add_script(js_code, item.script_url or "inline", raw_hash)
                await _decrement_page_tracker(pt, executor, loop)

        except Exception as e:
            log_message("ERROR", f"JS audit error: {e}")
        finally:
            js_queue.task_done()


async def _decrement_page_tracker(page_tracker, executor, loop):
    """Decrement a PageTracker and run cross-file analysis when all scripts are done."""
    if page_tracker is None:
        return
    async with page_tracker.lock:
        page_tracker.remaining -= 1
        if page_tracker.remaining <= 0:
            analyzer = get_ast_analyzer()
            if analyzer and page_tracker.cross_file.scripts:
                try:
                    await loop.run_in_executor(
                        executor,
                        page_tracker.cross_file.collect_globals, analyzer,
                    )
                    page_tracker.cross_file.emit_cross_file_findings(page_tracker.page_url)
                except Exception as e:
                    log_message("ERROR", f"Cross-file analysis failed for {page_tracker.page_url}: {e}")


# --- Producer Coroutines ---

async def seed_urls_into_pipeline(initial_urls, url_queue, domain_queue, args, executor):
    """Seed initial URLs and domains into the pipeline."""
    urls_to_seed = set(initial_urls)

    # Wayback: run in executor since it's blocking
    if args.wayback:
        loop = asyncio.get_event_loop()
        log_message("INFO", "Fetching Wayback Machine URLs...")
        wayback_urls = await loop.run_in_executor(
            executor, fetch_wayback_urls, list(urls_to_seed), Config.USER_AGENT,
        )
        urls_to_seed.update(wayback_urls)
        log_message("INFO", f"Wayback added {len(wayback_urls)} URLs")

    # URL cleaning
    if not args.no_clean_url:
        cleaned = {}
        for url in urls_to_seed:
            clean = url.split('?')[0].split('#')[0]
            existing_score = cleaned.get(clean, -1)
            new_score = score_url(url)
            if new_score > existing_score:
                cleaned[clean] = new_score
        urls_to_seed = set(cleaned.keys())

    # Extract domains for discovery
    if args.discover:
        domains = set()
        for url in urls_to_seed:
            parsed = urlparse(url)
            if parsed.hostname:
                domains.add(parsed.hostname)
        for domain in domains:
            await domain_queue.put(domain)

    # Sort and seed
    url_list = list(urls_to_seed)
    if args.smart_sort:
        url_list.sort(key=score_url, reverse=True)
    else:
        shuffle(url_list)

    for url in url_list:
        url_hash = get_sha256(url)
        if url_hash not in DISCOVERED_URLS:
            DISCOVERED_URLS.add(url_hash)
            await url_queue.put(url)

    log_message("INFO", f"Seeded {len(url_list)} initial URLs into pipeline")


async def ct_producer(url_queue, domain_queue, args, executor):
    """Fetches CT months in executor, streams URLs/domains into queues."""
    domain = args.ct
    loop = asyncio.get_event_loop()
    state = await loop.run_in_executor(executor, ct_load_state, domain)

    if state['related_domains']:
        log_message("INFO", f"Known related domains: "
                    f"{', '.join(state['related_domains'][:20])}"
                    + (f" ... +{len(state['related_domains'])-20} more"
                       if len(state['related_domains']) > 20 else ""))

    while True:
        log_message("INFO", f"CT: fetching next month for {domain}...")
        new_subs, new_related, exhausted = await loop.run_in_executor(
            executor, ct_fetch_next_month, domain, state,
        )

        if exhausted:
            log_message("INFO", "CT: all months exhausted.")
            break

        if new_related:
            log_message("INFO", f"CT: {len(new_related)} new related domains: "
                        f"{', '.join(sorted(new_related))}")

        if new_subs:
            log_message("INFO", f"CT: {len(new_subs)} new subdomains to scan")
            for sub in new_subs:
                await url_queue.put(f'https://{sub}/')
            if args.discover:
                for sub in new_subs:
                    await domain_queue.put(sub)
            state['scanned_subdomains'] = sorted(
                set(state['scanned_subdomains']) | new_subs
            )

        await loop.run_in_executor(executor, ct_save_state, state, domain)

    await loop.run_in_executor(executor, ct_save_state, state, domain)
    log_message("INFO", f"CT complete: {len(state['scanned_subdomains'])} subdomains total")


# --- Pipeline Orchestrator ---

async def run_pipeline(args, client, initial_urls):
    """Set up queues, workers, and producers; run until all work is done."""
    domain_queue = asyncio.Queue(maxsize=100)
    url_queue = asyncio.Queue(maxsize=500)
    js_queue = asyncio.Queue(maxsize=200)

    executor = concurrent.futures.ThreadPoolExecutor(
        max_workers=max(4, args.concurrency // 2),
    )

    num_domain_workers = 2
    num_crawl_workers = args.concurrency
    num_js_workers = max(4, args.concurrency // 2)

    # url_queue producer tracker — poison pills go to page_crawl_workers
    url_tracker = ProducerTracker(url_queue, num_crawl_workers)

    # Start workers
    domain_tasks = [
        asyncio.create_task(domain_discovery_worker(domain_queue, url_queue, client, args))
        for _ in range(num_domain_workers)
    ]
    crawl_tasks = [
        asyncio.create_task(page_crawl_worker(url_queue, js_queue, client, args, url_tracker))
        for _ in range(num_crawl_workers)
    ]
    js_tasks = [
        asyncio.create_task(js_audit_worker(js_queue, client, args, executor))
        for _ in range(num_js_workers)
    ]

    # Start producers
    producers = []

    # Seed URLs producer
    async def seed_producer():
        await url_tracker.register()
        try:
            await seed_urls_into_pipeline(initial_urls, url_queue, domain_queue, args, executor)
        finally:
            await url_tracker.unregister()
    producers.append(asyncio.create_task(seed_producer()))

    # CT producer
    if args.ct:
        async def ct_wrapper():
            await url_tracker.register()
            try:
                await ct_producer(url_queue, domain_queue, args, executor)
            finally:
                await url_tracker.unregister()
        producers.append(asyncio.create_task(ct_wrapper()))

    # Domain discovery workers are also url_queue producers
    for _ in range(num_domain_workers):
        await url_tracker.register()

    # Wait for all producers to finish seeding
    await asyncio.gather(*producers)

    # Shut down domain_queue
    for _ in range(num_domain_workers):
        await domain_queue.put(_POISON)
    await asyncio.gather(*domain_tasks)

    # Domain workers done — unregister them as url producers
    for _ in range(num_domain_workers):
        await url_tracker.unregister()

    # url_tracker will send poison pills to crawl workers when all producers are done
    await asyncio.gather(*crawl_tasks)

    # Crawl workers done — shut down js_queue
    for _ in range(num_js_workers):
        await js_queue.put(_POISON)
    await asyncio.gather(*js_tasks)

    executor.shutdown(wait=False)


# --- Main ---

async def main(args):
    """Main execution function — sets up and runs the async pipeline."""
    import analysis
    output.ARGS = args
    analysis.ARGS = args

    if args.ignore_hashes:
        try:
            with open(args.ignore_hashes, 'r', encoding='utf-8') as f:
                IGNORED_HASHES.update(line.strip() for line in f if line.strip())
                log_message("INFO", f"Loaded {len(IGNORED_HASHES)} hashes to ignore.")
        except IOError as e:
            log_message("ERROR", f"Unable to read ignore_hashes file '{args.ignore_hashes}': {e}")
            return

    # Load initial URLs
    initial_urls = []
    if args.url_file:
        if args.url_file == '-' or not sys.stdin.isatty():
            initial_urls = [line.strip() for line in sys.stdin if line.strip()]
        else:
            try:
                with open(args.url_file, 'r', encoding='utf-8') as f:
                    initial_urls = [line.strip() for line in f if line.strip()]
            except IOError as e:
                log_message("ERROR", f"Unable to read file '{args.url_file}': {e}")
                return

    # Client configuration
    headers = {'User-Agent': Config.USER_AGENT}
    if args.header:
        for header in args.header:
            if ':' in header:
                key, value = header.split(':', 1)
                headers[key.strip()] = value.strip()
    if args.cookie:
        headers['Cookie'] = args.cookie

    limits = httpx.Limits(
        max_connections=args.concurrency,
        max_keepalive_connections=args.concurrency,
    )

    async with httpx.AsyncClient(
        http2=True, limits=limits,
        follow_redirects=not args.no_redirects,
        verify=not args.insecure, headers=headers,
    ) as client:
        await run_pipeline(args, client, initial_urls)

    log_message("INFO", "Scan finished.")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description="JSBot 5.0 — Opinionated JavaScript security scanner with AST analysis, secret detection, and smart discovery.",
        formatter_class=argparse.RawTextHelpFormatter
    )

    parser.add_argument('url_file', nargs='?', default=None, help="Path to a file with URLs, or '-' to read from stdin.")

    scan_group = parser.add_argument_group('Scan Configuration')
    scan_group.add_argument('-c', '--concurrency', type=int, default=20, help="Number of concurrent requests. (Default: 20)")
    scan_group.add_argument('-w', '--wayback', action='store_true', help="Fetch historical URLs from the Wayback Machine.")
    scan_group.add_argument('--no-clean-url', action='store_true', help="Don't clean URL parameters before scanning.")
    scan_group.add_argument('--link-mode', action='store_true', help="Only find and output links/URLs found in JS files.")
    scan_group.add_argument('--minimal', action='store_true', help="Disable all auto-discovery (discover, spider, smart-sort).")

    taint_group = parser.add_argument_group('Taint Analysis')
    taint_group.add_argument('--context-lines', type=int, default=3, help="Lines of context around findings. (Default: 3)")
    taint_group.add_argument('--include-sink-only', action='store_true', help="Include sink-only findings (no source matched).")

    discovery_group = parser.add_argument_group('Target Discovery')
    discovery_group.add_argument('--ct', metavar='DOMAIN', help="Discover subdomains via Certificate Transparency logs (crt.sh).")
    discovery_group.add_argument('--smart-sort', action='store_true', default=True, help="Score and prioritize URLs by vulnerability likelihood. (Default: on)")
    discovery_group.add_argument('--no-smart-sort', action='store_true', help="Disable URL scoring/sorting.")
    discovery_group.add_argument('--discover', action='store_true', default=True, help="Discover paths from robots.txt and sitemap.xml. (Default: on)")
    discovery_group.add_argument('--no-discover', action='store_true', help="Disable path discovery.")
    discovery_group.add_argument('--spider', action='store_true', default=True, help="Follow <a href> links to discover deeper endpoints. (Default: on)")
    discovery_group.add_argument('--no-spider', action='store_true', help="Disable spider mode.")
    discovery_group.add_argument('--min-score', type=int, default=0, help="Skip URLs scoring below this threshold. (Default: 0)")

    http_group = parser.add_argument_group('HTTP Configuration')
    http_group.add_argument('-H', '--header', action='append', help="Add a custom header (e.g., 'X-API-Key: 123').")
    http_group.add_argument('-b', '--cookie', help="Set the cookie header string.")
    http_group.add_argument('--no-redirects', action='store_true', help="Don't follow HTTP redirects.")
    http_group.add_argument('-k', '--insecure', action='store_true', help="Disable SSL/TLS certificate verification.")

    output_group = parser.add_argument_group('Output & Analysis')
    output_group.add_argument('-s', '--save', action='store_true', help="Save unique JS files to disk, named by SHA256 hash.")
    output_group.add_argument('-v', '--verbose', action='store_true', help="Enable verbose informational output.")
    output_group.add_argument('--show-errors', action='store_true', help="Show error messages for failed requests.")
    output_group.add_argument('--ignore-hashes', help="Path to a file containing SHA256 hashes of JS files to ignore.")
    output_group.add_argument('--format-js', action='store_true', default=True, help="Beautify JS before analysis if jsbeautifier available. (Default: on)")
    output_group.add_argument('--no-format', action='store_true', help="Disable JS beautification.")
    output_group.add_argument('--no-sourcemaps', action='store_true', help="Disable automatic source map fetching.")

    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)

    args = parser.parse_args()

    # Apply --minimal: disable all auto-discovery
    if args.minimal:
        args.discover = False
        args.spider = False
        args.smart_sort = False

    # Apply --no-* flags
    if args.no_discover:
        args.discover = False
    if args.no_spider:
        args.spider = False
    if args.no_smart_sort:
        args.smart_sort = False
    if args.no_format:
        args.format_js = False

    if not args.url_file and not args.ct:
        parser.error("Either url_file or --ct DOMAIN is required.")

    if args.wayback and not WAYBACK_AVAILABLE:
        print("[!] [ERROR] --wayback requires 'waybackpy'. Install it with: pip install waybackpy", file=sys.stderr)
        sys.exit(1)
    if args.ct and not PSYCOPG2_AVAILABLE:
        print("[!] [ERROR] --ct requires 'psycopg2-binary'. Install it with: pip install psycopg2-binary", file=sys.stderr)
        sys.exit(1)

    try:
        asyncio.run(main(args))
    except KeyboardInterrupt:
        print("\n[*] [INFO] Scan interrupted by user.", file=sys.stderr)
        sys.exit(0)
