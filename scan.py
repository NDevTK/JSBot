"""JSBot 5.0 — Opinionated JavaScript security scanner.

Async pipeline: domain discovery → page crawling → JS audit.
All three stages run concurrently via asyncio.Queue.
"""
import argparse
import asyncio
import concurrent.futures
import os
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

# --- Global State ---
CHECKED_URLS = set()
DISCOVERED_URLS = set()
DEAD_DOMAINS = set()  # domains that failed with connection errors — skip future requests

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
            if domain in DEAD_DOMAINS:
                continue
            discovered = await discover_paths(domain, client)
            for url in discovered:
                url_hash = get_sha256(url)
                if url_hash not in DISCOVERED_URLS:
                    DISCOVERED_URLS.add(url_hash)
                    await url_queue.put(url)
            if discovered:
                log_message("INFO", f"Discovery for {domain}: {len(discovered)} URLs")
        except (httpx.ConnectError, httpx.ConnectTimeout) as e:
            DEAD_DOMAINS.add(domain)
            log_message("ERROR", f"Domain unreachable, skipping: {domain} ({e})")
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

            # Skip URLs on domains we already know are dead
            parsed = urlparse(url)
            if parsed.hostname and parsed.hostname in DEAD_DOMAINS:
                continue

            log_message("INFO", f"Crawling: {url}")
            response = await client.get(url, timeout=timeout)
            page_url = str(response.url)  # Final URL after redirects
            content_type = response.headers.get('content-type', '').lower()

            # Direct JS file
            if 'javascript' in content_type:
                await js_queue.put(JsWorkItem(
                    js_code=response.text,
                    page_url=page_url,
                    script_url=page_url,
                    page_tracker=None,
                ))

            # HTML content
            elif 'html' in content_type:
                page_parser = BeautifulSoup(response.text, 'lxml')

                # Collect all scripts for this page
                script_items = []
                for script in page_parser.find_all('script'):
                    if not script.get('src'):
                        js = script.string or ""
                        if js.strip():
                            script_items.append((js, None))

                for script in page_parser.find_all('script', src=True):
                    script_url = urljoin(page_url, script['src'])
                    hashed_script_url = get_sha256(script_url)
                    if hashed_script_url in CHECKED_JS_URLS:
                        continue
                    CHECKED_JS_URLS.add(hashed_script_url)
                    try:
                        resp = await client.get(script_url, timeout=timeout)
                        if resp.status_code < 400:
                            script_items.append((resp.text, str(resp.url)))
                    except httpx.RequestError as e:
                        log_message("ERROR", f"Failed to fetch script {script_url}: {e}")

                # Build PageTracker for cross-file analysis
                tracker = None
                if script_items:
                    cross_file = CrossFileState()
                    tracker = PageTracker(
                        page_url=page_url,
                        cross_file=cross_file,
                        total=len(script_items),
                    )

                # Enqueue each script
                for js_code, script_url in script_items:
                    await js_queue.put(JsWorkItem(
                        js_code=js_code,
                        page_url=page_url,
                        script_url=script_url,
                        page_tracker=tracker,
                    ))

                # Discover JS paths referenced in HTML
                for match in re.finditer(JS_PATH_FINDER, response.text):
                    path = match.group(1).replace('\\/', '/')
                    if '%{' in path or '${' in path or '{{' in path:
                        continue
                    if path.startswith('//'):
                        path = f"https:{path}"
                    js_url = urljoin(page_url, path)
                    hashed = get_sha256(js_url)
                    if hashed in CHECKED_JS_URLS:
                        continue
                    CHECKED_JS_URLS.add(hashed)
                    try:
                        js_resp = await client.get(js_url, timeout=timeout)
                        if js_resp.status_code < 400:
                            await js_queue.put(JsWorkItem(
                                js_code=js_resp.text,
                                page_url=page_url,
                                script_url=js_url,
                                page_tracker=None,
                            ))
                    except httpx.RequestError:
                        pass

                # Spider: feed links back into url_queue
                parsed_url = urlparse(page_url)
                base_domain = '.'.join((parsed_url.hostname or '').split('.')[-2:])
                new_links = spider_links(response.text, response.url, base_domain)
                for link in new_links:
                    link_hash = get_sha256(link)
                    if link_hash not in DISCOVERED_URLS and link_hash not in CHECKED_URLS:
                        DISCOVERED_URLS.add(link_hash)
                        await url_queue.put(link)

            else:
                log_message("INFO", f"Skipping non-HTML/JS content at {url}")

        except (httpx.ConnectError, httpx.ConnectTimeout) as e:
            host = urlparse(url).hostname
            if host:
                DEAD_DOMAINS.add(host)
            log_message("ERROR", f"Domain unreachable, skipping future requests: {url} ({e})")
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
                if item.script_url and item.script_url != "inline":
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
                    path = match.group(1).replace('\\/', '/')
                    if '%{' in path or '${' in path or '{{' in path:
                        continue
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
        if page_tracker.remaining <= 0 and page_tracker.cross_file.scripts:
            analyzer = get_ast_analyzer()
            try:
                await loop.run_in_executor(
                    executor,
                    page_tracker.cross_file.collect_globals, analyzer,
                )
                page_tracker.cross_file.emit_cross_file_findings(page_tracker.page_url)
            except Exception as e:
                log_message("ERROR", f"Cross-file analysis failed for {page_tracker.page_url}: {e}")


# --- Producer Coroutines ---

def _clean_urls(urls):
    """Strip query params/fragments, keep highest-scored version of each URL."""
    cleaned = {}
    for url in urls:
        clean = url.split('?')[0].split('#')[0]
        existing_score = cleaned.get(clean, -1)
        new_score = score_url(url)
        if new_score > existing_score:
            cleaned[clean] = new_score
    return set(cleaned.keys())


async def _seed_urls(urls, url_queue, domain_queue):
    """Clean, sort, and push a set of URLs into the pipeline queues."""
    cleaned = _clean_urls(urls)

    # Extract domains for discovery
    domains = set()
    for url in cleaned:
        parsed = urlparse(url)
        if parsed.hostname:
            domains.add(parsed.hostname)
    for domain in domains:
        await domain_queue.put(domain)

    # Sort by interestingness and seed
    url_list = sorted(cleaned, key=score_url, reverse=True)
    added = 0
    for url in url_list:
        url_hash = get_sha256(url)
        if url_hash not in DISCOVERED_URLS:
            DISCOVERED_URLS.add(url_hash)
            await url_queue.put(url)
            added += 1
    return added


async def seed_urls_into_pipeline(initial_urls, url_queue, domain_queue, args, executor):
    """Seed initial URLs into the pipeline immediately."""
    added = await _seed_urls(initial_urls, url_queue, domain_queue)
    log_message("INFO", f"Seeded {added} initial URLs into pipeline")


async def wayback_producer(url_queue, domain_queue, hosts, executor):
    """Fetch Wayback Machine URLs for a set of hostnames and feed into the pipeline."""
    if not hosts:
        return
    loop = asyncio.get_event_loop()
    log_message("INFO", f"Fetching Wayback Machine URLs for {len(hosts)} hosts...")
    wayback_urls = await loop.run_in_executor(
        executor, fetch_wayback_urls, list(hosts), Config.USER_AGENT,
    )
    if not wayback_urls:
        log_message("INFO", "Wayback: no new URLs found")
        return
    added = await _seed_urls(wayback_urls, url_queue, domain_queue)
    log_message("INFO", f"Wayback added {added} new URLs")


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
            for sub in new_subs:
                await domain_queue.put(sub)
            state['scanned_subdomains'] = sorted(
                set(state['scanned_subdomains']) | new_subs
            )

        await loop.run_in_executor(executor, ct_save_state, state, domain)

    await loop.run_in_executor(executor, ct_save_state, state, domain)
    log_message("INFO", f"CT complete: {len(state['scanned_subdomains'])} subdomains total")
    return set(state['scanned_subdomains'])


# --- Pipeline Orchestrator ---

async def run_pipeline(args, client, initial_urls):
    """Set up queues, workers, and producers; run until all work is done."""
    domain_queue = asyncio.Queue(maxsize=100)
    url_queue = asyncio.Queue(maxsize=500)
    js_queue = asyncio.Queue(maxsize=200)

    executor = concurrent.futures.ThreadPoolExecutor(
        max_workers=max(4, args.concurrency // 2),
    )

    num_domain_workers = 5
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

    # Start producers (seed + CT run in parallel, Wayback runs after CT)
    producers = []
    ct_subdomains = set()

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
            nonlocal ct_subdomains
            await url_tracker.register()
            try:
                ct_subdomains = await ct_producer(url_queue, domain_queue, args, executor)
            finally:
                await url_tracker.unregister()
        producers.append(asyncio.create_task(ct_wrapper()))

    # Domain discovery workers are also url_queue producers
    for _ in range(num_domain_workers):
        await url_tracker.register()

    # Wait for seed + CT to finish
    await asyncio.gather(*producers)

    # Wayback runs after CT so it can query all discovered subdomains
    wb_hosts = set()
    for url in initial_urls:
        parsed = urlparse(url)
        if parsed.hostname:
            wb_hosts.add(parsed.hostname)
    wb_hosts |= ct_subdomains
    await url_tracker.register()
    try:
        await wayback_producer(url_queue, domain_queue, wb_hosts, executor)
    finally:
        await url_tracker.unregister()

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

    # Load initial URLs based on auto-detected input type
    initial_urls = []
    if args._input_type == 'stdin':
        initial_urls = [line.strip() for line in sys.stdin if line.strip()]
    elif args._input_type == 'file':
        try:
            with open(args.input, 'r', encoding='utf-8') as f:
                initial_urls = [line.strip() for line in f if line.strip()]
        except IOError as e:
            log_message("ERROR", f"Unable to read file '{args.input}': {e}")
            return
    elif args._input_type == 'url':
        initial_urls = [args.input]
    elif args._input_type == 'domain':
        initial_urls = [f'https://{args.input}/']

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
        max_connections=args.concurrency + 15,  # crawl + domain + JS workers
        max_keepalive_connections=args.concurrency,
    )

    async with httpx.AsyncClient(
        http2=True, limits=limits,
        follow_redirects=True, verify=True, headers=headers,
    ) as client:
        await run_pipeline(args, client, initial_urls)

    log_message("INFO", "Scan finished.")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description="JSBot — Opinionated JavaScript security scanner. Give it a domain, it does the rest.",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument('input', nargs='?', default=None,
                        help="Domain, URL, file of URLs, or '-' for stdin.")
    parser.add_argument('-H', '--header', action='append',
                        help="Custom HTTP header (repeatable).")
    parser.add_argument('-b', '--cookie',
                        help="Cookie header value.")
    parser.add_argument('-v', '--verbose', action='store_true',
                        help="Verbose logging to stderr.")
    parser.add_argument('--show-errors', action='store_true',
                        help="Show HTTP error details on stderr.")
    parser.add_argument('-s', '--save', action='store_true',
                        help="Save unique JS files to disk (SHA256-named).")
    parser.add_argument('--ignore-hashes',
                        help="File of SHA256 hashes to skip.")

    if len(sys.argv) == 1 and sys.stdin.isatty():
        parser.print_help(sys.stderr)
        sys.exit(1)

    args = parser.parse_args()

    # --- Auto-detect input type ---
    if args.input is None:
        if not sys.stdin.isatty():
            args._input_type = 'stdin'
        else:
            parser.print_help(sys.stderr)
            sys.exit(1)
    elif args.input == '-':
        args._input_type = 'stdin'
    elif os.path.isfile(args.input):
        args._input_type = 'file'
    elif args.input.startswith(('http://', 'https://')):
        args._input_type = 'url'
    else:
        args._input_type = 'domain'

    args.concurrency = 20

    # CT discovery: automatic for domain input
    args.ct = args.input if args._input_type == 'domain' else None

    try:
        asyncio.run(main(args))
    except KeyboardInterrupt:
        print("\n[*] Scan interrupted.", file=sys.stderr)
        sys.exit(0)
