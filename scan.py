"""JSBot 5.0 — Opinionated JavaScript security scanner.

Orchestrator: CLI, crawling, scan loops. Analysis lives in analysis.py,
patterns in patterns.py, discovery in discovery.py, scoring in scoring.py.
"""
import argparse
import asyncio
import httpx
import sys
from urllib.parse import urljoin, urlparse
from random import shuffle

from bs4 import BeautifulSoup

import output
from output import log_message
from scoring import score_url
from analysis import (
    process_javascript, find_and_process_js_paths, get_sha256,
    SEEN_SCRIPTS, CHECKED_JS_URLS, IGNORED_HASHES,
    CrossFileState, get_ast_analyzer,
)
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


async def crawl_url(url, client, workers, args, spider_queue=None):
    """Crawls a single URL, extracts and processes scripts."""
    async with workers:
        try:
            hashed_url = get_sha256(url)
            if hashed_url in CHECKED_URLS:
                return
            CHECKED_URLS.add(hashed_url)

            log_message("INFO", f"Crawling: {url}")
            response = await client.get(url, timeout=10)
            content_type = response.headers.get('content-type', '').lower()

            # Direct JS file
            if 'javascript' in content_type:
                await process_javascript(response.text, url, client, script_url=str(response.url))
                return

            # HTML content
            if 'html' in content_type:
                # Cross-file state collects scripts from this page
                cross_file = CrossFileState()
                analyzer = get_ast_analyzer()

                page_parser = BeautifulSoup(response.text, 'lxml')
                tasks = []
                for script in page_parser.find_all('script'):
                    if not script.get('src'):
                        tasks.append(process_javascript(
                            script.string or "", url, client,
                            cross_file_state=cross_file if analyzer else None,
                        ))
                for script in page_parser.find_all('script', src=True):
                    script_url = urljoin(str(response.url), script['src'])
                    hashed_script_url = get_sha256(script_url)
                    if hashed_script_url in CHECKED_JS_URLS:
                        continue
                    CHECKED_JS_URLS.add(hashed_script_url)
                    try:
                        script_response = await client.get(script_url, timeout=10)
                        tasks.append(process_javascript(
                            script_response.text, url, client, script_url=script_url,
                            cross_file_state=cross_file if analyzer else None,
                        ))
                    except httpx.RequestError as e:
                        log_message("ERROR", f"Failed to fetch script {script_url}: {e}")

                await asyncio.gather(*tasks)
                await find_and_process_js_paths(response.text, str(response.url), client)

                # Cross-file analysis: check for taint flows across scripts
                if analyzer and cross_file.scripts:
                    try:
                        cross_file.collect_globals(analyzer)
                        cross_file.emit_cross_file_findings(url)
                    except Exception as e:
                        log_message("ERROR", f"Cross-file analysis failed for {url}: {e}")

                # Spider mode: collect same-domain links
                if spider_queue is not None and args.spider:
                    parsed_url = urlparse(url)
                    base_domain = '.'.join((parsed_url.hostname or '').split('.')[-2:])
                    new_links = spider_links(response.text, response.url, base_domain)
                    for link in new_links:
                        link_hash = get_sha256(link)
                        if link_hash not in DISCOVERED_URLS and link_hash not in CHECKED_URLS:
                            DISCOVERED_URLS.add(link_hash)
                            spider_queue.append(link)

            else:
                log_message("INFO", f"Skipping non-HTML/JS content at {url}")

        except httpx.RequestError as e:
            log_message("ERROR", f"HTTP request failed for {url}: {e}")
        except Exception as e:
            log_message("ERROR", f"An unexpected error occurred for {url}: {e}")


async def scan_url_batch(args, client, workers, urls):
    """Score, sort, and scan a batch of URLs."""
    url_scores = {url: score_url(url) for url in urls}

    if not args.no_clean_url:
        cleaned_scores = {}
        for url in urls:
            cleaned = url.split('?')[0].split('#')[0]
            if cleaned not in cleaned_scores or url_scores[url] > cleaned_scores[cleaned]:
                cleaned_scores[cleaned] = url_scores[url]
        urls = set(cleaned_scores.keys())
        url_scores = cleaned_scores

    if args.discover:
        domains = set()
        for url in urls:
            parsed = urlparse(url)
            if parsed.hostname:
                domains.add(parsed.hostname)
        if domains:
            log_message("INFO", f"Running path discovery on {len(domains)} domains...")
            discover_tasks = [discover_paths(domain, client) for domain in domains]
            results = await asyncio.gather(*discover_tasks)
            for path_set in results:
                for new_url in path_set:
                    if new_url not in url_scores:
                        url_scores[new_url] = score_url(new_url)
                urls.update(path_set)
            log_message("INFO", f"Discovery added {sum(len(r) for r in results)} new URLs.")

    final_urls = list(urls)
    if args.smart_sort:
        final_urls.sort(key=lambda u: url_scores.get(u, 0), reverse=True)
    else:
        shuffle(final_urls)

    if args.min_score > 0:
        final_urls = [u for u in final_urls if url_scores.get(u, 0) >= args.min_score]

    if not final_urls:
        return

    log_message("INFO", f"Scanning {len(final_urls)} URLs...")

    spider_queue = [] if args.spider else None
    tasks = [crawl_url(url, client, workers, args, spider_queue) for url in final_urls]
    await asyncio.gather(*tasks)

    if spider_queue:
        log_message("INFO", f"Spider discovered {len(spider_queue)} new URLs. Scanning...")
        if args.smart_sort:
            spider_queue.sort(key=score_url, reverse=True)
        if args.min_score > 0:
            spider_queue = [u for u in spider_queue if score_url(u) >= args.min_score]
        spider_tasks = [crawl_url(url, client, workers, args) for url in spider_queue]
        await asyncio.gather(*spider_tasks)


async def standard_scan(args, client, workers, initial_urls):
    """Original scan flow: load URLs, optionally wayback, scan all at once."""
    urls_to_scan = set(initial_urls)
    if args.wayback:
        wayback_urls = fetch_wayback_urls(list(urls_to_scan), Config.USER_AGENT)
        urls_to_scan.update(wayback_urls)
    await scan_url_batch(args, client, workers, urls_to_scan)


async def ct_scan_loop(args, client, workers, seed_urls):
    """Incremental CT discovery: fetch one month, scan new subdomains, repeat."""
    import concurrent.futures

    domain = args.ct
    state = ct_load_state(domain)
    scanned = set(state['scanned_subdomains'])
    executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)

    # Scan seed URLs first
    if seed_urls:
        log_message("INFO", f"Scanning {len(seed_urls)} seed URLs before CT discovery...")
        await scan_url_batch(args, client, workers, set(seed_urls))

    # Report related domains from previous runs
    if state['related_domains']:
        log_message("INFO", f"Known related domains: {', '.join(state['related_domains'][:20])}" +
                    (f" ... +{len(state['related_domains'])-20} more" if len(state['related_domains']) > 20 else ""))

    while True:
        log_message("INFO", f"CT: fetching next month for {domain}...")
        loop = asyncio.get_event_loop()
        new_subs, new_related, exhausted = await loop.run_in_executor(
            executor, ct_fetch_next_month, domain, state
        )

        if exhausted:
            log_message("INFO", "CT: all months exhausted.")
            break

        if not new_subs and not new_related:
            continue

        if new_related:
            log_message("INFO", f"CT: found {len(new_related)} new related domains: {', '.join(sorted(new_related))}")

        if new_subs:
            log_message("INFO", f"CT: found {len(new_subs)} new subdomains to scan")
            urls = {f'https://{sub}/' for sub in new_subs}
            await scan_url_batch(args, client, workers, urls)
            scanned.update(new_subs)
            state['scanned_subdomains'] = sorted(scanned)

        ct_save_state(state, domain)

    ct_save_state(state, domain)
    log_message("INFO", f"CT scan complete: {len(scanned)} total subdomains scanned")


async def main(args):
    """Main execution function."""
    import analysis
    # Wire up shared args reference to modules
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

    limits = httpx.Limits(max_connections=args.concurrency, max_keepalive_connections=args.concurrency)
    workers = asyncio.Semaphore(args.concurrency)

    async with httpx.AsyncClient(
        http2=True, limits=limits, follow_redirects=not args.no_redirects,
        verify=not args.insecure, headers=headers
    ) as client:
        if args.ct:
            await ct_scan_loop(args, client, workers, initial_urls)
        else:
            await standard_scan(args, client, workers, initial_urls)

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
