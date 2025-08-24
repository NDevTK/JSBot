import argparse
import asyncio
import httpx
import re
import json
import sys
from hashlib import sha256
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from random import shuffle

# --- Dependency Availability Checks ---
try:
    from waybackpy import WaybackMachineCDXServerAPI
    WAYBACK_AVAILABLE = True
except ImportError:
    WAYBACK_AVAILABLE = False

try:
    import jsbeautifier
    JSBEAUTIFIER_AVAILABLE = True
except ImportError:
    JSBEAUTIFIER_AVAILABLE = False

# --- Global Sets for State Tracking ---
SEEN_SCRIPTS = set()
CHECKED_URLS = set()
CHECKED_JS_URLS = set()
SEEN_LINKS = set()
IGNORED_HASHES = set()

# --- Configuration ---
class Config:
    USER_AGENT = 'JSBot/2.1 (Autonomous Security Agent)'

# --- Enhanced Regex for Security Checks ---
PATTERNS = {
    "DOM Clobbering": r"""\b(innerHTML|outerHTML|insertAdjacentHTML)\s*=""",
    "Open Redirect": r"""\b(location\s*[.=]\s*href|location\s*=\s*|location\.assign|location\.replace)\s*=""",
    "Eval Injection": r"""\b(eval|setTimeout|setInterval|execScript)\s*\(?""",
    "Cookie Manipulation": r"""\b(document\.cookie)\s*=""",
    "Potentially Unsafe Sink": r"""\b(postMessage|localStorage|sessionStorage|indexedDB|openDatabase)\b""",
    "Link Finder": r"""https?:\/\/[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b[-a-zA-Z0-9()@:%_\+.~#?&//=]*"""
}

# --- Utility Functions ---

def get_sha256(data):
    """Computes SHA256 hash of the given data."""
    return sha256(data.encode('utf-8')).hexdigest()

def format_javascript(js_code):
    """Beautifies JavaScript code if the library is available."""
    if JSBEAUTIFIER_AVAILABLE and ARGS.format_js:
        return jsbeautifier.beautify(js_code)
    return js_code

def log_message(level, message):
    """Prints log messages based on verbosity level."""
    if level == "INFO" and ARGS.verbose:
        print(f"[*] [INFO] {message}", file=sys.stderr)
    elif level == "ERROR" and ARGS.show_errors:
        print(f"[!] [ERROR] {message}", file=sys.stderr)
    elif level == "FINDING":
        print(json.dumps(message))

def check_script_safety(script_content, url, script_url=None):
    """Checks script content against defined regex patterns."""
    findings = []
    # In link-mode, only run the Link Finder pattern. Otherwise, run all other patterns.
    patterns_to_run = {"Link Finder": PATTERNS["Link Finder"]} if ARGS.link_mode else {k: v for k, v in PATTERNS.items() if k != "Link Finder"}

    for category, pattern in patterns_to_run.items():
        matches = re.finditer(pattern, script_content, re.IGNORECASE)
        for match in matches:
            finding = {
                "source_url": url,
                "script_url": script_url or "inline",
                "category": category,
                "matched_text": match.group(0),
                "line_number": script_content.count('\n', 0, match.start()) + 1
            }
            if ARGS.link_mode:
                hashed_link = get_sha256(match.group(0))
                if hashed_link not in SEEN_LINKS:
                    log_message("FINDING", finding)
                    SEEN_LINKS.add(hashed_link)
            else:
                log_message("FINDING", finding)

# --- Core Logic ---

async def process_javascript(js_code, url, script_url=None):
    """Processes and analyzes a piece of JavaScript code."""
    if not js_code:
        return

    js_code = format_javascript(js_code)
    hashed_script = get_sha256(js_code)

    if hashed_script in IGNORED_HASHES:
        log_message("INFO", f"Skipping ignored script hash: {hashed_script}")
        return
    if hashed_script in SEEN_SCRIPTS:
        return
    SEEN_SCRIPTS.add(hashed_script)

    check_script_safety(js_code, url, script_url)

    if ARGS.save:
        try:
            with open(f"{hashed_script}.js", 'w', encoding='utf-8') as f:
                f.write(f"// Source: {url}\n// Script URL: {script_url or 'inline'}\n\n{js_code}")
        except IOError as e:
            log_message("ERROR", f"Failed to save script {hashed_script}: {e}")

async def crawl_url(url, client, workers):
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
            if 'javascript' in content_type:
                await process_javascript(response.text, url, script_url=str(response.url))
                return
            if 'html' not in content_type:
                log_message("INFO", f"Skipping non-HTML content at {url}")
                return

            parser = BeautifulSoup(response.text, 'lxml')
            tasks = []
            for script in parser.find_all('script'):
                script_src = script.get('src')
                if script_src:
                    if ARGS.no_external:
                        continue
                    script_url = urljoin(str(response.url), script_src)
                    
                    hashed_script_url = get_sha256(script_url)
                    if hashed_script_url in CHECKED_JS_URLS:
                        continue
                    CHECKED_JS_URLS.add(hashed_script_url)

                    try:
                        script_response = await client.get(script_url, timeout=10)
                        tasks.append(process_javascript(script_response.text, url, script_url=script_url))
                    except httpx.RequestError as e:
                        log_message("ERROR", f"Failed to fetch script {script_url}: {e}")

                elif script.string:
                    tasks.append(process_javascript(script.string, url))
            
            await asyncio.gather(*tasks)

        except httpx.RequestError as e:
            log_message("ERROR", f"HTTP request failed for {url}: {e}")
        except Exception as e:
            log_message("ERROR", f"An unexpected error occurred for {url}: {e}")


# --- Wayback Machine Functions ---
def fetch_wayback_urls(domains):
    if not WAYBACK_AVAILABLE:
        log_message("ERROR", "WaybackPy not installed. Skipping wayback machine fetch.")
        return []

    all_urls = set()
    for domain in domains:
        domain = domain.strip()
        if not domain: continue
        log_message("INFO", f"Fetching wayback URLs for: {domain}")
        try:
            cdx = WaybackMachineCDXServerAPI(
                url=domain,
                user_agent=Config.USER_AGENT,
                collapses=["urlkey"],
                filters=["statuscode:200", "mimetype:(text/html|application/javascript)"]
            )
            snapshots = {s.original for s in cdx.snapshots()}
            log_message("INFO", f"Found {len(snapshots)} URLs for {domain} from Wayback Machine.")
            all_urls.update(snapshots)
        except Exception as e:
            log_message("ERROR", f"Wayback Machine request failed for {domain}: {e}")
    return list(all_urls)

# --- Main Execution ---
async def main(args):
    global ARGS
    ARGS = args

    if args.ignore_hashes:
        try:
            with open(args.ignore_hashes, 'r', encoding='utf-8') as f:
                IGNORED_HASHES.update(line.strip() for line in f if line.strip())
                log_message("INFO", f"Loaded {len(IGNORED_HASHES)} hashes to ignore.")
        except IOError as e:
            log_message("ERROR", f"Unable to read ignore_hashes file '{args.ignore_hashes}': {e}")
            return
    
    if args.url_file == '-' or not sys.stdin.isatty():
        initial_urls = [line.strip() for line in sys.stdin if line.strip()]
    else:
        try:
            with open(args.url_file, 'r', encoding='utf-8') as f:
                initial_urls = [line.strip() for line in f if line.strip()]
        except IOError as e:
            log_message("ERROR", f"Unable to read file '{args.url_file}': {e}")
            return

    urls_to_scan = set(initial_urls)

    if args.wayback:
        wayback_urls = fetch_wayback_urls(list(urls_to_scan))
        urls_to_scan.update(wayback_urls)

    if args.no_clean_url is False:
        cleaned_urls = {url.split('?')[0].split('#')[0] for url in urls_to_scan}
        urls_to_scan = cleaned_urls

    final_urls = list(urls_to_scan)
    shuffle(final_urls)
    
    log_message("INFO", f"Starting scan with {len(final_urls)} unique URLs.")
    
    limits = httpx.Limits(max_connections=args.concurrency, max_keepalive_connections=args.concurrency)
    workers = asyncio.Semaphore(args.concurrency)
    
    async with httpx.AsyncClient(
        http2=True, limits=limits, follow_redirects=not args.no_redirects,
        verify=not args.insecure, headers={'User-Agent': Config.USER_AGENT}
    ) as client:
        tasks = [crawl_url(url, client, workers) for url in final_urls]
        await asyncio.gather(*tasks)

    log_message("INFO", "Scan finished.")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description="JSBot 2.1 - An autonomous script to find interesting JavaScript for security research.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    
    parser.add_argument('url_file', help="Path to a file with URLs, or '-' to read from stdin.")
    parser.add_argument('-s', '--save', action='store_true', help="Save unique JS files to disk, named by SHA256 hash.")
    parser.add_argument('-v', '--verbose', action='store_true', help="Enable verbose informational output.")
    parser.add_argument('--show-errors', action='store_true', help="Show error messages for failed requests.")
    parser.add_argument('-c', '--concurrency', type=int, default=20, help="Number of concurrent requests. (Default: 20)")
    parser.add_argument('--ignore-hashes', help="Path to a file containing SHA256 hashes of JS files to ignore.")
    parser.add_argument('--no-external', action='store_true', help="Don't fetch external JavaScript files.")
    parser.add_argument('--no-redirects', action='store_true', help="Don't follow HTTP redirects.")
    parser.add_argument('-k', '--insecure', action='store_true', help="Disable SSL/TLS certificate verification.")
    parser.add_argument('-w', '--wayback', action='store_true', help="Fetch historical URLs from the Wayback Machine for the given domains.")
    parser.add_argument('--no-clean-url', action='store_true', help="Don't clean URL parameters before scanning.")
    parser.add_argument('--link-mode', action='store_true', help="Only find and output links/URLs found in JS files.")
    parser.add_argument('--format-js', action='store_true', help="Beautify JS code before analysis (requires 'jsbeautifier').")

    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)
        
    args = parser.parse_args()

    if args.wayback and not WAYBACK_AVAILABLE:
        print("[!] [ERROR] --wayback requires 'waybackpy'. Install it with: pip install waybackpy", file=sys.stderr)
        sys.exit(1)
    if args.format_js and not JSBEAUTIFIER_AVAILABLE:
        print("[!] [ERROR] --format-js requires 'jsbeautifier'. Install it with: pip install jsbeautifier", file=sys.stderr)
        sys.exit(1)

    try:
        asyncio.run(main(args))
    except KeyboardInterrupt:
        print("\n[*] [INFO] Scan interrupted by user.", file=sys.stderr)
        sys.exit(0)
