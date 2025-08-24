import argparse
import asyncio
import httpx
import re
import json
import sys
from hashlib import sha256
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
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
    USER_AGENT = 'JSBot/3.0 (Autonomous Security Agent)'

# --- Enhanced Regex for Security Checks ---
PATTERNS = {
    "DOM Clobbering": r"""\b(innerHTML|outerHTML|insertAdjacentHTML)\s*=""",
    "Open Redirect": r"""\b(location\s*[.=]\s*href|location\s*=\s*|location\.assign|location\.replace)\s*=""",
    "Eval Injection": r"""\b(eval|setTimeout|setInterval|execScript)\s*\(?""",
    "Cookie Manipulation": r"""\b(document\.cookie)\s*=""",
    "Potentially Unsafe Sink": r"""\b(postMessage|localStorage|sessionStorage|indexedDB|openDatabase)\b""",
    "Link Finder": r"""https?:\/\/[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b[-a-zA-Z0-9()@:%_\+.~#?&//=]*"""
}
# Regex to find relative or absolute paths to JS files within content
JS_PATH_FINDER = r"""['"](/[^"']+\.js|[^"']+\.js)['"]"""

# --- Utility Functions ---

def get_sha256(data):
    """Computes SHA256 hash of the given data."""
    return sha256(data.encode('utf-8')).hexdigest()

def format_javascript(js_code):
    """Beautifies JavaScript code. Does not de-obfuscate."""
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

def check_script_safety(script_content, script_hash, url, script_url=None):
    """Checks script content against defined regex patterns."""
    patterns_to_run = {"Link Finder": PATTERNS["Link Finder"]} if ARGS.link_mode else {k: v for k, v in PATTERNS.items() if k != "Link Finder"}

    for category, pattern in patterns_to_run.items():
        matches = re.finditer(pattern, script_content, re.IGNORECASE)
        for match in matches:
            finding = {
                "source_url": url,
                "script_url": script_url or "inline",
                "script_hash": script_hash,  # CRITICAL: Link the finding to the script content
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

async def process_javascript(js_code, url, client, script_url=None):
    """Processes, analyzes, and saves a piece of JavaScript code."""
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

    check_script_safety(js_code, hashed_script, url, script_url)

    if ARGS.save:
        try:
            with open(f"{hashed_script}.js", 'w', encoding='utf-8') as f:
                f.write(f"// Source: {url}\n// Script URL: {script_url or 'inline'}\n\n{js_code}")
        except IOError as e:
            log_message("ERROR", f"Failed to save script {hashed_script}: {e}")
    
    # Enhanced Script Discovery: Look for more JS paths inside this script
    await find_and_process_js_paths(js_code, url, client)


async def find_and_process_js_paths(content, base_url, client):
    """Finds potential JS file paths in content and schedules them for processing."""
    tasks = []
    for match in re.finditer(JS_PATH_FINDER, content):
        path = match.group(1)
        if path.startswith('//'):
            path = f"https:{path}"
            
        script_url = urljoin(base_url, path)
        hashed_url = get_sha256(script_url)
        
        if hashed_url in CHECKED_JS_URLS:
            continue
        CHECKED_JS_URLS.add(hashed_url)

        log_message("INFO", f"Discovered potential JS file via regex: {script_url}")
        try:
            script_response = await client.get(script_url, timeout=10)
            tasks.append(process_javascript(script_response.text, base_url, client, script_url=script_url))
        except httpx.RequestError as e:
            log_message("ERROR", f"Failed to fetch discovered script {script_url}: {e}")
    await asyncio.gather(*tasks)

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

            # Direct JS file
            if 'javascript' in content_type:
                await process_javascript(response.text, url, client, script_url=str(response.url))
                return
            
            # HTML content
            if 'html' in content_type:
                parser = BeautifulSoup(response.text, 'lxml')
                tasks = []
                # Process inline scripts
                for script in parser.find_all('script'):
                    if not script.get('src'):
                        tasks.append(process_javascript(script.string or "", url, client))
                # Process external scripts from <script src="...">
                for script in parser.find_all('script', src=True):
                    script_url = urljoin(str(response.url), script['src'])
                    hashed_script_url = get_sha256(script_url)
                    if hashed_script_url in CHECKED_JS_URLS:
                        continue
                    CHECKED_JS_URLS.add(hashed_script_url)
                    try:
                        script_response = await client.get(script_url, timeout=10)
                        tasks.append(process_javascript(script_response.text, url, client, script_url=script_url))
                    except httpx.RequestError as e:
                        log_message("ERROR", f"Failed to fetch script {script_url}: {e}")
                
                await asyncio.gather(*tasks)
                # Enhanced discovery on the raw HTML body
                await find_and_process_js_paths(response.text, str(response.url), client)

            else:
                log_message("INFO", f"Skipping non-HTML/JS content at {url}")

        except httpx.RequestError as e:
            log_message("ERROR", f"HTTP request failed for {url}: {e}")
        except Exception as e:
            log_message("ERROR", f"An unexpected error occurred for {url}: {e}")


def fetch_wayback_urls(domains):
    """Fetches historical URLs from the Wayback Machine."""
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
                url=domain, user_agent=Config.USER_AGENT, collapses=["urlkey"],
                filters=["statuscode:200", "mimetype:(text/html|application/javascript)"]
            )
            snapshots = {s.original for s in cdx.snapshots()}
            log_message("INFO", f"Found {len(snapshots)} URLs for {domain} from Wayback Machine.")
            all_urls.update(snapshots)
        except Exception as e:
            log_message("ERROR", f"Wayback Machine request failed for {domain}: {e}")
    return list(all_urls)

async def main(args):
    """Main execution function."""
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

    if not args.no_clean_url:
        cleaned_urls = {url.split('?')[0].split('#')[0] for url in urls_to_scan}
        urls_to_scan = cleaned_urls

    final_urls = list(urls_to_scan)
    shuffle(final_urls)
    
    log_message("INFO", f"Starting scan with {len(final_urls)} unique URLs.")
    
    # --- Client Configuration with Custom Headers/Cookies ---
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
        tasks = [crawl_url(url, client, workers) for url in final_urls]
        await asyncio.gather(*tasks)

    log_message("INFO", "Scan finished.")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description="JSBot 3.0 - An autonomous script to find interesting JavaScript for security research.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    
    parser.add_argument('url_file', help="Path to a file with URLs, or '-' to read from stdin.")
    
    scan_group = parser.add_argument_group('Scan Configuration')
    scan_group.add_argument('-c', '--concurrency', type=int, default=20, help="Number of concurrent requests. (Default: 20)")
    scan_group.add_argument('-w', '--wayback', action='store_true', help="Fetch historical URLs from the Wayback Machine.")
    scan_group.add_argument('--no-clean-url', action='store_true', help="Don't clean URL parameters before scanning.")
    scan_group.add_argument('--link-mode', action='store_true', help="Only find and output links/URLs found in JS files.")

    http_group = parser.add_argument_group('HTTP Configuration')
    http_group.add_argument('-H', '--header', action='append', help="Add a custom header (e.g., 'X-API-Key: 123'). Can be used multiple times.")
    http_group.add_argument('-b', '--cookie', help="Set the cookie header string.")
    http_group.add_argument('--no-redirects', action='store_true', help="Don't follow HTTP redirects.")
    http_group.add_argument('-k', '--insecure', action='store_true', help="Disable SSL/TLS certificate verification.")

    output_group = parser.add_argument_group('Output & Analysis')
    output_group.add_argument('-s', '--save', action='store_true', help="Save unique JS files to disk, named by SHA256 hash.")
    output_group.add_argument('-v', '--verbose', action='store_true', help="Enable verbose informational output.")
    output_group.add_argument('--show-errors', action='store_true', help="Show error messages for failed requests.")
    output_group.add_argument('--ignore-hashes', help="Path to a file containing SHA256 hashes of JS files to ignore.")
    output_group.add_argument('--format-js', action='store_true', help="Beautify JS code before analysis (requires 'jsbeautifier').")

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
