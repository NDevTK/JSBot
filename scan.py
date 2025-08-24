import argparse
import asyncio
import httpx
import re
import json
from hashlib import sha256
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import sys
from random import shuffle

# Optional dependencies check
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


# --- Configuration ---
class Config:
    ALLOWLIST_URLS = set([
        'https://www.gstatic.com/external_hosted/modernizr/csstransforms3d_csstransitions_search_webp_addtest_shiv_dontmin/modernizr-custom.js',
        'https://www.gstatic.com/external_hosted/lottie/lottie.js', 'https://cdn.jsdelivr.net/npm/bootstrap@5.2.1/dist/js/bootstrap.bundle.min.js',
        'https://www.google-analytics.com/analytics.js', 'https://ajax.googleapis.com/ajax/libs/jqueryui/1.13.2/jquery-ui.min.js',
        'https://ajax.googleapis.com/ajax/libs/jquery/3.6.1/jquery.min.js', 'https://www.gstatic.com/external_hosted/modernizr/modernizr.js',
        'https://www.gstatic.com/external_hosted/scrollmagic/ScrollMagic.min.js', 'https://www.gstatic.com/external_hosted/scrollmagic/animation.gsap.min.js',
        'https://www.gstatic.com/external_hosted/picturefill/picturefill.min.js', 'https://www.gstatic.com/external_hosted/hammerjs/v2_0_2/hammer.min.js',
        'https://www.gstatic.com/external_hosted/gsap/v1_18_0/TweenMax.min.js', 'https://ssl.google-analytics.com/ga.js'
    ])
    USER_AGENT = 'JSBot/2.0 (Security Research)'


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
    for category, pattern in PATTERNS.items():
        if category == "Link Finder" and not ARGS.link_mode:
            continue

        matches = re.finditer(pattern, script_content, re.IGNORECASE)
        for match in matches:
            finding = {
                "source_url": url,
                "script_url": script_url or "inline",
                "category": category,
                "matched_text": match.group(0),
                "line_number": script_content.count('\n', 0, match.start()) + 1
            }
            if ARGS.link_mode and category == "Link Finder":
                hashed_link = get_sha256(match.group(0))
                if hashed_link not in SEEN_LINKS:
                    log_message("FINDING", finding)
                    SEEN_LINKS.add(hashed_link)
            elif category != "Link Finder":
                findings.append(finding)

    return findings

# --- Core Logic ---

async def process_javascript(js_code, url, client, script_url=None):
    """Processes and analyzes a piece of JavaScript code."""
    if not js_code:
        return

    js_code = format_javascript(js_code)
    hashed_script = get_sha256(js_code)

    if hashed_script in SEEN_SCRIPTS:
        return
    SEEN_SCRIPTS.add(hashed_script)

    findings = check_script_safety(js_code, url, script_url)
    for finding in findings:
        log_message("FINDING", finding)

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
                await process_javascript(response.text, url, client, script_url=str(response.url))
                return
            if 'html' not in content_type:
                log_message("INFO", f"Skipping non-HTML content at {url}")
                return

            parser = BeautifulSoup(response.text, 'lxml')
            tasks = []
            for script in parser.find_all('script'):
                script_src = script.get('src')
                if script_src:
                    if not ARGS.external:
                        continue
                    script_url = urljoin(url, script_src)
                    if script_url in Config.ALLOWLIST_URLS:
                        continue
                    
                    hashed_script_url = get_sha256(script_url)
                    if hashed_script_url in CHECKED_JS_URLS:
                        continue
                    CHECKED_JS_URLS.add(hashed_script_url)

                    try:
                        script_response = await client.get(script_url, timeout=10)
                        tasks.append(process_javascript(script_response.text, url, client, script_url=script_url))
                    except httpx.RequestError as e:
                        log_message("ERROR", f"Failed to fetch script {script_url}: {e}")

                else:
                    tasks.append(process_javascript(script.string, url, client))
            
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

    all_urls = []
    for domain in domains:
        log_message("INFO", f"Fetching wayback URLs for: {domain}")
        cdx = WaybackMachineCDXServerAPI(
            url=domain,
            user_agent=Config.USER_AGENT,
            collapses=["urlkey"],
            filters=["statuscode:200", "mimetype:text/html", "mimetype:application/javascript"]
        )
        try:
            snapshots = [s.original for s in cdx.snapshots()]
            log_message("INFO", f"Found {len(snapshots)} URLs for {domain} from Wayback Machine.")
            all_urls.extend(snapshots)
        except Exception as e:
            log_message("ERROR", f"Wayback Machine request failed for {domain}: {e}")

    return list(set(all_urls))

# --- Main Execution ---
async def main(args):
    global ARGS
    ARGS = args
    
    try:
        with open(args.url_file, 'r', encoding='utf-8') as f:
            initial_urls = [line.strip() for line in f if line.strip()]
    except IOError as e:
        log_message("ERROR", f"Unable to read file '{args.url_file}': {e}")
        return

    urls_to_scan = list(set(initial_urls))

    if args.wayback:
        wayback_urls = fetch_wayback_urls(urls_to_scan)
        urls_to_scan.extend(wayback_urls)
        urls_to_scan = list(set(urls_to_scan))

    if args.clean_url:
        urls_to_scan = [url.split('?')[0].split('#')[0] for url in urls_to_scan]
        urls_to_scan = list(set(urls_to_scan))

    shuffle(urls_to_scan)
    
    log_message("INFO", f"Starting scan with {len(urls_to_scan)} unique URLs.")
    
    limits = httpx.Limits(max_connections=args.concurrency, max_keepalive_connections=args.concurrency)
    workers = asyncio.Semaphore(args.concurrency)
    
    async with httpx.AsyncClient(
        http2=True,
        limits=limits,
        follow_redirects=args.redirects,
        verify=not args.insecure,
        headers={'User-Agent': Config.USER_AGENT}
    ) as client:
        tasks = [crawl_url(url, client, workers) for url in urls_to_scan]
        await asyncio.gather(*tasks)

    log_message("INFO", "Scan finished.")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="JSBot 2.0 - A script to find interesting JavaScript for security research.")
    
    parser.add_argument('url_file', help="Path to a file containing URLs to scan (one per line).")
    parser.add_argument('-s', '--save', action='store_true', help="Save unique JS files to disk.")
    parser.add_argument('-v', '--verbose', action='store_true', help="Enable verbose informational output.")
    parser.add_argument('--show-errors', action='store_true', help="Show error messages for failed requests.")
    parser.add_argument('-c', '--concurrency', type=int, default=20, help="Number of concurrent requests.")
    parser.add_argument('--no-external', dest='external', action='store_false', default=True, help="Don't fetch external JavaScript files.")
    parser.add_argument('--no-redirects', dest='redirects', action='store_false', default=True, help="Don't follow HTTP redirects.")
    parser.add_argument('-k', '--insecure', action='store_true', help="Disable SSL/TLS certificate verification.")
    parser.add_argument('-w', '--wayback', action='store_true', help="Fetch URLs from the Wayback Machine for the given domains.")
    parser.add_argument('--no-clean-url', dest='clean_url', action='store_false', default=True, help="Don't clean URL parameters before scanning.")
    parser.add_argument('--link-mode', action='store_true', help="Only find and output links/URLs found in JS files.")
    parser.add_argument('--format-js', action='store_true', help="Beautify JS code before analysis (requires 'jsbeautifier').")

    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)
        
    args = parser.parse_args()

    if args.wayback and not WAYBACK_AVAILABLE:
        print("[!] [ERROR] --wayback requires 'waybackpy' to be installed (pip install waybackpy).", file=sys.stderr)
        sys.exit(1)
    if args.format_js and not JSBEAUTIFIER_AVAILABLE:
        print("[!] [ERROR] --format-js requires 'jsbeautifier' to be installed (pip install jsbeautifier).", file=sys.stderr)
        sys.exit(1)

    try:
        asyncio.run(main(args))
    except KeyboardInterrupt:
        print("\n[*] [INFO] Scan interrupted by user.", file=sys.stderr)
        sys.exit(0)
