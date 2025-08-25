import asyncio
import httpx
import re
import json
import sys
from hashlib import sha256
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import database

# --- Dependency Availability Checks ---
try:
    import jsbeautifier
    JSBEAUTIFIER_AVAILABLE = True
except ImportError:
    JSBEAUTIFIER_AVAILABLE = False

# --- Configuration ---
class Config:
    USER_AGENT = 'JSBot/3.0 (Autonomous Security Agent)'
    CONCURRENCY = 20
    REQUEST_TIMEOUT = 10
    FORMAT_JS = True
    VERBOSE = True
    SHOW_ERRORS = True
    # In a real system, these might come from a config file
    HTTP_HEADERS = {'User-Agent': USER_AGENT}
    COOKIE = None
    NO_REDIRECTS = False
    INSECURE = False

# --- Global State (Loaded from DB) ---
IGNORED_HASHES = set()

# --- Enhanced Regex for Security Checks ---
PATTERNS = {
    "DOM Clobbering": r"""\b(innerHTML|outerHTML|insertAdjacentHTML)\s*=""",
    "Open Redirect": r"""\b(location\s*[.=]\s*href|location\s*=\s*|location\.assign|location\.replace)\s*=""",
    "Eval Injection": r"""\b(eval|setTimeout|setInterval|execScript)\s*\(?""",
    "Cookie Manipulation": r"""\b(document\.cookie)\s*=""",
    "Potentially Unsafe Sink": r"""\b(postMessage|localStorage|sessionStorage|indexedDB|openDatabase)\b""",
    "Link Finder": r"""https?:\/\/[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b[-a-zA-Z0-9()@:%_\+.~#?&//=]*"""
}
JS_PATH_FINDER = r"""['"](/[^"']+\.js|[^"']+\.js)['"]"""

# --- Utility Functions ---

def get_sha256(data):
    return sha256(data.encode('utf-8')).hexdigest()

def format_javascript(js_code):
    if JSBEAUTIFIER_AVAILABLE and Config.FORMAT_JS:
        return jsbeautifier.beautify(js_code)
    return js_code

def log_message(level, message):
    if level == "INFO" and Config.VERBOSE:
        print(f"[*] [INFO] {message}", file=sys.stderr)
    elif level == "ERROR" and Config.SHOW_ERRORS:
        print(f"[!] [ERROR] {message}", file=sys.stderr)

# --- Core Logic ---

def check_script_safety(script_content, script_hash, url, script_url=None):
    """Checks script content against regex patterns and saves findings to DB."""
    # This function no longer supports link-mode directly, that would be a separate analysis step
    patterns_to_run = {k: v for k, v in PATTERNS.items() if k != "Link Finder"}

    for category, pattern in patterns_to_run.items():
        matches = re.finditer(pattern, script_content, re.IGNORECASE)
        for match in matches:
            line_number = script_content.count('\n', 0, match.start()) + 1
            matched_text = match.group(0)
            log_message("INFO", f"Found potential '{category}' in {script_url or 'inline'} from {url}")
            database.add_finding(script_hash, script_url or url, category, matched_text, line_number)

async def process_javascript(js_code, url, client, script_url=None):
    """Processes, analyzes, and saves a piece of JavaScript code to the DB."""
    if not js_code:
        return

    js_code = format_javascript(js_code)
    hashed_script = get_sha256(js_code)

    if hashed_script in IGNORED_HASHES:
        log_message("INFO", f"Skipping ignored script hash: {hashed_script}")
        return

    if database.script_exists(hashed_script):
        return

    database.add_script(hashed_script, js_code, script_url or url)
    log_message("INFO", f"Saved new script {hashed_script} from {script_url or 'inline'}")

    check_script_safety(js_code, hashed_script, url, script_url)
    
    await find_and_process_js_paths(js_code, url, client)

async def find_and_process_js_paths(content, base_url, client):
    """Finds potential JS file paths in content and schedules them for processing."""
    tasks = []
    for match in re.finditer(JS_PATH_FINDER, content):
        path = match.group(1)
        if path.startswith('//'):
            path = f"https:{path}"
            
        script_url = urljoin(base_url, path)
        
        try:
            # Note: This recursive processing can be deep. In a larger system,
            # this would add the new URL to the main queue instead of processing directly.
            script_response = await client.get(script_url, timeout=Config.REQUEST_TIMEOUT)
            tasks.append(process_javascript(script_response.text, base_url, client, script_url=script_url))
        except httpx.RequestError as e:
            log_message("ERROR", f"Failed to fetch discovered script {script_url}: {e}")
    await asyncio.gather(*tasks)

async def crawl_url(url, client, workers):
    """Crawls a single URL, extracts and processes scripts, and updates DB."""
    async with workers:
        try:
            database.update_url_status(url, 'scanning')
            log_message("INFO", f"Crawling: {url}")
            response = await client.get(url, timeout=Config.REQUEST_TIMEOUT)
            content_type = response.headers.get('content-type', '').lower()

            if 'javascript' in content_type:
                await process_javascript(response.text, url, client, script_url=str(response.url))
            elif 'html' in content_type:
                parser = BeautifulSoup(response.text, 'lxml')
                tasks = []
                # Inline scripts
                for script in parser.find_all('script'):
                    if not script.get('src'):
                        tasks.append(process_javascript(script.string or "", url, client))
                # External scripts
                for script in parser.find_all('script', src=True):
                    script_url = urljoin(str(response.url), script['src'])
                    try:
                        script_response = await client.get(script_url, timeout=Config.REQUEST_TIMEOUT)
                        tasks.append(process_javascript(script_response.text, url, client, script_url=script_url))
                    except httpx.RequestError as e:
                        log_message("ERROR", f"Failed to fetch script {script_url}: {e}")
                
                await asyncio.gather(*tasks)
                await find_and_process_js_paths(response.text, str(response.url), client)
            else:
                log_message("INFO", f"Skipping non-HTML/JS content at {url}")

            database.update_url_status(url, 'completed')
            log_message("INFO", f"Finished crawling: {url}")

        except httpx.RequestError as e:
            log_message("ERROR", f"HTTP request failed for {url}: {e}")
            database.update_url_status(url, 'error')
        except Exception as e:
            log_message("ERROR", f"An unexpected error occurred for {url}: {e}")
            database.update_url_status(url, 'error')

async def main():
    """Main execution function to run the scanner engine."""
    global IGNORED_HASHES
    IGNORED_HASHES = database.get_known_hashes()
    log_message("INFO", f"Loaded {len(IGNORED_HASHES)} hashes to ignore.")

    urls_to_scan = database.fetch_pending_urls(batch_size=Config.CONCURRENCY * 2)
    if not urls_to_scan:
        log_message("INFO", "No pending URLs found in the queue. Exiting.")
        return

    log_message("INFO", f"Starting scan with {len(urls_to_scan)} URLs.")
    
    headers = Config.HTTP_HEADERS
    if Config.COOKIE:
        headers['Cookie'] = Config.COOKIE

    limits = httpx.Limits(max_connections=Config.CONCURRENCY, max_keepalive_connections=Config.CONCURRENCY)
    workers = asyncio.Semaphore(Config.CONCURRENCY)
    
    async with httpx.AsyncClient(
        http2=True, limits=limits, follow_redirects=not Config.NO_REDIRECTS,
        verify=not Config.INSECURE, headers=headers
    ) as client:
        tasks = [crawl_url(url, client, workers) for url in urls_to_scan]
        await asyncio.gather(*tasks)

    log_message("INFO", "Scan batch finished.")

if __name__ == '__main__':
    if JSBEAUTIFIER_AVAILABLE == False:
        log_message("ERROR", "'jsbeautifier' is not installed. JS formatting will be disabled. Install with: pip install jsbeautifier")

    try:
        # Initialize the DB just in case it hasn't been done
        database.init_db()
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[*] [INFO] Scan interrupted by user.", file=sys.stderr)
        sys.exit(0)
