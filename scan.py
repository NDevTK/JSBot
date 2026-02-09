import argparse
import asyncio
import httpx
import re
import json
import sys
from hashlib import sha256
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs
from random import shuffle
from xml.etree import ElementTree

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
DISCOVERED_URLS = set()
SEEN_FINDINGS = set()  # Dedup findings by (hash, sink, source, lines)

# --- Configuration ---
class Config:
    USER_AGENT = 'JSBot/4.0 (Autonomous Security Agent)'

# --- Taint Analysis: Sources & Sinks ---
SOURCES = {
    "location.hash":        r"""\blocation\.hash\b""",
    "location.search":      r"""\blocation\.search\b""",
    "location.href_read":   r"""\blocation\.href\b(?!\s*=)""",
    "location.pathname":    r"""\blocation\.pathname\b""",
    "document.URL":         r"""\bdocument\.URL\b""",
    "document.documentURI": r"""\bdocument\.documentURI\b""",
    "document.referrer":    r"""\bdocument\.referrer\b""",
    "window.name":          r"""\bwindow\.name\b""",
    "postMessage data":     r"""\b(?:event|e|evt|msg)\.data\b""",
    "URLSearchParams":      r"""\bURLSearchParams\b""",
    "getItem":              r"""\b(?:localStorage|sessionStorage)\.getItem\b""",
    "cookie_read":          r"""\bdocument\.cookie\b(?!\s*=)""",
    "input.value":          r"""\b(?:target|currentTarget|srcElement)\.value\b""",
}

SINKS = {
    "DOM XSS": {
        "pattern": r"""\b(?:innerHTML|outerHTML)\s*=""",
        "severity": 9,
    },
    "insertAdjacentHTML": {
        "pattern": r"""\binsertAdjacentHTML\s*\(""",
        "severity": 9,
    },
    "document.write": {
        "pattern": r"""\bdocument\.(?:write|writeln)\s*\(""",
        "severity": 9,
    },
    "Eval Injection": {
        "pattern": r"""\b(?:eval|Function)\s*\(""",
        "severity": 10,
    },
    "setTimeout/setInterval string": {
        "pattern": r"""\b(?:setTimeout|setInterval)\s*\(\s*['"` ]""",
        "severity": 8,
    },
    "Open Redirect": {
        "pattern": r"""\b(?:location\s*=|location\.assign|location\.replace|location\.href\s*=)\s*""",
        "severity": 7,
    },
    "jQuery HTML Sink": {
        "pattern": r"""\$\s*\(.*?\)\s*\.\s*(?:html|append|prepend|after|before)\s*\(""",
        "severity": 8,
    },
    "Framework Sink": {
        "pattern": r"""\b(?:v-html|dangerouslySetInnerHTML)\b""",
        "severity": 8,
    },
    "Cookie Write": {
        "pattern": r"""\bdocument\.cookie\s*=""",
        "severity": 5,
    },
    "postMessage": {
        "pattern": r"""\.postMessage\s*\(""",
        "severity": 4,
    },
}

LINK_FINDER_PATTERN = r"""https?:\/\/[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b[-a-zA-Z0-9()@:%_\+.~#?&//=]*"""

JS_PATH_FINDER = r"""['"](/[^"']+\.js|[^"']+\.js)['"]"""

# --- URL Scoring for Smart Target Discovery ---
PATH_KEYWORDS = {
    'admin', 'api', 'debug', 'test', 'staging', 'internal', 'upload',
    'callback', 'redirect', 'oauth', 'login', 'search', 'proxy',
    'gateway', 'graphql', 'config', 'setup', 'dashboard', 'console',
    'manage', 'cgi-bin', 'servlet', 'handler', 'endpoint', 'webhook',
}

PARAM_KEYWORDS = {
    'url', 'redirect', 'callback', 'next', 'return', 'goto', 'target',
    'path', 'ref', 'link', 'q', 'search', 'query', 'data', 'file',
    'page', 'view', 'template', 'html', 'uri', 'dest', 'continue',
    'returnto', 'return_url', 'redirect_uri', 'next_url',
}

SUBDOMAIN_KEYWORDS = {
    'dev', 'staging', 'test', 'api', 'admin', 'internal', 'beta',
    'sandbox', 'debug', 'preview', 'canary', 'uat', 'qa', 'pre',
    'stg', 'demo', 'lab', 'old', 'legacy', 'backup',
}

def score_url(url):
    """Scores a URL by how likely it is to contain vulnerabilities."""
    score = 0
    try:
        parsed = urlparse(url)
    except Exception:
        return 0

    # Path keyword scoring (+3 each) — match whole path segments only
    path_segments = set(parsed.path.lower().strip('/').split('/'))
    score += 3 * len(path_segments & PATH_KEYWORDS)

    # Parameter name scoring (+5 each)
    params = parse_qs(parsed.query)
    for param_name in params:
        if param_name.lower() in PARAM_KEYWORDS:
            score += 5

    # Has any query parameters at all (+2)
    if parsed.query:
        score += 2

    # Subdomain scoring
    hostname = parsed.hostname or ''
    parts = hostname.split('.')
    if len(parts) > 2:
        subdomain = '.'.join(parts[:-2]).lower()
        if subdomain and subdomain != 'www':
            score += 2  # Non-www subdomain bonus
            for kw in SUBDOMAIN_KEYWORDS:
                if kw in subdomain:
                    score += 4
                    break  # Only count once

    return score


# --- Scope Splitting for Taint Analysis ---

def split_into_scopes(js_code):
    """Splits JavaScript into function-level scope blocks.

    Uses a lightweight state machine to track brace depth while skipping
    braces inside strings, template literals, and comments. Returns a list
    of (start_line, end_line, block_text) tuples. Falls back to treating
    the entire file as one scope if no function boundaries are found.
    """
    lines = js_code.split('\n')
    func_pattern = re.compile(
        r'(?:'
        r'function\s*\w*\s*\('          # function declarations
        r'|'
        r'(?:\w+|\))\s*=>\s*\{'         # arrow functions with block body
        r'|'
        r'\w+\s*\([^)]*\)\s*\{'         # method definitions
        r')'
    )

    func_starts = []
    for i, line in enumerate(lines):
        for _ in func_pattern.finditer(line):
            func_starts.append(i)

    if not func_starts:
        return [(0, len(lines) - 1, js_code)]

    scopes = []
    code = js_code
    covered_ranges = []  # Track what lines are inside function scopes

    for func_line in func_starts:
        line_start = sum(len(lines[j]) + 1 for j in range(func_line))
        brace_pos = code.find('{', line_start)
        if brace_pos == -1:
            continue

        depth = 0
        pos = brace_pos
        in_single_quote = False
        in_double_quote = False
        in_template = False
        in_line_comment = False
        in_block_comment = False
        end_pos = len(code)

        while pos < len(code):
            ch = code[pos]
            next_ch = code[pos + 1] if pos + 1 < len(code) else ''

            if in_line_comment:
                if ch == '\n':
                    in_line_comment = False
            elif in_block_comment:
                if ch == '*' and next_ch == '/':
                    in_block_comment = False
                    pos += 1
            elif in_single_quote:
                if ch == '\\':
                    pos += 1
                elif ch == "'":
                    in_single_quote = False
            elif in_double_quote:
                if ch == '\\':
                    pos += 1
                elif ch == '"':
                    in_double_quote = False
            elif in_template:
                if ch == '\\':
                    pos += 1
                elif ch == '`':
                    in_template = False
            else:
                if ch == '/' and next_ch == '/':
                    in_line_comment = True
                    pos += 1
                elif ch == '/' and next_ch == '*':
                    in_block_comment = True
                    pos += 1
                elif ch == "'":
                    in_single_quote = True
                elif ch == '"':
                    in_double_quote = True
                elif ch == '`':
                    in_template = True
                elif ch == '{':
                    depth += 1
                elif ch == '}':
                    depth -= 1
                    if depth == 0:
                        end_pos = pos
                        break
            pos += 1

        block_text = code[brace_pos:end_pos + 1]
        block_start_line = code[:brace_pos].count('\n')
        block_end_line = code[:end_pos + 1].count('\n')
        scopes.append((block_start_line, block_end_line, block_text))
        covered_ranges.append((block_start_line, block_end_line))

    # Build global scope from lines NOT inside any function
    global_lines = []
    for i, line in enumerate(lines):
        inside = any(start <= i <= end for start, end in covered_ranges)
        if not inside:
            global_lines.append(line)
        else:
            global_lines.append('')  # Preserve line numbering
    global_text = '\n'.join(global_lines)
    if global_text.strip():
        scopes.append((0, len(lines) - 1, global_text))

    return scopes


# --- Taint Flow Analysis ---

def get_context_lines(js_code, line_number, context_size):
    """Extracts surrounding lines for a finding."""
    lines = js_code.split('\n')
    start = max(0, line_number - context_size - 1)
    end = min(len(lines), line_number + context_size)
    return [lines[i].rstrip() for i in range(start, end) if lines[i].strip()]


def analyze_taint_flow(script_content, script_hash, url, script_url=None):
    """Performs source-to-sink taint analysis within function scopes."""
    context_size = ARGS.context_lines if hasattr(ARGS, 'context_lines') else 3
    scopes = split_into_scopes(script_content)

    for scope_start, scope_end, block_text in scopes:
        # Find all sources in this scope
        found_sources = []
        for source_name, source_pattern in SOURCES.items():
            for m in re.finditer(source_pattern, block_text, re.IGNORECASE):
                source_line = scope_start + block_text[:m.start()].count('\n') + 1
                found_sources.append({
                    "category": source_name,
                    "match": m.group(0),
                    "line": source_line,
                })

        # Find all sinks in this scope
        for sink_name, sink_info in SINKS.items():
            for m in re.finditer(sink_info["pattern"], block_text, re.IGNORECASE):
                sink_line = scope_start + block_text[:m.start()].count('\n') + 1

                if found_sources:
                    closest_source = min(found_sources, key=lambda s: abs(s["line"] - sink_line))

                    # Dedup: skip if we already reported this exact flow
                    finding_key = f"{script_hash}:{sink_name}:{sink_line}:{closest_source['category']}:{closest_source['line']}"
                    if finding_key in SEEN_FINDINGS:
                        continue
                    SEEN_FINDINGS.add(finding_key)

                    finding = {
                        "source_url": url,
                        "script_url": script_url or "inline",
                        "script_hash": script_hash,
                        "finding_type": "taint_flow",
                        "sink_category": sink_name,
                        "sink_match": m.group(0),
                        "sink_line": sink_line,
                        "source_category": closest_source["category"],
                        "source_match": closest_source["match"],
                        "source_line": closest_source["line"],
                        "severity": sink_info["severity"],
                        "context": get_context_lines(script_content, sink_line, context_size),
                    }
                    log_message("FINDING", finding)
                else:
                    # Dedup sink-only findings too
                    finding_key = f"{script_hash}:{sink_name}:{sink_line}:none:none"
                    if finding_key in SEEN_FINDINGS:
                        continue
                    SEEN_FINDINGS.add(finding_key)

                    finding = {
                        "source_url": url,
                        "script_url": script_url or "inline",
                        "script_hash": script_hash,
                        "finding_type": "sink_only",
                        "sink_category": sink_name,
                        "sink_match": m.group(0),
                        "sink_line": sink_line,
                        "source_category": None,
                        "source_match": None,
                        "source_line": None,
                        "severity": sink_info["severity"] // 2,
                        "context": get_context_lines(script_content, sink_line, context_size),
                    }
                    log_message("FINDING", finding)


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
    """Runs taint analysis or link extraction on a script."""
    if ARGS.link_mode:
        for match in re.finditer(LINK_FINDER_PATTERN, script_content, re.IGNORECASE):
            finding = {
                "source_url": url,
                "script_url": script_url or "inline",
                "script_hash": script_hash,
                "category": "Link Finder",
                "matched_text": match.group(0),
                "line_number": script_content.count('\n', 0, match.start()) + 1,
            }
            hashed_link = get_sha256(match.group(0))
            if hashed_link not in SEEN_LINKS:
                log_message("FINDING", finding)
                SEEN_LINKS.add(hashed_link)
        return

    analyze_taint_flow(script_content, script_hash, url, script_url)


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


# --- Target Discovery ---

async def discover_paths(domain, client):
    """Discovers URLs from robots.txt and sitemap.xml for a domain."""
    discovered = set()
    base = f"https://{domain}"

    # robots.txt — disallowed paths are often the most interesting
    try:
        resp = await client.get(f"{base}/robots.txt", timeout=10)
        if resp.status_code == 200:
            for line in resp.text.splitlines():
                line = line.strip()
                if line.lower().startswith(('disallow:', 'allow:')):
                    path = line.split(':', 1)[1].strip()
                    if path and path != '/':
                        clean_path = path.replace('*', '').rstrip('$')
                        if clean_path:
                            discovered.add(urljoin(base, clean_path))
            log_message("INFO", f"Found {len(discovered)} paths from robots.txt for {domain}")
    except Exception as e:
        log_message("ERROR", f"Failed to fetch robots.txt for {domain}: {e}")

    # sitemap.xml
    sitemap_urls = set()
    try:
        resp = await client.get(f"{base}/sitemap.xml", timeout=10)
        if resp.status_code == 200:
            try:
                root = ElementTree.fromstring(resp.text)
                ns = ''
                if root.tag.startswith('{'):
                    ns = root.tag.split('}')[0] + '}'
                for loc in root.iter(f'{ns}loc'):
                    if loc.text:
                        sitemap_urls.add(loc.text.strip())
                log_message("INFO", f"Found {len(sitemap_urls)} URLs from sitemap.xml for {domain}")
            except ElementTree.ParseError:
                log_message("ERROR", f"Failed to parse sitemap.xml for {domain}")
    except Exception as e:
        log_message("ERROR", f"Failed to fetch sitemap.xml for {domain}: {e}")

    discovered.update(sitemap_urls)
    return discovered


def spider_links(response_text, response_url, base_domain):
    """Extracts same-domain <a href> links from an HTML page."""
    discovered = set()
    try:
        parser = BeautifulSoup(response_text, 'lxml')
        for a_tag in parser.find_all('a', href=True):
            href = a_tag['href'].strip()
            if not href or href.startswith(('#', 'javascript:', 'mailto:', 'tel:')):
                continue
            full_url = urljoin(str(response_url), href)
            parsed = urlparse(full_url)
            if parsed.hostname and base_domain in parsed.hostname:
                discovered.add(full_url)
    except Exception:
        pass
    return discovered


async def crawl_url(url, client, workers, spider_queue=None):
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
                for script in parser.find_all('script'):
                    if not script.get('src'):
                        tasks.append(process_javascript(script.string or "", url, client))
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
                await find_and_process_js_paths(response.text, str(response.url), client)

                # Spider mode: collect same-domain links
                if spider_queue is not None and ARGS.spider:
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

    # Score URLs BEFORE cleaning so parameter scores aren't lost
    url_scores = {url: score_url(url) for url in urls_to_scan}

    # Clean URLs (strip query params and fragments) — carry forward max score
    if not args.no_clean_url:
        cleaned_scores = {}
        for url in urls_to_scan:
            cleaned = url.split('?')[0].split('#')[0]
            if cleaned not in cleaned_scores or url_scores[url] > cleaned_scores[cleaned]:
                cleaned_scores[cleaned] = url_scores[url]
        urls_to_scan = set(cleaned_scores.keys())
        url_scores = cleaned_scores

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

        # --- Active Discovery: robots.txt & sitemap.xml ---
        if args.discover:
            domains = set()
            for url in urls_to_scan:
                parsed = urlparse(url)
                if parsed.hostname:
                    domains.add(parsed.hostname)
            log_message("INFO", f"Running path discovery on {len(domains)} domains...")
            discover_tasks = [discover_paths(domain, client) for domain in domains]
            results = await asyncio.gather(*discover_tasks)
            for path_set in results:
                for new_url in path_set:
                    if new_url not in url_scores:
                        url_scores[new_url] = score_url(new_url)
                urls_to_scan.update(path_set)
            log_message("INFO", f"Discovery added {sum(len(r) for r in results)} new URLs.")

        # --- URL Scoring & Sorting (using cached scores) ---
        final_urls = list(urls_to_scan)
        if args.smart_sort:
            final_urls.sort(key=lambda u: url_scores.get(u, 0), reverse=True)
            critical = sum(1 for u in final_urls if url_scores.get(u, 0) > 10)
            interesting = sum(1 for u in final_urls if 5 <= url_scores.get(u, 0) <= 10)
            baseline = sum(1 for u in final_urls if url_scores.get(u, 0) < 5)
            log_message("INFO", f"URL scores: {critical} critical (>10), {interesting} interesting (5-10), {baseline} baseline (0-4)")
        else:
            shuffle(final_urls)

        if args.min_score > 0:
            before = len(final_urls)
            final_urls = [u for u in final_urls if url_scores.get(u, 0) >= args.min_score]
            log_message("INFO", f"Score filter: {before} -> {len(final_urls)} URLs (min_score={args.min_score})")

        log_message("INFO", f"Starting scan with {len(final_urls)} unique URLs.")

        # --- Main Crawl ---
        spider_queue = [] if args.spider else None
        tasks = [crawl_url(url, client, workers, spider_queue) for url in final_urls]
        await asyncio.gather(*tasks)

        # --- Spider Pass: crawl discovered links ---
        if spider_queue:
            log_message("INFO", f"Spider discovered {len(spider_queue)} new URLs. Scanning...")
            if args.smart_sort:
                spider_queue.sort(key=score_url, reverse=True)
            if args.min_score > 0:
                spider_queue = [u for u in spider_queue if score_url(u) >= args.min_score]
            spider_tasks = [crawl_url(url, client, workers) for url in spider_queue]
            await asyncio.gather(*spider_tasks)

    log_message("INFO", "Scan finished.")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description="JSBot 4.0 - Autonomous JavaScript security scanner with taint analysis and smart target discovery.",
        formatter_class=argparse.RawTextHelpFormatter
    )

    parser.add_argument('url_file', help="Path to a file with URLs, or '-' to read from stdin.")

    scan_group = parser.add_argument_group('Scan Configuration')
    scan_group.add_argument('-c', '--concurrency', type=int, default=20, help="Number of concurrent requests. (Default: 20)")
    scan_group.add_argument('-w', '--wayback', action='store_true', help="Fetch historical URLs from the Wayback Machine.")
    scan_group.add_argument('--no-clean-url', action='store_true', help="Don't clean URL parameters before scanning.")
    scan_group.add_argument('--link-mode', action='store_true', help="Only find and output links/URLs found in JS files.")

    taint_group = parser.add_argument_group('Taint Analysis')
    taint_group.add_argument('--context-lines', type=int, default=3, help="Lines of context around findings. (Default: 3)")

    discovery_group = parser.add_argument_group('Target Discovery')
    discovery_group.add_argument('--smart-sort', action='store_true', help="Score and prioritize URLs by vulnerability likelihood.")
    discovery_group.add_argument('--discover', action='store_true', help="Discover paths from robots.txt and sitemap.xml.")
    discovery_group.add_argument('--spider', action='store_true', help="Follow <a href> links to discover deeper endpoints.")
    discovery_group.add_argument('--min-score', type=int, default=0, help="Skip URLs scoring below this threshold. (Default: 0)")

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
