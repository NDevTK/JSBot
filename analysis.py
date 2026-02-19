"""Regex-based script analysis — scores scripts by interestingness for manual review."""
import re
import asyncio
import httpx
from hashlib import sha256
from urllib.parse import urljoin, urlparse

from patterns import (SOURCES, SINKS, TAINT_SINKS, JS_PATH_FINDER,
                      ENDPOINT_PATTERNS, INTERESTING_STRING_PATTERNS,
                      PROTOTYPE_POLLUTION_SINKS, PROTOTYPE_POLLUTION_SOURCES)
from output import log_message, SEEN_FINDINGS, SCRIPT_METADATA
from scoring import looks_minified, _is_known_library, check_known_cves
from sourcemaps import try_fetch_sourcemap, get_original_source
from anomaly import ScriptRecord

# --- Global State (managed by scan.py) ---
SEEN_SCRIPTS = set()
CHECKED_JS_URLS = set()
ARGS = None  # Set by scan.py at startup

# Pre-compiled regex: matches any backslash-escaped character (\. \/ etc.)
_RE_ESCAPED = re.compile(r'\\.')


def get_sha256(data):
    """Computes SHA256 hash of the given data."""
    return sha256(data.encode('utf-8')).hexdigest()


# --- Internal signal scoring (not exposed as separate findings) ---


_POSTMESSAGE_HANDLER_RE = re.compile(
    r"""addEventListener\s*\(\s*['"]message['"]"""
    r"""|onmessage\s*=""",
    re.IGNORECASE,
)
_STRONG_ORIGIN_CHECK_RE = re.compile(
    r"""\.origin\s*(?:===?|!==?)""",
    re.IGNORECASE,
)
_WEAK_ORIGIN_CHECK_RE = re.compile(
    r"""\.origin\s*\.(?:includes|startsWith|match|indexOf|endsWith)\s*\(""",
    re.IGNORECASE,
)


def _score_postmessage(script_content, is_minified=False):
    """Score based on postMessage handlers with missing or weak origin checks."""
    window_size = 1500 if is_minified else 5000
    best = 0
    for m in _POSTMESSAGE_HANDLER_RE.finditer(script_content):
        window_start = m.start()
        window_end = min(len(script_content), m.start() + window_size)
        handler_window = script_content[window_start:window_end]

        has_strong_check = bool(_STRONG_ORIGIN_CHECK_RE.search(handler_window))
        has_weak_check = bool(_WEAK_ORIGIN_CHECK_RE.search(handler_window))

        has_sinks = False
        for sink_info in SINKS.values():
            if re.search(sink_info["pattern"], handler_window):
                has_sinks = True
                break
        if not has_sinks:
            for sink_info in TAINT_SINKS.values():
                if re.search(sink_info["pattern"], handler_window):
                    has_sinks = True
                    break

        if has_strong_check and not has_sinks:
            continue

        if not has_strong_check and not has_weak_check:
            # No origin check at all
            best = max(best, 9 if has_sinks else 7)
        elif has_weak_check and not has_strong_check:
            # Bypassable check (includes/startsWith/indexOf/endsWith)
            best = max(best, 8 if has_sinks else 6)
        else:
            # Strong check but sinks present
            best = max(best, 6)

    return best


def _score_prototype_pollution(script_content):
    """Score based on deep merge/extend calls, boosted when PP sources co-occur."""
    has_sink = False
    for pattern in PROTOTYPE_POLLUTION_SINKS:
        if re.search(pattern, script_content):
            has_sink = True
            break
    if not has_sink:
        return 0

    for pattern in PROTOTYPE_POLLUTION_SOURCES:
        if re.search(pattern, script_content):
            return 8  # source + sink = confirmed PP chain
    return 7  # sink only


def _score_endpoints(script_content):
    """Score based on interesting API endpoints found."""
    best = 0
    for pattern, category in ENDPOINT_PATTERNS:
        for match in re.finditer(pattern, script_content, re.IGNORECASE):
            endpoint = match.group(1).strip()
            if len(endpoint) < 5 or endpoint.startswith(('data:', 'blob:')):
                continue
            ep_lower = endpoint.lower()
            if category == 'redirect_endpoint':
                best = max(best, 7)
            elif category == 'jsonp_endpoint':
                best = max(best, 6)
            elif any(kw in ep_lower for kw in ('admin', 'internal', 'debug', 'private')):
                best = max(best, 6)
            elif any(kw in ep_lower for kw in ('graphql', 'webhook', 'oauth', 'auth')):
                best = max(best, 5)
            elif category == 'websocket':
                best = max(best, 5)
            else:
                best = max(best, 4)
    return best


_STATIC_EXTENSIONS = frozenset({
    '.js', '.css', '.png', '.jpg', '.jpeg', '.gif', '.svg',
    '.ico', '.woff', '.woff2', '.ttf', '.eot', '.map',
})


def _score_interesting_strings(script_content):
    """Score based on sensitive strings (secrets, internal IPs, cloud URLs, etc.)."""
    best = 0
    for pattern, str_type, severity in INTERESTING_STRING_PATTERNS:
        if re.search(pattern, script_content, re.IGNORECASE):
            best = max(best, severity)
    return best


_TAINT_PROXIMITY_CHARS = 5000       # ~150 lines of non-minified code
_TAINT_PROXIMITY_CHARS_MIN = 1500   # equivalent range in minified code


def _score_taint_flow(script_content, is_minified=False):
    """Score based on source+sink co-occurrence with proximity analysis.

    Proximity-confirmed (source and sink within ~150 lines): higher score.
    File-level only (both present but far apart): lower score.
    Window scales based on minification — minified code is ~3x denser.
    """
    proximity = _TAINT_PROXIMITY_CHARS_MIN if is_minified else _TAINT_PROXIMITY_CHARS

    source_positions = []
    for source_pattern in SOURCES.values():
        for m in re.finditer(source_pattern, script_content):
            source_positions.append(m.start())
    if not source_positions:
        return 0

    sink_hits = []
    for sink_info in SINKS.values():
        for m in re.finditer(sink_info["pattern"], script_content):
            sink_hits.append((m.start(), sink_info["severity"]))
    for sink_info in TAINT_SINKS.values():
        for m in re.finditer(sink_info["pattern"], script_content):
            sink_hits.append((m.start(), sink_info["severity"]))
    if not sink_hits:
        return 0

    best_proximate = 0
    best_any = 0
    for sink_pos, sink_sev in sink_hits:
        best_any = max(best_any, sink_sev)
        for src_pos in source_positions:
            if abs(sink_pos - src_pos) <= proximity:
                best_proximate = max(best_proximate, sink_sev)
                break

    # Proximity-confirmed: source and sink in same function/block
    if best_proximate >= 8:
        return 8
    if best_proximate >= 6:
        return 7

    # File-level co-occurrence only (weaker signal)
    if best_any >= 8:
        return 6
    if best_any >= 6:
        return 5
    return 0


def _score_library_cves(script_content):
    """Score based on known library CVEs."""
    vulns = check_known_cves(script_content)
    if not vulns:
        return 0
    return max(v['severity'] for v in vulns)


# --- Main Script Analysis Pipeline ---

def check_script_safety(script_content, script_hash, url, script_url=None,
                        struct_hash=None, anomaly_detector=None, is_minified=False):
    """Analyze script and emit a single combined finding if interesting enough."""
    minified = is_minified
    line_count = script_content.count('\n') + 1
    SCRIPT_METADATA[script_hash] = {
        "minified": minified,
        "line_count": line_count,
    }

    # --- Anomaly detection (feeds the change-detection system) ---
    has_sources = False
    has_sinks = False
    sink_cats = ()
    if anomaly_detector is not None and struct_hash is not None:
        sinks_list = []
        for sink_name, sink_info in SINKS.items():
            if re.search(sink_info["pattern"], script_content):
                sinks_list.append(sink_name)
        has_sinks = bool(sinks_list)
        sink_cats = tuple(sinks_list)

        for source_pattern in SOURCES.values():
            if re.search(source_pattern, script_content):
                has_sources = True
                break

        parsed_script = urlparse(script_url) if script_url else None
        parsed_page = urlparse(url) if url else None
        record = ScriptRecord(
            script_hash=script_hash,
            structural_hash=struct_hash,
            script_url=script_url or 'inline',
            page_url=url or '',
            subdomain=parsed_page.hostname if parsed_page else 'unknown',
            script_origin=parsed_script.hostname if parsed_script else '',
            is_minified=minified,
            is_known_library=_is_known_library(script_content),
            line_count=line_count,
            has_sources=has_sources,
            has_sinks=has_sinks,
            sink_categories=sink_cats,
        )
        anomaly_detector.ingest(record)

    # --- Combined interestingness score ---
    finding_key = f"script:{script_hash}"
    if finding_key in SEEN_FINDINGS:
        return
    SEEN_FINDINGS.add(finding_key)

    scores = []

    pm_score = _score_postmessage(script_content, minified)
    if pm_score:
        scores.append(pm_score)

    pp_score = _score_prototype_pollution(script_content)
    if pp_score:
        scores.append(pp_score)

    ep_score = _score_endpoints(script_content)
    if ep_score:
        scores.append(ep_score)

    str_score = _score_interesting_strings(script_content)
    if str_score:
        scores.append(str_score)

    taint_score = _score_taint_flow(script_content, minified)
    if taint_score:
        scores.append(taint_score)

    cve_score = _score_library_cves(script_content)
    if cve_score:
        scores.append(cve_score)

    if not scores:
        return

    scores.sort(reverse=True)
    severity = scores[0] + sum(s * 0.1 for s in scores[1:])
    severity = min(10, round(severity))

    log_message("FINDING", {
        'finding_type': 'interesting_script',
        'source_url': url,
        'script_url': script_url or 'inline',
        'script_hash': script_hash,
        'severity': severity,
        'confidence': 'low',
        'analysis_method': 'regex',
    })


def structural_hash(js_code):
    """Compute a structural hash that normalizes whitespace/comments."""
    cleaned = re.sub(r'//[^\n]*', '', js_code)
    cleaned = re.sub(r'/\*.*?\*/', '', cleaned, flags=re.DOTALL)
    cleaned = re.sub(r'\s+', ' ', cleaned).strip()
    return sha256(cleaned.encode('utf-8')).hexdigest()


async def process_javascript(js_code, url, client, script_url=None):
    """Processes, analyzes, and saves a piece of JavaScript code."""
    if not js_code:
        return

    is_minified = looks_minified(js_code)
    raw_hash = get_sha256(js_code)
    structural = structural_hash(js_code)

    if raw_hash in SEEN_SCRIPTS or structural in SEEN_SCRIPTS:
        return
    SEEN_SCRIPTS.add(raw_hash)
    SEEN_SCRIPTS.add(structural)

    check_script_safety(js_code, raw_hash, url, script_url, structural,
                        is_minified=is_minified)

    # Source map: try to fetch and re-analyze original source
    if ARGS and not getattr(ARGS, 'no_sourcemaps', False) and script_url and script_url != "inline":
        try:
            sourcemap = await try_fetch_sourcemap(script_url, js_code, client)
            if sourcemap:
                original = get_original_source(sourcemap)
                if original and len(original) > 50:
                    original_hash = get_sha256(original)
                    if original_hash not in SEEN_SCRIPTS:
                        SEEN_SCRIPTS.add(original_hash)
                        log_message("INFO", f"Re-analyzing original source from source map for {script_url}")
                        original_struct = structural_hash(original)
                        check_script_safety(original, original_hash, url,
                                            script_url + " (source map)", original_struct)
        except Exception as e:
            log_message("ERROR", f"Source map processing failed for {script_url}: {e}")

    if ARGS and ARGS.save:
        try:
            with open(f"{raw_hash}.js", 'w', encoding='utf-8') as f:
                f.write(f"// Source: {url}\n// Script URL: {script_url or 'inline'}\n\n{js_code}")
        except IOError as e:
            log_message("ERROR", f"Failed to save script {raw_hash}: {e}")

    await find_and_process_js_paths(js_code, url, client)
    await find_and_process_template_urls(js_code, url, client)


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


# --- Template URL patterns for SPA frameworks ---
# Matches: templateUrl: '/path.html', templateUrl: "/path.html", templateUrl: `path.html`
_TEMPLATE_URL_DIRECT = re.compile(
    r"""templateUrl\s*:\s*['"`]([^'"`\n]+\.html?)['"`]""",
    re.IGNORECASE,
)
# Matches helper calls: templateUrl: getPartialUrl('name'), templateUrl: helper("name")
_TEMPLATE_URL_HELPER = re.compile(
    r"""templateUrl\s*:\s*(\w+)\s*\(\s*['"`]([^'"`\n]+)['"`]\s*\)""",
)
# Matches simple string-returning functions:
# function foo(x) { return "/prefix/" + x + ".html"; }
_HELPER_FUNC = re.compile(
    r"""function\s+(\w+)\s*\(\s*\w+\s*\)\s*\{[^}]*?return\s+['"`]([^'"`]*?)['"`]\s*\+\s*\w+\s*\+\s*['"`]([^'"`]*?)['"`]""",
)


def _extract_template_urls(content, base_url):
    """Extract HTML template URLs from SPA framework route configurations.

    Handles:
    - Direct: templateUrl: '/views/page.html'
    - Helper: templateUrl: getUrl('page') where getUrl builds a path
    """
    urls = set()

    # Resolve helper functions: function name(x) { return prefix + x + suffix; }
    helpers = {}
    for m in _HELPER_FUNC.finditer(content):
        func_name, prefix, suffix = m.group(1), m.group(2), m.group(3)
        helpers[func_name] = (prefix, suffix)

    # Direct templateUrl strings
    for m in _TEMPLATE_URL_DIRECT.finditer(content):
        path = m.group(1)
        urls.add(urljoin(base_url, path))

    # Helper-based templateUrl: resolve using detected helpers
    for m in _TEMPLATE_URL_HELPER.finditer(content):
        func_name, arg = m.group(1), m.group(2)
        if func_name in helpers:
            prefix, suffix = helpers[func_name]
            path = prefix + arg + suffix
            urls.add(urljoin(base_url, path))

    return urls


async def find_and_process_template_urls(content, base_url, client):
    """Find SPA template URLs in JS and analyze their inline scripts."""
    urls = _extract_template_urls(content, base_url)
    if not urls:
        return

    tasks = []
    for template_url in urls:
        hashed = get_sha256(template_url)
        if hashed in CHECKED_JS_URLS:
            continue
        CHECKED_JS_URLS.add(hashed)

        log_message("INFO", f"Discovered template URL: {template_url}")
        try:
            resp = await client.get(template_url, timeout=10)
            if resp.status_code >= 400:
                continue
            html = resp.text
            # Extract inline scripts from the template
            for m in re.finditer(
                r'<script[^>]*>(.*?)</script>', html, re.DOTALL | re.IGNORECASE,
            ):
                js = m.group(1).strip()
                if js:
                    tasks.append(process_javascript(
                        js, base_url, client, script_url=template_url,
                    ))
        except httpx.RequestError as e:
            log_message("ERROR", f"Failed to fetch template {template_url}: {e}")

    if tasks:
        await asyncio.gather(*tasks)
