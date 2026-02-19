"""URL scoring, novelty scoring, and script classification helpers."""
import re
import threading
import httpx
from urllib.parse import urlparse, parse_qs

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

    # Path keyword scoring (+3 each, capped at 9) — exact word match within segments
    segs = [s for s in parsed.path.lower().strip('/').split('/') if s]
    path_bonus = 0
    for seg in segs:
        seg_parts = re.split(r'[-_.]', seg)
        if any(p in PATH_KEYWORDS for p in seg_parts):
            path_bonus += 3
    score += min(path_bonus, 9)

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
            sub_parts = re.split(r'[-_.]', subdomain)
            for part in sub_parts:
                if part in SUBDOMAIN_KEYWORDS:
                    score += 4
                    break  # Only count once

    return score


# --- Novelty-Based URL Scoring ---

def url_path_key(url):
    """Normalize URL to scheme://host/path — strips query/fragment, lowercases."""
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}{parsed.path}".lower().rstrip('/')


def path_segments(url):
    """Return host-scoped cumulative path prefixes for novelty tracking.

    https://a.com/x/y → {'a.com:/x', 'a.com:/x/y'}

    Host prefix ensures cross-subdomain paths don't contaminate each other
    (mail.google.com/api and docs.google.com/api are different apps).
    Cumulative prefixes prevent common segments (en, us, v1) from killing
    novelty of structurally distinct paths within the same host.
    """
    parsed = urlparse(url)
    host = parsed.hostname or ''
    parts = [s for s in parsed.path.strip('/').split('/') if s]
    return {(host + ':/' + '/'.join(parts[:i + 1])) for i in range(len(parts))}


def novelty_score(url, seen_keys, seen_segments):
    """0.0 = redundant, 1.0 = completely new path segments."""
    pk = url_path_key(url)
    if pk in seen_keys:
        return 0.0
    segs = path_segments(url)
    if not segs:
        return 0.5  # Root URLs get moderate novelty
    new_segs = segs - seen_segments
    return len(new_segs) / len(segs)


def combined_url_score(url, seen_keys, seen_segments):
    """Combine novelty with URL interestingness scoring.

    Novelty (0-1 scaled to 0-20) is primary, interestingness is bonus.
    """
    nov = novelty_score(url, seen_keys, seen_segments)
    interest = score_url(url)
    return nov * 20 + interest


# --- Known Library Signatures ---
_LIBRARY_SIGNATURES = [
    (r'/\*!?\s*jQuery\s+v', "jQuery"),
    (r'React\.createElement|react\.production', "React"),
    (r'angular\.module|ng\.core', "Angular"),
    (r'Vue\.config|vue\.runtime', "Vue"),
    (r'[Ll]odash|_\.VERSION', "Lodash"),
    (r'moment\.js|moment\.version', "Moment.js"),
    (r'bootstrap\.js|Bootstrap\s+v', "Bootstrap"),
    (r'google-analytics|GoogleAnalyticsObject|gtag\(', "Google Analytics"),
    (r'fbevents\.js|fbq\(', "Facebook Pixel"),
]


def _is_known_library(content):
    """Check if script is a known third-party library by signature."""
    first_5k = content[:5000]
    for pattern, _ in _LIBRARY_SIGNATURES:
        if re.search(pattern, first_5k, re.IGNORECASE):
            return True
    return False


def looks_minified(content):
    """Heuristic: is this script minified?"""
    lines = content.split('\n')
    if not lines:
        return False
    avg_line_length = sum(len(l) for l in lines) / len(lines)
    return avg_line_length > 200 or len(lines) < 10


# --- Library Version Detection + Known CVE Database ---

_LIBRARY_VERSIONS = [
    (r'/\*!?\s*jQuery\s+v?([\d.]+)', "jQuery"),
    (r'/\*!?\s*jQuery\s+[^\n]*?v([\d.]+)', "jQuery"),
    (r'jQuery\.fn\.jquery\s*=\s*[\'"]([^\'"]+)', "jQuery"),
    (r'\bjquery\s*:\s*["\'](\d+\.\d+[\d.]*)["\']', "jQuery"),
    (r'angular[^.]*\.version\s*=\s*\{[^}]*full\s*:\s*[\'"]([^\'"]+)', "Angular.js"),
    (r'AngularJS\s+v?([\d.]+)', "Angular.js"),
    (r'Vue\.version\s*=\s*[\'"]([^\'"]+)', "Vue.js"),
    (r'_\.VERSION\s*=\s*[\'"]([^\'"]+)', "Lodash"),
    (r'Bootstrap\s+v([\d.]+)', "Bootstrap"),
    (r'moment\.version\s*=\s*[\'"]([^\'"]+)', "Moment.js"),
]

# Generic header pattern for broader library detection
# Catches /*! LibName v1.2.3 — the minification-preserved comment format
_GENERIC_LIB_PATTERN = re.compile(
    r'/\*!\s*([A-Za-z][\w.-]{1,50}?)(?:\.js)?\s+(?:[-|]+\s+)?v?(\d+\.\d+(?:\.\d+)?)',
    re.IGNORECASE,
)

# Map detected library names → npm package names (only where they differ)
_NPM_NAME_MAP = {
    'angular': 'angular', 'angularjs': 'angular', 'angular.js': 'angular',
    'chart': 'chart.js', 'chartjs': 'chart.js',
    'cropper': 'cropperjs', 'cropperjs': 'cropperjs',
    'filesaver': 'file-saver',
    'hammer': 'hammerjs', 'hammerjs': 'hammerjs',
    'highlight': 'highlight.js', 'hljs': 'highlight.js',
    'masonry': 'masonry-layout',
    'popper': 'popper.js', 'popperjs': '@popperjs/core',
    'prism': 'prismjs',
    'socket.io': 'socket.io-client',
    'sortable': 'sortablejs',
    'typed': 'typed.js',
    'velocity': 'velocity-animate',
    'video': 'video.js', 'videojs': 'video.js',
    'ace': 'ace-builds',
    'anime': 'animejs',
    'slick': 'slick-carousel',
    'wow': 'wowjs',
}


def _normalize_npm_name(detected_name):
    """Map detected library name to npm package name."""
    clean = re.sub(r'\.js$', '', detected_name.lower()).strip('.-')
    return _NPM_NAME_MAP.get(clean, clean)


# --- OSV.dev Integration (real-time CVE lookup) ---

_OSV_SEVERITY_MAP = {
    'CRITICAL': 9, 'HIGH': 8, 'MODERATE': 6, 'MEDIUM': 6, 'LOW': 4,
}
_osv_cache = {}
_osv_lock = threading.Lock()


def _query_osv(npm_name, version):
    """Query OSV.dev for vulnerabilities affecting npm_name@version. Thread-safe + cached."""
    cache_key = f"{npm_name}@{version}"
    with _osv_lock:
        if cache_key in _osv_cache:
            return _osv_cache[cache_key]

    try:
        resp = httpx.post(
            "https://api.osv.dev/v1/query",
            json={"package": {"name": npm_name, "ecosystem": "npm"}, "version": version},
            timeout=5,
        )
        vulns = resp.json().get("vulns", []) if resp.status_code == 200 else []
    except Exception:
        vulns = []

    results = []
    for v in vulns:
        cves = [a for a in v.get("aliases", []) if a.startswith("CVE-")]
        if not cves:
            cves = [v.get("id", "unknown")]
        severity = 7  # default
        db_sev = v.get("database_specific", {}).get("severity", "")
        if db_sev:
            severity = _OSV_SEVERITY_MAP.get(db_sev.upper(), 7)
        fix_version = None
        for affected in v.get("affected", []):
            for range_info in affected.get("ranges", []):
                for event in range_info.get("events", []):
                    if "fixed" in event:
                        fix_version = event["fixed"]
                        break
        results.append({
            'cves': cves,
            'description': v.get("summary", "")[:200],
            'severity': severity,
            'fix_below': fix_version or "unknown",
        })

    with _osv_lock:
        _osv_cache[cache_key] = results
    return results


def _parse_version(version_str):
    """Parse version string to tuple for comparison."""
    try:
        return tuple(int(p) for p in version_str.split('.')[:3])
    except (ValueError, AttributeError):
        return None


# Fallback version patterns for minified code where variable names are mangled.
# Used only when a library is identified by signature but no version was found.
_MINIFIED_VERSION_FALLBACKS = {
    "lodash": re.compile(r'\.VERSION\s*=\s*["\'](\d+\.\d+\.\d+)["\']'),
}


def _detect_libraries(content):
    """Detect all library name+version pairs from script content."""
    first_10k = content[:10000]
    results = []
    seen_names = set()

    # Specific patterns first (high confidence)
    for pattern, name in _LIBRARY_VERSIONS:
        m = re.search(pattern, first_10k, re.IGNORECASE)
        if m:
            name_lower = name.lower()
            if name_lower not in seen_names:
                seen_names.add(name_lower)
                results.append((name, m.group(1)))

    # Generic header pattern for smaller/unknown libraries
    for m in _GENERIC_LIB_PATTERN.finditer(first_10k):
        name = m.group(1)
        version = m.group(2)
        name_lower = re.sub(r'\.js$', '', name.lower()).strip('.-')
        if name_lower not in seen_names and len(name_lower) >= 2:
            seen_names.add(name_lower)
            results.append((name, version))

    # Fallback: library identified by signature but version not found in first 10K
    # (handles minified code where variable names are mangled)
    first_5k = content[:5000]
    for sig_pattern, sig_name in _LIBRARY_SIGNATURES:
        if re.search(sig_pattern, first_5k, re.IGNORECASE):
            name_lower = sig_name.lower()
            if name_lower not in seen_names:
                fallback = _MINIFIED_VERSION_FALLBACKS.get(name_lower)
                if fallback:
                    m = fallback.search(content)
                    if m:
                        seen_names.add(name_lower)
                        results.append((sig_name, m.group(1)))

    return results


def detect_library_version(content):
    """Detect library name and version from script content."""
    results = _detect_libraries(content)
    return results[0] if results else None


def check_known_cves(content):
    """Check if script contains a library with known CVEs via OSV.dev."""
    detections = _detect_libraries(content)
    if not detections:
        return []

    all_findings = []
    seen_cves = set()

    for name, version in detections:
        npm_name = _normalize_npm_name(name)
        osv_findings = _query_osv(npm_name, version)
        for of in osv_findings:
            if not any(c in seen_cves for c in of['cves']):
                seen_cves.update(of['cves'])
                all_findings.append({
                    'library': name,
                    'version': version,
                    'cves': of['cves'],
                    'description': of['description'],
                    'severity': of['severity'],
                    'fix_below': of['fix_below'],
                })

    return all_findings


