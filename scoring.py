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

    # Path keyword scoring (+3 each) — substring match on segments
    segs = [s for s in parsed.path.lower().strip('/').split('/') if s]
    for seg in segs:
        if any(kw in seg for kw in PATH_KEYWORDS):
            score += 3

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
    (r'lodash\.js|_\.VERSION', "Lodash"),
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
    (r'jQuery\.fn\.jquery\s*=\s*[\'"]([^\'"]+)', "jQuery"),
    (r'angular[^.]*\.version\s*=\s*\{[^}]*full\s*:\s*[\'"]([^\'"]+)', "Angular.js"),
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


_KNOWN_VULNS = {
    "jQuery": [
        {"below": "3.5.0", "cves": ["CVE-2020-11022", "CVE-2020-11023"],
         "desc": "XSS via HTML containing <option> passed to DOM manipulation methods", "severity": 8},
        {"below": "3.0.0", "cves": ["CVE-2015-9251"],
         "desc": "XSS via cross-domain ajax when dataType is not specified", "severity": 7},
        {"below": "1.12.0", "cves": ["CVE-2012-6708"],
         "desc": "XSS via selector string misinterpreted as HTML", "severity": 9},
    ],
    "Angular.js": [
        {"below": "1.6.9", "cves": ["CVE-2019-14863"],
         "desc": "XSS via SVG animate elements", "severity": 8},
        {"below": "1.6.0", "cves": ["CVE-2019-10768"],
         "desc": "Prototype pollution in merge function", "severity": 8},
    ],
    "Lodash": [
        {"below": "4.17.21", "cves": ["CVE-2021-23337"],
         "desc": "Command injection via template function", "severity": 9},
        {"below": "4.17.12", "cves": ["CVE-2019-10744"],
         "desc": "Prototype pollution via defaultsDeep/merge", "severity": 8},
    ],
    "Vue.js": [
        {"below": "2.5.0", "cves": ["CVE-2018-6341"],
         "desc": "XSS via v-bind:href with javascript: protocol", "severity": 8},
    ],
    "Bootstrap": [
        {"below": "3.4.0", "cves": ["CVE-2018-14040", "CVE-2018-14041", "CVE-2018-14042"],
         "desc": "XSS via tooltip/popover data-template attributes", "severity": 7},
    ],
    "Moment.js": [
        {"below": "2.29.4", "cves": ["CVE-2022-31129"],
         "desc": "ReDoS in string parsing", "severity": 5},
        {"below": "2.29.2", "cves": ["CVE-2022-24785"],
         "desc": "Path traversal in moment.locale", "severity": 7},
    ],
}


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

    return results


def detect_library_version(content):
    """Detect library name and version from script content."""
    results = _detect_libraries(content)
    return results[0] if results else None


def check_known_cves(content):
    """Check if script contains a library with known CVEs. Hardcoded DB + OSV.dev lookup."""
    detections = _detect_libraries(content)
    if not detections:
        return []

    all_findings = []
    seen_cves = set()

    for name, version in detections:
        ver_tuple = _parse_version(version)

        # Hardcoded database (fast, no network)
        if name in _KNOWN_VULNS and ver_tuple:
            for vuln in _KNOWN_VULNS[name]:
                threshold = _parse_version(vuln['below'])
                if threshold and ver_tuple < threshold:
                    seen_cves.update(vuln['cves'])
                    all_findings.append({
                        'library': name,
                        'version': version,
                        'cves': vuln['cves'],
                        'description': vuln['desc'],
                        'severity': vuln['severity'],
                        'fix_below': vuln['below'],
                    })

        # OSV.dev for additional/supplementary CVEs
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


