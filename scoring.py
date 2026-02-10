"""URL scoring, novelty scoring, and script interestingness scoring."""
import re
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

    # Path keyword scoring (+3 each) -- match whole path segments only
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


# --- Novelty-Based URL Scoring ---

def url_path_key(url):
    """Normalize URL to scheme://host/path — strips query/fragment, lowercases."""
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}{parsed.path}".lower().rstrip('/')


def path_segments(url):
    """Return the set of non-empty path segments."""
    return set(s for s in urlparse(url).path.strip('/').split('/') if s)


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


def _looks_minified(content):
    """Heuristic: is this script minified?"""
    lines = content.split('\n')
    if not lines:
        return False
    avg_line_length = sum(len(l) for l in lines) / len(lines)
    return avg_line_length > 200 or len(lines) < 10


def score_script(content, script_url=""):
    """Score a JavaScript file for security research interestingness.

    Returns (score, list_of_reasons).
    """
    score = 0
    reasons = []

    # Known library -- not interesting
    if _is_known_library(content):
        return 0, ["Known library"]

    # Trivial script
    if len(content) < 100:
        return 0, ["Trivial script"]

    # Auth/login logic
    auth_patterns = re.findall(
        r'\b(?:authenticate|authorize|login|signup|register|password|credential|oauth|token|jwt|bearer)\b',
        content, re.IGNORECASE
    )
    if len(auth_patterns) >= 2:
        score += 15
        reasons.append(f"Auth logic ({len(auth_patterns)} keywords)")

    # API key handling
    if re.search(r'(?i)api[_-]?key|api[_-]?secret|apiToken', content):
        score += 10
        reasons.append("API key handling")

    # Dynamic code generation
    dynamic_count = len(re.findall(r'\beval\s*\(|\bFunction\s*\(|\bnew\s+Function\b', content))
    if dynamic_count:
        score += 8 * min(dynamic_count, 3)
        reasons.append(f"Dynamic code gen ({dynamic_count}x)")

    # postMessage usage
    if re.search(r'\.postMessage\s*\(', content):
        score += 10
        reasons.append("postMessage")
    if re.search(r'addEventListener\s*\(\s*[\'"]message[\'"]', content):
        score += 12
        reasons.append("Message listener")

    # URL/redirect handling
    redirect_count = len(re.findall(
        r'(?:location\.(?:href|assign|replace)|window\.open|window\.location)\s*=',
        content
    ))
    if redirect_count:
        score += 5 * min(redirect_count, 3)
        reasons.append(f"Redirects ({redirect_count}x)")

    # DOM manipulation sinks
    dom_sinks = len(re.findall(r'innerHTML\s*=|outerHTML\s*=|document\.write', content))
    if dom_sinks:
        score += 6 * min(dom_sinks, 4)
        reasons.append(f"DOM sinks ({dom_sinks}x)")

    # File upload handling
    if re.search(r'(?:FileReader|FormData|\.upload\b|multipart)', content, re.IGNORECASE):
        score += 8
        reasons.append("File upload")

    # CORS / cross-origin
    if re.search(r'(?:Access-Control|crossOrigin|withCredentials)', content, re.IGNORECASE):
        score += 8
        reasons.append("CORS handling")

    # Crypto operations
    if re.search(r'(?:crypto\.subtle|CryptoJS|sjcl|forge\.)', content):
        score += 10
        reasons.append("Crypto operations")

    # Prototype manipulation
    if re.search(r'(?:__proto__|Object\.setPrototypeOf|prototype\s*=)', content):
        score += 10
        reasons.append("Prototype manipulation")

    # Fetch with dynamic URL
    if re.search(r'fetch\s*\([^)]*\+|fetch\s*\(`', content):
        score += 7
        reasons.append("Dynamic fetch URL")

    # Large non-minified script
    line_count = content.count('\n')
    if line_count > 500 and not _looks_minified(content):
        score += 5
        reasons.append(f"Large script ({line_count} lines)")

    # Source map available
    if re.search(r'sourceMappingURL\s*=', content):
        score += 3
        reasons.append("Source map available")

    return score, reasons
