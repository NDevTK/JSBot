"""URL scoring, novelty scoring, and script classification helpers."""
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


