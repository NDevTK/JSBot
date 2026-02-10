"""Taint source/sink patterns for AST analysis, URL/JS path discovery."""

# --- Taint Analysis: Sources & Sinks (used by ASTAnalyzer) ---
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

# --- Discovery Patterns ---
LINK_FINDER_PATTERN = r"""https?:\/\/[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b[-a-zA-Z0-9()@:%_\+.~#?&//=]*"""

JS_PATH_FINDER = r"""['"](/[^"']+\.js|[^"']+\.js)['"]"""

# --- Source Map URL Pattern ---
SOURCE_MAP_URL_PATTERN = r"""//[#@]\s*sourceMappingURL\s*=\s*(\S+)"""

# --- Endpoint Extraction Patterns ---
# Each entry: (regex with group 1 = endpoint, category label)
ENDPOINT_PATTERNS = [
    # fetch/axios calls: fetch('/api/users'), axios.get('/admin/config')
    (r"""(?:fetch|axios\.(?:get|post|put|delete|patch))\s*\(\s*['"`]([^'"`\n]{5,})['"`]""", "fetch_call"),
    # XMLHttpRequest.open('GET', '/api/users')
    (r"""\.open\s*\(\s*['"](?:GET|POST|PUT|DELETE|PATCH)['"]\s*,\s*['"]([^'"]+)['"]""", "xhr_open"),
    # String literals that look like API/internal paths
    (r"""['"](/(?:api|graphql|rest|v[0-9]+|internal|admin|auth|oauth|webhook|socket\.io)/[^'"\s]{2,})['"]""", "api_path"),
    # WebSocket endpoints
    (r"""['"`](wss?://[^'"`\s\n]+)['"`]""", "websocket"),
]

# --- Interesting String Patterns ---
# Each entry: (regex with group 1 = value, type label, severity)
INTERESTING_STRING_PATTERNS = [
    # Internal/RFC1918 IPs in strings or URLs
    (r"""(?:['"`]|https?://)((?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})(?::\d+)?)""",
     "internal_ip", 6),
    # AWS S3 bucket URLs
    (r"""['"`]((?:[a-z0-9][-a-z0-9]{2,62}\.)?s3[-.](?:us|eu|ap|sa|ca|me|af)[-a-z0-9]*\.amazonaws\.com/[^'"`\s]*)['"`]""",
     "s3_url", 7),
    (r"""['"`]s3://([a-z0-9][-a-z0-9]{2,62}[^'"`\s]*)['"`]""", "s3_bucket", 7),
    # Firebase realtime DB
    (r"""['"`](https?://[a-z0-9][-a-z0-9]*\.firebaseio\.com[^'"`\s]*)['"`]""", "firebase_db", 7),
    # Supabase
    (r"""['"`](https?://[a-z0-9]+\.supabase\.co[^'"`\s]*)['"`]""", "supabase_url", 6),
    # Google Cloud Storage
    (r"""['"`](https?://storage\.googleapis\.com/[^'"`\s]+)['"`]""", "gcs_bucket", 6),
    # Azure storage
    (r"""['"`](https?://[a-z0-9]+\.(?:blob|table|queue)\.core\.windows\.net[^'"`\s]*)['"`]""",
     "azure_storage", 6),
    # JWT tokens hardcoded in source
    (r"""['"`](eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+)['"`]""",
     "jwt_token", 8),
    # Debug/admin flags set to true
    (r"""(?:debug|isDebug|debugMode|devMode|isDev|testMode|adminMode|isAdmin)\s*[:=]\s*(true|1)\b""",
     "debug_flag", 5),
    # Security-related TODOs/comments
    (r"""(?://|/\*)\s*((?:TODO|FIXME|HACK|XXX|BUG)\s*:?\s*[^\n*]{0,40}(?:auth|secur|cred|passw|secret|token|xss|csrf|inject|bypass|vuln)[^\n*]{0,40})""",
     "security_todo", 5),
]
