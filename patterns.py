"""Taint source/sink patterns for regex-based analysis, URL/JS path discovery."""

# --- Taint Analysis: Sources & Sinks (used by regex source/sink detection) ---
SOURCES = {
    "location.hash":        r"""\blocation\.hash\b""",
    "location.search":      r"""\blocation\.search\b""",
    "location.href_read":   r"""\blocation\.href\b(?!\s*=)""",
    "location.pathname":    r"""\blocation\.pathname\b""",
    "location_whole":       r"""\b(?:window|document|self|globalThis)\.location\b(?!\.)""",
    "document.URL":         r"""\bdocument\.URL\b""",
    "document.documentURI": r"""\bdocument\.documentURI\b""",
    "document.baseURI":     r"""\bdocument\.baseURI\b""",
    "document.URLUnencoded": r"""\bdocument\.URLUnencoded\b""",
    "document.referrer":    r"""\bdocument\.referrer\b""",
    "window.name":          r"""\b(?:window|top|self|parent|frames)\.name\b""",
    "postMessage data":     r"""\bevent\.data\b""",
    "URLSearchParams":      r"""\bURLSearchParams\b""",
    "getItem":              r"""\b(?:localStorage|sessionStorage)\.getItem\b""",
    "storage_bracket":      r"""\b(?:localStorage|sessionStorage)\s*\[""",
    "storage_property":     r"""\b(?:localStorage|sessionStorage)\.(?!getItem\b|setItem\b|removeItem\b|clear\b|key\b|length\b)\w+""",
    "cookie_read":          r"""\bdocument\.cookie\b(?!\s*=)""",
    "input.value":          r"""\b(?:target|currentTarget|srcElement)\.value\b""",
    "queryParams":          r"""\.queryParams\b""",
    "queryParamMap":        r"""\.queryParamMap\b""",
    "history.state":        r"""\bhistory\.state\b""",
    "searchParams":         r"""\.searchParams\b""",
    "clipboardData":        r"""\b(?:clipboardData|dataTransfer)\.getData\b""",
}

# Context-dependent sources: only matched inside message event handler scopes.
# Short parameter names like `e` are reused everywhere in minified code;
# matching `e.data` globally produces false taint in jQuery, Angular, etc.
CONTEXT_SOURCES = {
    "postMessage data": r"""\b(?:e|evt|msg)\.data\b""",
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
    "Angular Security Bypass": {
        "pattern": r"""\bbypassSecurityTrust(?:Html|ResourceUrl|Url|Style|Script)\s*\(""",
        "severity": 9,
    },
    "Angular innerHTML Binding": {
        "pattern": r"""\.(?:Y8G|ɵɵproperty)\s*\(\s*["'](?:innerHtml|innerHTML)["']""",
        "severity": 8,
    },
    "iframe srcdoc Injection": {
        "pattern": r"""\bsrcdoc\s*=""",
        "severity": 9,
    },
    "Cookie Write": {
        "pattern": r"""\bdocument\.cookie\s*=""",
        "severity": 5,
    },
    "postMessage": {
        "pattern": r"""\.postMessage\s*\(""",
        "severity": 4,
    },
    "postMessage Wildcard": {
        "pattern": r"""\.postMessage\s*\([^)]+,\s*['"`]\*['"`]\s*\)""",
        "severity": 7,
    },
}

# Taint-only sinks: used by source+sink co-occurrence but NOT anomaly has_sinks detection.
# These patterns are too broad for anomaly (setTimeout fires on 90% of scripts)
# but useful for flagging when they co-occur with a user-controlled source.
TAINT_SINKS = {
    "createContextualFragment": {
        "pattern": r"""\bcreateContextualFragment\s*\(""",
        "severity": 9,
    },
    "setAttribute Event Handler": {
        "pattern": r"""\.setAttribute\s*\(\s*['"]on""",
        "severity": 8,
    },
    "setTimeout/setInterval": {
        "pattern": r"""\b(?:setTimeout|setInterval)\s*\(""",
        "severity": 7,
    },
    "window.open": {
        "pattern": r"""\bwindow\.open\s*\(""",
        "severity": 6,
    },
    "Script/Link Source": {
        "pattern": r"""(?:\.(?:src|href|action|formAction|data)\s*=|\.setAttribute(?:NS)?\s*\()""",
        "severity": 6,
    },
    "Fetch/XHR": {
        "pattern": r"""\b(?:fetch|\.open)\s*\(""",
        "severity": 5,
    },
    "Dynamic Import": {
        "pattern": r"""\bimport\s*\(""",
        "severity": 9,
    },
    "ServiceWorker Registration": {
        "pattern": r"""\.register\s*\(""",
        "severity": 9,
    },
    "Worker Constructor": {
        "pattern": r"""\bnew\s+(?:Worker|SharedWorker)\s*\(""",
        "severity": 8,
    },
    "jQuery Script Exec": {
        "pattern": r"""\$\s*\.\s*(?:getScript|globalEval)\s*\(""",
        "severity": 8,
    },
    "Template Compilation": {
        "pattern": r"""\b(?:Handlebars\.compile|_\.template|doT\.template|ejs\.render)\s*\(""",
        "severity": 8,
    },
    "Blob URL": {
        "pattern": r"""\bURL\.createObjectURL\s*\(""",
        "severity": 7,
    },
    "Trusted Types Bypass": {
        "pattern": r"""\bcreatePolicy\s*\(""",
        "severity": 7,
    },
    "execCommand insertHTML": {
        "pattern": r"""\bexecCommand\s*\(\s*['"]insertHTML['"]""",
        "severity": 7,
    },
    "document.domain": {
        "pattern": r"""\bdocument\.domain\s*=""",
        "severity": 7,
    },
    "jQuery Selector Injection": {
        "pattern": r"""\b(?:\$|jQuery)\s*\(""",
        "severity": 7,
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
    # Server-side redirect endpoints with controllable target parameter
    (r"""['"`]([^'"`\s]*(?:redirect|redir)[^'"`\s]*\?[^'"`\s]*(?:to|url|next|return|goto|dest|destination|redirect_uri)=[^'"`\s]*)['"`]""", "redirect_endpoint"),
    # JSONP endpoints — callback parameter enables data exfil / XSS
    (r"""['"`]([^'"`\s\n]*\?[^'"`\s\n]*(?:callback|jsonp|cb|jsonpcallback)=[^'"`\s\n]*)['"`]""", "jsonp_endpoint"),
]

# --- Interesting String Patterns ---
# Each entry: (regex with group 1 = value, type label, severity)
INTERESTING_STRING_PATTERNS = [
    # Internal/RFC1918 IPs in strings or URLs
    (r"""(?:['"`]|https?://)((?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})(?::\d+)?)""",
     "internal_ip", 6),
    # AWS S3 bucket URLs
    (r"""['"`](https?://(?:[a-z0-9][-a-z0-9]{2,62}\.)?s3[-.](?:us|eu|ap|sa|ca|me|af)[-a-z0-9]*\.amazonaws\.com/[^'"`\s]*)['"`]""",
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
    # Math.random() used for security tokens/nonces — not cryptographically secure
    (r"""(?:token|nonce|secret|csrf|key|salt|random_?id)\s*[:=]\s*[^;\n]*?(Math\.random\s*\(\s*\))""",
     "insecure_random", 6),

    # --- Secret / Credential Patterns ---
    # AWS access keys (always start with AKIA)
    (r"""(?:['"`\s;=(]|^)(AKIA[0-9A-Z]{16})\b""", "aws_access_key", 9),
    # GitHub tokens (ghp_ personal, ghs_ app install, gho_ OAuth, ghr_ refresh)
    (r"""(?:['"`\s;=(]|^)(gh[psro]_[A-Za-z0-9_]{36,255})""", "github_token", 9),
    # Slack tokens
    (r"""(?:['"`\s;=(]|^)(xox[bpas]-[0-9a-zA-Z-]{10,})""", "slack_token", 9),
    # Stripe secret keys
    (r"""(?:['"`\s;=(]|^)(sk_live_[0-9a-zA-Z]{20,})""", "stripe_secret_key", 9),
    # Stripe publishable keys (public by design — can only create tokens, not charges)
    (r"""(?:['"`\s;=(]|^)(pk_live_[0-9a-zA-Z]{20,})""", "stripe_publishable_key", 2),
    # Google API keys (public by design — restricted by referrer/IP, on every Maps/YouTube page)
    (r"""(?:['"`\s;=(]|^)(AIza[0-9A-Za-z_-]{35})""", "google_api_key", 2),
    # Private key blocks
    (r"""(-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----)""", "private_key", 9),
    # Generic API key/secret assignments (noisy — matches config values and public keys)
    (r"""(?:api[_-]?key|apikey|api[_-]?secret|secret[_-]?key|access[_-]?token|auth[_-]?token)\s*[:=]\s*['"`]([A-Za-z0-9_/+=.-]{20,})['"`]""",
     "api_key_generic", 3),
]

# --- Prototype Pollution Sink Patterns ---
# Functions known to perform deep merge/extend with attacker-controlled input.
# If these are called with user-controlled data, prototype pollution is possible.
PROTOTYPE_POLLUTION_SINKS = [
    # lodash/underscore deep merge/set
    r"""\b(?:_|lodash)\.(?:merge|defaultsDeep|set|setWith|mergeWith)\s*\(""",
    # jQuery deep extend: $.extend(true, target, source)
    r"""\$\.extend\s*\(\s*true\b""",
    # angular.merge (CVE-2019-10768)
    r"""\bangular\.merge\s*\(""",
    # hoek.merge / hoek.applyToDefaults
    r"""\b(?:Hoek|hoek)\.(?:merge|applyToDefaults)\s*\(""",
    # Generic recursive merge/deepMerge/deepExtend/deepAssign function names
    r"""\b(?:deepMerge|deepExtend|deepAssign|recursiveMerge|deepCopy)\s*\(""",
]

# Prototype pollution source patterns — URL param parsers that create nested objects
PROTOTYPE_POLLUTION_SOURCES = [
    # qs.parse, deparam — create nested objects from bracket notation
    r"""\b(?:qs|querystring)\.parse\s*\(""",
    r"""\$\.deparam\s*\(""",
    # JSON.parse of user-controlled data (combined with merge = pollution)
    r"""\bJSON\.parse\s*\(""",
]
