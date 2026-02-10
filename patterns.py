"""All detection patterns: regex sources/sinks, tree-sitter queries, secrets."""

# --- Taint Analysis: Sources & Sinks (regex) ---
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

# --- Secret Detection Patterns ---
SECRET_PATTERNS = {
    "AWS Access Key": {
        "pattern": r"""(?:AKIA|A3T|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}""",
        "severity": 10,
        "confidence": "high",
    },
    "AWS Secret Key": {
        "pattern": r"""(?i)(?:aws_secret_access_key|aws_secret_key)\s*[=:]\s*['"]?([A-Za-z0-9/+=]{40})""",
        "severity": 10,
        "confidence": "high",
    },
    "Google API Key": {
        "pattern": r"""AIza[0-9A-Za-z_-]{35}""",
        "severity": 7,
        "confidence": "high",
    },
    "GitHub Token": {
        "pattern": r"""(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,255}""",
        "severity": 9,
        "confidence": "high",
    },
    "Slack Token": {
        "pattern": r"""xox[bpoa]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,34}""",
        "severity": 8,
        "confidence": "high",
    },
    "Stripe Secret Key": {
        "pattern": r"""(?:sk_live|rk_live)_[A-Za-z0-9]{20,}""",
        "severity": 10,
        "confidence": "high",
    },
    "Private Key Block": {
        "pattern": r"""-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----""",
        "severity": 10,
        "confidence": "high",
    },
    "JWT Token": {
        "pattern": r"""eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}""",
        "severity": 6,
        "confidence": "medium",
    },
    "Generic API Key Assignment": {
        "pattern": r"""(?i)(?:api[_-]?key|api[_-]?secret|auth[_-]?token|access[_-]?token|secret[_-]?key)\s*[=:]\s*['"][A-Za-z0-9_\-/+=]{16,}['"]""",
        "severity": 7,
        "confidence": "medium",
    },
    "Hardcoded Password": {
        "pattern": r"""(?i)(?:password|passwd|pwd)\s*[=:]\s*['"][^'"]{8,}['"]""",
        "severity": 7,
        "confidence": "low",
    },
}

# --- Prototype Pollution Patterns (regex) ---
PROTO_POLLUTION_PATTERNS = {
    "__proto__ in bracket access": {
        "pattern": r"""\[['"]__proto__['"]\]""",
        "severity": 8,
        "confidence": "medium",
    },
}

# --- SSRF Patterns ---
SSRF_PATTERNS = {
    "fetch with dynamic URL": {
        "pattern": r"""\bfetch\s*\(\s*(?:[a-zA-Z_$][\w$]*(?:\.[a-zA-Z_$][\w$]*)*|`[^`]*\$\{)""",
        "severity": 7,
        "confidence": "medium",
    },
    "XMLHttpRequest open": {
        "pattern": r"""\.open\s*\(\s*['"][A-Z]+['"]\s*,\s*(?:[a-zA-Z_$][\w$]*(?:\.[a-zA-Z_$][\w$]*)*|`[^`]*\$\{)""",
        "severity": 7,
        "confidence": "medium",
    },
}

# --- Insecure Randomness Patterns ---
INSECURE_RANDOMNESS_PATTERNS = {
    "Math.random in security context": {
        "pattern": r"""\bMath\.random\s*\(\s*\)""",
        "severity": 5,
        "confidence": "low",
    },
}

# --- Dynamic Script Creation ---
DYNAMIC_SCRIPT_PATTERNS = {
    "createElement script": {
        "pattern": r"""createElement\s*\(\s*['"]script['"]\s*\)""",
        "severity": 6,
        "confidence": "medium",
    },
}

# --- postMessage Origin Check Pattern ---
POSTMESSAGE_HANDLER_PATTERN = r"""addEventListener\s*\(\s*['"]message['"]"""
POSTMESSAGE_ORIGIN_CHECK = r"""(?:event|e|evt|msg)\.origin\s*[!=]==?\s*['"]"""

# --- Source Map URL Pattern ---
SOURCE_MAP_URL_PATTERN = r"""//[#@]\s*sourceMappingURL\s*=\s*(\S+)"""
