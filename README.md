# JSBot

Opinionated JavaScript security scanner. Give it a domain, it does the rest.

JSBot handles target discovery, crawling, JS extraction, deduplication, and security analysis as a single pipeline. Point it at a domain — it finds subdomains via CT logs, pulls historical URLs from Common Crawl, discovers paths from robots.txt and sitemaps, spiders for deeper pages, fetches source maps for original code, deduplicates scripts by structural hash, analyzes with tree-sitter AST parsing, tracks taint flows across scripts on the same page, and scores every script for security research interestingness. You don't pick the tools or tune the settings — JSBot decides.

## Install

```
pip install -r requirements.txt
```

## Usage

```bash
# Give it a domain — that's it
python scan.py example.com > results.jsonl

# Or give it URLs if you already have them
python scan.py urls.txt > results.jsonl

# Stdin works too
echo "https://example.com" | python scan.py > results.jsonl

# Authenticated scan
python scan.py example.com -b "session=abc123" -H "X-CSRF-Token: xyz" > results.jsonl
```

JSBot auto-detects whether you gave it a domain, a URL, a file, or stdin. For domains, it automatically runs CT log subdomain discovery. Common Crawl history, path discovery (robots.txt/sitemap.xml), spidering, source maps, JS beautification, and smart URL prioritization are always on.

## Options

```
python scan.py [input] [-H HEADER] [-b COOKIE] [-v] [--show-errors] [-s] [--ignore-hashes FILE]

  input               Domain, URL, file of URLs, or '-' for stdin
  -H, --header        Custom HTTP header (repeatable)
  -b, --cookie        Cookie header value
  -v, --verbose       Verbose logging to stderr
  --show-errors       Show HTTP error details on stderr
  -s, --save          Save unique JS files to disk (SHA256-named)
  --ignore-hashes     File of SHA256 hashes to skip
```

That's it. Everything else is automatic.

## What It Finds

### Taint Flows (AST)

User-controllable **sources** flowing into dangerous **sinks** within the same function scope. Uses tree-sitter for real function boundaries and filters false positives (e.g., `eval("2+2")` with only literal arguments is suppressed).

**Sources**: `location.hash/search/href/pathname`, `document.URL/referrer`, `window.name`, `event.data` (postMessage), `URLSearchParams`, `localStorage/sessionStorage.getItem`, `document.cookie`, `e.target.value`

**Sinks**: `innerHTML/outerHTML =`, `insertAdjacentHTML()`, `document.write()`, `eval()/Function()`, `setTimeout/setInterval` with strings, `location.assign/replace/href =`, jQuery `.html()/.append()/.prepend()/.after()/.before()`, `v-html`, `dangerouslySetInnerHTML`, `document.cookie =`, `.postMessage()`

When a single source reaches multiple sinks, findings are grouped:

```json
{
  "finding_type": "taint_flow_grouped",
  "source_category": "location.hash",
  "source_line": 3,
  "sink_count": 2,
  "sinks": [
    {"category": "DOM XSS", "match": "innerHTML =", "line": 10},
    {"category": "document.write", "match": "document.write(", "line": 15}
  ],
  "severity": 9,
  "analysis_method": "ast"
}
```

### Secrets

Hardcoded credentials detected by high-confidence regex patterns:

| Pattern | Example | Severity |
|---------|---------|----------|
| AWS Access Key | `AKIA...` | 10 |
| AWS Secret Key | `aws_secret_access_key = "..."` | 10 |
| Stripe Secret Key | `sk_live_...` | 10 |
| Private Key Block | `-----BEGIN RSA PRIVATE KEY-----` | 10 |
| GitHub Token | `ghp_...` | 9 |
| Slack Token | `xox[bpoa]-...` | 8 |
| Google API Key | `AIza...` | 7 |
| Generic API Key Assignment | `api_key = "..."` | 7 |
| Hardcoded Password | `password = "..."` | 7 |
| JWT Token | `eyJ...eyJ...` | 6 |

### Prototype Pollution

- `__proto__` references
- `Object.assign/create`, `_.merge/extend/defaults/defaultsDeep`
- Dynamic bracket assignment: `obj[a][b] = c`

### postMessage Without Origin Check

AST-based: finds `addEventListener("message", handler)` where the handler body doesn't check `event.origin`. These are exploitable from any origin via an attacker-controlled iframe.

### SSRF Patterns

- `fetch()` with dynamic URL (variable or template literal)
- `XMLHttpRequest.open()` with dynamic URL

### Other Detections

- **Insecure Randomness**: `Math.random()` near security-sensitive keywords (token, nonce, csrf, session, password)
- **Dynamic Script Creation**: `createElement("script")` with dynamic src
- **Interesting Scripts**: Scripts scoring 30+ on a heuristic scale (auth logic, API key handling, crypto, CORS, postMessage, dynamic code gen) — flags code worth manual review even when no specific vulnerability is detected

### Cross-File Taint Analysis

Tracks `window.X = taintedValue` assignments across all scripts on the same page. If script A writes tainted data to a global and script B reads that global into a sink, JSBot emits a `cross_file_taint` finding. Also detects dangerous global functions — `window.renderHTML = (html) => { el.innerHTML = html }` — that any script can call.


### Source Map Analysis

Automatically fetches `.map` files for every script:

1. Checks `//# sourceMappingURL=` comment
2. Tries `<script_url>.map` convention
3. Handles `data:` URI inline maps (base64)

If `sourcesContent` is present, JSBot re-analyzes the original unminified source — better variable names, real structure, more accurate findings.

### Deduplication

Scripts are deduplicated two ways:
- **Raw SHA256**: exact match, compatible with `--ignore-hashes`
- **Structural hash**: strips comments and normalizes whitespace before hashing — catches the same code with different minification

Same logic seen on 50 pages is analyzed once.

## How It Works

### Auto-Detection

JSBot figures out what you gave it:

| Input | What happens |
|-------|-------------|
| `example.com` | CT log subdomain discovery + Common Crawl + full scan |
| `https://example.com/app` | Crawl that URL + discovery + spider |
| `urls.txt` | Read file, crawl all URLs |
| stdin | Read piped URLs, crawl all |

### Async Pipeline

Three stages run concurrently — discovery doesn't block crawling, crawling doesn't block analysis:

```
CT logs / Common Crawl / seed URLs
        ↓
   domain_queue → domain_discovery_worker (robots.txt, sitemap.xml)
        ↓
   url_queue → page_crawl_worker (fetch pages, extract scripts, spider)
        ↓
   js_queue → js_audit_worker (dedup, analyze, source maps, cross-file)
```

Spider links feed back into the URL queue. JS paths discovered inside scripts feed back into the JS queue. Everything flows.

### URL Scoring

URLs are scored by **novelty + interestingness** and scanned highest-first. Novelty is the primary signal — URLs with path segments JSBot hasn't seen before get prioritized over redundant variations of the same endpoint.

**Novelty** (0–20 points):

| Condition | Score |
|-----------|-------|
| All path segments are new | 20 |
| Some segments new, some seen | proportional (e.g., 2/4 new = 10) |
| Root URL (no path) | 10 |
| Exact path already seen | 0 |

Path segments seen during a scan are persisted to disk, so repeat scans automatically deprioritize already-explored areas.

**Interestingness** (0–∞ bonus points):

| Signal | Points | Examples |
|--------|--------|---------|
| Path segment keyword | +3 each | `/admin/`, `/api/`, `/callback/`, `/oauth/` |
| Query parameter keyword | +5 each | `?redirect=`, `?url=`, `?callback=` |
| Non-www subdomain | +2 | `dev.example.com` |
| Subdomain keyword | +4 | `staging.`, `internal.`, `beta.` |
| Has query parameters | +2 | Any URL with `?` |

## Finding Types Reference

| Type | Method | Description |
|------|--------|-------------|
| `taint_flow` | AST | Source flows into sink in same scope |
| `taint_flow_grouped` | AST | One source reaches multiple sinks |
| `secret` | regex | Hardcoded API key, token, or credential |
| `prototype_pollution` | regex | `__proto__`, Object.assign, bracket chains |
| `postmessage_no_origin` | AST | Message listener without origin check |
| `ssrf` | regex | fetch/XHR with dynamic URL |
| `insecure_randomness` | regex | Math.random() in security context |
| `dynamic_script_creation` | regex | createElement("script") |
| `interesting_script` | heuristic | Script scoring 30+ on interestingness scale |
| `cross_file_taint` | AST | Tainted global written by one script, read into sink by another |
| `dangerous_global_function` | AST | Function on window/globalThis containing sinks |

## Examples

```bash
# Scan a domain
python scan.py target.com > findings.jsonl

# Scan a domain with auth
python scan.py target.com -b "session=abc" -H "X-CSRF-Token: xyz" > findings.jsonl

# Scan URLs from a file
python scan.py urls.txt > findings.jsonl

# Save scripts for later review
python scan.py target.com -s > findings.jsonl

# Skip known libraries on repeat scans
python scan.py target.com --ignore-hashes known_libs.txt > findings.jsonl

# Filter results with jq
python scan.py target.com | jq 'select(.severity >= 8)'
python scan.py target.com | jq 'select(.finding_type == "secret")'
python scan.py target.com | jq 'select(.finding_type == "cross_file_taint")'
```
