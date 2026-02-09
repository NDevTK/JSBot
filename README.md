# JSBot

Opinionated JavaScript security scanner. Give it a domain, it does the rest.

JSBot handles target discovery, crawling, JS extraction, deduplication, and security analysis as a single pipeline. Point it at a domain — it finds subdomains via CT logs, discovers paths from robots.txt and sitemaps, spiders for deeper pages, fetches source maps for original code, deduplicates scripts by structural hash, analyzes with tree-sitter AST parsing (regex fallback), tracks taint flows across scripts on the same page, and scores every script for security research interestingness. You don't pick the tools or tune the settings — JSBot decides.

## Install

```
pip install -r requirements.txt
```

Core: `httpx[http2]`, `beautifulsoup4`, `lxml`, `jsbeautifier`
AST analysis: `tree-sitter`, `tree-sitter-javascript` (optional — falls back to regex)
Discovery: `waybackpy` (for Wayback), `psycopg2-binary` (for CT logs)

## Quick Start

```bash
# Give it a domain — CT log subdomain discovery, Wayback history, spidering, source maps, all automatic
python scan.py --ct example.com -w -v > results.jsonl

# Or give it URLs if you already have them
python scan.py urls.txt > results.jsonl

# Stdin works too
echo "https://example.com" | python scan.py - > results.jsonl

# Authenticated scan
python scan.py --ct example.com -b "session=abc123" -H "X-CSRF-Token: xyz" > results.jsonl

# Fast targeted scan — skip discovery, just crawl and analyze
python scan.py --minimal urls.txt > results.jsonl
```

Zero flags needed for a good scan. Discovery, spidering, smart sorting, source maps, and beautification are all on by default. `--minimal` strips it back to bare crawl-and-analyze.

## What It Finds

### Taint Flows (AST + regex)

User-controllable **sources** flowing into dangerous **sinks** within the same function scope. AST mode uses tree-sitter for real function boundaries and filters false positives (e.g., `eval("2+2")` with only literal arguments is suppressed). Falls back to regex scope splitting when tree-sitter is unavailable.

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

Requires tree-sitter (AST mode only).

### Source Map Analysis

Automatically fetches `.map` files for every script:

1. Checks `//# sourceMappingURL=` comment
2. Tries `<script_url>.map` convention
3. Handles `data:` URI inline maps (base64)

If `sourcesContent` is present, JSBot re-analyzes the original unminified source — better variable names, real structure, more accurate findings. Disable with `--no-sourcemaps`.

### Deduplication

Scripts are deduplicated two ways:
- **Raw SHA256**: exact match, compatible with `--ignore-hashes`
- **Structural hash**: strips comments and normalizes whitespace before hashing — catches the same code with different minification

Same logic seen on 50 pages is analyzed once.

## Target Discovery

All discovery features are **on by default**. Use `--no-*` flags or `--minimal` to disable.

### URL Scoring

URLs are scored and scanned highest-first:

| Signal | Points | Examples |
|--------|--------|---------|
| Path segment keyword | +3 each | `/admin/`, `/api/`, `/callback/`, `/oauth/` |
| Query parameter keyword | +5 each | `?redirect=`, `?url=`, `?callback=` |
| Non-www subdomain | +2 | `dev.example.com` |
| Subdomain keyword | +4 | `staging.`, `internal.`, `beta.` |
| Has query parameters | +2 | Any URL with `?` |

Use `--min-score N` to skip low-value targets.

### CT Log Discovery (`--ct DOMAIN`)

Discovers subdomains from Certificate Transparency logs via the crt.sh PostgreSQL database.

1. Queries crt.sh one month at a time (current backward to 2019)
2. Extracts subdomains from certificate SANs
3. Feeds discovered URLs into the scan pipeline immediately — scanning and discovery run concurrently
4. Caches results in `.ct_cache/` — re-running resumes where it left off
5. Reports related domains (shared SANs from the same organization)

### Path Discovery

Fetches `robots.txt` and `sitemap.xml` from each domain. Disallowed paths are often the most interesting.

### Spider

Follows same-domain `<a href>` links (depth 1) after the main crawl.

## All Options

```
Scan Configuration:
  -c, --concurrency N     Concurrent requests (default: 20)
  -w, --wayback           Expand scope with Wayback Machine URLs
  --no-clean-url          Keep query parameters (default strips for dedup)
  --link-mode             Only extract URLs found in JS files
  --minimal               Disable all auto-discovery at once

Taint Analysis:
  --context-lines N       Lines of context in findings (default: 3)
  --include-sink-only     Include sink-only findings (no source in scope)

Target Discovery:
  --ct DOMAIN             Discover subdomains from CT logs
  --smart-sort            Prioritize by vulnerability likelihood (default: on)
  --no-smart-sort         Disable URL scoring
  --discover              Find paths from robots.txt/sitemap.xml (default: on)
  --no-discover           Disable path discovery
  --spider                Follow links for deeper endpoints (default: on)
  --no-spider             Disable spidering
  --min-score N           Skip URLs scoring below N (default: 0)

HTTP:
  -H, --header HEADER     Custom header (repeatable)
  -b, --cookie COOKIE     Cookie header string
  --no-redirects          Don't follow redirects
  -k, --insecure          Skip TLS verification

Output & Analysis:
  -s, --save              Save unique JS files to disk (SHA256-named)
  -v, --verbose           Verbose logging to stderr
  --show-errors           Show HTTP error details
  --ignore-hashes FILE    SHA256 hashes of scripts to skip
  --format-js             Beautify JS before analysis (default: on)
  --no-format             Disable JS beautification
  --no-sourcemaps         Disable source map fetching
```

## Finding Types Reference

| Type | Method | Description |
|------|--------|-------------|
| `taint_flow` | AST/regex | Source flows into sink in same scope |
| `taint_flow_grouped` | AST/regex | One source reaches multiple sinks |
| `sink_only` | AST/regex | Sink without source in scope (opt-in: `--include-sink-only`) |
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
# Full recon on a domain — finds subdomains, crawls, spiders, analyzes
python scan.py --ct target.com -w -v > findings.jsonl

# Scan specific URLs
python scan.py urls.txt > findings.jsonl

# Fast targeted scan, no discovery
python scan.py --minimal urls.txt > findings.jsonl

# Authenticated app
python scan.py --ct target.com -b "session=abc" -H "X-CSRF-Token: xyz" > findings.jsonl

# Save scripts, skip known libraries
python scan.py -s --ignore-hashes known_libs.txt urls.txt > findings.jsonl

# Filter high-severity taint flows
python scan.py urls.txt | jq 'select(.finding_type | startswith("taint_flow")) | select(.severity >= 8)'

# Just secrets
python scan.py urls.txt | jq 'select(.finding_type == "secret")'

# Cross-file issues only
python scan.py urls.txt | jq 'select(.finding_type == "cross_file_taint")'

# Scripts worth manual review
python scan.py urls.txt | jq 'select(.finding_type == "interesting_script") | {url: .script_url, score: .interestingness_score, reasons}'
```
