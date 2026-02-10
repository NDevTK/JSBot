# JSBot

Opinionated JavaScript security scanner. Give it a domain, it does the rest.

JSBot handles target discovery, crawling, JS extraction, deduplication, and security analysis as a single pipeline. Point it at a domain — it finds subdomains via CT logs, pulls historical URLs from Common Crawl, discovers paths from robots.txt and sitemaps, spiders for deeper pages, fetches source maps for original code, and deduplicates scripts by structural hash. Analysis covers intra-file taint flow (AST), cross-file taint flow (AST), anomaly detection (change + context signals), postMessage origin bypass, secret/credential detection, endpoint/string extraction for recon, library CVE detection, and response header analysis. Zero external analysis tools — everything runs inline via tree-sitter AST. You don't pick the tools or tune the settings — JSBot decides.

## Install

```
pip install -r requirements.txt
```

No external analysis tools required — all security analysis runs inline via tree-sitter AST.

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

## Analysis

### Taint Flow (Intra-File)

Tree-sitter AST analysis tracks user-controlled data from sources to sinks within each script. JSBot walks all variable assignments — if the right-hand side reads from a taint source (`location.hash`, `document.cookie`, `URLSearchParams`, `event.data`, etc.) or references a previously tainted variable, the left-hand side variable becomes tainted. Then checks whether any tainted variable appears in a sink expression (`innerHTML`, `eval`, `document.write`, etc.).

This catches the two most common vulnerability patterns:

```javascript
// Direct: source flows straight into sink
el.innerHTML = location.hash;

// Via variable: source stored, then used in sink
var input = new URLSearchParams(location.search).get('q');
document.getElementById('results').innerHTML = input;
```

Findings include the taint source, sink category, tainted variable name, and line number.

### Secret Detection

Regex patterns detect hardcoded credentials and API keys in JavaScript source:

- **AWS access keys** (severity 9) — `AKIA...` patterns
- **GitHub tokens** (severity 9) — `ghp_`, `ghs_`, `gho_`, `ghr_` prefixed tokens
- **Slack tokens** (severity 9) — `xoxb-`, `xoxp-`, `xoxa-`, `xoxs-` tokens
- **Stripe secret keys** (severity 9) — `sk_live_...` patterns
- **Google API keys** (severity 5) — `AIza...` patterns
- **Private key blocks** (severity 9) — `-----BEGIN PRIVATE KEY-----` and variants
- **Generic API keys** (severity 5) — `apiKey = "..."`, `secret_key = "..."` assignment patterns
- **JWTs** (severity 8) — Hardcoded `eyJ...` tokens in string literals

### Cross-File Taint

Tracks `window.X = taintedValue` assignments across all scripts on the same page. If script A writes tainted data to a global and script B reads that global into a sink, JSBot emits a `cross_file_taint` finding. Also detects dangerous global functions — `window.renderHTML = (html) => { el.innerHTML = html }` — that any script can call.

### Anomaly Detection

JSBot tracks scripts across scans to detect changes and contextual anomalies. Profiles are persisted in `.ct_cache/{domain}/anomaly_profiles.json` — the first scan builds a baseline, subsequent scans detect deviations.

**Change signals** (require previous scan data):

- **`new_script`** (severity 7) — script URL not seen in previous scan of this subdomain. Primary signal for compromise or supply chain injection. Cache-busted filenames (`app.abc123.js` → `app.def456.js`) are normalized so deploys don't trigger false positives.
- **`modified_script`** (severity 8) — same script URL (or same URL after cache-bust normalization) but structural hash changed since last scan. Indicates tampered or updated code.
- **`origin_anomaly`** (severity 8) — script served from a hostname not previously seen for this subdomain. Everything loads from `cdn.example.com` but one script loads from `sketchy-cdn.net`.

**Vulnerability surface signals** (current scan only, no history needed):

- **`has_sinks`** (severity 5) — script contains dangerous sink patterns (innerHTML, eval, document.write, etc.). Indicates attack surface worth reviewing.
- **`source_and_sink`** (severity 6) — script reads user input (location.hash, postMessage, URLSearchParams, etc.) AND writes to dangerous sinks. The ingredients for a vulnerability are in the same file.
- **`inline_with_sinks`** (severity 7) — inline `<script>` block containing sinks. High priority because inline scripts are often server-rendered with user data.

**Overlooked code signals** (code that likely got less scrutiny):

- **`not_minified`** (severity 5) — unminified custom code on a subdomain where 85%+ of scripts are minified. Skipped the build pipeline, likely got less review.
- **`small_non_library`** (severity 5) — custom script under 100 lines on a library-heavy subdomain (>50% libraries). Small custom scripts among polished libraries often mean quick fixes, debug helpers, or glue code that got less review.

Overlooked signals compound with vulnerability surface: overlooked + sinks → severity 6, overlooked + source-and-sink → severity 7. This surfaces "under-reviewed code with attack surface" as a high-priority finding.

Findings include `sink_categories` (e.g. `["DOM XSS", "Eval Injection"]`) so you can see the attack surface type without opening the script.

### postMessage Analysis

Dedicated AST analysis for message event handlers — one of the most common client-side bug classes. JSBot finds `addEventListener('message', ...)` and `window.onmessage = ...` patterns, then checks:

- **Origin validation**: Does the handler check `event.origin` before acting?
- **Sink flow**: Does `event.data` reach a dangerous sink (innerHTML, eval, etc.)?

| Issue | Severity | Meaning |
|-------|----------|---------|
| `no_origin_check_with_sink` | 9 | No origin check + data flows to sink. Likely exploitable. |
| `no_origin_check` | 7 | No origin check, but no obvious sink. Still worth reviewing. |
| `data_to_sink` | 6 | Origin is checked, but data still reaches a sink. Check if the validation is sufficient. |

### Endpoint Extraction

Extracts API endpoints, internal paths, and WebSocket URLs from JavaScript source. These are recon findings — they reveal the backend attack surface without opening a single script.

Captured patterns: `fetch()`, `axios.*()`, `XMLHttpRequest.open()`, string literals matching `/api/`, `/graphql/`, `/internal/`, `/admin/`, and `wss://` WebSocket URLs. Static file extensions (`.js`, `.css`, `.png`, etc.) are filtered out.

Severity scales with endpoint interestingness: admin/internal/debug paths get severity 6, auth/graphql/webhook paths get 5, others get 4.

### Interesting String Extraction

Extracts sensitive recon data embedded in JavaScript:

- **Internal IPs** (severity 6) — RFC1918 addresses (`10.x`, `172.16-31.x`, `192.168.x`) in strings or URLs
- **Cloud URLs** (severity 6-7) — AWS S3 buckets, Firebase realtime DBs, Supabase, Google Cloud Storage, Azure storage
- **JWT tokens** (severity 8) — Hardcoded JWTs in source code. Claims reveal user roles, service names, expiration.
- **Debug flags** (severity 5) — `debugMode = true`, `isAdmin = true`, etc.
- **Security TODOs** (severity 5) — Comments containing `TODO`/`FIXME`/`HACK` + security keywords (auth, bypass, vuln, etc.)

### Known CVE Detection

Two-layer library vulnerability detection:

1. **Specific fingerprints** — high-confidence regex patterns for jQuery, Angular.js, Vue.js, Lodash, Bootstrap, and Moment.js with a hardcoded CVE database (works offline, instant).
2. **Generic detection + OSV.dev** — a generic `/*! LibName v1.2.3 */` header pattern catches smaller libraries (DOMPurify, Flatpickr, Select2, etc.), then queries the [OSV.dev](https://osv.dev) vulnerability database for real CVE data. OSV covers the entire npm advisory database (GHSA + CVE). Results are cached per library+version.

The hardcoded database provides a fast baseline. OSV supplements it with broader coverage and catches CVEs that haven't been manually added. If the network is unavailable, the hardcoded database still works.

Findings include the exact version detected, CVE IDs, severity, and a fix threshold.

### Response Headers

Checks HTTP response headers for exploitable misconfigurations. Runs once per subdomain (first page seen):

- **CORS wildcard + credentials** (severity 9) — `Access-Control-Allow-Origin: *` with `Access-Control-Allow-Credentials: true`. Exploitable for credential theft.

CSP analysis uses **anomaly detection** instead of static checks — "this page has unsafe-inline" is true for most of the internet and isn't actionable. Instead, JSBot tracks CSP state per subdomain across scans and detects changes:

- **`csp_removed`** (severity 7) — CSP header was present in the previous scan but is now missing.
- **`csp_weakened`** (severity 7) — CSP gained `unsafe-inline` or `unsafe-eval` since the previous scan.

### Source Maps

Automatically fetches `.map` files for every script. If `sourcesContent` is present, JSBot re-analyzes the original unminified source — better variable names, real structure, more accurate findings.

### Deduplication

Scripts are deduplicated two ways:
- **Raw SHA256**: exact match, compatible with `--ignore-hashes`
- **Structural hash**: strips comments and normalizes whitespace before hashing

Same logic seen on 50 pages is analyzed once.

## Discovery

### CT Logs (Find Targets)

Certificate Transparency logs reveal subdomains — even ones not in DNS or Common Crawl. JSBot queries crt.sh month-by-month, caches results, and streams discovered subdomains into the crawl queue as they're found.

### Common Crawl (Find URLs)

Historical URLs from the Common Crawl archive. These are pages that existed in the past and may still serve interesting JavaScript, even if they're no longer linked from the main site.

### robots.txt, sitemaps, spidering

Standard path discovery: robots.txt disallowed paths (often the most interesting), sitemap.xml entries, and recursive link following within the same domain.

### URL Scoring

URLs are scored by **novelty + interestingness** and scanned highest-first. Novelty is the primary signal — URLs with path prefixes JSBot hasn't seen before get prioritized. Path prefixes are host-scoped (crawling `/api` on one subdomain doesn't reduce novelty of `/api` on another). Keyword bonuses boost paths containing `admin`, `api`, `debug`, `oauth`, `upload`, etc.

Hosts that produce findings get **crawl credits** — the scanner automatically digs deeper into subdomains where it's finding results, while still maintaining broad coverage of unexplored hosts.

## Finding Types

| Type | Method | Description |
|------|--------|-------------|
| `taint_flow` | AST | User input flows to dangerous sink via variable tracking within a script |
| `cross_file_taint` | AST | Tainted global written by one script, read into sink by another |
| `dangerous_global_function` | AST | Function on window/globalThis containing sinks |
| `anomaly` | change detection + AST | Script change, origin anomaly, or vulnerability surface (sinks, source+sink, inline) |
| `postmessage_issue` | AST | Message handler with missing origin check or data flowing to sink |
| `endpoint` | regex | API endpoint, WebSocket URL, or internal path extracted from JS |
| `interesting_string` | regex | Internal IP, cloud URL, JWT, secret, debug flag, or security TODO found in JS |
| `known_cve` | version detection | Library with known CVE (jQuery, Angular.js, Lodash, Bootstrap, Moment.js, + OSV.dev) |
| `header_issue` | header analysis | CORS misconfiguration or weak CSP on a subdomain |

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
python scan.py target.com | jq 'select(.finding_type == "taint_flow")'
python scan.py target.com | jq 'select(.finding_type == "anomaly")'
python scan.py target.com | jq 'select(.finding_type == "cross_file_taint")'

# See modified or new scripts (change detection)
python scan.py target.com | jq 'select(.finding_type == "anomaly" and (.signals | index("modified_script", "new_script")))'

# Find scripts with both user input sources and dangerous sinks
python scan.py target.com | jq 'select(.signals and (.signals | index("source_and_sink")))'

# Filter by sink type
python scan.py target.com | jq 'select(.sink_categories and (.sink_categories | index("DOM XSS")))'

# postMessage handlers without origin checks
python scan.py target.com | jq 'select(.finding_type == "postmessage_issue")'

# Extracted API endpoints (recon)
python scan.py target.com | jq 'select(.finding_type == "endpoint") | .endpoints[]'

# Interesting strings (cloud URLs, internal IPs, JWTs)
python scan.py target.com | jq 'select(.finding_type == "interesting_string") | .strings[]'

# Known CVEs in libraries
python scan.py target.com | jq 'select(.finding_type == "known_cve")'

# Header issues (CORS, CSP)
python scan.py target.com | jq 'select(.finding_type == "header_issue")'
```
