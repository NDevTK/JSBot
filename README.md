# JSBot

Opinionated JavaScript security scanner. Give it a domain, it does the rest.

JSBot handles target discovery, crawling, JS extraction, deduplication, and security analysis as a single pipeline. Point it at a domain — it finds subdomains via CT logs, pulls historical URLs from Common Crawl, discovers paths from robots.txt and sitemaps, spiders for deeper pages, fetches source maps for original code, and deduplicates scripts by structural hash. Analysis is three-pronged: Semgrep runs battle-tested rules for real vulnerabilities (XSS, secrets, SSRF), AST analysis tracks taint flow across scripts on the same page, and an anomaly system detects script changes across scans and flags vulnerability surface using source/sink detection. You don't pick the tools or tune the settings — JSBot decides.

## Install

```
pip install -r requirements.txt
```

Requires Semgrep for static vulnerability detection.

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

### Semgrep (Static Vulnerabilities)

Semgrep runs periodically during the scan (every 60s) on accumulated scripts. This catches real vulnerabilities using thousands of community-maintained rules:

- **XSS**: DOM injection, `eval()` with user input, unsafe jQuery methods
- **Secrets**: AWS keys, GitHub tokens, Stripe keys, private key blocks, JWTs, hardcoded passwords
- **SSRF**: `fetch()`/`XMLHttpRequest` with dynamic URLs
- **Prototype pollution**: `__proto__` manipulation
- **postMessage**: Missing origin checks on message handlers
- **And more**: The `p/secrets` and `p/security-audit` rule packs cover OWASP top 10 for JavaScript

Findings include CWE and OWASP classifications from Semgrep's rule metadata.

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
| `semgrep` | Semgrep | Static vulnerability (XSS, secrets, SSRF, etc.) with CWE/OWASP metadata |
| `cross_file_taint` | AST | Tainted global written by one script, read into sink by another |
| `dangerous_global_function` | AST | Function on window/globalThis containing sinks |
| `anomaly` | change detection + AST | Script change, origin anomaly, or vulnerability surface (sinks, source+sink, inline) |

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
python scan.py target.com | jq 'select(.finding_type == "semgrep")'
python scan.py target.com | jq 'select(.finding_type == "anomaly")'
python scan.py target.com | jq 'select(.finding_type == "cross_file_taint")'

# See modified or new scripts (change detection)
python scan.py target.com | jq 'select(.finding_type == "anomaly" and (.signals | index("modified_script", "new_script")))'

# Find scripts with both user input sources and dangerous sinks
python scan.py target.com | jq 'select(.signals and (.signals | index("source_and_sink")))'

# Filter by sink type
python scan.py target.com | jq 'select(.sink_categories and (.sink_categories | index("DOM XSS")))'
```
