# JSBot

Opinionated JavaScript security scanner. Give it a domain, it does the rest.

JSBot handles target discovery, crawling, JS extraction, deduplication, and security analysis as a single pipeline. Point it at a domain — it finds subdomains via CT logs, pulls historical URLs from Common Crawl, discovers paths from robots.txt and sitemaps, spiders for deeper pages, fetches source maps for original code, and deduplicates scripts by structural hash. Analysis is two-pronged: Semgrep runs battle-tested rules for real vulnerabilities (XSS, secrets, SSRF), while a custom anomaly detection system builds per-subdomain profiles and flags scripts that are unusual for their context. You don't pick the tools or tune the settings — JSBot decides.

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

If Semgrep is installed, JSBot runs it as a batch after collecting all unique scripts. This catches real vulnerabilities using thousands of community-maintained rules:

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

JSBot builds a statistical profile for each subdomain during a scan. For every script, it extracts a feature vector:

- **Size**: byte count, line count, average line length
- **Structure**: minified or not, known library or custom code, source map available
- **Functionality**: eval/Function usage, DOM sinks, fetch calls, postMessage, redirects, cookie access, crypto operations, storage access
- **AST-derived**: taint source count, taint sink count, global write count

After all scripts are collected, each script is scored against its subdomain's profile. Scripts that deviate significantly from the norm get flagged:

- A non-minified script on a subdomain where 80%+ is minified (no hardened build process = more bugs = faster to review)
- Unusual functionality (eval on a content page, crypto on a marketing page)
- Size outliers (one massive script among small ones)
- Custom code on a library-heavy subdomain

Profiles are persisted across scans. On repeat scans, JSBot scores against the historical baseline — new scripts that don't match established patterns get surfaced automatically.

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

URLs are scored by **novelty + interestingness** and scanned highest-first. Novelty is the primary signal — URLs with path segments JSBot hasn't seen before get prioritized. Path segments are persisted across scans.

## Finding Types

| Type | Method | Description |
|------|--------|-------------|
| `semgrep` | Semgrep | Static vulnerability (XSS, secrets, SSRF, etc.) with CWE/OWASP metadata |
| `cross_file_taint` | AST | Tainted global written by one script, read into sink by another |
| `dangerous_global_function` | AST | Function on window/globalThis containing sinks |
| `anomaly` | statistical | Script deviates from subdomain's behavioral profile |

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

# See anomalous non-minified scripts
python scan.py target.com | jq 'select(.finding_type == "anomaly" and .is_minified == false)'
```
