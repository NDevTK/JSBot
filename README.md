# JSBot

JavaScript security scanner with source-to-sink taint analysis and smart target discovery.

Crawls web pages, extracts JavaScript, and identifies data flows from user-controllable inputs into dangerous sinks. Prioritizes targets most likely to contain vulnerabilities so you find XSS on `dev.example.com/admin/callback?redirect=` before wasting time on `www.example.com`.

## Install

```
pip install -r requirements.txt
```

## Quick Start

```bash
# Scan a list of URLs
python scan.py urls.txt > results.jsonl

# Pipe from subdomain discovery, enable everything
subfinder -d example.com | python scan.py -w --discover --spider --smart-sort -v - > results.jsonl

# Only scan high-value targets
python scan.py --smart-sort --min-score 5 --no-clean-url urls.txt > results.jsonl
```

## What It Finds

JSBot detects when user-controllable **sources** flow into dangerous **sinks** within the same function scope.

**Sources** (user input): `location.hash`, `location.search`, `document.URL`, `document.referrer`, `window.name`, `postMessage` event data, `URLSearchParams`, `localStorage.getItem`, `document.cookie`, `e.target.value`

**Sinks** (dangerous operations): `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`, `eval`, `Function()`, `setTimeout` with strings, `location.assign`, `location.replace`, jQuery `.html()/.append()`, `v-html`, `dangerouslySetInnerHTML`, `document.cookie` writes, `.postMessage()`

### Finding Types

**`taint_flow`** — source and sink in the same function scope. These are the ones you care about.

```json
{
  "source_url": "https://dev.example.com/app",
  "script_url": "https://dev.example.com/js/app.js",
  "script_hash": "a1b2c3...",
  "finding_type": "taint_flow",
  "sink_category": "DOM XSS",
  "sink_match": "innerHTML =",
  "sink_line": 42,
  "source_category": "location.hash",
  "source_match": "location.hash",
  "source_line": 38,
  "severity": 9,
  "context": ["  var input = location.hash.slice(1);", "  processInput(input);", "  el.innerHTML = input;"]
}
```

**`sink_only`** — dangerous sink found but no user-controllable source in scope. Severity is halved. Still worth reviewing if the function receives data from callers.

```json
{
  "source_url": "https://example.com/page",
  "script_url": "https://example.com/js/utils.js",
  "script_hash": "d4e5f6...",
  "finding_type": "sink_only",
  "sink_category": "Eval Injection",
  "sink_match": "eval(",
  "sink_line": 15,
  "source_category": null,
  "source_match": null,
  "source_line": null,
  "severity": 5,
  "context": ["  function run(code) {", "    eval(code);", "  }"]
}
```

Findings are deduplicated by script hash + sink + source + line numbers. Same code seen on multiple pages is reported once.

## Target Discovery

### URL Scoring (`--smart-sort`)

URLs are scored and scanned in priority order:

| Signal | Points | Examples |
|--------|--------|---------|
| Path segment matches keyword | +3 each | `/admin/`, `/api/`, `/callback/`, `/oauth/` |
| Query parameter name matches keyword | +5 each | `?redirect=`, `?url=`, `?callback=` |
| Non-www subdomain | +2 | `dev.example.com`, `api.example.com` |
| Subdomain contains keyword | +4 | `staging.`, `internal.`, `beta.` |
| Has any query parameters | +2 | Any URL with `?` |

Path matching uses whole segments — `/latest/` won't false-match on `test`. Scores are computed before URL cleaning, so even when params are stripped for dedup the highest score from any variant carries forward.

Use `--min-score N` to skip low-value URLs entirely.

### Path Discovery (`--discover`)

Fetches `robots.txt` and `sitemap.xml` from each domain. Disallowed paths in robots.txt are often the most interesting endpoints — admin panels, internal APIs, debug routes that someone tried to hide.

### Spider Mode (`--spider`)

Follows same-domain `<a href>` links found on crawled pages. Runs as a single pass after the main crawl (depth 1) to avoid spiraling.

## All Options

```
Scan Configuration:
  -c, --concurrency N     Concurrent requests (default: 20)
  -w, --wayback           Expand scope with Wayback Machine historical URLs
  --no-clean-url          Keep query parameters (default strips them for dedup)
  --link-mode             Only extract URLs found in JS files

Taint Analysis:
  --context-lines N       Lines of context in findings (default: 3)

Target Discovery:
  --smart-sort            Prioritize URLs by vulnerability likelihood
  --discover              Find paths from robots.txt and sitemap.xml
  --spider                Follow links to discover deeper endpoints
  --min-score N           Skip URLs scoring below N (default: 0)

HTTP:
  -H, --header HEADER     Custom header (repeatable)
  -b, --cookie COOKIE     Cookie header string
  --no-redirects          Don't follow redirects
  -k, --insecure          Skip TLS verification

Output:
  -s, --save              Save unique JS files to disk (named by SHA256)
  -v, --verbose           Verbose logging to stderr
  --show-errors           Show HTTP error details
  --ignore-hashes FILE    SHA256 hashes of scripts to skip
  --format-js             Beautify JS before analysis
```

## Examples

**Bug bounty recon** — discover subdomains, pull historical URLs, find hidden paths, spider for depth, scan highest-value targets first:

```bash
subfinder -d target.com | python scan.py -w --discover --spider --smart-sort -v - > findings.jsonl
```

**Targeted scan with auth** — scan an authenticated app:

```bash
python scan.py -b "session=abc123" -H "X-CSRF-Token: xyz" --no-clean-url urls.txt > findings.jsonl
```

**Save all scripts for manual review:**

```bash
python scan.py -s --ignore-hashes known_libs.txt urls.txt > findings.jsonl
```

**Filter to only taint flows** (skip sink-only noise):

```bash
python scan.py urls.txt | jq 'select(.finding_type == "taint_flow")'
```

**Grep findings for specific sink types:**

```bash
python scan.py urls.txt | jq 'select(.sink_category == "DOM XSS" and .severity >= 8)'
```
