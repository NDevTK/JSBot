# JSBot

Continuous JavaScript security scanner. Runs in the background, finds vulnerabilities, persists results. Review findings when you're ready.

```bash
# Start scanning
python cli.py start example.com

# Check what it found
python cli.py findings

# See what's running
python cli.py status

# Stop
python cli.py stop example.com
```

## Install

```
pip install -r requirements.txt
```

No external analysis tools — all security analysis runs inline via tree-sitter AST. Findings persist to SQLite — no external database required.

## Commands

| Command                           | Description                                                |
| --------------------------------- | ---------------------------------------------------------- |
| `python cli.py start <domain>`    | Start background scan. Runs continuously, re-scans hourly. |
| `python cli.py stop [domain]`     | Stop a running scan. Omit domain to stop all.              |
| `python cli.py status`            | Show running scans, uptimes, finding counts.               |
| `python cli.py findings [domain]` | Review findings with filters.                              |
| `python cli.py domains`           | List all scanned domains with summaries.                   |
| `python cli.py clear <domain>`    | Delete all state and findings for a domain.                |

### Start Options

```bash
# Basic
python cli.py start example.com

# With authentication
python cli.py start example.com -b "session=abc123" -H "X-CSRF-Token: xyz"

# Force re-analysis of everything
python cli.py start example.com --rescan
```

The scanner runs in the background. Each cycle: discovers subdomains via CT logs, pulls historical URLs from Common Crawl, discovers paths from robots.txt and sitemaps, spiders for deeper pages, fetches source maps, and analyzes every script it finds. After a full pass, it sleeps for an hour and re-scans — detecting new scripts, modified code, and configuration changes.

### Reviewing Findings

```bash
# All findings, newest first
python cli.py findings example.com

# High severity only
python cli.py findings --severity 8

# By type
python cli.py findings --type taint_flow
python cli.py findings --type postmessage_issue
python cli.py findings --type anomaly

# JSONL export (for jq, scripts, etc.)
python cli.py findings --json

# Show more
python cli.py findings --limit 200
```

## Analysis

### Taint Flow (Intra-File)

Tree-sitter AST analysis tracks user-controlled data from sources to sinks within each script. Taint tracking is scoped to function boundaries — each function gets its own taint map, child functions inherit from parents, and local declarations/parameters shadow inherited taint. This prevents minified variable name collisions across functions from producing false positives.

Two detection modes:

```javascript
// Direct: source flows straight into sink (AST extracts the value
// portion of the sink expression, not the whole line)
el.innerHTML = location.hash;

// Via variable: source stored, then used in sink
var input = new URLSearchParams(location.search).get("q");
document.getElementById("results").innerHTML = input;
```

Direct mode uses AST to extract only the value flowing into the sink (RHS for assignments, arguments for calls). Self-assignments like `location.href = location.href` produce no finding — no new data flows.

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

JSBot tracks scripts across scans to detect changes and contextual anomalies. Profiles are persisted in the SQLite database (`anomaly_profiles` table) — the first scan builds a baseline, subsequent scans detect deviations.

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

Overlooked signals compound with vulnerability surface: overlooked + sinks → severity 6, overlooked + source-and-sink → severity 7.

### postMessage Analysis

Dedicated AST analysis for message event handlers. JSBot finds `addEventListener('message', ...)` and `window.onmessage = ...` patterns, then checks:

- **Origin validation**: Does the handler check `event.origin` before acting?
- **Sink flow**: Does `event.data` reach a dangerous sink (innerHTML, eval, etc.)?

| Issue                       | Severity | Meaning                                                                                  |
| --------------------------- | -------- | ---------------------------------------------------------------------------------------- |
| `no_origin_check_with_sink` | 9        | No origin check + data flows to sink. Likely exploitable.                                |
| `no_origin_check`           | 7        | No origin check, but no obvious sink. Still worth reviewing.                             |
| `data_to_sink`              | 6        | Origin is checked, but data still reaches a sink. Check if the validation is sufficient. |

### Endpoint Extraction

Extracts API endpoints, internal paths, and WebSocket URLs from JavaScript source. Captured patterns: `fetch()`, `axios.*()`, `XMLHttpRequest.open()`, string literals matching `/api/`, `/graphql/`, `/internal/`, `/admin/`, and `wss://` WebSocket URLs.

### Interesting String Extraction

Extracts sensitive recon data embedded in JavaScript:

- **Internal IPs** (severity 6) — RFC1918 addresses
- **Cloud URLs** (severity 6-7) — AWS S3, Firebase, Supabase, GCS, Azure
- **JWT tokens** (severity 8) — Hardcoded JWTs
- **Debug flags** (severity 5) — `debugMode = true`, `isAdmin = true`
- **Security TODOs** (severity 5) — Comments containing security keywords

### Known CVE Detection

Two-layer library vulnerability detection:

1. **Specific fingerprints** — high-confidence regex patterns for jQuery, Angular.js, Vue.js, Lodash, Bootstrap, and Moment.js with a hardcoded CVE database (works offline).
2. **Generic detection + OSV.dev** — catches smaller libraries, queries the OSV.dev vulnerability database. Results are cached per library+version.

### Response Headers

Checks HTTP response headers for exploitable misconfigurations:

- **CORS wildcard + credentials** (severity 9) — `Access-Control-Allow-Origin: *` with `Access-Control-Allow-Credentials: true`.

CSP analysis uses **anomaly detection** — tracks CSP state per subdomain across scans and detects changes:

- **`csp_removed`** (severity 7) — CSP header was present in the previous scan but is now missing.
- **`csp_weakened`** (severity 7) — CSP gained `unsafe-inline` or `unsafe-eval` since the previous scan.

## Discovery

### CT Logs

Certificate Transparency logs reveal subdomains. JSBot queries crt.sh month-by-month, caches results, and streams discovered subdomains into the crawl queue.

### Common Crawl

Historical URLs from the Common Crawl archive — pages that existed in the past and may still serve interesting JavaScript.

### robots.txt, sitemaps, spidering

Standard path discovery: robots.txt disallowed paths, sitemap.xml entries, and recursive link following within the same domain.

### URL Scoring

URLs are scored by novelty + interestingness and scanned highest-first. Novelty persists across sessions — repeat scans automatically prioritize unexplored URLs. Hosts that produce findings get crawl credits.

## State & Storage

All state lives in a single `jsbot.db` (SQLite, WAL mode) in the project root:

| Table              | Purpose                                              |
| ------------------ | ---------------------------------------------------- |
| `findings`         | All scan findings with dedup and filtering           |
| `scan_sessions`    | Scan lifecycle tracking (start/end, status)          |
| `scan_state`       | Path segments + analyzed script hashes               |
| `anomaly_profiles` | Per-subdomain script baselines for change detection  |
| `ct_state`         | CT log state — which crt.sh months have been fetched |
| `ct_cache`         | Cached CT results per month                          |
| `daemons`          | Running scanner PIDs                                 |
| `daemon_logs`      | Recent log entries from scanner processes            |

All tables are domain-scoped. No filesystem state — everything in one file.

## Finding Types

| Type                        | Method                 | Description                                                       |
| --------------------------- | ---------------------- | ----------------------------------------------------------------- |
| `taint_flow`                | AST                    | User input flows to dangerous sink via variable tracking          |
| `cross_file_taint`          | AST                    | Tainted global written by one script, read into sink by another   |
| `dangerous_global_function` | AST                    | Function on window/globalThis containing sinks                    |
| `anomaly`                   | change detection + AST | Script change, origin anomaly, or vulnerability surface           |
| `postmessage_issue`         | AST                    | Message handler with missing origin check or data flowing to sink |
| `endpoint`                  | regex                  | API endpoint, WebSocket URL, or internal path                     |
| `interesting_string`        | regex                  | Internal IP, cloud URL, JWT, secret, debug flag, or security TODO |
| `known_cve`                 | version detection      | Library with known CVE                                            |
| `header_issue`              | header analysis        | CORS misconfiguration or CSP weakening                            |
