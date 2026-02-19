# JSBot

Target page finder. Scans JavaScript at scale, scores scripts by interestingness, shows you which pages to open in a browser. One entry per script — no duplicates, no noise.

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

All analysis runs inline via regex pattern matching — no external tools, no AST parsing. Findings persist to SQLite.

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

The scanner runs in the background. Each cycle: discovers subdomains via CT logs, pulls historical URLs from Common Crawl, discovers paths from robots.txt and sitemaps, spiders for deeper pages, fetches source maps, and scores every script it finds. After a full pass, it sleeps for an hour and re-scans.

### Reviewing Findings

```bash
# All findings, highest score first
python cli.py findings example.com

# High score only
python cli.py findings --score 8

# JSONL export (for jq, scripts, etc.)
python cli.py findings --json

# Show more
python cli.py findings --limit 200
```

Output shows one line per script: score, script URL, and an example page URL where the script is loaded.

## Philosophy

JSBot is a **target page finder**. It tells you which scripts are worth opening in a browser. It doesn't try to prove vulnerabilities — it scores interestingness.

- **One entry per script hash.** Multiple signals (source+sink co-occurrence, postMessage handlers, prototype pollution, endpoints, secrets, CVEs) are combined into a single interestingness score. The breakdown is internal.
- **Regex-based.** All analysis uses compiled regex patterns. No AST parsing, no tree-sitter, no heavyweight dependencies.
- **Fast iteration.** Scans complete quickly because analysis is lightweight. Re-scans detect changes via anomaly detection.

## How Scoring Works

Each script is scored across multiple signal types:

| Signal                | What it detects                                                          | Score  |
| --------------------- | ------------------------------------------------------------------------ | ------ |
| postMessage handler   | `addEventListener('message')` without or with weak origin check + sinks  | 6-9    |
| Prototype pollution   | Deep merge/extend calls, boosted when PP sources co-occur                | 7-8    |
| Taint flow            | User-controlled sources near dangerous sinks (proximity-weighted)        | 5-8    |
| Interesting endpoints | Redirect/JSONP/admin/auth/GraphQL/WebSocket URLs                         | 4-7    |
| Sensitive strings     | Hardcoded secrets, internal IPs, cloud URLs, JWTs (public-by-design keys deprioritized) | 2-9    |
| Known CVEs            | Library with published vulnerabilities                                   | By CVE |

The highest signal sets the base score. Each additional signal adds 10% of its own value, capped at 10. A script with multiple independent attack surfaces ranks higher than one with a single signal at the same severity. The individual signals are not exposed — just the final score.

### Anomaly Detection

Anomaly findings are separate from script scoring. The first scan builds a baseline — no anomaly findings are emitted. Subsequent scans detect changes and flag overlooked code:

- **`new_script`** (score 7-8) — script URL not seen in previous scan (boosted to 8 if script contains sinks)
- **`modified_script`** (score 8-9) — same URL but structural hash changed (boosted to 9 if script contains sinks)
- **`origin_anomaly`** (score 8) — script served from unexpected hostname
- **`inline_with_sinks`** (score 7) — inline script block containing sinks
- **`not_minified`** / **`small_non_library`** (score 5-6) — code that likely got less scrutiny (boosted to 6 if sinks present)

Profiles merge across scans — scripts from previous scans that weren't reached this time are retained, preventing false `new_script` alerts from intermittent availability.

### Response Headers

- **CORS wildcard + credentials** (score 9) — exploitable misconfiguration
- **CSP removed/weakened** (score 7) — CSP header disappeared or gained unsafe-inline/unsafe-eval

## Discovery

### CT Logs

Certificate Transparency logs reveal subdomains. JSBot queries crt.sh month-by-month, caches results, and streams discovered subdomains into the crawl queue.

### Common Crawl

Historical URLs from the Common Crawl archive — pages that existed in the past and may still serve interesting JavaScript.

### robots.txt, sitemaps, spidering

Standard path discovery: robots.txt disallowed paths, `Sitemap:` directives, sitemap index support (follows child sitemaps one level deep), and recursive link following within the same domain. Spider extracts links from `<a href>`, `<iframe src>`, and `<form action>`.

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
