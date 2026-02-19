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

Each script is scored by the highest signal found:

| Signal                | What it detects                                                | Score  |
| --------------------- | -------------------------------------------------------------- | ------ |
| postMessage handler   | `addEventListener('message')` without origin check, near sinks | 7-9    |
| Prototype pollution   | Deep merge/extend calls (`_.merge`, `$.extend(true, ...)`)     | 7      |
| Interesting endpoints | Internal, admin, auth, GraphQL, WebSocket URLs                 | 4-6    |
| Sensitive strings     | Hardcoded secrets, internal IPs, cloud URLs, JWTs              | 5-9    |
| Known CVEs            | Library with published vulnerabilities                         | By CVE |

If a script has multiple signals, the highest score wins. The individual signals are not exposed — just the final score.

### Anomaly Detection

Anomaly findings are separate from script scoring. They track changes across scans:

- **`new_script`** (score 7) — script URL not seen in previous scan
- **`modified_script`** (score 8) — same URL but structural hash changed
- **`origin_anomaly`** (score 8) — script served from unexpected hostname
- **`source_and_sink`** (score 6) — reads user input AND writes to dangerous sinks
- **`inline_with_sinks`** (score 7) — inline script block containing sinks
- **`not_minified`** / **`small_non_library`** (score 5) — code that likely got less scrutiny

### Response Headers

- **CORS wildcard + credentials** (score 9) — exploitable misconfiguration
- **CSP removed/weakened** (score 7) — CSP header disappeared or gained unsafe-inline/unsafe-eval

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
