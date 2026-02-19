# CLAUDE.md

## What this is

JSBot is a continuous JavaScript security scanner. It runs in the background, scores scripts by interestingness for manual review, and persists results. One finding per script hash — no duplicates, no noise. Review findings when you're ready.

## Architecture

```
cli.py           Unified CLI — start/stop/status/findings/domains/clear
scan.py          Pipeline orchestrator — crawling, queuing, URL scoring, continuous loop
analysis.py      Core analysis — scores scripts by combined interestingness signals
patterns.py      Source/sink/secret pattern definitions (SOURCES, SINKS, TAINT_SINKS)
anomaly.py       Per-subdomain change detection across scans
scoring.py       URL novelty scoring, library detection, CVE lookup (hardcoded + OSV.dev)
discovery.py     CT logs, Common Crawl, robots.txt, sitemaps, spidering
store.py         SQLite findings database — always active, handles dedup and queries
daemon.py        Background process management — PID tracking, start/stop/status
sourcemaps.py    Source map fetching and extraction
output.py        Finding persistence (→ store only, no stdout)
```

## CLI Commands

```bash
python cli.py start <domain>          # Start background scan — runs continuously
python cli.py stop [domain]           # Stop scanner (no domain = stop all)
python cli.py status                  # Running scans + finding counts
python cli.py findings [domain]       # Review findings (--score, --type, --json)
python cli.py domains                 # List all scanned domains
python cli.py clear <domain>          # Delete all state for a domain
```

Run as `python cli.py <command>`.

## Core principle: target page finder

JSBot is a target finder. It identifies scripts worth opening in a browser and looking at manually. It does not try to prove vulnerabilities — it scores interestingness.

**One finding per script hash.** Every script gets at most one entry. Multiple signals (source+sink co-occurrence, postMessage handlers, prototype pollution, endpoints, interesting strings, CVEs) are combined into a single interestingness score. The individual signals are internal — not exposed.

**Output is a ranked list.** Each finding shows: score, script URL, example page URL. That's it.

**Regex-based analysis.** All checks use compiled regex patterns. No AST parsing, no tree-sitter, no heavyweight dependencies.

**No hardcoded exclusion rules.** Don't skip analysis based on filenames, library names, or URL patterns. The scoring system handles prioritization.

## Finding types

Only three finding types in the output:

| Type                 | Source      | What it means                                                               |
| -------------------- | ----------- | --------------------------------------------------------------------------- |
| `interesting_script` | analysis.py | Script scored high enough on combined signals to be worth reviewing         |
| `anomaly`            | anomaly.py  | Script changed, came from unexpected origin, or has unusual characteristics |
| `header_issue`       | scan.py     | Missing security headers on the page                                        |

## Interestingness signals (internal, not shown)

These contribute to the `interesting_script` score but are not exposed as separate findings:

- postMessage handlers without origin checks
- Prototype pollution sinks (deep merge/extend)
- Interesting API endpoints
- Sensitive strings (secrets, internal IPs, cloud URLs)
- Known library CVEs

## State storage

All state lives in a single `jsbot.db` (SQLite, WAL mode) in the project root. All tables are domain-scoped. Tables: findings, scan_sessions, scan_state (path segments + script hashes), anomaly_profiles (per-subdomain baselines), ct_state (fetched months), ct_cache (per-month subdomain results), daemons (running PIDs), daemon_logs (recent log entries). No filesystem state files. The store initializes automatically when a scan starts. Deduplication happens at the store level by finding key.

## Background scanning

`python cli.py start` launches scan.py as a detached background process:

- PID tracked in `daemons` table of `jsbot.db`
- Log entries stored in `daemon_logs` table
- Scan runs in a continuous loop — after each full cycle, sleeps 1 hour, then re-scans
- In-memory crawl state resets between cycles; SEEN_SCRIPTS and path segments persist
- Clean shutdown via `python cli.py stop` (sends SIGTERM/taskkill)

There is no foreground mode. The scanner always runs in the background.

## Testing changes

Start a scan and review findings:

```
python cli.py start public-firing-range.appspot.com
python cli.py findings public-firing-range.appspot.com
```

## What not to do

- Don't add `if library: skip` guards. Fix the analysis to be correct.
- Don't expose individual signal types as separate findings. Combine into one score per script.
- Don't hardcode URL or filename exclusions. The scoring system handles prioritization.
- Don't make the database optional. It is always on.
- Don't add foreground or one-shot modes. The scanner runs in the background only.
