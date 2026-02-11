# CLAUDE.md

## What this is

JSBot is a continuous JavaScript security scanner. It runs in the background, finds client-side vulnerabilities (DOM XSS, open redirects, eval injection, postMessage issues) by tracking data flow from user-controlled sources to dangerous sinks using tree-sitter AST analysis. Findings persist to a SQLite database. Review them with CLI commands when you're ready.

## Architecture

```
cli.py           Unified CLI — start/stop/status/findings/domains/clear
scan.py          Pipeline orchestrator — crawling, queuing, URL scoring, continuous loop
analysis.py      Core security analysis — taint flow, postMessage, cross-file taint, endpoints
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
python cli.py findings [domain]       # Review findings (--severity, --type, --json)
python cli.py domains                 # List all scanned domains
python cli.py clear <domain>          # Delete all state for a domain
```

Run as `python cli.py <command>`.

## Core principle: AST over regex

This is a high-signal security tool. Every detection must be grounded in actual code structure, not pattern guessing.

**Use tree-sitter AST** for understanding code behavior — variable assignments, function boundaries, call expressions, argument values. The AST tells you what the code actually does.

**Avoid line-level regex** for security analysis. Regex can't scope variables to functions, can't distinguish LHS from RHS in assignments, can't tell if a source is flowing into a sink or just happens to be on the same line. Every time regex was used for detection, it produced false positives that had to be fixed with AST.

**No hardcoded exclusion rules.** Don't skip analysis based on filenames, library names, or URL patterns. If the analysis produces false positives on jQuery or Angular, the analysis logic is wrong — fix the logic so it's correct for ALL code, not just non-library code.

## State storage

All state lives in a single `jsbot.db` (SQLite, WAL mode) in the project root. All tables are domain-scoped. Tables: findings, scan_sessions, scan_state (path segments + script hashes), anomaly_profiles (per-subdomain baselines), ct_state (fetched months), ct_cache (per-month subdomain results), daemons (running PIDs), daemon_logs (recent log entries). No filesystem state files. The store initializes automatically when a scan starts. Deduplication happens at the store level by finding key.

## Taint tracking design

Taint flows through `_collect_taint_per_scope` in analysis.py:

1. Each function (`function_declaration`, `function_expression`, `arrow_function`, `method_definition`) gets its own scope
2. Child scopes inherit parent tainted variables
3. Local `var`/`let`/`const` declarations and function parameters shadow parent taint
4. Two-phase: build the scope's taint map first (skipping child functions), then recurse into children with the completed map
5. Processing is source-order (reversed children on stack) so taint chains work (`a = source; b = a; sink(b)`)

Direct mode (source directly in sink expression, no intermediate variable) uses `_extract_sink_value`:

- Finds the specific AST node matching the sink at that line
- Extracts only the value portion (RHS for assignments, arguments for calls)
- Self-assignment (LHS == RHS) returns no value — structural no-op detection

## Pattern definitions (patterns.py)

- **SOURCES** — user-controlled input origins (location.hash, document.cookie, event.data, etc.)
- **SINKS** — dangerous operations detected via AST call/assignment analysis (eval, innerHTML, document.write, etc.). Used by both taint analysis and anomaly detection.
- **TAINT_SINKS** — patterns too broad for anomaly detection but valid when tainted data reaches them (setTimeout, window.open, .src/.href assignment, fetch). Only checked during taint analysis, not anomaly scoring.
- **INTERESTING_STRING_PATTERNS** — recon extraction (internal IPs, cloud URLs, JWTs, debug flags)

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
- Don't use regex to determine if code is safe or unsafe. Use AST structure.
- Don't hardcode URL or filename exclusions. The scoring system handles prioritization.
- Don't add severity based on guesses about what a pattern "usually means." Severity should reflect actual exploitability based on the source-to-sink flow.
- Don't create per-API-name special cases. Write general rules that handle all APIs correctly through structural analysis.
- Don't make the database optional. It is always on.
- Don't add foreground or one-shot modes. The scanner runs in the background only.
