# CLAUDE.md

## What this is

JSBot is a continuous JavaScript security scanner. It finds client-side vulnerabilities (DOM XSS, open redirects, eval injection, postMessage issues) by tracking data flow from user-controlled sources to dangerous sinks using tree-sitter AST analysis. It runs against live targets, persists state across sessions, and prioritizes unexplored content.

## Architecture

```
scan.py          Pipeline orchestrator — crawling, queuing, URL scoring, state persistence
analysis.py      Core security analysis — taint flow, postMessage, cross-file taint, endpoints
patterns.py      Source/sink/secret pattern definitions (SOURCES, SINKS, TAINT_SINKS)
anomaly.py       Per-subdomain change detection across scans
scoring.py       URL novelty scoring, library detection, CVE lookup (hardcoded + OSV.dev)
discovery.py     CT logs, Common Crawl, robots.txt, sitemaps, spidering
sourcemaps.py    Source map fetching and extraction
output.py        JSONL output formatting
```

## Core principle: AST over regex

This is a high-signal security tool. Every detection must be grounded in actual code structure, not pattern guessing.

**Use tree-sitter AST** for understanding code behavior — variable assignments, function boundaries, call expressions, argument values. The AST tells you what the code actually does.

**Avoid line-level regex** for security analysis. Regex can't scope variables to functions, can't distinguish LHS from RHS in assignments, can't tell if a source is flowing into a sink or just happens to be on the same line. Every time regex was used for detection, it produced false positives that had to be fixed with AST.

**No hardcoded exclusion rules.** Don't skip analysis based on filenames, library names, or URL patterns. If the analysis produces false positives on jQuery or Angular, the analysis logic is wrong — fix the logic so it's correct for ALL code, not just non-library code. The taint tracker should be structurally sound enough that it produces correct results on any JavaScript, regardless of whether it's a library, minified, or hand-written.

Examples of what went wrong with non-AST approaches and how they were fixed:
- **Line-level direct mode** checked if a source pattern appeared anywhere on a sink line. `console.log(location.href); el.src = "/safe.png"` false-positived. Fixed by using AST to extract only the value flowing into the specific sink expression.
- **Flat-scope taint tracking** walked the entire file as one scope. In minified jQuery, `var c = location.hash` in function A tainted every other `c` in function B/C/D. Fixed by scoping taint to function boundaries via AST.
- **Self-assignment** `location.href = location.href` was flagged as an open redirect. Fixed by comparing AST LHS and RHS — if they're identical, no data flows.
- **Library skipping** was proposed as a fix for jQuery false positives. Rejected — the real fix was function-scoped taint tracking, which is correct for all code.

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

When adding new sources or sinks: add to the appropriate dict in patterns.py. Prefer SINKS for patterns specific enough to indicate attack surface on their own. Use TAINT_SINKS for patterns that are common in benign code but dangerous when receiving tainted input.

## State persistence

All state lives in `.ct_cache/{domain}/`. The scanner is designed to run repeatedly — each run builds on previous state. `--rescan` forces re-analysis when detection logic changes. State saves on exit, on Ctrl+C, and periodically during scans.

## Testing changes

Run against Google's Firing Range to validate detection accuracy:
```
python scan.py "https://public-firing-range.appspot.com" --rescan > results.jsonl
```
Check for false positives by examining findings on known-safe patterns. Check for false negatives by comparing against Firing Range's known test cases. The scanner runs continuously — don't wait for it to finish, interrupt and analyze what you have.

## What not to do

- Don't add `if library: skip` guards. Fix the analysis to be correct.
- Don't use regex to determine if code is safe or unsafe. Use AST structure.
- Don't hardcode URL or filename exclusions. The scoring system handles prioritization.
- Don't add severity based on guesses about what a pattern "usually means." Severity should reflect actual exploitability based on the source-to-sink flow.
- Don't create per-API-name special cases. Write general rules that handle all APIs correctly through structural analysis.
