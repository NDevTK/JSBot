"""Quality review tool for JSBot — inspect what the scanner sees and why.

Not part of the scanner. This is a separate research tool for reviewing
pattern matches, scoring decisions, discovery results, and finding quality.

Usage:
    python review.py patterns <file.js or URL>      Show all pattern matches with context
    python review.py score <file.js or URL>          Show full scoring breakdown for a script
    python review.py url <url> [url2 ...]            Show URL scoring breakdown
    python review.py discovery <domain>              Live-test robots/sitemap/CT discovery
    python review.py findings <domain>               Review findings from DB with signal detail
"""
import argparse
import asyncio
import re
import sys
from urllib.parse import urlparse, parse_qs

import httpx

from patterns import (
    SOURCES, SINKS, TAINT_SINKS, ENDPOINT_PATTERNS,
    INTERESTING_STRING_PATTERNS, PROTOTYPE_POLLUTION_SINKS,
    PROTOTYPE_POLLUTION_SOURCES,
)
from scoring import (
    score_url, PATH_KEYWORDS, PARAM_KEYWORDS, SUBDOMAIN_KEYWORDS,
    looks_minified, check_known_cves,
)
from analysis import (
    _score_postmessage, _score_prototype_pollution, _score_endpoints,
    _score_interesting_strings, _score_taint_flow, _score_library_cves,
)


# --- Helpers ---

def _fetch_js(target):
    """Load JS from a file path or URL."""
    if target.startswith(('http://', 'https://')):
        resp = httpx.get(target, follow_redirects=True, timeout=15)
        if resp.status_code >= 400:
            print(f"HTTP {resp.status_code} for {target}", file=sys.stderr)
            return resp.text  # still return content for review
        return resp.text
    with open(target, 'r', encoding='utf-8', errors='replace') as f:
        return f.read()


def _context(content, start, end, chars=80):
    """Extract a context snippet around a match."""
    ctx_start = max(0, start - chars)
    ctx_end = min(len(content), end + chars)
    before = content[ctx_start:start].replace('\n', '\\n')
    match_text = content[start:end].replace('\n', '\\n')
    after = content[end:ctx_end].replace('\n', '\\n')
    return f"...{before}\033[91m{match_text}\033[0m{after}..."


def _line_number(content, pos):
    """Get line number for a character position."""
    return content[:pos].count('\n') + 1


# --- Commands ---

def cmd_patterns(args):
    """Show every pattern match in a JS file with context."""
    content = _fetch_js(args.target)
    print(f"File: {args.target}")
    print(f"Size: {len(content)} chars, {content.count(chr(10)) + 1} lines")
    print(f"Minified: {looks_minified(content)}")
    print()

    # Flags must match the real scanner: sources/sinks are case-sensitive,
    # endpoints and strings use IGNORECASE (see analysis.py _score_* functions)
    sections = [
        ("SOURCES (user-controlled inputs)", 0, [
            (name, pattern, None) for name, pattern in SOURCES.items()
        ]),
        ("SINKS (dangerous outputs)", 0, [
            (name, info["pattern"], info["severity"])
            for name, info in SINKS.items()
        ]),
        ("TAINT_SINKS (taint-only sinks)", 0, [
            (name, info["pattern"], info["severity"])
            for name, info in TAINT_SINKS.items()
        ]),
        ("ENDPOINT_PATTERNS", re.IGNORECASE, [
            (cat, pattern, None) for pattern, cat in ENDPOINT_PATTERNS
        ]),
        ("INTERESTING_STRING_PATTERNS", re.IGNORECASE, [
            (stype, pattern, sev)
            for pattern, stype, sev in INTERESTING_STRING_PATTERNS
        ]),
        ("PROTOTYPE_POLLUTION_SINKS", 0, [
            (f"PP sink #{i+1}", p, None)
            for i, p in enumerate(PROTOTYPE_POLLUTION_SINKS)
        ]),
        ("PROTOTYPE_POLLUTION_SOURCES", 0, [
            (f"PP source #{i+1}", p, None)
            for i, p in enumerate(PROTOTYPE_POLLUTION_SOURCES)
        ]),
    ]

    total_matches = 0
    for section_name, flags, patterns in sections:
        matches = []
        for name, pattern, severity in patterns:
            for m in re.finditer(pattern, content, flags):
                sev_str = f" (severity {severity})" if severity else ""
                matches.append((m.start(), name, sev_str, m))
        if not matches:
            continue
        matches.sort()
        print(f"=== {section_name} ({len(matches)} matches) ===")
        for pos, name, sev_str, m in matches:
            line = _line_number(content, pos)
            ctx = _context(content, m.start(), m.end())
            print(f"  L{line:>5}  {name}{sev_str}")
            print(f"         {ctx}")
        print()
        total_matches += len(matches)

    if total_matches == 0:
        print("No pattern matches found.")
    else:
        print(f"Total: {total_matches} matches")


def cmd_score(args):
    """Show full scoring breakdown for a script."""
    content = _fetch_js(args.target)
    is_min = looks_minified(content)
    print(f"File: {args.target}")
    print(f"Size: {len(content)} chars, {content.count(chr(10)) + 1} lines")
    print(f"Minified: {is_min}")
    print()

    # Run each scorer and show results
    scores = []
    scorers = [
        ("postMessage handler", _score_postmessage, (content, is_min)),
        ("Prototype pollution", _score_prototype_pollution, (content,)),
        ("Interesting endpoints", _score_endpoints, (content,)),
        ("Sensitive strings", _score_interesting_strings, (content,)),
        ("Taint flow", _score_taint_flow, (content, is_min)),
        ("Known CVEs", _score_library_cves, (content,)),
    ]

    print("Signal breakdown:")
    print(f"  {'Signal':<25} {'Score':>5}")
    print(f"  {'-'*25} {'-'*5}")
    for name, func, func_args in scorers:
        s = func(*func_args)
        indicator = "*" if s > 0 else " "
        print(f" {indicator} {name:<25} {s:>5}")
        if s > 0:
            scores.append(s)

    print()
    if not scores:
        print("Final score: 0 (no signals fired)")
        return

    scores.sort(reverse=True)
    base = scores[0]
    bonus = sum(s * 0.1 for s in scores[1:])
    raw = base + bonus
    final = min(10, round(raw))
    print(f"Scoring formula:")
    print(f"  Base (highest signal):  {base}")
    if len(scores) > 1:
        print(f"  Bonus signals:         +{bonus:.1f}  ({' + '.join(f'{s}*0.1' for s in scores[1:])})")
    print(f"  Raw total:             {raw:.1f}")
    print(f"  Final score (cap 10):  {final}")

    # CVE detail
    vulns = check_known_cves(content)
    if vulns:
        print()
        print("CVE details:")
        for v in vulns:
            cves = ', '.join(v['cves'])
            print(f"  {v['library']} {v['version']}: {cves} (severity {v['severity']})")
            print(f"    {v['description']}")
            print(f"    Fixed in: {v['fix_below']}")


def cmd_url(args):
    """Show URL scoring breakdown."""
    for url in args.urls:
        parsed = urlparse(url)
        total = score_url(url)

        print(f"URL: {url}")
        print(f"  Total score: {total}")
        print()

        # Path keywords
        segs = [s for s in parsed.path.lower().strip('/').split('/') if s]
        path_hits = []
        for seg in segs:
            seg_parts = re.split(r'[-_.]', seg)
            matched = [p for p in seg_parts if p in PATH_KEYWORDS]
            if matched:
                path_hits.append((seg, matched))
        if path_hits:
            print(f"  Path keywords (+3 each, cap 9):")
            for seg, kws in path_hits:
                print(f"    /{seg}/  matched: {', '.join(kws)}")
        else:
            print(f"  Path keywords: none")

        # Param keywords
        params = parse_qs(parsed.query)
        param_hits = [p for p in params if p.lower() in PARAM_KEYWORDS]
        if param_hits:
            print(f"  Param keywords (+5 each): {', '.join(param_hits)}")
        elif parsed.query:
            print(f"  Has query params (+2) but no keyword matches")
            print(f"    Params: {', '.join(params.keys())}")

        # Subdomain
        hostname = parsed.hostname or ''
        parts = hostname.split('.')
        if len(parts) > 2:
            subdomain = '.'.join(parts[:-2]).lower()
            if subdomain and subdomain != 'www':
                sub_parts = re.split(r'[-_.]', subdomain)
                sub_hits = [p for p in sub_parts if p in SUBDOMAIN_KEYWORDS]
                if sub_hits:
                    print(f"  Subdomain '{subdomain}' (+2 base, +4 keyword): {', '.join(sub_hits)}")
                else:
                    print(f"  Subdomain '{subdomain}' (+2, no keyword match)")
        print()


def cmd_discovery(args):
    """Live-test discovery against a domain."""
    domain = args.domain

    async def _run():
        timeout = httpx.Timeout(10.0, connect=5.0)
        async with httpx.AsyncClient(
            http2=True, follow_redirects=True, verify=True,
            headers={'User-Agent': 'JSBot-Review/1.0'},
        ) as client:
            base = f"https://{domain}"

            # --- robots.txt ---
            print(f"=== robots.txt ({base}/robots.txt) ===")
            sitemap_directives = []
            try:
                resp = await client.get(f"{base}/robots.txt", timeout=timeout)
                if resp.status_code == 200:
                    paths = []
                    for line in resp.text.splitlines():
                        line = line.strip()
                        if line.lower().startswith(('disallow:', 'allow:')):
                            path = line.split(':', 1)[1].strip()
                            if path and path != '/':
                                paths.append(line)
                        elif line.lower().startswith('sitemap:'):
                            sitemap_directives.append(line.split(':', 1)[1].strip())
                    print(f"  Disallow/Allow paths: {len(paths)}")
                    for p in paths[:20]:
                        print(f"    {p}")
                    if len(paths) > 20:
                        print(f"    ... +{len(paths)-20} more")
                    if sitemap_directives:
                        print(f"  Sitemap directives: {len(sitemap_directives)}")
                        for s in sitemap_directives:
                            print(f"    {s}")
                    else:
                        print(f"  No Sitemap: directives found")
                else:
                    print(f"  HTTP {resp.status_code}")
            except Exception as e:
                print(f"  Error: {e}")
            print()

            # --- Sitemaps ---
            from discovery import _parse_sitemap
            from xml.etree import ElementTree

            sitemap_urls_to_try = set()
            sitemap_urls_to_try.add(f"{base}/sitemap.xml")
            if sitemap_directives:
                sitemap_urls_to_try.update(sitemap_directives)

            total_pages = 0
            for sitemap_url in sorted(sitemap_urls_to_try):
                print(f"=== Sitemap: {sitemap_url} ===")
                try:
                    resp = await client.get(sitemap_url, timeout=timeout)
                    if resp.status_code == 200:
                        pages, children = _parse_sitemap(resp.text)
                        if children:
                            print(f"  Sitemap index with {len(children)} child sitemaps:")
                            for child in sorted(children)[:15]:
                                print(f"    {child}")
                            if len(children) > 15:
                                print(f"    ... +{len(children)-15} more")
                            # Fetch first few children to show sample
                            sample_count = 0
                            for child in sorted(children)[:3]:
                                try:
                                    child_resp = await client.get(child, timeout=timeout)
                                    if child_resp.status_code == 200:
                                        child_pages, _ = _parse_sitemap(child_resp.text)
                                        sample_count += len(child_pages)
                                        print(f"  Sample child {child}: {len(child_pages)} URLs")
                                        for u in sorted(child_pages)[:5]:
                                            print(f"    {u}")
                                        if len(child_pages) > 5:
                                            print(f"    ...")
                                except Exception:
                                    pass
                            print(f"  (Sampled {sample_count} URLs from first 3 children)")
                        elif pages:
                            print(f"  {len(pages)} page URLs:")
                            for u in sorted(pages)[:20]:
                                print(f"    {u}")
                            if len(pages) > 20:
                                print(f"    ... +{len(pages)-20} more")
                            total_pages += len(pages)
                        else:
                            print(f"  Parsed but no URLs found (possibly not XML)")
                    else:
                        print(f"  HTTP {resp.status_code}")
                except Exception as e:
                    print(f"  Error: {e}")
                print()

            # --- Spider sample ---
            print(f"=== Spider sample ({base}/) ===")
            try:
                resp = await client.get(f"{base}/", timeout=timeout)
                if resp.status_code < 400:
                    from discovery import spider_links, _is_same_domain
                    base_domain = '.'.join(domain.split('.')[-2:])
                    links = spider_links(resp.text, resp.url, base_domain)
                    print(f"  Found {len(links)} same-domain links on homepage:")
                    # Show by type
                    from bs4 import BeautifulSoup
                    parser = BeautifulSoup(resp.text, 'lxml')
                    a_count = len(parser.find_all('a', href=True))
                    iframe_count = len(parser.find_all('iframe', src=True))
                    form_count = len(parser.find_all('form', action=True))
                    print(f"    <a>: {a_count}, <iframe>: {iframe_count}, <form>: {form_count}")
                    for link in sorted(links)[:20]:
                        print(f"    {link}")
                    if len(links) > 20:
                        print(f"    ... +{len(links)-20} more")

                    # Scripts on page
                    scripts = parser.find_all('script', src=True)
                    inline_scripts = [s for s in parser.find_all('script') if not s.get('src') and (s.string or '').strip()]
                    print(f"\n  Scripts: {len(scripts)} external, {len(inline_scripts)} inline")
                    for s in scripts[:10]:
                        print(f"    {s['src']}")
                    if len(scripts) > 10:
                        print(f"    ... +{len(scripts)-10} more")
                else:
                    print(f"  HTTP {resp.status_code}")
            except Exception as e:
                print(f"  Error: {e}")
            print()

            # --- CT check ---
            print(f"=== CT log check (crt.sh) ===")
            try:
                ct_resp = await client.get(
                    f"https://crt.sh/?q=%.{domain}&output=json",
                    timeout=httpx.Timeout(20.0, connect=10.0),
                )
                if ct_resp.status_code == 200:
                    entries = ct_resp.json()
                    subs = set()
                    for entry in entries:
                        for name in entry.get('name_value', '').split('\n'):
                            name = name.strip().lstrip('*.')
                            if name and (name == domain or name.endswith('.' + domain)):
                                subs.add(name)
                    print(f"  Found {len(subs)} subdomains via crt.sh JSON API:")
                    for sub in sorted(subs)[:30]:
                        print(f"    {sub}")
                    if len(subs) > 30:
                        print(f"    ... +{len(subs)-30} more")
                else:
                    print(f"  crt.sh returned HTTP {ct_resp.status_code}")
            except Exception as e:
                print(f"  crt.sh check failed: {e}")

    asyncio.run(_run())


def cmd_findings(args):
    """Review findings from DB with detailed signal breakdown."""
    from store import FindingsStore
    store = FindingsStore(args.domain)

    findings = store.get_findings(limit=args.limit or 50)
    if not findings:
        print(f"No findings for {args.domain}")
        store.close()
        return

    print(f"=== Findings for {args.domain} ({len(findings)} shown) ===\n")

    by_type = {}
    for f in findings:
        ft = f.get('finding_type', 'unknown')
        by_type.setdefault(ft, []).append(f)

    print(f"Summary: {len(findings)} findings")
    for ft, items in sorted(by_type.items()):
        severities = [i.get('severity', 0) for i in items]
        print(f"  {ft}: {len(items)} (severity {min(severities)}-{max(severities)})")
    print()

    # Show each finding with detail
    for i, f in enumerate(findings, 1):
        sev = f.get('severity', '?')
        ftype = f.get('finding_type', 'unknown')
        script = f.get('script_url', 'unknown')
        page = f.get('source_url', 'unknown')

        print(f"[{i}] Score {sev} | {ftype}")
        print(f"    Script: {script}")
        print(f"    Page:   {page}")

        # Anomaly signals
        signals = f.get('signals', [])
        if signals:
            print(f"    Signals: {', '.join(signals)}")

        ctx = f.get('subdomain_context', {})
        if ctx:
            print(f"    Context: {ctx.get('total_scripts', '?')} scripts, "
                  f"{ctx.get('minified_rate', '?')} minified rate, "
                  f"{ctx.get('library_rate', '?')} library rate")

        sink_cats = f.get('sink_categories', [])
        if sink_cats:
            print(f"    Sinks: {', '.join(sink_cats)}")

        # For interesting_script findings, re-score if we can fetch the script
        if ftype == 'interesting_script' and args.rescore and script != 'inline':
            try:
                content = _fetch_js(script)
                is_min = looks_minified(content)
                pm = _score_postmessage(content, is_min)
                pp = _score_prototype_pollution(content)
                ep = _score_endpoints(content)
                ss = _score_interesting_strings(content)
                tf = _score_taint_flow(content, is_min)
                cv = _score_library_cves(content)
                active = {k: v for k, v in [
                    ('postMessage', pm), ('protoPollution', pp),
                    ('endpoints', ep), ('strings', ss),
                    ('taintFlow', tf), ('cves', cv),
                ] if v > 0}
                if active:
                    print(f"    Rescore: {active}")
            except Exception as e:
                print(f"    Rescore failed: {e}")

        print()

    store.close()


# --- Main ---

def main():
    parser = argparse.ArgumentParser(
        description="JSBot quality review tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    sub = parser.add_subparsers(dest='command')

    p_patterns = sub.add_parser('patterns', help='Show all pattern matches in a JS file/URL')
    p_patterns.add_argument('target', help='JS file path or URL')

    p_score = sub.add_parser('score', help='Show scoring breakdown for a script')
    p_score.add_argument('target', help='JS file path or URL')

    p_url = sub.add_parser('url', help='Show URL scoring breakdown')
    p_url.add_argument('urls', nargs='+', help='URLs to score')

    p_disc = sub.add_parser('discovery', help='Live-test discovery against a domain')
    p_disc.add_argument('domain', help='Domain to test')

    p_find = sub.add_parser('findings', help='Review findings from DB')
    p_find.add_argument('domain', help='Domain to review')
    p_find.add_argument('--limit', type=int, default=50, help='Max findings to show')
    p_find.add_argument('--rescore', action='store_true',
                        help='Re-fetch scripts and show signal breakdown')

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(1)

    commands = {
        'patterns': cmd_patterns,
        'score': cmd_score,
        'url': cmd_url,
        'discovery': cmd_discovery,
        'findings': cmd_findings,
    }
    commands[args.command](args)


if __name__ == '__main__':
    main()
