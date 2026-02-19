#!/usr/bin/env python3
"""JSBot CLI - Continuous JavaScript security scanner.

Usage:
    python cli.py start <domain>     Start background scan
    python cli.py stop [domain]      Stop background scan (no domain = stop all)
    python cli.py status             Show running scans and finding counts
    python cli.py findings [domain]  Review findings
    python cli.py domains [domain]   List scanned domains, or show subdomains for one
    python cli.py clear <domain>     Delete all state for a domain
"""
import argparse
import json
import os
import sys
import time

from store import FindingsStore, get_all_domains, get_domain_summary
from daemon import (
    start_daemon, stop_daemon, stop_all, get_status,
    get_all_running, is_running,
)



# --- Formatting Helpers ---

_SCORE_COLORS = {
    9: '\033[91m',  # bright red
    8: '\033[91m',  # red
    7: '\033[93m',  # yellow
    6: '\033[93m',  # yellow
    5: '\033[94m',  # blue
}
_RESET = '\033[0m'
_BOLD = '\033[1m'
_DIM = '\033[2m'


def _score_label(score):
    color = _SCORE_COLORS.get(score, _DIM)
    return f'{color}[{score}]{_RESET}'


def _time_ago(timestamp):
    if not timestamp:
        return 'never'
    delta = time.time() - timestamp
    if delta < 60:
        return f'{int(delta)}s ago'
    if delta < 3600:
        return f'{int(delta / 60)}m ago'
    if delta < 86400:
        return f'{int(delta / 3600)}h ago'
    return f'{int(delta / 86400)}d ago'


def _format_uptime(seconds):
    if seconds < 60:
        return f'{seconds}s'
    if seconds < 3600:
        return f'{seconds // 60}m {seconds % 60}s'
    h = seconds // 3600
    m = (seconds % 3600) // 60
    return f'{h}h {m}m'


# --- Commands ---

def cmd_start(args):
    """Start a background scan."""
    domain = args.domain

    extra = []
    if args.cookie:
        extra.extend(['-b', args.cookie])
    if args.header:
        for h in args.header:
            extra.extend(['-H', h])
    if args.rescan:
        extra.append('--rescan')
    if args.verbose:
        extra.append('-v')

    success, msg = start_daemon(domain, extra if extra else None)
    if success:
        print(f'{_BOLD}[+]{_RESET} {msg}')
        print(f'  Review findings:  python cli.py findings {domain}')
        print(f'  Check status:     python cli.py status')
        print(f'  Stop scanner:     python cli.py stop {domain}')
    else:
        print(f'[-] {msg}', file=sys.stderr)
        sys.exit(1)


def cmd_stop(args):
    """Stop a background scan."""
    if args.domain:
        success, msg = stop_daemon(args.domain)
        if success:
            print(f'{_BOLD}[+]{_RESET} {msg}')
        else:
            print(f'[-] {msg}', file=sys.stderr)
            sys.exit(1)
    else:
        results = stop_all()
        if not results:
            print('No scanners running.')
            return
        for domain, success, msg in results:
            prefix = f'{_BOLD}[+]{_RESET}' if success else '[-]'
            print(f'{prefix} {msg}')


def cmd_status(args):
    """Show status of running scans and domain summaries."""
    running = get_all_running()

    if running:
        print(f'{_BOLD}Running Scans{_RESET}')
        print()
        for domain in running:
            status = get_status(domain)
            uptime = _format_uptime(status.get('uptime_seconds', 0))
            pid = status.get('pid', '?')
            print(f'  {_BOLD}{domain}{_RESET}  PID {pid}  uptime {uptime}')

            # Show finding count from store
            try:
                store = FindingsStore(domain)
                total = store.get_total_count()
                store.close()
                if total:
                    print(f'    {total} findings')
            except Exception:
                pass
        print()
    else:
        print(f'{_DIM}No scanners running.{_RESET}')
        print()

    # Show domains with findings
    domains = get_all_domains()
    if domains:
        print(f'{_BOLD}Domains with Findings{_RESET}')
        print()
        for domain in domains:
            try:
                info = get_domain_summary(domain)
                total = info['total_findings']
                marker = ' *' if domain in running else ''
                session = info.get('last_session')
                last_scan = ''
                if session and session.get('finished_at'):
                    last_scan = f'  last scan {_time_ago(session["finished_at"])}'
                elif session and session.get('started_at'):
                    last_scan = f'  scanning since {_time_ago(session["started_at"])}'
                print(f'  {domain}  {total} findings{last_scan}{marker}')
            except Exception:
                print(f'  {domain}  (error reading)')
        print()


def cmd_findings(args):
    """Show findings for a domain or all domains."""
    domains = [args.domain] if args.domain else get_all_domains()

    if not domains:
        print('No findings yet. Start a scan with: python cli.py start <domain>')
        return

    for domain in domains:
        try:
            store = FindingsStore(domain)
        except Exception as e:
            print(f'Error opening store for {domain}: {e}', file=sys.stderr)
            continue

        try:
            findings = store.get_findings(
                severity_min=args.score or 0,
                finding_type=args.type,
                limit=args.limit,
            )

            if not findings:
                if args.domain:
                    print(f'No findings for {domain}' +
                          (f' matching filters' if args.score or args.type else ''))
                continue

            if args.json:
                for f in findings:
                    data = json.loads(f['data_json'])
                    print(json.dumps(data))
                continue

            # Pretty print
            if len(domains) > 1:
                print(f'\n{_BOLD}-- {domain} --{_RESET}')

            for f in findings:
                data = json.loads(f['data_json'])
                score = data.get('severity', 0)
                source = data.get('source_url', '')
                script = data.get('script_url', '')

                print(f'\n  {_score_label(score)}  {script or source or "inline"}')

                # Example page URL
                if source and source != script:
                    label = source
                    if len(label) > 80:
                        label = '...' + label[-77:]
                    print(f'       {_DIM}{label}{_RESET}')

            total = store.get_total_count()
            shown = len(findings)
            if shown < total:
                print(f'\n  {_DIM}Showing {shown} of {total} findings. '
                      f'Use --limit to see more.{_RESET}')
            print()
        finally:
            store.close()


def cmd_domains(args):
    """List scanned domains, or show subdomains for a specific domain."""
    # If a specific domain is given, show its subdomains
    if args.domain:
        _show_subdomains(args.domain, getattr(args, 'json', False))
        return

    # Otherwise list all scanned domains
    domains = get_all_domains()
    if not domains:
        print('No domains scanned yet. Start with: python cli.py start <domain>')
        return

    running = set(get_all_running())

    print(f'\n{_BOLD}Scanned Domains{_RESET}\n')
    for domain in domains:
        try:
            store = FindingsStore(domain)
            try:
                info = get_domain_summary(domain)
                total = info['total_findings']
                status_marker = f' {_BOLD}* running{_RESET}' if domain in running else ''

                # Break down by type
                type_counts = {}
                for row in info['by_type']:
                    ft = row['finding_type']
                    type_counts[ft] = type_counts.get(ft, 0) + row['count']

                types_str = ', '.join(f'{k}: {v}' for k, v in
                                      sorted(type_counts.items(), key=lambda x: -x[1]))

                # Load CT discovery state for subdomain/related counts
                ct_state = store.load_ct_state()
                subs = ct_state.get('scanned_subdomains', [])
                related = ct_state.get('related_domains', [])
                fetched = ct_state.get('fetched_months', [])

                print(f'  {_BOLD}{domain}{_RESET}{status_marker}')
                print(f'    {total} findings ({types_str})')

                # Show subdomain discovery info
                discovery_parts = []
                if subs:
                    discovery_parts.append(f'{len(subs)} subdomains')
                if related:
                    discovery_parts.append(f'{len(related)} related domains')
                if fetched:
                    discovery_parts.append(f'{len(fetched)} CT months fetched')
                if discovery_parts:
                    print(f'    {", ".join(discovery_parts)}')

                session = info.get('last_session')
                if session:
                    if session.get('finished_at'):
                        print(f'    last scan: {_time_ago(session["finished_at"])}')
                    elif session.get('started_at'):
                        print(f'    scanning since: {_time_ago(session["started_at"])}')
                print()
            finally:
                store.close()
        except Exception as e:
            print(f'  {domain}  (error: {e})')


def _show_subdomains(domain, as_json=False):
    """Show discovered subdomains and related domains for a domain."""
    store = FindingsStore(domain)
    try:
        ct_state = store.load_ct_state()
        subs = sorted(ct_state.get('scanned_subdomains', []))
        related = sorted(ct_state.get('related_domains', []))
        fetched = ct_state.get('fetched_months', [])

        if not subs and not related:
            print(f'No subdomains discovered yet for {domain}.')
            print(f'Start a scan to begin CT log discovery: python cli.py start {domain}')
            return

        if as_json:
            import json
            print(json.dumps({
                'domain': domain,
                'subdomains': subs,
                'related_domains': related,
                'fetched_months': len(fetched),
            }, indent=2))
            return

        print(f'{_BOLD}{domain}{_RESET}  ({len(fetched)} CT months fetched)')
        print()

        if subs:
            print(f'{_BOLD}Subdomains ({len(subs)}):{_RESET}')
            for sub in subs:
                print(f'  {sub}')
            print()

        if related:
            print(f'{_BOLD}Related domains ({len(related)}):{_RESET}')
            for rel in related:
                print(f'  {rel}')
    finally:
        store.close()


def cmd_clear(args):
    """Delete all state and findings for a domain."""
    domain = args.domain

    if is_running(domain):
        print(f'Scanner is running for {domain}. Stop it first: python cli.py stop {domain}',
              file=sys.stderr)
        sys.exit(1)

    # Check if domain has any data
    store = FindingsStore(domain)
    try:
        total = store.get_total_count()
        session = store.get_last_session()
        if total == 0 and session is None:
            print(f'No data found for {domain}.')
            return

        if not args.force:
            answer = input(f'Delete all data for {domain}? [y/N] ')
            if answer.lower() not in ('y', 'yes'):
                print('Cancelled.')
                return

        store.clear_domain()
        print(f'{_BOLD}[+]{_RESET} Cleared all data for {domain}')
    finally:
        store.close()


# --- Main Parser ---

def main():
    parser = argparse.ArgumentParser(
        prog='jsbot',
        description='JSBot - Continuous JavaScript security scanner.',
    )
    subparsers = parser.add_subparsers(dest='command', help='Available commands')

    # start
    p_start = subparsers.add_parser('start', help='Start background scan')
    p_start.add_argument('domain', help='Domain to scan')
    p_start.add_argument('-H', '--header', action='append', help='Custom HTTP header')
    p_start.add_argument('-b', '--cookie', help='Cookie header value')
    p_start.add_argument('--rescan', action='store_true', help='Re-analyze all scripts')
    p_start.add_argument('-v', '--verbose', action='store_true', help='Verbose logging')
    p_start.set_defaults(func=cmd_start)

    # stop
    p_stop = subparsers.add_parser('stop', help='Stop background scan')
    p_stop.add_argument('domain', nargs='?', help='Domain to stop (omit to stop all)')
    p_stop.set_defaults(func=cmd_stop)

    # status
    p_status = subparsers.add_parser('status', help='Show scanner status')
    p_status.set_defaults(func=cmd_status)

    # findings
    p_findings = subparsers.add_parser('findings', help='Review findings')
    p_findings.add_argument('domain', nargs='?', help='Domain (omit for all)')
    p_findings.add_argument('--score', type=int, help='Minimum score (1-10)')
    p_findings.add_argument('--type', help='Finding type filter')
    p_findings.add_argument('--limit', type=int, default=50, help='Max findings to show')
    p_findings.add_argument('--json', action='store_true', help='Output as JSONL')
    p_findings.set_defaults(func=cmd_findings)

    # domains
    p_domains = subparsers.add_parser('domains', help='List scanned domains or show subdomains')
    p_domains.add_argument('domain', nargs='?', help='Domain to show subdomains for (omit to list all)')
    p_domains.add_argument('--json', action='store_true', help='Output as JSON')
    p_domains.set_defaults(func=cmd_domains)

    # clear
    p_clear = subparsers.add_parser('clear', help='Delete all data for a domain')
    p_clear.add_argument('domain', help='Domain to clear')
    p_clear.add_argument('-f', '--force', action='store_true', help='Skip confirmation')
    p_clear.set_defaults(func=cmd_clear)

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(1)

    args.func(args)


if __name__ == '__main__':
    main()
