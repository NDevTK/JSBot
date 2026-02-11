"""Background process management for JSBot continuous scanning."""
import os
import signal
import subprocess
import sys
import time

_SCAN_PY = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'scan.py')


def _pid_alive(pid):
    """Check if a process is running."""
    if sys.platform == 'win32':
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            handle = kernel32.OpenProcess(0x1000, False, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
            if handle:
                kernel32.CloseHandle(handle)
                return True
            return False
        except Exception:
            return False
    else:
        try:
            os.kill(pid, 0)
            return True
        except OSError:
            return False


def is_running(domain):
    """Check if a daemon is running for this domain."""
    from store import FindingsStore
    store = FindingsStore(domain)
    try:
        info = store.get_daemon()
        if info is None:
            return False
        if _pid_alive(info['pid']):
            return True
        # Stale record — clean up
        store.remove_daemon()
        return False
    finally:
        store.close()


def start_daemon(domain, extra_args=None):
    """Start a background scan for a domain.

    Returns (success, message).
    """
    from store import FindingsStore

    if is_running(domain):
        store = FindingsStore(domain)
        try:
            info = store.get_daemon()
            pid = info['pid'] if info else '?'
        finally:
            store.close()
        return False, f'Scanner already running for {domain} (PID {pid})'

    # Build command
    cmd = [sys.executable, _SCAN_PY, domain]
    if extra_args:
        cmd.extend(extra_args)

    # Launch detached process — stderr goes to DEVNULL since logs go to DB
    kwargs = {
        'stdout': subprocess.DEVNULL,
        'stderr': subprocess.DEVNULL,
        'stdin': subprocess.DEVNULL,
    }
    if sys.platform == 'win32':
        kwargs['creationflags'] = (
            subprocess.CREATE_NO_WINDOW | subprocess.DETACHED_PROCESS
        )
    else:
        kwargs['start_new_session'] = True

    proc = subprocess.Popen(cmd, **kwargs)

    # Record PID in database
    store = FindingsStore(domain)
    try:
        store.save_daemon(proc.pid)
    finally:
        store.close()

    return True, f'Started scanner for {domain} (PID {proc.pid})'


def stop_daemon(domain):
    """Stop a running daemon for a domain.

    Returns (success, message).
    """
    from store import FindingsStore

    store = FindingsStore(domain)
    try:
        info = store.get_daemon()
        if info is None:
            return False, f'No scanner running for {domain}'

        pid = info['pid']

        if not _pid_alive(pid):
            store.remove_daemon()
            return False, f'Scanner for {domain} was not running (stale PID {pid})'

        # Send termination signal
        try:
            if sys.platform == 'win32':
                subprocess.run(['taskkill', '/F', '/PID', str(pid)],
                               capture_output=True, timeout=10)
            else:
                os.kill(pid, signal.SIGTERM)
                for _ in range(30):
                    if not _pid_alive(pid):
                        break
                    time.sleep(0.1)
                else:
                    os.kill(pid, signal.SIGKILL)
        except (ProcessLookupError, OSError):
            pass

        store.remove_daemon()
        return True, f'Stopped scanner for {domain} (PID {pid})'
    finally:
        store.close()


def get_status(domain):
    """Get detailed status for a domain's daemon.

    Returns dict with pid, running, uptime, log_tail.
    """
    from store import FindingsStore

    store = FindingsStore(domain)
    try:
        info = store.get_daemon()
        pid = info['pid'] if info else None
        running = pid is not None and _pid_alive(pid)

        result = {
            'domain': domain,
            'pid': pid,
            'running': running,
        }

        if info and running:
            result['started_at'] = info['started_at']
            result['uptime_seconds'] = int(time.time() - info['started_at'])

        # Get recent log entries from DB
        log_entries = store.get_log_tail(10)
        if log_entries:
            result['log_tail'] = '\n'.join(
                f"[{e['level']}] {e['message']}" for e in log_entries
            )

        return result
    finally:
        store.close()


def get_all_running():
    """List all domains with running daemons."""
    from store import get_all_daemons
    running = []
    for rec in get_all_daemons():
        if _pid_alive(rec['pid']):
            running.append(rec['domain'])
    return sorted(running)


def stop_all():
    """Stop all running daemons. Returns list of (domain, success, message)."""
    results = []
    for domain in get_all_running():
        success, msg = stop_daemon(domain)
        results.append((domain, success, msg))
    return results
