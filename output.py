"""Output, logging, finding deduplication, and persistent storage."""
import json
import sys

# --- Global State ---
SEEN_FINDINGS = set()
SCRIPT_METADATA = {}  # script_hash -> {"minified": bool, "line_count": int}

# Module-level reference to args, set by scan.py at startup
ARGS = None

# Module-level reference to FindingsStore — always active during scans
STORE = None


def set_store(store):
    """Set the active findings store. Called during scan init."""
    global STORE
    STORE = store


def log_message(level, message):
    """Log messages and persist findings to the database."""
    if ARGS is None:
        return
    if level == "INFO" and ARGS.verbose:
        print(f"[*] [INFO] {message}", file=sys.stderr)
    elif level == "ERROR" and ARGS.show_errors:
        print(f"[!] [ERROR] {message}", file=sys.stderr)
    elif level == "FINDING":
        # Inject script metadata (minified status) if available
        sh = message.get("script_hash")
        if sh and sh in SCRIPT_METADATA:
            message.update(SCRIPT_METADATA[sh])

        # Persist to store
        if STORE is not None:
            try:
                STORE.add_finding(message)
            except Exception:
                pass  # Don't let store errors break the scan

    # Persist log messages to DB (not findings — those go via add_finding)
    if STORE is not None and level != "FINDING":
        try:
            text = str(message) if not isinstance(message, str) else message
            STORE.add_log(level, text)
        except Exception:
            pass
