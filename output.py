"""Output, logging, and finding deduplication."""
import json
import sys

# --- Global State ---
SEEN_FINDINGS = set()
SEEN_LINKS = set()

# Module-level reference to args, set by scan.py at startup
ARGS = None


def log_message(level, message):
    """Prints log messages based on verbosity level."""
    if ARGS is None:
        return
    if level == "INFO" and ARGS.verbose:
        print(f"[*] [INFO] {message}", file=sys.stderr)
    elif level == "ERROR" and ARGS.show_errors:
        print(f"[!] [ERROR] {message}", file=sys.stderr)
    elif level == "FINDING":
        print(json.dumps(message))
