"""Output, logging, and finding deduplication."""
import json
import sys

# --- Global State ---
SEEN_FINDINGS = set()
SCRIPT_METADATA = {}  # script_hash -> {"minified": bool, "line_count": int}

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
        # Inject script metadata (minified status) if available
        sh = message.get("script_hash")
        if sh and sh in SCRIPT_METADATA:
            message.update(SCRIPT_METADATA[sh])
        print(json.dumps(message))
