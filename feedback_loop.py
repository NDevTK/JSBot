import database
import re
from urllib.parse import urlparse
import sys

LINK_FINDER_REGEX = r"""https?:\/\/[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b[-a-zA-Z0-9()@:%_\+.~#?&//=]*"""

def log_message(level, message):
    """Prints log messages."""
    print(f"[*] [{level}] {message}", file=sys.stderr)

def extract_domains_from_script(script_content):
    """Uses regex to find all URLs and extracts their domains."""
    urls = re.findall(LINK_FINDER_REGEX, script_content)
    domains = set()
    for url in urls:
        try:
            domain = urlparse(url).netloc
            if domain:
                domains.add(domain)
        except Exception:
            continue
    return list(domains)

def main():
    """Main function to run the feedback loop."""
    log_message("INFO", "Starting feedback loop...")

    database.init_db() # Ensure DB is initialized

    findings_to_process = database.get_high_priority_unprocessed_findings()

    if not findings_to_process:
        log_message("INFO", "No new high-priority findings to process for feedback. Exiting.")
        return

    log_message("INFO", f"Found {len(findings_to_process)} high-priority findings to analyze for new targets.")

    all_new_domains = set()
    processed_finding_ids = []

    for finding in findings_to_process:
        finding_id = finding['id']
        script_hash = finding['script_hash']

        script_content = database.get_script_by_hash(script_hash)
        if not script_content:
            log_message("ERROR", f"Could not retrieve script for hash {script_hash}. Skipping.")
            continue

        new_domains = extract_domains_from_script(script_content)
        if new_domains:
            log_message("INFO", f"Found {len(new_domains)} new domains in script from finding {finding_id}.")
            all_new_domains.update(new_domains)

        processed_finding_ids.append(finding_id)

    if all_new_domains:
        log_message("SUCCESS", f"Found a total of {len(all_new_domains)} unique domains to re-seed into the queue.")
        # We add these as URLs themselves, the scanner will handle them
        database.add_urls_to_queue(list(all_new_domains), priority=5) # Higher priority for feedback-driven targets
    else:
        log_message("INFO", "No new domains were discovered in any of the high-priority scripts.")

    # Mark all processed findings so they aren't checked again
    for finding_id in processed_finding_ids:
        database.mark_finding_as_processed(finding_id)

    log_message("INFO", f"Marked {len(processed_finding_ids)} findings as processed.")
    log_message("INFO", "Feedback loop complete.")

if __name__ == '__main__':
    main()
