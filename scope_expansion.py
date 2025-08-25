import argparse
import subprocess
import sys
import database

# --- Dependency Availability Checks ---
try:
    from waybackpy import WaybackMachineCDXServerAPI
    WAYBACK_AVAILABLE = True
except ImportError:
    WAYBACK_AVAILABLE = False

def log_message(level, message):
    """Prints log messages."""
    print(f"[*] [{level}] {message}", file=sys.stderr)

def run_subfinder(domain):
    """Runs the subfinder tool and returns a list of subdomains."""
    log_message("INFO", f"Running subfinder for {domain}...")
    try:
        command = ['subfinder', '-d', domain, '-silent']
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        subdomains = result.stdout.strip().split('\n')
        log_message("SUCCESS", f"Found {len(subdomains)} subdomains for {domain}.")
        return subdomains
    except FileNotFoundError:
        log_message("ERROR", "subfinder command not found. Please install it and ensure it's in your PATH.")
        return []
    except subprocess.CalledProcessError as e:
        log_message("ERROR", f"Subfinder failed for {domain}: {e.stderr}")
        return []

def fetch_wayback_urls(domains):
    """Fetches historical URLs from the Wayback Machine for a list of domains."""
    if not WAYBACK_AVAILABLE:
        log_message("ERROR", "WaybackPy not installed. Skipping wayback machine fetch.")
        return set()

    all_urls = set()
    for domain in domains:
        domain = domain.strip()
        if not domain: continue
        log_message("INFO", f"Fetching wayback URLs for: {domain}")
        try:
            cdx = WaybackMachineCDXServerAPI(
                url=domain, user_agent="JSBot/3.0", collapses=["urlkey"],
                filters=["statuscode:200", "mimetype:(text/html|application/javascript)"]
            )
            snapshots = {s.original for s in cdx.snapshots()}
            log_message("INFO", f"Found {len(snapshots)} historical URLs for {domain}.")
            all_urls.update(snapshots)
        except Exception as e:
            log_message("ERROR", f"Wayback Machine request failed for {domain}: {e}")
    return all_urls

def main():
    """Main function to run scope expansion."""
    parser = argparse.ArgumentParser(description="Expand scope by finding subdomains and historical URLs.")
    parser.add_argument('domain', help="The root domain to expand (e.g., example.com).")
    parser.add_argument('--no-wayback', action='store_true', help="Skip fetching historical URLs from the Wayback Machine.")

    args = parser.parse_args()

    if not WAYBACK_AVAILABLE and not args.no_wayback:
        log_message("ERROR", "--wayback requires 'waybackpy'. Install it with: pip install waybackpy")
        sys.exit(1)

    subdomains = run_subfinder(args.domain)
    if not subdomains:
        log_message("INFO", "No subdomains found. Exiting.")
        return

    urls_to_add = set(subdomains)

    if not args.no_wayback:
        historical_urls = fetch_wayback_urls(subdomains)
        urls_to_add.update(historical_urls)

    if not urls_to_add:
        log_message("INFO", "No new URLs to add to the queue.")
        return

    # Clean URLs before adding
    cleaned_urls = {url.split('?')[0].split('#')[0] for url in urls_to_add}

    log_message("INFO", f"Adding {len(cleaned_urls)} unique URLs to the queue.")
    database.init_db()
    database.add_urls_to_queue(list(cleaned_urls))
    log_message("SUCCESS", "Scope expansion complete. URLs added to the queue.")

if __name__ == '__main__':
    main()
