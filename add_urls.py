import argparse
import sys
import database

def main():
    """Main function to add URLs to the queue from a file."""
    parser = argparse.ArgumentParser(description="Add URLs to the scanning queue.")
    parser.add_argument('url_file', help="Path to a file containing URLs, one per line. Use '-' to read from stdin.")
    parser.add_argument('-p', '--priority', type=int, default=1, help="Set a priority for these URLs (higher is scanned sooner).")

    args = parser.parse_args()

    if args.url_file == '-':
        urls = [line.strip() for line in sys.stdin if line.strip()]
    else:
        try:
            with open(args.url_file, 'r', encoding='utf-8') as f:
                urls = [line.strip() for line in f if line.strip()]
        except IOError as e:
            print(f"[!] [ERROR] Unable to read file '{args.url_file}': {e}", file=sys.stderr)
            sys.exit(1)

    if not urls:
        print("[*] [INFO] No URLs provided. Exiting.", file=sys.stderr)
        return

    try:
        # Initialize DB in case it's the first run
        database.init_db()
        database.add_urls_to_queue(urls, args.priority)
        print(f"[*] [SUCCESS] Added {len(urls)} URLs to the queue with priority {args.priority}.")
    except Exception as e:
        print(f"[!] [ERROR] Failed to add URLs to the database: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == '__main__':
    main()
