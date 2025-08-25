import argparse
import subprocess
import sys

def run_script(script_name, args_list=None):
    """A helper function to run a Python script with arguments."""
    command = [sys.executable, script_name]
    if args_list:
        command.extend(args_list)

    print(f"--- Running {script_name} ---")
    try:
        subprocess.run(command, check=True)
    except FileNotFoundError:
        print(f"Error: Script '{script_name}' not found.")
    except subprocess.CalledProcessError as e:
        print(f"Error: Script '{script_name}' exited with error code {e.returncode}.")
    print("-" * (len(script_name) + 14))


def main():
    parser = argparse.ArgumentParser(
        description="Master Orchestrator for the JS Security Analysis Framework.",
        formatter_class=argparse.RawTextHelpFormatter
    )

    parser.add_argument('--init-db', action='store_true', help="Initialize the database.")
    parser.add_argument('--add-urls', metavar='FILE', help="Add URLs from a file to the queue.")
    parser.add_argument('--expand-scope', metavar='DOMAIN', help="Run scope expansion for a domain.")
    parser.add_argument('--scan', action='store_true', help="Run the scanner on the current queue.")
    parser.add_argument('--review', action='store_true', help="Start the interactive agent review CLI.")
    parser.add_argument('--report', action='store_true', help="Generate a report of confirmed vulnerabilities.")
    parser.add_argument('--feedback', action='store_true', help="Run the feedback loop to find targets from findings.")
    parser.add_argument('--full-cycle', action='store_true', help="Run a full cycle: scan -> feedback.")

    args = parser.parse_args()

    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)

    if args.init_db:
        run_script('database.py')

    if args.add_urls:
        run_script('add_urls.py', [args.add_urls])

    if args.expand_scope:
        run_script('scope_expansion.py', [args.expand_scope])

    if args.scan:
        run_script('scan.py')

    if args.review:
        run_script('agent_review.py')

    if args.report:
        run_script('report.py')

    if args.feedback:
        run_script('feedback_loop.py')

    if args.full_cycle:
        run_script('scan.py')
        run_script('feedback_loop.py')


if __name__ == '__main__':
    main()
