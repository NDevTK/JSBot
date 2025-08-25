import database
import json

def generate_report():
    """Generates and prints a report of exploitable findings."""
    print("--- Confirmed Vulnerability Report ---")

    conn = database.get_db_connection()
    cursor = conn.cursor()

    # Fetch all reviewed findings
    cursor.execute("SELECT id, source_url, category, agent_verdict_json FROM findings WHERE status = 'reviewed'")
    reviewed_findings = cursor.fetchall()

    conn.close()

    if not reviewed_findings:
        print("\nNo findings have been reviewed yet.")
        return

    exploitable_findings = []
    for finding in reviewed_findings:
        try:
            verdict = json.loads(finding['agent_verdict_json'])
            # Check for a boolean true or a string "true" for flexibility
            if str(verdict.get("is_exploitable")).lower() == 'true':
                exploitable_findings.append({
                    "id": finding['id'],
                    "source_url": finding['source_url'],
                    "category": finding['category'],
                    "verdict": verdict
                })
        except (json.JSONDecodeError, AttributeError):
            print(f"\n[!] Warning: Could not parse verdict for Finding ID {finding['id']}.")
            continue

    if not exploitable_findings:
        print("\nNo exploitable vulnerabilities found in the reviewed findings.")
        return

    print(f"\nFound {len(exploitable_findings)} confirmed exploitable vulnerabilities:\n")

    for i, finding in enumerate(exploitable_findings, 1):
        verdict = finding['verdict']
        print(f"{'='*20} Finding #{i} {'='*20}")
        print(f"  Finding ID: {finding['id']}")
        print(f"  Source URL: {finding['source_url']}")
        print(f"  Vulnerability Type: {verdict.get('vulnerability_type', 'N/A')}")
        print(f"  Priority: {verdict.get('priority', 'N/A')}")
        print(f"  Confidence: {verdict.get('confidence', 'N/A')}")
        print("\n  Agent's Reasoning:")
        print(f"    {verdict.get('reasoning', 'No reasoning provided.')}")
        print(f"{'='*52}\n")

def main():
    """Main function to run the reporting tool."""
    try:
        database.init_db() # Ensure DB is initialized
        generate_report()
    except Exception as e:
        print(f"[!] An unexpected error occurred: {e}")

if __name__ == '__main__':
    main()
