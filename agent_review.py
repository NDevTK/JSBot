import database
import json
import textwrap

VERDICT_TEMPLATE = {
    "is_exploitable": "false",
    "vulnerability_type": "False Positive",
    "confidence": "High",
    "priority": "Informational",
    "reasoning": "Explain your reasoning here."
}

def print_code_with_highlight(script_content, line_number, context_lines=10):
    """Prints the script content with line numbers and highlights the target line."""
    lines = script_content.split('\n')
    start = max(0, line_number - context_lines - 1)
    end = min(len(lines), line_number + context_lines)

    print("-" * 80)
    for i, line in enumerate(lines[start:end], start=start + 1):
        prefix = ">>" if i == line_number else "  "
        print(f"{prefix} {i:4d} | {line}")
    print("-" * 80)

def get_verdict_from_agent():
    """Prompts the agent to enter a JSON verdict."""
    print("\nPlease provide your verdict. The required format is a JSON object.")
    print("Here is a template (you can copy, edit, and paste this):")
    print(json.dumps(VERDICT_TEMPLATE, indent=4))
    print("\nEnter your JSON verdict below. Press Ctrl+D (or Ctrl+Z on Windows) when you are done.")

    lines = []
    while True:
        try:
            line = input()
            lines.append(line)
        except EOFError:
            break

    verdict_str = "".join(lines)

    try:
        verdict_json = json.loads(verdict_str)
        # Basic validation
        if not all(key in verdict_json for key in VERDICT_TEMPLATE.keys()):
            print("[!] Invalid JSON structure. Please ensure all keys from the template are present.")
            return None
        return json.dumps(verdict_json) # Return as a string for the DB
    except json.JSONDecodeError:
        print("[!] Invalid JSON. Please try again.")
        return None

def main():
    """Main function to run the agent review CLI."""
    print("--- JS Agent Review CLI ---")

    while True:
        # Fetch one finding to review
        findings = database.fetch_pending_findings(batch_size=1)
        if not findings:
            print("\nNo more pending findings to review. Good job!")
            break

        finding = findings[0]
        finding_id = finding['id']

        print("\n" + "="*80)
        print(f"Now reviewing Finding ID: {finding_id}")
        print(f"  Source URL: {finding['source_url']}")
        print(f"  Category: {finding['category']}")
        print(f"  Matched Text: {finding['matched_text']}")

        script_content = database.get_script_by_hash(finding['script_hash'])
        if not script_content:
            print(f"[!] [ERROR] Could not retrieve script content for hash: {finding['script_hash']}")
            # We should probably mark this finding as an error and continue
            continue

        print_code_with_highlight(script_content, finding['line_number'])

        verdict = None
        while verdict is None:
            verdict = get_verdict_from_agent()

        database.update_finding_verdict(finding_id, verdict)
        print(f"\n[SUCCESS] Verdict for Finding ID {finding_id} has been saved.")
        print("="*80)


if __name__ == '__main__':
    database.init_db() # Ensure DB exists
    main()
