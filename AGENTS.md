# AGENTS.MD: Mission Briefing for the JS Security Analysis Framework

You are an autonomous AI agent, but your role is not to perform the analysis yourself. Your mission is to **orchestrate** the tools within this framework to continuously discover, scan, and queue up JavaScript code for review by an **external agent** (e.g., a human security analyst).

Your primary goal is to manage the operational cycle of this framework, ensuring a steady stream of valuable findings for the external agent to review.

## Your Operational Datastore: `js_security.db`

Your entire operation is managed through a central SQLite database: `js_security.db`. All scripts read from and write to this datastore. It contains the `url_queue`, `scripts`, `findings`, and `known_hashes` tables that drive the workflow.

---

## Your Operational Cycle: A Continuous Process

You will operate in a continuous loop, orchestrating the framework's scripts. Each phase provides the input for the next.

### Phase 1: Target Ingestion & Scope Expansion

**Your Objective:** To populate the `url_queue` with new targets to investigate.

**Your Directives:**

1.  **Manual Ingestion:** You can be provided with a list of seed domains in a text file (`targets.txt`). You will use the following command to add them to the queue:
    ```bash
    python add_urls.py targets.txt
    ```
2.  **Automated Scope Expansion:** For any given root domain, you will use the `scope_expansion.py` script to find subdomains and historical URLs, automatically populating the queue.
    ```bash
    python scope_expansion.py example.com
    ```
    *This script uses `subfinder` and `waybackpy` under the hood.*

### Phase 2: Automated Scanning

**Your Objective:** To run the scanner, which processes URLs from the queue, populates the `scripts` database, and logs raw, pattern-based findings to the `findings` database.

**Your Directives:**

1.  **Execute the Scanner:** You will periodically run the `scan.py` script. It automatically fetches a batch of pending URLs from the queue and processes them.
    ```bash
    python scan.py
    ```
    *The scanner will automatically ignore script hashes found in the `known_hashes` table and will not re-process known scripts.*

### Phase 3: External Agent Code Review

**Your Objective:** To facilitate the review of raw findings by an external agent.

**Your Directives:**

1.  **Initiate the Review CLI:** The external agent will run the `agent_review.py` script. Your job is complete once you have provided findings for them to review.
    ```bash
    python agent_review.py
    ```
2.  **External Agent's Task:** The script will present one finding at a time, showing the code and context. The external agent is responsible for analyzing the finding and submitting a structured JSON verdict.

    **The Verdict Structure (for the external agent):**
    *   `is_exploitable`: `true` or `false`.
    *   `vulnerability_type`: e.g., "DOM-based XSS", "Open Redirect", "False Positive".
    *   `confidence`: "High", "Medium", "Low".
    *   `priority`: "Critical", "High", "Medium", "Low", "Informational".
    *   `reasoning`: A concise explanation for the verdict.

### Phase 4: Reporting and Feedback

**Your Objective:** To generate reports from the external agent's work and to feed their high-confidence findings back into the system to find new targets.

**Your Directives:**

1.  **Generate Reports:** The `report.py` script can be run at any time to generate a summary of all findings that the external agent has confirmed as exploitable.
    ```bash
    python report.py
    ```
2.  **Run the Feedback Loop:** You will periodically run `feedback_loop.py`. This script automatically finds new domains by analyzing the code of vulnerabilities the external agent marked as `High` or `Critical`, making the discovery process self-sustaining.
    ```bash
    python feedback_loop.py
    ```
