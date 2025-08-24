# AGENTS.MD: An Autonomous Framework for JavaScript Security Analysis

This document outlines a framework for an autonomous agent system designed to continuously discover, analyze, and prioritize JavaScript code for security research. The system is built around `JSBot` as its core analysis engine and is designed to operate in a self-perpetuating loop.

## Core Components & Data Stores

The agent's operation relies on several key data stores to manage state and track findings across its continuous lifecycle.

1.  **URLQueue**: A persistent queue (e.g., Redis list, RabbitMQ, or a database table) of URLs that are pending reconnaissance and analysis.
2.  **ScriptDB**: A key-value store or file directory where the key is the SHA256 hash of a JavaScript file's content and the value is the beautified code. The `--save` flag in `JSBot` handles this automatically.
3.  **FindingsDB**: A structured database (e.g., Elasticsearch, PostgreSQL) that stores the JSON output from `JSBot`, linking findings to script hashes and source URLs.
4.  **KnownHashesDB**: A simple text file or database set containing SHA256 hashes of common, benign third-party libraries (e.g., jQuery, React, Google Analytics). This is used to filter out noise.

---

## The Agent Workflow: A Cyclical Process

The agent operates in a continuous loop, with each phase feeding into the next.

### Phase 1: Target Ingestion

**Objective:** To populate the `URLQueue` with new seed domains.

This is the entry point for the agent. It should be configured to run periodically.

**Actions:**

1.  **Monitor Certificate Transparency:** Use a client to connect to a CT log stream (e.g., `certstream`) to find new domains and subdomains in real-time. Add discovered root domains to the `URLQueue`.
2.  **Scrape Bug Bounty Programs:** Periodically run scrapers against platforms like HackerOne and Bugcrowd to fetch lists of in-scope domains for public programs. Add these domains to the `URLQueue`.
3.  **Ingest Public Code Repositories:** Search platforms like GitHub for files that indicate a web presence, such as `security.txt`, using queries like `"/.well-known/security.txt"`. Extract the associated domains and add them to the `URLQueue`.

### Phase 2: Scope Expansion

**Objective:** To expand a seed domain into a comprehensive list of scannable URLs.

**Actions:**

1.  **Dequeue a Domain:** Take one domain from the `URLQueue`.
2.  **Enumerate Subdomains:** Use an external tool to find all associated subdomains.
    ```bash
    subfinder -d example.com -o subdomains.txt
    ```
3.  **Gather Historical URLs:** For each discovered domain and subdomain, use JSBot's Wayback Machine integration to gather a massive list of historical URLs. This is the most effective way to uncover old and forgotten endpoints.
    ```bash
    python scan.py --wayback subdomains.txt --link-mode | jq -r '.matched_text' | sort -u >> wayback_urls.txt
    ```
4.  **Enqueue for Analysis:** Add all unique URLs from `wayback_urls.txt` back into the `URLQueue`.

### Phase 3: Analysis & Collection

**Objective:** To run `JSBot` at scale, populating the `ScriptDB` and `FindingsDB`.

**Actions:**

1.  **Dequeue a Batch:** Take a batch of URLs from the `URLQueue`.
2.  **Execute JSBot Scan:** Run `JSBot` with the `--save` flag to ensure all unique scripts are saved to the `ScriptDB`. Use the `--ignore-hashes` flag to avoid re-analyzing known-benign libraries.
    ```bash
    # known_hashes.txt is the KnownHashesDB
    python scan.py --save --ignore-hashes known_hashes.txt url_batch.txt > findings.jsonl
    ```
3.  **Store Findings:** Parse the `findings.jsonl` output and load each JSON object into the `FindingsDB`, ensuring it is linked to the script's SHA256 hash.

### Phase 4: Prioritization Engine

**Objective:** To score and rank findings to identify the most promising targets for human review.

**Actions:**

1.  **Query Findings:** Fetch all new, unscored findings from the `FindingsDB`.
2.  **Apply Scoring Algorithm:** For each finding associated with a unique script hash, calculate a priority score.

    **Score = (Severity * Criticality) + DensityBonus**

    *   **Severity:** A score based on the finding's `category`.
        *   `Eval Injection`: 10
        *   `Open Redirect`: 8
        *   `DOM Clobbering`: 7
        *   `Potentially Unsafe Sink`: 5
        *   `Cookie Manipulation`: 3
    *   **Criticality:** A score based on keywords in the `source_url`.
        *   Contains `auth`, `admin`, `api`, `dev`, `sso`, `payment`: 1.5x multiplier
        *   Otherwise: 1.0x multiplier
    *   **DensityBonus:** If a single script hash has findings from 3 or more unique categories, add a bonus of +15 to its total score. This highlights complex, custom scripts.

3.  **Generate Ranked Output:** Store the scores in the `FindingsDB`. The primary output for a human researcher is a query that sorts scripts by their highest associated score in descending order.

### Phase 5: Feedback & Re-seeding

**Objective:** To discover new assets from high-priority scripts and feed them back into the loop.

**Actions:**

1.  **Identify High-Value Scripts:** Select the Top 20 highest-scoring scripts from the `FindingsDB` that have not been processed in this phase before.
2.  **Extract Links:** For each script's hash, retrieve its content from the `ScriptDB` and run `JSBot` on it in `--link-mode`.
    ```bash
    # script_content.js is the file from ScriptDB
    python scan.py --link-mode script_content.js | jq -r '.matched_text' | sort -u
    ```
3.  **Discover New Domains:** Parse the extracted URLs to find new, unique domains or subdomains.
4.  **Re-seed:** Add these newly discovered domains back into the **`URLQueue`** for Phase 1, thus completing the loop.
