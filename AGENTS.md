# AGENTS.MD: A Framework for Autonomous JS Security Research

This document outlines a conceptual framework for an autonomous agent system designed to continuously discover, analyze, and prioritize JavaScript code for security research. The goal is to create a self-perpetuating loop that feeds new targets into the system, using `JSBot` as the core analysis engine.

## Core Philosophy

The agent operates on a continuous, cyclical model comprised of five phases: **Discovery -> Reconnaissance -> Analysis -> Prioritization -> Feedback**. This loop ensures that the agent not only finds new targets but also learns from its findings to become more effective over time. By automating the large-scale, low-yield parts of reconnaissance, it allows human researchers to focus their attention on the most promising leads.



---

## The Agent Loop: Continuous Operation Phases

### Phase 1: Target Discovery (Seed Generation)

**Objective:** To find new, high-quality seed domains and applications to investigate.

The agent's primary task in this phase is to monitor various sources for previously unknown web assets.

**Actions:**

1.  **Monitor Certificate Transparency Logs:** Continuously watch CT log streams (e.g., using services like `certstream`) to discover newly issued SSL certificates for domains and subdomains. This is an excellent source of fresh, newly deployed assets.
2.  **Scan Public Code Repositories:** Periodically search platforms like GitHub and GitLab for code related to public bug bounty programs. Use search queries like `"security.txt"`, `"/.well-known/security.txt"`, or keywords related to a company's infrastructure to find associated domains.
3.  **Ingest Bug Bounty Program Lists:** Automatically scrape lists of in-scope domains from public bug bounty platforms (HackerOne, Bugcrowd, Intigriti, etc.). This ensures the agent's activities remain within authorized boundaries.
4.  **Process Public Datasets:** Ingest large-scale domain datasets (e.g., TLD zone files, public DNS data) to identify new parent domains to add to the discovery queue.

### Phase 2: Scope Expansion & Reconnaissance

**Objective:** To take a seed domain and expand it into a comprehensive list of scannable URLs.

Once a new domain is discovered, the agent must perform broad reconnaissance to map out its attack surface.

**Actions:**

1.  **Subdomain Enumeration:** Use tools like `subfinder` or `amass` to perform deep subdomain enumeration on the seed domain.
2.  **Historical URL Gathering:** Feed all discovered subdomains into **JSBot**'s Wayback Machine feature (`-w` or `--wayback`). This single step can expand a few dozen subdomains into tens of thousands of unique, historical URLs, uncovering old endpoints and forgotten scripts.
3.  **Active Crawling:** Perform a shallow crawl on the main subdomains to identify initially visible pages and links that may not be in historical archives.
4.  **Asset Collection:** The final output of this phase is a massive, de-duplicated list of URLs ready for analysis.

### Phase 3: JavaScript Collection & Analysis

**Objective:** To execute `JSBot` at scale and save all relevant JavaScript artifacts.

This is the core analysis phase where the collected URLs are processed.

**Actions:**

1.  **Execute Scaled Scans:** Run `JSBot` against the URL list generated in Phase 2. The script should be configured for automation:
    *   `--show-errors`: To log and potentially retry failed requests.
    *   `--save` (`-s`): **Crucially**, this saves every unique JavaScript file to a central storage location, named by its SHA256 hash. This creates a permanent, de-duplicated database of all encountered scripts.
    *   `--no-clean-url`: To preserve URL parameters, as they can sometimes influence script behavior.
2.  **Parse and Store Findings:** Pipe the JSON output from `JSBot` into a database (e.g., Elasticsearch, PostgreSQL, or a simple JSONL file store). This database links findings to the script hash and the source URLs.

### Phase 4: Prioritization & Triage

**Objective:** To score and rank findings, transforming raw data into actionable intelligence for a human researcher.

An unaided stream of findings can be overwhelming. This phase uses a scoring algorithm to highlight the most interesting targets.

**Actions:**

1.  **Implement a Scoring Algorithm:** Automatically score each finding based on a weighted set of criteria:
    *   **Pattern Severity:** A finding in the "Eval Injection" category receives a higher score than "Cookie Manipulation."
    *   **Asset Criticality:** A script found on `auth.example.com` is more critical than one on `blog.example.com`. Use keywords in domain names (e.g., `api`, `admin`, `auth`, `dev`) to influence the score.
    *   **Code Originality:** Decrease the score if the script's hash or filename matches known third-party libraries (`jquery.min.js`, `react.dom.js`, etc.). Increase the score for bespoke, custom-written JavaScript.
    *   **Finding Density:** A script with multiple, varied findings (e.g., both a `postMessage` sink and a `location.href` redirect) is a high-value target and should be scored exponentially higher.
2.  **Generate Prioritized Output:** The agent's final output should be a ranked list or dashboard (e.g., "Top 100 Most Interesting Scripts This Week"). This allows a human researcher to immediately focus on what matters most.

### Phase 5: Feedback & Re-seeding

**Objective:** To use the results of the analysis to fuel new discovery cycles.

This phase makes the agent loop self-sustaining and ever-improving.

**Actions:**

1.  **Extract New Domains:** Run `JSBot` in `--link-mode` on all the saved, high-priority JavaScript files. This will extract any domains, subdomains, and API endpoints hardcoded within the scripts.
2.  **Re-seed the Loop:** Add these newly discovered domains back into the **Target Discovery** (Phase 1) queue. This is a powerful way to uncover hidden, non-public infrastructure.
3.  **Monitor for Changes:** The agent should periodically re-scan high-priority URLs. By comparing the hashes of the JavaScript files found, it can immediately flag when a new version of a script is deployed, triggering a fresh analysis.
