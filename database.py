import sqlite3
import datetime

DB_FILE = "js_security.db"

def get_db_connection():
    """Establishes a connection to the SQLite database."""
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initializes the database and creates tables if they don't exist."""
    conn = get_db_connection()
    cursor = conn.cursor()

    # URL Queue: Stores URLs to be scanned
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS url_queue (
        url TEXT PRIMARY KEY,
        status TEXT NOT NULL DEFAULT 'pending',
        priority INTEGER NOT NULL DEFAULT 1,
        added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    # Scripts: Stores the content of discovered JavaScript files
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS scripts (
        hash TEXT PRIMARY KEY,
        content TEXT NOT NULL,
        source_url TEXT NOT NULL,
        discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    # Findings: Stores raw findings from the scanner for agent review
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS findings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        script_hash TEXT NOT NULL,
        source_url TEXT NOT NULL,
        category TEXT NOT NULL,
        matched_text TEXT NOT NULL,
        line_number INTEGER NOT NULL,
        status TEXT NOT NULL DEFAULT 'pending_review',
        agent_verdict_json TEXT,
        found_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        feedback_processed BOOLEAN NOT NULL DEFAULT 0,
        FOREIGN KEY (script_hash) REFERENCES scripts (hash)
    )
    """)

    # Known Hashes: Stores hashes of known, benign libraries to ignore
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS known_hashes (
        hash TEXT PRIMARY KEY
    )
    """)

    conn.commit()
    conn.close()
    print("Database initialized successfully.")

def fetch_pending_urls(batch_size=10):
    """Fetches a batch of pending URLs from the queue."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT url FROM url_queue WHERE status = 'pending' ORDER BY priority DESC, added_at ASC LIMIT ?", (batch_size,))
    urls = [row['url'] for row in cursor.fetchall()]
    conn.close()
    return urls

def update_url_status(url, status):
    """Updates the status of a URL in the queue."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE url_queue SET status = ? WHERE url = ?", (status, url))
    conn.commit()
    conn.close()

def script_exists(script_hash):
    """Checks if a script with the given hash already exists."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT 1 FROM scripts WHERE hash = ?", (script_hash,))
    exists = cursor.fetchone() is not None
    conn.close()
    return exists

def add_script(script_hash, content, source_url):
    """Adds a new script to the database."""
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT INTO scripts (hash, content, source_url) VALUES (?, ?, ?)", (script_hash, content, source_url))
        conn.commit()
    except sqlite3.IntegrityError:
        # Ignore if the script hash already exists (e.g., race condition)
        pass
    finally:
        conn.close()

def add_finding(script_hash, source_url, category, matched_text, line_number):
    """Adds a new finding to the database."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO findings (script_hash, source_url, category, matched_text, line_number) VALUES (?, ?, ?, ?, ?)",
        (script_hash, source_url, category, matched_text, line_number)
    )
    conn.commit()
    conn.close()

def add_urls_to_queue(urls, priority=1):
    """Adds a list of URLs to the queue, ignoring duplicates."""
    conn = get_db_connection()
    cursor = conn.cursor()
    data = [(url, priority) for url in urls]
    cursor.executemany("INSERT OR IGNORE INTO url_queue (url, priority) VALUES (?, ?)", data)
    conn.commit()
    conn.close()

def fetch_pending_findings(batch_size=5):
    """Fetches a batch of findings pending review."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, script_hash, source_url, category, matched_text, line_number FROM findings WHERE status = 'pending_review' LIMIT ?", (batch_size,))
    findings = cursor.fetchall()
    conn.close()
    return findings

def get_script_by_hash(script_hash):
    """Retrieves the content of a script by its hash."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT content FROM scripts WHERE hash = ?", (script_hash,))
    row = cursor.fetchone()
    conn.close()
    return row['content'] if row else None

def update_finding_verdict(finding_id, verdict_json):
    """Updates a finding with the agent's verdict and marks it as reviewed."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE findings SET status = 'reviewed', agent_verdict_json = ? WHERE id = ?", (verdict_json, finding_id))
    conn.commit()
    conn.close()

def get_high_priority_unprocessed_findings():
    """Fetches reviewed, high-priority findings that haven't been processed for feedback."""
    conn = get_db_connection()
    cursor = conn.cursor()
    # This is a complex query. We need to parse the JSON in the query.
    # SQLite's json_extract is perfect for this.
    # We look for verdicts where priority is High or Critical.
    cursor.execute("""
        SELECT id, script_hash FROM findings
        WHERE status = 'reviewed'
        AND feedback_processed = 0
        AND (
            json_extract(agent_verdict_json, '$.priority') = 'High' OR
            json_extract(agent_verdict_json, '$.priority') = 'Critical'
        )
    """)
    findings = cursor.fetchall()
    conn.close()
    return findings

def mark_finding_as_processed(finding_id):
    """Marks a finding as processed for the feedback loop."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE findings SET feedback_processed = 1 WHERE id = ?", (finding_id,))
    conn.commit()
    conn.close()

def get_known_hashes():
    """Retrieves all known hashes to be ignored."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT hash FROM known_hashes")
    hashes = {row['hash'] for row in cursor.fetchall()}
    conn.close()
    return hashes

if __name__ == '__main__':
    init_db()
