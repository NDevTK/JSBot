"""SQLite store for all JSBot state — single jsbot.db file."""
import json
import os
import sqlite3
import threading
import time

_DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'jsbot.db')


class FindingsStore:
    """Thread-safe SQLite store for scan findings and all state.

    Single global database at jsbot.db in the project root.
    All tables are domain-scoped.
    Uses WAL mode for concurrent read/write access.
    """

    def __init__(self, domain):
        self.domain = domain
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(_DB_PATH, check_same_thread=False)
        self._conn.execute('PRAGMA journal_mode=WAL')
        self._conn.execute('PRAGMA synchronous=NORMAL')
        self._conn.row_factory = sqlite3.Row
        self._init_schema()

    def _init_schema(self):
        self._conn.executescript('''
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT NOT NULL,
                finding_type TEXT NOT NULL,
                severity INTEGER NOT NULL DEFAULT 0,
                confidence TEXT DEFAULT 'medium',
                source_url TEXT,
                script_url TEXT,
                data_json TEXT NOT NULL,
                finding_key TEXT,
                created_at REAL NOT NULL,
                scan_session TEXT,
                UNIQUE(domain, finding_key)
            );
            CREATE INDEX IF NOT EXISTS idx_findings_type ON findings(finding_type);
            CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
            CREATE INDEX IF NOT EXISTS idx_findings_domain ON findings(domain);
            CREATE INDEX IF NOT EXISTS idx_findings_created ON findings(created_at);

            CREATE TABLE IF NOT EXISTS scan_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT NOT NULL,
                started_at REAL NOT NULL,
                finished_at REAL,
                status TEXT DEFAULT 'running',
                findings_count INTEGER DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS scan_state (
                domain TEXT NOT NULL,
                key TEXT NOT NULL,
                value TEXT NOT NULL,
                PRIMARY KEY (domain, key)
            );

            CREATE TABLE IF NOT EXISTS anomaly_profiles (
                domain TEXT NOT NULL,
                subdomain TEXT NOT NULL,
                data_json TEXT NOT NULL,
                updated_at REAL NOT NULL,
                PRIMARY KEY (domain, subdomain)
            );

            CREATE TABLE IF NOT EXISTS ct_state (
                domain TEXT NOT NULL,
                key TEXT NOT NULL,
                value_json TEXT NOT NULL,
                PRIMARY KEY (domain, key)
            );

            CREATE TABLE IF NOT EXISTS ct_cache (
                domain TEXT NOT NULL,
                month_key TEXT NOT NULL,
                subdomains_json TEXT NOT NULL,
                related_json TEXT NOT NULL,
                cached_at REAL NOT NULL,
                PRIMARY KEY (domain, month_key)
            );

            CREATE TABLE IF NOT EXISTS daemons (
                domain TEXT PRIMARY KEY,
                pid INTEGER NOT NULL,
                started_at REAL NOT NULL
            );

            CREATE TABLE IF NOT EXISTS daemon_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT NOT NULL,
                level TEXT NOT NULL,
                message TEXT NOT NULL,
                created_at REAL NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_daemon_logs_domain ON daemon_logs(domain, created_at);
        ''')
        self._conn.commit()

    # --- Findings ---

    def add_finding(self, finding):
        """Insert a finding. Skips duplicates by finding_key.

        Returns True if inserted, False if duplicate.
        """
        finding_type = finding.get('finding_type', 'unknown')
        severity = finding.get('severity', 0)
        confidence = finding.get('confidence', 'medium')
        source_url = finding.get('source_url', '')
        script_url = finding.get('script_url', '')

        finding_key = self._build_finding_key(finding)

        with self._lock:
            try:
                self._conn.execute(
                    '''INSERT OR IGNORE INTO findings
                       (domain, finding_type, severity, confidence, source_url,
                        script_url, data_json, finding_key, created_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                    (self.domain, finding_type, severity, confidence, source_url,
                     script_url, json.dumps(finding), finding_key, time.time()),
                )
                self._conn.commit()
                return self._conn.total_changes > 0
            except sqlite3.Error:
                return False

    def _build_finding_key(self, finding):
        """Build a dedup key from finding fields."""
        ft = finding.get('finding_type', '')
        parts = [ft]

        if ft == 'interesting_script':
            parts.append(finding.get('script_hash', ''))
        elif ft == 'anomaly':
            parts += [
                finding.get('script_url', ''),
                finding.get('structural_hash', ''),
            ]
        elif ft == 'header_issue':
            parts.append(finding.get('subdomain', ''))
        else:
            parts.append(json.dumps(finding, sort_keys=True)[:200])

        return ':'.join(parts)

    def get_findings(self, severity_min=0, finding_type=None, limit=100,
                     source_url=None):
        """Query findings with optional filters."""
        query = 'SELECT * FROM findings WHERE domain = ? AND severity >= ?'
        params = [self.domain, severity_min]

        if finding_type:
            query += ' AND finding_type = ?'
            params.append(finding_type)
        if source_url:
            query += ' AND source_url LIKE ?'
            params.append(f'%{source_url}%')

        query += ' ORDER BY severity DESC, created_at DESC LIMIT ?'
        params.append(limit)

        return [dict(row) for row in self._conn.execute(query, params)]

    def get_summary(self):
        """Get counts by finding type and severity."""
        rows = self._conn.execute(
            '''SELECT finding_type, severity, COUNT(*) as count
               FROM findings WHERE domain = ?
               GROUP BY finding_type, severity
               ORDER BY severity DESC, count DESC''',
            (self.domain,),
        ).fetchall()
        return [dict(r) for r in rows]

    def get_total_count(self):
        """Total number of findings for this domain."""
        row = self._conn.execute(
            'SELECT COUNT(*) FROM findings WHERE domain = ?',
            (self.domain,),
        ).fetchone()
        return row[0] if row else 0

    # --- Scan Sessions ---

    def start_session(self):
        """Record a new scan session. Returns session ID."""
        cur = self._conn.execute(
            'INSERT INTO scan_sessions (domain, started_at) VALUES (?, ?)',
            (self.domain, time.time()),
        )
        self._conn.commit()
        return cur.lastrowid

    def end_session(self, session_id, findings_count=0):
        """Mark a scan session as finished."""
        self._conn.execute(
            '''UPDATE scan_sessions SET finished_at = ?, status = 'done',
               findings_count = ? WHERE id = ?''',
            (time.time(), findings_count, session_id),
        )
        self._conn.commit()

    def get_last_session(self):
        """Get the most recent scan session."""
        row = self._conn.execute(
            'SELECT * FROM scan_sessions WHERE domain = ? ORDER BY started_at DESC LIMIT 1',
            (self.domain,),
        ).fetchone()
        return dict(row) if row else None

    # --- Scan State (path segments + script hashes) ---

    def load_scan_state(self):
        """Load persisted path segments and analyzed script hashes.

        Returns (seen_path_segments: set, seen_scripts: set).
        """
        segments = set()
        scripts = set()
        row = self._conn.execute(
            "SELECT value FROM scan_state WHERE domain = ? AND key = 'seen_path_segments'",
            (self.domain,),
        ).fetchone()
        if row:
            segments = set(json.loads(row['value']))

        row = self._conn.execute(
            "SELECT value FROM scan_state WHERE domain = ? AND key = 'seen_scripts'",
            (self.domain,),
        ).fetchone()
        if row:
            scripts = set(json.loads(row['value']))

        return segments, scripts

    def save_scan_state(self, seen_path_segments, seen_scripts):
        """Persist path segments and analyzed script hashes."""
        self._conn.execute(
            "INSERT OR REPLACE INTO scan_state (domain, key, value) VALUES (?, ?, ?)",
            (self.domain, 'seen_path_segments', json.dumps(sorted(seen_path_segments))),
        )
        self._conn.execute(
            "INSERT OR REPLACE INTO scan_state (domain, key, value) VALUES (?, ?, ?)",
            (self.domain, 'seen_scripts', json.dumps(sorted(seen_scripts))),
        )
        self._conn.commit()

    # --- Anomaly Profiles ---

    def load_anomaly_profiles(self):
        """Load anomaly profile data for all subdomains.

        Returns dict of {subdomain: profile_data_dict}.
        """
        rows = self._conn.execute(
            'SELECT subdomain, data_json FROM anomaly_profiles WHERE domain = ?',
            (self.domain,),
        ).fetchall()
        return {row['subdomain']: json.loads(row['data_json']) for row in rows}

    def save_anomaly_profiles(self, profiles_dict):
        """Persist anomaly profiles. profiles_dict is {subdomain: data_dict}.

        Replaces all existing profiles atomically.
        """
        self._conn.execute(
            'DELETE FROM anomaly_profiles WHERE domain = ?', (self.domain,),
        )
        now = time.time()
        for subdomain, data in profiles_dict.items():
            self._conn.execute(
                'INSERT INTO anomaly_profiles (domain, subdomain, data_json, updated_at) VALUES (?, ?, ?, ?)',
                (self.domain, subdomain, json.dumps(data), now),
            )
        self._conn.commit()

    # --- CT State ---

    def load_ct_state(self):
        """Load CT scan state.

        Returns dict with keys: scanned_subdomains, fetched_months, related_domains.
        """
        default = {'scanned_subdomains': [], 'fetched_months': [], 'related_domains': []}
        row = self._conn.execute(
            "SELECT value_json FROM ct_state WHERE domain = ? AND key = 'state'",
            (self.domain,),
        ).fetchone()
        if row:
            return json.loads(row['value_json'])
        return default

    def save_ct_state(self, state):
        """Persist CT scan state."""
        self._conn.execute(
            "INSERT OR REPLACE INTO ct_state (domain, key, value_json) VALUES (?, ?, ?)",
            (self.domain, 'state', json.dumps(state)),
        )
        self._conn.commit()

    # --- CT Cache (per-month results) ---

    def load_ct_cache(self, month_key):
        """Load cached CT results for a month.

        Returns (subdomains: set, related: set) or None if not cached.
        """
        row = self._conn.execute(
            'SELECT subdomains_json, related_json FROM ct_cache WHERE domain = ? AND month_key = ?',
            (self.domain, month_key),
        ).fetchone()
        if row:
            return set(json.loads(row['subdomains_json'])), set(json.loads(row['related_json']))
        return None

    def save_ct_cache(self, month_key, subdomains, related):
        """Save CT results for a month."""
        self._conn.execute(
            '''INSERT OR REPLACE INTO ct_cache
               (domain, month_key, subdomains_json, related_json, cached_at)
               VALUES (?, ?, ?, ?, ?)''',
            (self.domain, month_key, json.dumps(sorted(subdomains)),
             json.dumps(sorted(related)), time.time()),
        )
        self._conn.commit()

    # --- Daemon Management ---

    def save_daemon(self, pid):
        """Record a running daemon PID."""
        self._conn.execute(
            'INSERT OR REPLACE INTO daemons (domain, pid, started_at) VALUES (?, ?, ?)',
            (self.domain, pid, time.time()),
        )
        self._conn.commit()

    def get_daemon(self):
        """Get daemon info for this domain. Returns dict or None."""
        row = self._conn.execute(
            'SELECT pid, started_at FROM daemons WHERE domain = ?',
            (self.domain,),
        ).fetchone()
        return dict(row) if row else None

    def remove_daemon(self):
        """Remove daemon record."""
        self._conn.execute(
            'DELETE FROM daemons WHERE domain = ?', (self.domain,),
        )
        self._conn.commit()

    # --- Daemon Logs ---

    def add_log(self, level, message, max_entries=1000):
        """Store a log entry. Trims old entries beyond max_entries."""
        now = time.time()
        with self._lock:
            self._conn.execute(
                'INSERT INTO daemon_logs (domain, level, message, created_at) VALUES (?, ?, ?, ?)',
                (self.domain, level, str(message)[:2000], now),
            )
            # Periodically trim — check every ~100 inserts (cheap heuristic)
            if now % 100 < 1:
                self._conn.execute(
                    '''DELETE FROM daemon_logs WHERE domain = ? AND id NOT IN (
                        SELECT id FROM daemon_logs WHERE domain = ?
                        ORDER BY created_at DESC LIMIT ?
                    )''',
                    (self.domain, self.domain, max_entries),
                )
            self._conn.commit()

    def get_log_tail(self, limit=10):
        """Get the last N log entries."""
        rows = self._conn.execute(
            'SELECT level, message, created_at FROM daemon_logs WHERE domain = ? ORDER BY created_at DESC LIMIT ?',
            (self.domain, limit),
        ).fetchall()
        return [dict(r) for r in reversed(rows)]

    # --- Clear Domain ---

    def clear_domain(self):
        """Delete ALL data for this domain from every table."""
        tables = [
            'findings', 'scan_sessions', 'scan_state', 'anomaly_profiles',
            'ct_state', 'ct_cache', 'daemons', 'daemon_logs',
        ]
        for table in tables:
            self._conn.execute(f'DELETE FROM {table} WHERE domain = ?', (self.domain,))
        self._conn.commit()

    # --- Lifecycle ---

    def close(self):
        """Close the database connection."""
        self._conn.close()


def get_all_domains():
    """List all domains that have data in the database."""
    if not os.path.isfile(_DB_PATH):
        return []
    conn = sqlite3.connect(_DB_PATH)
    try:
        rows = conn.execute(
            '''SELECT DISTINCT domain FROM (
                SELECT domain FROM findings
                UNION SELECT domain FROM scan_sessions
                UNION SELECT domain FROM daemons
            )'''
        ).fetchall()
        return sorted(r[0] for r in rows)
    except sqlite3.Error:
        return []
    finally:
        conn.close()


def get_domain_summary(domain):
    """Get a quick summary for a domain without keeping the connection open."""
    store = FindingsStore(domain)
    try:
        total = store.get_total_count()
        summary = store.get_summary()
        session = store.get_last_session()
        return {
            'domain': domain,
            'total_findings': total,
            'by_type': summary,
            'last_session': session,
        }
    finally:
        store.close()


def get_all_daemons():
    """Get all daemon records from the database."""
    if not os.path.isfile(_DB_PATH):
        return []
    conn = sqlite3.connect(_DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute('SELECT domain, pid, started_at FROM daemons').fetchall()
        return [dict(r) for r in rows]
    except sqlite3.Error:
        return []
    finally:
        conn.close()
