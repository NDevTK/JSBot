"""Semgrep integration for static vulnerability detection."""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading

from output import log_message, SEEN_FINDINGS


def _find_semgrep():
    """Find the semgrep executable and return (path, env).

    Checks PATH first, then Python's Scripts dirs (where pip installs).
    Returns env with Scripts dir prepended so semgrep can find pysemgrep.
    """
    if shutil.which('semgrep') and shutil.which('pysemgrep'):
        return 'semgrep', None

    import site
    exe_name = 'semgrep.exe' if os.name == 'nt' else 'semgrep'
    user_base = site.getuserbase()
    vi = sys.version_info
    search_dirs = [
        os.path.join(user_base, f'Python{vi.major}{vi.minor}', 'Scripts'),
        os.path.join(user_base, 'Scripts' if os.name == 'nt' else 'bin'),
        os.path.join(os.path.dirname(sys.executable), 'Scripts'),
    ]
    for scripts_dir in search_dirs:
        scripts_dir = os.path.normpath(scripts_dir)
        if os.path.isfile(os.path.join(scripts_dir, exe_name)):
            env = os.environ.copy()
            env['PATH'] = scripts_dir + os.pathsep + env.get('PATH', '')
            return os.path.join(scripts_dir, exe_name), env

    return 'semgrep', None

# Rule packs to run (security-focused only)
DEFAULT_RULES = [
    'p/secrets',
    'p/security-audit',
]


class SemgrepBatch:
    """Collects scripts for batch Semgrep analysis."""

    def __init__(self):
        self._temp_dir = None
        self._hash_to_meta = {}  # script_hash -> {page_url, script_url}
        self._lock = threading.Lock()

    def add_script(self, js_code, script_hash, page_url, script_url):
        """Write script to temp dir for later batch analysis. Thread-safe."""
        with self._lock:
            if self._temp_dir is None:
                self._temp_dir = tempfile.mkdtemp(prefix='jsbot_semgrep_')
            if script_hash in self._hash_to_meta:
                return  # already collected
            filepath = os.path.join(self._temp_dir, f'{script_hash}.js')
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(js_code)
            self._hash_to_meta[script_hash] = {
                'page_url': page_url,
                'script_url': script_url or 'inline',
            }

    @property
    def script_count(self):
        return len(self._hash_to_meta)

    def run(self, rules=None):
        """Run Semgrep on all collected scripts. Returns list of finding dicts."""
        if not self._temp_dir or not self._hash_to_meta:
            return []

        rules = rules or DEFAULT_RULES
        semgrep_bin, env = _find_semgrep()
        cmd = [
            semgrep_bin, 'scan',
            '--json', '--quiet',
            '--no-git-ignore',
            '--timeout', '30',
            '--timeout-threshold', '3',
        ]
        for rule in rules:
            cmd.extend(['--config', rule])
        cmd.append(self._temp_dir)

        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True,
                timeout=300, env=env,  # 5 min total
            )
            return self._parse_output(result.stdout)
        except subprocess.TimeoutExpired:
            log_message('ERROR', 'Semgrep batch timed out after 5 minutes')
            return []
        except FileNotFoundError:
            raise RuntimeError(
                'Semgrep is required but not installed. Install with: pip install semgrep'
            )

    def _parse_output(self, json_output):
        """Parse Semgrep JSON output into JSBot findings."""
        if not json_output or not json_output.strip():
            return []
        try:
            data = json.loads(json_output)
        except json.JSONDecodeError:
            log_message('ERROR', 'Failed to parse Semgrep JSON output')
            return []

        findings = []
        for result in data.get('results', []):
            filename = os.path.basename(result.get('path', ''))
            script_hash = filename.replace('.js', '')
            meta = self._hash_to_meta.get(script_hash, {})

            check_id = result.get('check_id', '')
            start_line = result.get('start', {}).get('line', 0)
            finding_key = f'{script_hash}:semgrep:{check_id}:{start_line}'
            if finding_key in SEEN_FINDINGS:
                continue
            SEEN_FINDINGS.add(finding_key)

            extra = result.get('extra', {})
            metadata = extra.get('metadata', {})
            severity = self._map_severity(result)

            findings.append({
                'source_url': meta.get('page_url', ''),
                'script_url': meta.get('script_url', 'inline'),
                'script_hash': script_hash,
                'finding_type': 'semgrep',
                'category': check_id,
                'message': extra.get('message', ''),
                'line': start_line,
                'end_line': result.get('end', {}).get('line', 0),
                'matched_text': extra.get('lines', '')[:200],
                'severity': severity,
                'confidence': metadata.get('confidence', 'medium').lower(),
                'analysis_method': 'semgrep',
                'semgrep_rule': check_id,
                'cwe': metadata.get('cwe', []),
                'owasp': metadata.get('owasp', []),
            })

        return findings

    def _map_severity(self, result):
        """Map Semgrep severity to JSBot 1-10 scale."""
        semgrep_sev = result.get('extra', {}).get('severity', 'WARNING')
        return {'ERROR': 9, 'WARNING': 7, 'INFO': 4}.get(semgrep_sev, 5)

    def cleanup(self):
        """Remove temp directory."""
        if self._temp_dir and os.path.exists(self._temp_dir):
            shutil.rmtree(self._temp_dir, ignore_errors=True)
            self._temp_dir = None
