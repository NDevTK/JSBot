"""Per-subdomain anomaly detection via change detection and context signals."""
import threading
from dataclasses import dataclass
from urllib.parse import urlparse


# --- Script Record ---

@dataclass
class ScriptRecord:
    """Lightweight record for one observed script."""
    script_hash: str
    structural_hash: str
    script_url: str
    page_url: str
    subdomain: str       # from page_url hostname (page context, not CDN)
    script_origin: str   # from script_url hostname (where script is served from)
    is_minified: bool
    is_known_library: bool
    line_count: int


# --- Per-Subdomain Profile (persisted across scans) ---

class SubdomainProfile:
    """Persisted knowledge about a subdomain's scripts from previous scans."""

    def __init__(self, subdomain):
        self.subdomain = subdomain
        self.known_scripts = {}   # script_url -> structural_hash
        self.known_origins = set()  # hostnames scripts are normally served from
        self.script_count = 0
        self.minified_count = 0
        self.library_count = 0

    def to_dict(self):
        return {
            'known_scripts': self.known_scripts,
            'known_origins': sorted(self.known_origins),
            'script_count': self.script_count,
            'minified_count': self.minified_count,
            'library_count': self.library_count,
        }

    @classmethod
    def from_dict(cls, subdomain, data):
        profile = cls(subdomain)
        profile.known_scripts = data.get('known_scripts', {})
        profile.known_origins = set(data.get('known_origins', []))
        profile.script_count = data.get('script_count', 0)
        profile.minified_count = data.get('minified_count', 0)
        profile.library_count = data.get('library_count', 0)
        return profile


# --- Anomaly Detector ---

class AnomalyDetector:
    """Change detection + context signals across scans.

    First scan: builds baseline (context signals only).
    Subsequent scans: detects new/modified scripts, origin anomalies, plus context signals.
    """

    def __init__(self):
        self.profiles = {}    # subdomain -> SubdomainProfile (from previous scan)
        self._records = []    # ScriptRecord list (current scan)
        self._lock = threading.Lock()

    def ingest(self, record):
        """Add a script record. Thread-safe (called from ThreadPoolExecutor)."""
        with self._lock:
            self._records.append(record)

    def score_all(self):
        """Score all scripts. Call after scan completes.

        Change signals (vs previous scan profiles):
          - new_script: script URL not seen before (severity 7)
          - modified_script: same URL but structural hash changed (severity 8)
          - origin_anomaly: script served from unknown hostname (severity 8)

        Context signals (current scan only):
          - not_minified: non-minified custom code on mostly-minified subdomain (severity 5)
          - custom_code: custom code on library-heavy subdomain (severity 4)

        Returns list of finding dicts.
        """
        # Build current-scan stats per subdomain
        current_stats = {}  # subdomain -> {script_count, minified_count, library_count, origins}
        for rec in self._records:
            if rec.subdomain not in current_stats:
                current_stats[rec.subdomain] = {
                    'script_count': 0, 'minified_count': 0,
                    'library_count': 0, 'origins': set(),
                }
            stats = current_stats[rec.subdomain]
            stats['script_count'] += 1
            if rec.is_minified:
                stats['minified_count'] += 1
            if rec.is_known_library:
                stats['library_count'] += 1
            if rec.script_origin:
                stats['origins'].add(rec.script_origin)

        findings = []
        for rec in self._records:
            if rec.is_known_library:
                continue

            signals = []
            max_severity = 0
            prev = self.profiles.get(rec.subdomain)
            stats = current_stats.get(rec.subdomain, {})

            # --- Change signals (require previous scan data) ---
            if prev and prev.known_scripts:
                if rec.script_url not in prev.known_scripts:
                    signals.append('new_script')
                    max_severity = max(max_severity, 7)
                else:
                    old_hash = prev.known_scripts[rec.script_url]
                    if old_hash != rec.structural_hash:
                        signals.append('modified_script')
                        max_severity = max(max_severity, 8)

            if prev and prev.known_origins and rec.script_origin:
                if rec.script_origin not in prev.known_origins:
                    signals.append('origin_anomaly')
                    max_severity = max(max_severity, 8)

            # --- Context signals (current scan only) ---
            sc = stats.get('script_count', 0)
            if sc >= 3:
                minified_rate = stats.get('minified_count', 0) / sc
                library_rate = stats.get('library_count', 0) / sc

                if not rec.is_minified and minified_rate > 0.7:
                    signals.append('not_minified')
                    max_severity = max(max_severity, 5)

                if not rec.is_known_library and library_rate > 0.7:
                    signals.append('custom_code')
                    max_severity = max(max_severity, 4)

            if not signals:
                continue

            findings.append({
                'finding_type': 'anomaly',
                'source_url': rec.page_url,
                'script_url': rec.script_url,
                'script_hash': rec.script_hash,
                'subdomain': rec.subdomain,
                'signals': signals,
                'severity': max_severity,
                'confidence': 'heuristic',
                'analysis_method': 'anomaly_detection',
                'is_minified': rec.is_minified,
                'line_count': rec.line_count,
                'subdomain_context': {
                    'total_scripts': sc,
                    'minified_rate': round(stats.get('minified_count', 0) / max(sc, 1), 2),
                    'library_rate': round(stats.get('library_count', 0) / max(sc, 1), 2),
                },
            })

        # Update profiles to current scan data (for next scan's persistence)
        self._update_profiles(current_stats)

        return findings

    def _update_profiles(self, current_stats):
        """Replace profiles with current scan data."""
        new_profiles = {}
        for rec in self._records:
            sub = rec.subdomain
            if sub not in new_profiles:
                new_profiles[sub] = SubdomainProfile(sub)
            profile = new_profiles[sub]
            profile.known_scripts[rec.script_url] = rec.structural_hash
            if rec.script_origin:
                profile.known_origins.add(rec.script_origin)

        # Copy current stats
        for sub, stats in current_stats.items():
            if sub in new_profiles:
                new_profiles[sub].script_count = stats['script_count']
                new_profiles[sub].minified_count = stats['minified_count']
                new_profiles[sub].library_count = stats['library_count']

        self.profiles = new_profiles

    def to_dict(self):
        """Serialize for cross-scan persistence."""
        return {
            subdomain: profile.to_dict()
            for subdomain, profile in self.profiles.items()
        }

    @classmethod
    def from_dict(cls, data):
        """Restore from persisted state."""
        detector = cls()
        for subdomain, pdata in data.items():
            detector.profiles[subdomain] = SubdomainProfile.from_dict(subdomain, pdata)
        return detector
