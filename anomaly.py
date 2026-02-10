"""Per-subdomain anomaly detection via change detection and context signals."""
import re
import threading
from dataclasses import dataclass
from urllib.parse import urlparse


# --- Cache-Bust URL Normalization ---

_HASH_SEGMENT_RE = re.compile(r'(?<=[.\-/])[0-9a-f]{8,}(?=[.\-])', re.IGNORECASE)


def _normalize_versioned_url(url):
    """Strip cache-bust hashes from script URLs for cross-deploy comparison.

    app.a1b2c3d4.min.js → app.*.min.js
    vendor-1234abcd.js  → vendor-*.js
    /chunks/abc12345.js → /chunks/*.js

    Only replaces segments that contain at least one digit (avoids matching
    English words that happen to be valid hex like 'deface' or 'accede').
    """
    parsed = urlparse(url)

    def _replace_if_hash(m):
        if any(c.isdigit() for c in m.group()):
            return '*'
        return m.group()

    normalized_path = _HASH_SEGMENT_RE.sub(_replace_if_hash, parsed.path)
    return f"{parsed.netloc}{normalized_path}".lower()


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
    has_sources: bool = False      # contains user input sources (location.hash, etc.)
    has_sinks: bool = False        # contains dangerous sinks (innerHTML, eval, etc.)
    sink_categories: tuple = ()    # deduplicated sink types, e.g. ("DOM XSS", "Eval Injection")


# --- Per-Subdomain Profile (persisted across scans) ---

class SubdomainProfile:
    """Persisted knowledge about a subdomain's scripts from previous scans."""

    def __init__(self, subdomain):
        self.subdomain = subdomain
        self.known_scripts = {}   # script_url -> structural_hash
        self.known_scripts_normalized = {}  # normalized_url -> structural_hash (derived, not persisted)
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
        # Rebuild normalized URL index for cache-bust detection
        for url, shash in profile.known_scripts.items():
            norm = _normalize_versioned_url(url)
            profile.known_scripts_normalized[norm] = shash
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

    def _build_stats(self):
        """Build current-scan stats per subdomain from ingested records."""
        current_stats = {}
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
        return current_stats

    def score(self, emitted_keys=None):
        """Score all ingested scripts. Safe to call repeatedly.

        Change signals (vs previous scan profiles):
          - new_script: script URL not seen before (severity 7)
          - modified_script: same URL but structural hash changed (severity 8)
            Includes cache-bust normalization: app.abc123.js → app.def456.js
            is detected as modified (not new) across deploys.
          - origin_anomaly: script served from unknown hostname (severity 8)

        Context signals (current scan only, vulnerability surface):
          - has_sinks: script contains dangerous sink patterns (severity 5)
          - source_and_sink: script has both sources and sinks (severity 6)
          - inline_with_sinks: inline script containing sinks (severity 7)

        Overlooked code signals (less scrutiny = more bugs):
          - not_minified: unminified custom code on a heavily-minified subdomain (severity 5)
          - small_non_library: short custom script on library-heavy subdomain (severity 5)
          Compound boost: overlooked + has_sinks → 6, overlooked + source_and_sink → 7.

        Args:
            emitted_keys: set of script_hashes already emitted. New findings are
                          added to this set. Pass the same set across calls to dedup.

        Returns list of finding dicts.
        """
        if emitted_keys is None:
            emitted_keys = set()

        current_stats = self._build_stats()

        findings = []
        for rec in self._records:
            if rec.is_known_library:
                continue
            if rec.script_hash in emitted_keys:
                continue

            signals = []
            max_severity = 0
            prev = self.profiles.get(rec.subdomain)
            stats = current_stats.get(rec.subdomain, {})

            # --- Change signals (require previous scan data) ---
            if prev and prev.known_scripts:
                if rec.script_url in prev.known_scripts:
                    old_hash = prev.known_scripts[rec.script_url]
                    if old_hash != rec.structural_hash:
                        signals.append('modified_script')
                        max_severity = max(max_severity, 8)
                else:
                    # Normalized URL catches cache-busted filenames across deploys
                    # (app.abc123.js → app.def456.js detected as modified, not new)
                    norm = _normalize_versioned_url(rec.script_url)
                    old_hash = prev.known_scripts_normalized.get(norm)
                    if old_hash is not None:
                        if old_hash != rec.structural_hash:
                            signals.append('modified_script')
                            max_severity = max(max_severity, 8)
                        # else: same content, just redeployed — not interesting
                    else:
                        signals.append('new_script')
                        max_severity = max(max_severity, 7)

            if prev and prev.known_origins and rec.script_origin:
                if rec.script_origin not in prev.known_origins:
                    signals.append('origin_anomaly')
                    max_severity = max(max_severity, 8)

            # --- Context signals (vulnerability surface) ---
            if rec.has_sinks:
                signals.append('has_sinks')
                max_severity = max(max_severity, 5)

            if rec.has_sources and rec.has_sinks:
                signals.append('source_and_sink')
                max_severity = max(max_severity, 6)

            if rec.has_sinks and (rec.script_url == 'inline' or not rec.script_origin):
                signals.append('inline_with_sinks')
                max_severity = max(max_severity, 7)

            # --- Overlooked code signals (less scrutiny = more bugs) ---
            sc = stats.get('script_count', 0)
            if sc >= 5:
                minified_rate = stats.get('minified_count', 0) / sc
                library_rate = stats.get('library_count', 0) / sc

                if (not rec.is_minified and not rec.is_known_library
                        and minified_rate > 0.85):
                    signals.append('not_minified')
                    max_severity = max(max_severity, 5)

                if (not rec.is_known_library and library_rate > 0.5
                        and rec.line_count < 100):
                    signals.append('small_non_library')
                    max_severity = max(max_severity, 5)

            # --- Compound: overlooked code with attack surface gets priority ---
            if {'not_minified', 'small_non_library'} & set(signals):
                if rec.has_sources and rec.has_sinks:
                    max_severity = max(max_severity, 7)
                elif rec.has_sinks:
                    max_severity = max(max_severity, 6)

            if not signals:
                continue

            emitted_keys.add(rec.script_hash)
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
                'sink_categories': list(rec.sink_categories),
                'subdomain_context': {
                    'total_scripts': sc,
                    'minified_rate': round(stats.get('minified_count', 0) / max(sc, 1), 2),
                    'library_rate': round(stats.get('library_count', 0) / max(sc, 1), 2),
                },
            })

        return findings

    def update_profiles(self):
        """Rebuild profiles from current records. Call at end of scan for persistence."""
        self._update_profiles(self._build_stats())

    def _update_profiles(self, current_stats):
        """Replace profiles with current scan data."""
        new_profiles = {}
        for rec in self._records:
            sub = rec.subdomain
            if sub not in new_profiles:
                new_profiles[sub] = SubdomainProfile(sub)
            profile = new_profiles[sub]
            profile.known_scripts[rec.script_url] = rec.structural_hash
            norm = _normalize_versioned_url(rec.script_url)
            profile.known_scripts_normalized[norm] = rec.structural_hash
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
