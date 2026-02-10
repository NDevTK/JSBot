"""Per-subdomain anomaly detection for JavaScript scripts."""
import re
import threading
from dataclasses import dataclass, field
from urllib.parse import urlparse

from scoring import looks_minified, _is_known_library


# --- Running Statistics (Welford's Online Algorithm) ---

class RunningStats:
    """Incremental mean/variance via Welford's algorithm. O(1) memory."""

    __slots__ = ('n', 'mean', 'M2')

    def __init__(self, n=0, mean=0.0, M2=0.0):
        self.n = n
        self.mean = mean
        self.M2 = M2

    def push(self, value):
        self.n += 1
        delta = value - self.mean
        self.mean += delta / self.n
        delta2 = value - self.mean
        self.M2 += delta * delta2

    @property
    def variance(self):
        return self.M2 / (self.n - 1) if self.n >= 2 else 0.0

    @property
    def stddev(self):
        return self.variance ** 0.5

    def to_dict(self):
        return {'n': self.n, 'mean': self.mean, 'M2': self.M2}

    @classmethod
    def from_dict(cls, d):
        return cls(n=d['n'], mean=d['mean'], M2=d['M2'])


# --- Script Feature Vector ---

TRACKED_FEATURES = [
    'byte_size', 'line_count', 'avg_line_length',
    'eval_count', 'dom_sink_count', 'fetch_count',
    'postmessage_count', 'redirect_count', 'cookie_access_count',
    'crypto_count', 'storage_count',
    'taint_source_count', 'taint_sink_count', 'global_write_count',
]


@dataclass
class ScriptFeatures:
    """Feature vector for one script."""
    script_hash: str
    script_url: str
    page_url: str
    subdomain: str

    # Size & structure
    byte_size: int = 0
    line_count: int = 0
    avg_line_length: float = 0.0
    is_minified: bool = False
    is_known_library: bool = False
    has_source_map: bool = False

    # Functionality counts
    eval_count: int = 0
    dom_sink_count: int = 0
    fetch_count: int = 0
    postmessage_count: int = 0
    redirect_count: int = 0
    cookie_access_count: int = 0
    crypto_count: int = 0
    storage_count: int = 0

    # AST-derived
    taint_source_count: int = 0
    taint_sink_count: int = 0
    global_write_count: int = 0


def extract_features(js_code, script_hash, script_url, page_url, analyzer, tree):
    """Extract feature vector from a parsed script.

    Uses existing ASTAnalyzer methods for source/sink/global counts,
    and simple regex for functionality fingerprinting.
    """
    source_bytes = js_code.encode('utf-8')
    total_lines = js_code.count('\n') + 1

    # Subdomain from page URL (scripts are served from CDNs, page URL is the context)
    parsed = urlparse(page_url) if page_url else None
    subdomain = parsed.hostname if parsed else 'unknown'

    # AST-derived counts
    sources = analyzer.find_sources_in_range(tree, source_bytes, 0, total_lines)
    sinks = analyzer.find_sinks_in_range(tree, source_bytes, 0, total_lines)
    global_assigns = analyzer.find_global_assignments(tree, source_bytes)

    # DOM sink subcategories
    dom_sink_cats = {'DOM XSS', 'document.write', 'insertAdjacentHTML'}
    dom_sink_count = sum(1 for s in sinks if s.get('category') in dom_sink_cats)

    return ScriptFeatures(
        script_hash=script_hash,
        script_url=script_url or 'inline',
        page_url=page_url or '',
        subdomain=subdomain,
        byte_size=len(js_code),
        line_count=total_lines,
        avg_line_length=len(js_code) / max(total_lines, 1),
        is_minified=looks_minified(js_code),
        is_known_library=_is_known_library(js_code),
        has_source_map=bool(re.search(r'sourceMappingURL\s*=', js_code[-500:])) if len(js_code) > 0 else False,
        eval_count=len(re.findall(r'\beval\s*\(|\bFunction\s*\(', js_code)),
        dom_sink_count=dom_sink_count,
        fetch_count=len(re.findall(r'\bfetch\s*\(|\bXMLHttpRequest\b', js_code)),
        postmessage_count=len(re.findall(
            r'\.postMessage\s*\(|addEventListener\s*\(\s*[\'"]message', js_code)),
        redirect_count=len(re.findall(
            r'location\.(?:href|assign|replace)\s*=|window\.open\s*\(', js_code)),
        cookie_access_count=len(re.findall(r'\bdocument\.cookie\b', js_code)),
        crypto_count=len(re.findall(r'crypto\.subtle|CryptoJS|sjcl|forge\.', js_code)),
        storage_count=len(re.findall(r'\b(?:localStorage|sessionStorage)\b', js_code)),
        taint_source_count=len(sources),
        taint_sink_count=len(sinks),
        global_write_count=len(global_assigns),
    )


# --- Per-Subdomain Profile ---

class SubdomainProfile:
    """Statistical profile built incrementally during a scan."""

    def __init__(self, subdomain):
        self.subdomain = subdomain
        self.script_count = 0
        self.minified_count = 0
        self.library_count = 0
        self._stats = {}  # feature_name -> RunningStats

    def update(self, features):
        """Add a script's features to the profile."""
        self.script_count += 1
        if features.is_minified:
            self.minified_count += 1
        if features.is_known_library:
            self.library_count += 1

        for feat_name in TRACKED_FEATURES:
            value = getattr(features, feat_name)
            if feat_name not in self._stats:
                self._stats[feat_name] = RunningStats()
            self._stats[feat_name].push(float(value))

    def anomaly_score(self, features):
        """Score how anomalous a script is vs this subdomain's profile.

        Returns (score 0-100, list of reason strings).
        """
        if self.script_count < 3:
            return 0.0, []

        anomalies = []
        total_z = 0.0
        counted = 0

        for feat_name in TRACKED_FEATURES:
            value = float(getattr(features, feat_name))
            stats = self._stats.get(feat_name)
            if not stats or stats.stddev == 0:
                continue

            z = abs(value - stats.mean) / stats.stddev
            if z > 2.0:
                anomalies.append(f"{feat_name}: {value:.0f} (mean={stats.mean:.1f}, z={z:.1f})")
                total_z += z
                counted += 1

        # Bonus: non-minified on mostly-minified subdomain
        minified_rate = self.minified_count / max(self.script_count, 1)
        if not features.is_minified and minified_rate > 0.8:
            anomalies.append(f"non-minified ({minified_rate:.0%} of subdomain is minified)")
            total_z += 3.0
            counted += 1

        # Bonus: custom code on library-heavy subdomain
        library_rate = self.library_count / max(self.script_count, 1)
        if not features.is_known_library and library_rate > 0.7:
            anomalies.append("custom code on library-heavy subdomain")
            total_z += 2.0
            counted += 1

        if counted == 0:
            return 0.0, []

        avg_z = total_z / counted
        score = min(100.0, avg_z * 15)
        return score, anomalies

    def to_dict(self):
        return {
            'script_count': self.script_count,
            'minified_count': self.minified_count,
            'library_count': self.library_count,
            'stats': {name: s.to_dict() for name, s in self._stats.items()},
        }

    @classmethod
    def from_dict(cls, subdomain, data):
        profile = cls(subdomain)
        profile.script_count = data['script_count']
        profile.minified_count = data['minified_count']
        profile.library_count = data['library_count']
        for name, sdata in data.get('stats', {}).items():
            profile._stats[name] = RunningStats.from_dict(sdata)
        return profile


# --- Anomaly Detector (Manager) ---

class AnomalyDetector:
    """Manages per-subdomain profiles and scores anomalies after scan."""

    def __init__(self):
        self.profiles = {}  # subdomain -> SubdomainProfile
        self._all_features = []  # all ingested ScriptFeatures
        self._lock = threading.Lock()

    def ingest(self, features):
        """Add a script's features. Thread-safe (called from ThreadPoolExecutor)."""
        with self._lock:
            subdomain = features.subdomain
            if subdomain not in self.profiles:
                self.profiles[subdomain] = SubdomainProfile(subdomain)
            self.profiles[subdomain].update(features)
            self._all_features.append(features)

    def score_all(self):
        """Score all scripts against their subdomain profile. Call after scan completes.

        Returns list of finding dicts for anomalous scripts.
        """
        findings = []
        for features in self._all_features:
            if features.is_known_library:
                continue

            profile = self.profiles.get(features.subdomain)
            if not profile:
                continue

            score, reasons = profile.anomaly_score(features)
            if score < 30:
                continue

            findings.append({
                'finding_type': 'anomaly',
                'source_url': features.page_url,
                'script_url': features.script_url,
                'script_hash': features.script_hash,
                'subdomain': features.subdomain,
                'anomaly_score': round(score, 1),
                'reasons': reasons,
                'severity': min(int(score // 10), 10),
                'confidence': 'heuristic',
                'analysis_method': 'anomaly_detection',
                'is_minified': features.is_minified,
                'line_count': features.line_count,
                'subdomain_context': {
                    'total_scripts': profile.script_count,
                    'minified_rate': round(profile.minified_count / max(profile.script_count, 1), 2),
                    'library_rate': round(profile.library_count / max(profile.script_count, 1), 2),
                },
            })

        return findings

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
