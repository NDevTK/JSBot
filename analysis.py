"""AST parsing, cross-file taint analysis, script safety checks."""
import re
import asyncio
import httpx
from hashlib import sha256
from urllib.parse import urljoin, urlparse

from patterns import SOURCES, SINKS, JS_PATH_FINDER, ENDPOINT_PATTERNS, INTERESTING_STRING_PATTERNS
from output import log_message, SEEN_FINDINGS, SCRIPT_METADATA
from scoring import looks_minified, _is_known_library, check_known_cves
from sourcemaps import try_fetch_sourcemap, get_original_source
from anomaly import ScriptRecord

import jsbeautifier
import tree_sitter_javascript as tsjs
from tree_sitter import Language, Parser

# --- Global State (managed by scan.py) ---
SEEN_SCRIPTS = set()
CHECKED_JS_URLS = set()
IGNORED_HASHES = set()
ARGS = None  # Set by scan.py at startup


def get_sha256(data):
    """Computes SHA256 hash of the given data."""
    return sha256(data.encode('utf-8')).hexdigest()


def format_javascript(js_code):
    """Beautifies JavaScript code."""
    return jsbeautifier.beautify(js_code)


# --- AST-Based Analysis (tree-sitter) ---

class ASTAnalyzer:
    """Tree-sitter based JavaScript AST analyzer."""

    def __init__(self):
        self.language = Language(tsjs.language())
        self.parser = Parser(self.language)

    def parse(self, source):
        """Parse JS source into AST. Returns tree or None."""
        try:
            return self.parser.parse(source.encode('utf-8'))
        except Exception:
            return None

    def get_node_text(self, node, source_bytes):
        """Get the text content of a node."""
        return source_bytes[node.start_byte:node.end_byte].decode('utf-8', errors='replace')

    def _get_member_chain(self, node, source_bytes):
        """Build clean property chain like 'location.search' from a member_expression.

        Returns None for complex base expressions (IIFEs, calls, etc.) so the
        caller can skip them — child nodes will be visited separately.
        """
        if node.type in ('identifier', 'this', 'property_identifier'):
            return self.get_node_text(node, source_bytes)
        if node.type == 'member_expression':
            obj = node.child_by_field_name('object')
            prop = node.child_by_field_name('property')
            if obj and prop:
                obj_text = self._get_member_chain(obj, source_bytes)
                if obj_text is None:
                    return None
                prop_text = self.get_node_text(prop, source_bytes)
                return f"{obj_text}.{prop_text}"
        return None

    def find_sources_in_range(self, tree, source_bytes, start_line, end_line):
        """Find taint source patterns in a line range using iterative AST walking."""
        results = []
        stack = [tree.root_node]
        while stack:
            node = stack.pop()
            if node.start_point[0] > end_line or node.end_point[0] < start_line:
                continue

            if node.type == 'member_expression':
                chain = self._get_member_chain(node, source_bytes)
                if chain:
                    for source_name, source_pattern in SOURCES.items():
                        if re.search(source_pattern, chain, re.IGNORECASE):
                            results.append({
                                "category": source_name,
                                "match": chain,
                                "line": node.start_point[0] + 1,
                            })
                            break

            if node.type == 'new_expression':
                for child in node.children:
                    if child.type in ('identifier', 'member_expression'):
                        ctor = self.get_node_text(child, source_bytes)
                        if ctor == 'URLSearchParams':
                            results.append({
                                "category": "URLSearchParams",
                                "match": "new URLSearchParams(...)",
                                "line": node.start_point[0] + 1,
                            })
                        break

            if node.type == 'call_expression':
                fn = node.child_by_field_name('function')
                if fn:
                    if fn.type == 'member_expression':
                        chain = self._get_member_chain(fn, source_bytes)
                    elif fn.type == 'identifier':
                        chain = self.get_node_text(fn, source_bytes)
                    else:
                        chain = None
                    if chain:
                        for source_name in ("getItem", "cookie_read"):
                            if re.search(SOURCES[source_name], chain, re.IGNORECASE):
                                results.append({
                                    "category": source_name,
                                    "match": chain + "(...)",
                                    "line": node.start_point[0] + 1,
                                })
                                break

            stack.extend(node.children)
        return results

    def find_sinks_in_range(self, tree, source_bytes, start_line, end_line):
        """Find taint sink patterns in a line range using iterative AST walking."""
        results = []
        stack = [tree.root_node]
        while stack:
            node = stack.pop()
            if node.start_point[0] > end_line or node.end_point[0] < start_line:
                continue

            # Assignment expressions: innerHTML=, outerHTML=, location.href=, document.cookie=
            if node.type == 'assignment_expression':
                left = node.child_by_field_name('left')
                if left and left.type == 'member_expression':
                    chain = self._get_member_chain(left, source_bytes)
                    left_text = chain if chain else self.get_node_text(left, source_bytes)[:200]
                    for sink_name, sink_info in SINKS.items():
                        if re.search(sink_info["pattern"], left_text + ' =', re.IGNORECASE):
                            right = node.child_by_field_name('right')
                            if right and self._is_literal(right):
                                continue
                            results.append({
                                "category": sink_name,
                                "match": left_text + ' =',
                                "line": node.start_point[0] + 1,
                                "severity": sink_info["severity"],
                            })
                            break

            # Call expressions: eval(), document.write(), insertAdjacentHTML(), etc.
            if node.type == 'call_expression':
                fn = node.child_by_field_name('function')
                if fn:
                    if fn.type == 'identifier':
                        fn_text = self.get_node_text(fn, source_bytes)
                    elif fn.type == 'member_expression':
                        fn_text = self._get_member_chain(fn, source_bytes)
                        if fn_text is None:
                            prop = fn.child_by_field_name('property')
                            obj = fn.child_by_field_name('object')
                            if prop and obj:
                                prop_text = self.get_node_text(prop, source_bytes)
                                if (prop_text in ('html', 'append', 'prepend', 'after', 'before')
                                        and obj.type == 'call_expression'):
                                    obj_fn = obj.child_by_field_name('function')
                                    if obj_fn:
                                        obj_fn_text = self.get_node_text(obj_fn, source_bytes)
                                        if obj_fn_text.strip() in ('$', 'jQuery'):
                                            if not self._has_only_literal_args(node):
                                                results.append({
                                                    "category": "jQuery HTML Sink",
                                                    "match": f"$(...).{prop_text}(",
                                                    "line": node.start_point[0] + 1,
                                                    "severity": 8,
                                                })
                    else:
                        fn_text = None

                    if fn_text:
                        for sink_name, sink_info in SINKS.items():
                            if re.search(sink_info["pattern"], fn_text + '(', re.IGNORECASE):
                                if sink_name == "Eval Injection" and self._has_only_literal_args(node):
                                    continue
                                results.append({
                                    "category": sink_name,
                                    "match": fn_text + '(',
                                    "line": node.start_point[0] + 1,
                                    "severity": sink_info["severity"],
                                })
                                break

            stack.extend(node.children)
        return results

    def _is_literal(self, node):
        """Check if a node is a literal value (string, number, boolean, null)."""
        return node.type in ('string', 'number', 'true', 'false', 'null', 'undefined')

    def _has_only_literal_args(self, call_node):
        """Check if a call expression has only literal arguments."""
        args = call_node.child_by_field_name('arguments')
        if args is None:
            return False
        for child in args.children:
            if child.type in ('(', ')', ','):
                continue
            if not self._is_literal(child):
                return False
        return True

    def find_global_assignments(self, tree, source_bytes):
        """Find window.X = ... assignments using iterative AST walking."""
        results = []
        stack = [tree.root_node]
        while stack:
            node = stack.pop()
            if node.type == 'assignment_expression':
                left = node.child_by_field_name('left')
                if left and left.type == 'member_expression':
                    obj = left.child_by_field_name('object')
                    prop = left.child_by_field_name('property')
                    if obj and prop:
                        obj_text = self.get_node_text(obj, source_bytes)
                        if obj_text in ('window', 'self', 'globalThis'):
                            prop_text = self.get_node_text(prop, source_bytes)
                            right = node.child_by_field_name('right')
                            right_text = self.get_node_text(right, source_bytes) if right else ''
                            is_tainted = False
                            taint_source = None
                            for source_name, source_pattern in SOURCES.items():
                                if re.search(source_pattern, right_text, re.IGNORECASE):
                                    is_tainted = True
                                    taint_source = source_name
                                    break
                            results.append({
                                "name": f"{obj_text}.{prop_text}",
                                "line": node.start_point[0] + 1,
                                "is_tainted": is_tainted,
                                "taint_source": taint_source,
                            })
            stack.extend(node.children)
        return results

    def find_postmessage_handlers(self, tree, source_bytes):
        """Find message event listeners, check origin validation and sink flow."""
        results = []
        stack = [tree.root_node]
        while stack:
            node = stack.pop()

            # addEventListener('message', handler)
            if node.type == 'call_expression':
                fn = node.child_by_field_name('function')
                if fn:
                    fn_name = None
                    if fn.type == 'member_expression':
                        prop = fn.child_by_field_name('property')
                        if prop:
                            fn_name = self.get_node_text(prop, source_bytes)
                    elif fn.type == 'identifier':
                        fn_name = self.get_node_text(fn, source_bytes)

                    if fn_name == 'addEventListener':
                        args = node.child_by_field_name('arguments')
                        if args:
                            arg_nodes = [c for c in args.children
                                         if c.type not in ('(', ')', ',')]
                            if len(arg_nodes) >= 2:
                                event_type = self.get_node_text(
                                    arg_nodes[0], source_bytes
                                ).strip('\'"` ')
                                if event_type == 'message':
                                    results.append(self._analyze_msg_handler(
                                        arg_nodes[1], node, tree, source_bytes
                                    ))

            # window.onmessage = handler
            if node.type == 'assignment_expression':
                left = node.child_by_field_name('left')
                if left and left.type == 'member_expression':
                    chain = self._get_member_chain(left, source_bytes)
                    if chain and chain.endswith('.onmessage'):
                        right = node.child_by_field_name('right')
                        if right:
                            results.append(self._analyze_msg_handler(
                                right, node, tree, source_bytes
                            ))

            stack.extend(node.children)
        return results

    def _analyze_msg_handler(self, handler_node, context_node, tree, source_bytes):
        """Analyze a message handler for origin checks and sink usage."""
        handler_text = self.get_node_text(handler_node, source_bytes)
        has_origin_check = bool(re.search(
            r'\b(?:event|e|evt|msg|ev)\.origin\b', handler_text
        ))
        sinks = []
        if handler_node.type in ('arrow_function', 'function_expression', 'function'):
            sinks = self.find_sinks_in_range(
                tree, source_bytes,
                handler_node.start_point[0], handler_node.end_point[0]
            )
        return {
            'line': context_node.start_point[0] + 1,
            'has_origin_check': has_origin_check,
            'sinks': sinks,
        }


# Singleton AST analyzer (created on first use)
_ast_analyzer = None


def get_ast_analyzer():
    """Get or create the singleton AST analyzer."""
    global _ast_analyzer
    if _ast_analyzer is None:
        _ast_analyzer = ASTAnalyzer()
    return _ast_analyzer


# --- Cross-File Analysis ---

class CrossFileState:
    """Tracks global namespace assignments across scripts on the same page."""

    def __init__(self):
        self.global_writes = []  # {name, line, script_url, is_tainted, taint_source}
        self.global_reads_into_sinks = []  # {name, sink_category, line, script_url, severity}
        self.dangerous_functions = []  # {name, sink_categories, line, script_url}
        self.scripts = []  # (script_content, script_url, script_hash)

    def add_script(self, content, script_url, script_hash):
        self.scripts.append((content, script_url, script_hash))

    def _find_assignment_rhs(self, root_node, global_name, source_bytes):
        """Find the RHS node of a `window.X = ...` assignment. Iterative."""
        stack = [root_node]
        while stack:
            node = stack.pop()
            if node.type == 'assignment_expression':
                left = node.child_by_field_name('left')
                if left and left.type == 'member_expression':
                    left_text = source_bytes[left.start_byte:left.end_byte].decode('utf-8', errors='replace')
                    if left_text == global_name:
                        return node.child_by_field_name('right')
            stack.extend(node.children)
        return None

    def collect_globals(self, analyzer):
        """After all scripts analyzed, collect global writes/reads."""
        for content, script_url, script_hash in self.scripts:
            source_bytes = content.encode('utf-8')
            tree = analyzer.parse(content)
            if not tree:
                continue

            # Find window.X = ... writes
            assigns = analyzer.find_global_assignments(tree, source_bytes)
            for a in assigns:
                self.global_writes.append({
                    **a, "script_url": script_url, "script_hash": script_hash
                })

            # Find dangerous functions: window.X = function that contains sinks
            for a in assigns:
                right_node = self._find_assignment_rhs(tree.root_node, a["name"], source_bytes)
                if right_node and right_node.type in ('arrow_function', 'function_expression', 'function'):
                    fn_sinks = analyzer.find_sinks_in_range(
                        tree, source_bytes, right_node.start_point[0], right_node.end_point[0]
                    )
                    if fn_sinks:
                        self.dangerous_functions.append({
                            "name": a["name"],
                            "sink_categories": [s["category"] for s in fn_sinks],
                            "line": a["line"],
                            "script_url": script_url,
                        })

            # Find reads of window.X flowing into sinks
            sinks = analyzer.find_sinks_in_range(tree, source_bytes, 0, content.count('\n'))
            for sink in sinks:
                # Check if any global name appears near the sink
                sink_line = sink["line"]
                lines = content.split('\n')
                start = max(0, sink_line - 3)
                end = min(len(lines), sink_line + 2)
                context = '\n'.join(lines[start:end])
                for w in self.global_writes:
                    short_name = w["name"].split(".", 1)[1] if "." in w["name"] else w["name"]
                    if short_name in context or w["name"] in context:
                        self.global_reads_into_sinks.append({
                            "global_name": w["name"],
                            "sink_category": sink["category"],
                            "sink_line": sink_line,
                            "script_url": script_url,
                            "script_hash": script_hash,
                            "severity": sink.get("severity", 5),
                        })

    def emit_cross_file_findings(self, page_url):
        """Emit findings where tainted globals flow into sinks across scripts.

        Returns the number of findings emitted.
        """
        count = 0
        tainted_globals = {w["name"] for w in self.global_writes if w["is_tainted"]}
        if not tainted_globals:
            return count

        for read in self.global_reads_into_sinks:
            if read["global_name"] not in tainted_globals:
                continue
            # Find the write that taints this global
            writer = next(
                (w for w in self.global_writes
                 if w["name"] == read["global_name"] and w["is_tainted"]),
                None
            )
            if not writer:
                continue
            # Don't emit if write and read are in the same script
            if writer["script_url"] == read["script_url"]:
                continue

            finding_key = f"crossfile:{read['global_name']}:{read['sink_category']}:{read['script_hash']}:{read['sink_line']}"
            if finding_key in SEEN_FINDINGS:
                continue
            SEEN_FINDINGS.add(finding_key)

            log_message("FINDING", {
                "source_url": page_url,
                "finding_type": "cross_file_taint",
                "global_name": read["global_name"],
                "taint_source": writer["taint_source"],
                "writer_script": writer["script_url"],
                "writer_line": writer["line"],
                "reader_script": read["script_url"],
                "sink_category": read["sink_category"],
                "sink_line": read["sink_line"],
                "severity": read["severity"],
                "confidence": "medium",
                "analysis_method": "ast",
            })
            count += 1

        # Emit dangerous function findings
        for df in self.dangerous_functions:
            finding_key = f"crossfile:dangerous_fn:{df['name']}:{df['script_url']}:{df['line']}"
            if finding_key in SEEN_FINDINGS:
                continue
            SEEN_FINDINGS.add(finding_key)
            log_message("FINDING", {
                "source_url": page_url,
                "finding_type": "dangerous_global_function",
                "global_name": df["name"],
                "sink_categories": df["sink_categories"],
                "defined_in": df["script_url"],
                "line": df["line"],
                "severity": 6,
                "confidence": "medium",
                "analysis_method": "ast",
            })
            count += 1

        return count


# --- Inline Finding Extractors (called from check_script_safety) ---

_STATIC_EXTENSIONS = frozenset({
    '.js', '.css', '.png', '.jpg', '.jpeg', '.gif', '.svg',
    '.ico', '.woff', '.woff2', '.ttf', '.eot', '.map',
})


def _extract_endpoints(script_content, script_hash, url, script_url):
    """Extract interesting API endpoints from JS. Emits finding if novel endpoints found."""
    novel = []
    for pattern, category in ENDPOINT_PATTERNS:
        for match in re.finditer(pattern, script_content, re.IGNORECASE):
            endpoint = match.group(1).strip()
            if len(endpoint) < 5 or endpoint.startswith(('data:', 'blob:')):
                continue
            # Skip static file extensions
            path_part = endpoint.split('?')[0].split('#')[0]
            if '.' in path_part.rsplit('/', 1)[-1]:
                ext = '.' + path_part.rsplit('.', 1)[-1].lower()
                if ext in _STATIC_EXTENSIONS:
                    continue
            dedup_key = f"ep:{endpoint}"
            if dedup_key in SEEN_FINDINGS:
                continue
            SEEN_FINDINGS.add(dedup_key)
            novel.append({
                'url': endpoint,
                'type': category,
                'line': script_content[:match.start()].count('\n') + 1,
            })

    if not novel:
        return

    # Score based on most interesting endpoint
    max_sev = 4
    for ep in novel:
        ep_lower = ep['url'].lower()
        if any(kw in ep_lower for kw in ('admin', 'internal', 'debug', 'private')):
            max_sev = max(max_sev, 6)
        elif any(kw in ep_lower for kw in ('graphql', 'webhook', 'oauth', 'auth')):
            max_sev = max(max_sev, 5)
        elif ep['type'] == 'websocket':
            max_sev = max(max_sev, 5)

    log_message("FINDING", {
        'finding_type': 'endpoint',
        'source_url': url,
        'script_url': script_url or 'inline',
        'script_hash': script_hash,
        'endpoints': novel,
        'severity': max_sev,
        'confidence': 'medium',
        'analysis_method': 'regex',
    })


def _extract_interesting_strings(script_content, script_hash, url, script_url):
    """Extract sensitive/recon strings from JS. Emits finding if novel strings found."""
    novel = []
    for pattern, str_type, severity in INTERESTING_STRING_PATTERNS:
        for match in re.finditer(pattern, script_content, re.IGNORECASE):
            value = match.group(1).strip()
            if len(value) < 3:
                continue
            dedup_key = f"str:{str_type}:{value[:100]}"
            if dedup_key in SEEN_FINDINGS:
                continue
            SEEN_FINDINGS.add(dedup_key)
            novel.append({
                'type': str_type,
                'value': value[:200],
                'line': script_content[:match.start()].count('\n') + 1,
                'severity': severity,
            })

    if not novel:
        return

    max_sev = max(s['severity'] for s in novel)
    log_message("FINDING", {
        'finding_type': 'interesting_string',
        'source_url': url,
        'script_url': script_url or 'inline',
        'script_hash': script_hash,
        'strings': novel,
        'severity': max_sev,
        'confidence': 'medium',
        'analysis_method': 'regex',
    })


def _check_postmessage_handlers(analyzer, tree, source_bytes, script_hash, url, script_url):
    """Check for postMessage handlers with missing origin validation. Emits findings."""
    handlers = analyzer.find_postmessage_handlers(tree, source_bytes)
    for handler in handlers:
        finding_key = f"postmsg:{script_hash}:{handler['line']}"
        if finding_key in SEEN_FINDINGS:
            continue
        SEEN_FINDINGS.add(finding_key)

        if not handler['has_origin_check']:
            severity = 7
            issue = 'no_origin_check'
            if handler['sinks']:
                severity = 9
                issue = 'no_origin_check_with_sink'
        elif handler['sinks']:
            severity = 6
            issue = 'data_to_sink'
        else:
            continue  # Origin check present, no sinks — not interesting

        finding = {
            'finding_type': 'postmessage_issue',
            'source_url': url,
            'script_url': script_url or 'inline',
            'script_hash': script_hash,
            'issue': issue,
            'handler_line': handler['line'],
            'severity': severity,
            'confidence': 'medium',
            'analysis_method': 'ast',
        }
        if handler['sinks']:
            finding['sink_categories'] = list({s['category'] for s in handler['sinks']})
        log_message("FINDING", finding)


def _check_library_cves(script_content, script_hash, url, script_url):
    """Check for known library CVEs. Emits findings."""
    vulns = check_known_cves(script_content)
    for vuln in vulns:
        finding_key = f"cve:{vuln['library']}:{vuln['version']}:{vuln['cves'][0]}"
        if finding_key in SEEN_FINDINGS:
            continue
        SEEN_FINDINGS.add(finding_key)
        log_message("FINDING", {
            'finding_type': 'known_cve',
            'source_url': url,
            'script_url': script_url or 'inline',
            'script_hash': script_hash,
            'library': vuln['library'],
            'version': vuln['version'],
            'cves': vuln['cves'],
            'description': vuln['description'],
            'fix_below': vuln['fix_below'],
            'severity': vuln['severity'],
            'confidence': 'high',
            'analysis_method': 'version_detection',
        })


# --- Main Script Analysis Pipeline ---

def check_script_safety(script_content, script_hash, url, script_url=None,
                        struct_hash=None, anomaly_detector=None, semgrep_batch=None):
    """Analyze script: anomaly detection, Semgrep, endpoints, strings, postMessage, CVEs."""
    minified = looks_minified(script_content)
    line_count = script_content.count('\n') + 1
    SCRIPT_METADATA[script_hash] = {
        "minified": minified,
        "line_count": line_count,
    }

    # Parse AST once — shared across anomaly, postMessage, and cross-file analysis
    analyzer = get_ast_analyzer()
    tree = analyzer.parse(script_content)
    source_bytes = script_content.encode('utf-8') if tree else None

    # --- Anomaly detection ---
    if anomaly_detector is not None and struct_hash is not None:
        has_sources = False
        has_sinks = False
        sink_cats = ()
        if tree:
            sources = analyzer.find_sources_in_range(tree, source_bytes, 0, line_count)
            sinks = analyzer.find_sinks_in_range(tree, source_bytes, 0, line_count)
            has_sources = len(sources) > 0
            has_sinks = len(sinks) > 0
            sink_cats = tuple({s['category'] for s in sinks})

        parsed_script = urlparse(script_url) if script_url else None
        parsed_page = urlparse(url) if url else None
        record = ScriptRecord(
            script_hash=script_hash,
            structural_hash=struct_hash,
            script_url=script_url or 'inline',
            page_url=url or '',
            subdomain=parsed_page.hostname if parsed_page else 'unknown',
            script_origin=parsed_script.hostname if parsed_script else '',
            is_minified=minified,
            is_known_library=_is_known_library(script_content),
            line_count=line_count,
            has_sources=has_sources,
            has_sinks=has_sinks,
            sink_categories=sink_cats,
        )
        anomaly_detector.ingest(record)

    # --- Semgrep ---
    if semgrep_batch is not None:
        semgrep_batch.add_script(script_content, script_hash, url, script_url)

    # --- Inline findings (always run) ---
    _extract_endpoints(script_content, script_hash, url, script_url)
    _extract_interesting_strings(script_content, script_hash, url, script_url)
    if tree:
        _check_postmessage_handlers(analyzer, tree, source_bytes, script_hash, url, script_url)
    _check_library_cves(script_content, script_hash, url, script_url)


def structural_hash(js_code):
    """Compute a structural hash that normalizes whitespace/comments."""
    # Strip single-line comments, block comments, and normalize whitespace
    stripped = re.sub(r'//[^\n]*', '', js_code)
    stripped = re.sub(r'/\*.*?\*/', '', stripped, flags=re.DOTALL)
    stripped = re.sub(r'\s+', ' ', stripped).strip()
    return get_sha256(stripped)


async def process_javascript(js_code, url, client, script_url=None, cross_file_state=None):
    """Processes, analyzes, and saves a piece of JavaScript code."""
    if not js_code:
        return

    js_code = format_javascript(js_code)
    raw_hash = get_sha256(js_code)
    structural = structural_hash(js_code)

    # Check both raw hash (--ignore-hashes compat) and structural hash for dedup
    if raw_hash in IGNORED_HASHES:
        log_message("INFO", f"Skipping ignored script hash: {raw_hash}")
        return
    if raw_hash in SEEN_SCRIPTS or structural in SEEN_SCRIPTS:
        return
    SEEN_SCRIPTS.add(raw_hash)
    SEEN_SCRIPTS.add(structural)

    check_script_safety(js_code, raw_hash, url, script_url, structural)

    # Source map: try to fetch and re-analyze original source
    if ARGS and not getattr(ARGS, 'no_sourcemaps', False) and script_url and script_url != "inline":
        try:
            sourcemap = await try_fetch_sourcemap(script_url, js_code, client)
            if sourcemap:
                original = get_original_source(sourcemap)
                if original and len(original) > 50:
                    original_hash = get_sha256(original)
                    if original_hash not in SEEN_SCRIPTS:
                        SEEN_SCRIPTS.add(original_hash)
                        log_message("INFO", f"Re-analyzing original source from source map for {script_url}")
                        original_struct = structural_hash(original)
                        check_script_safety(original, original_hash, url,
                                            script_url + " (source map)", original_struct)
        except Exception as e:
            log_message("ERROR", f"Source map processing failed for {script_url}: {e}")

    # Cross-file tracking
    if cross_file_state is not None:
        cross_file_state.add_script(js_code, script_url or "inline", raw_hash)

    if ARGS and ARGS.save:
        try:
            with open(f"{raw_hash}.js", 'w', encoding='utf-8') as f:
                f.write(f"// Source: {url}\n// Script URL: {script_url or 'inline'}\n\n{js_code}")
        except IOError as e:
            log_message("ERROR", f"Failed to save script {raw_hash}: {e}")

    await find_and_process_js_paths(js_code, url, client)


async def find_and_process_js_paths(content, base_url, client):
    """Finds potential JS file paths in content and schedules them for processing."""
    tasks = []
    for match in re.finditer(JS_PATH_FINDER, content):
        path = match.group(1)
        if path.startswith('//'):
            path = f"https:{path}"

        script_url = urljoin(base_url, path)
        hashed_url = get_sha256(script_url)

        if hashed_url in CHECKED_JS_URLS:
            continue
        CHECKED_JS_URLS.add(hashed_url)

        log_message("INFO", f"Discovered potential JS file via regex: {script_url}")
        try:
            script_response = await client.get(script_url, timeout=10)
            tasks.append(process_javascript(script_response.text, base_url, client, script_url=script_url))
        except httpx.RequestError as e:
            log_message("ERROR", f"Failed to fetch discovered script {script_url}: {e}")
    await asyncio.gather(*tasks)
