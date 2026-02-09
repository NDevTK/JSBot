"""AST parsing, taint flow analysis, cross-file state, regex fallback."""
import re
import asyncio
import httpx
from hashlib import sha256
from urllib.parse import urljoin

from patterns import (
    SOURCES, SINKS, LINK_FINDER_PATTERN, JS_PATH_FINDER, SECRET_PATTERNS,
    PROTO_POLLUTION_PATTERNS, SSRF_PATTERNS, INSECURE_RANDOMNESS_PATTERNS,
    DYNAMIC_SCRIPT_PATTERNS, POSTMESSAGE_HANDLER_PATTERN, POSTMESSAGE_ORIGIN_CHECK,
)
from output import log_message, SEEN_FINDINGS, SEEN_LINKS
from scoring import score_script
from sourcemaps import try_fetch_sourcemap, get_original_source

# --- Dependency Checks ---
try:
    import jsbeautifier
    JSBEAUTIFIER_AVAILABLE = True
except ImportError:
    JSBEAUTIFIER_AVAILABLE = False

try:
    import tree_sitter_javascript as tsjs
    from tree_sitter import Language, Parser
    TREESITTER_AVAILABLE = True
except ImportError:
    TREESITTER_AVAILABLE = False

# --- Global State (managed by scan.py) ---
SEEN_SCRIPTS = set()
CHECKED_JS_URLS = set()
IGNORED_HASHES = set()
ARGS = None  # Set by scan.py


def get_sha256(data):
    """Computes SHA256 hash of the given data."""
    return sha256(data.encode('utf-8')).hexdigest()


def format_javascript(js_code):
    """Beautifies JavaScript code if available and enabled."""
    if JSBEAUTIFIER_AVAILABLE and ARGS and ARGS.format_js:
        return jsbeautifier.beautify(js_code)
    return js_code


# --- Regex-Based Scope Splitting (Fallback) ---

def split_into_scopes(js_code):
    """Splits JavaScript into function-level scope blocks using regex.

    Falls back to treating the entire file as one scope if no function
    boundaries are found.
    """
    lines = js_code.split('\n')
    func_pattern = re.compile(
        r'(?:'
        r'function\s*\w*\s*\('
        r'|'
        r'(?:\w+|\))\s*=>\s*\{'
        r'|'
        r'\w+\s*\([^)]*\)\s*\{'
        r')'
    )

    func_starts = []
    for i, line in enumerate(lines):
        for _ in func_pattern.finditer(line):
            func_starts.append(i)

    if not func_starts:
        return [(0, len(lines) - 1, js_code)]

    scopes = []
    code = js_code
    covered_ranges = []

    for func_line in func_starts:
        line_start = sum(len(lines[j]) + 1 for j in range(func_line))
        brace_pos = code.find('{', line_start)
        if brace_pos == -1:
            continue

        depth = 0
        pos = brace_pos
        in_single_quote = False
        in_double_quote = False
        in_template = False
        in_line_comment = False
        in_block_comment = False
        end_pos = len(code)

        while pos < len(code):
            ch = code[pos]
            next_ch = code[pos + 1] if pos + 1 < len(code) else ''

            if in_line_comment:
                if ch == '\n':
                    in_line_comment = False
            elif in_block_comment:
                if ch == '*' and next_ch == '/':
                    in_block_comment = False
                    pos += 1
            elif in_single_quote:
                if ch == '\\':
                    pos += 1
                elif ch == "'":
                    in_single_quote = False
            elif in_double_quote:
                if ch == '\\':
                    pos += 1
                elif ch == '"':
                    in_double_quote = False
            elif in_template:
                if ch == '\\':
                    pos += 1
                elif ch == '`':
                    in_template = False
            else:
                if ch == '/' and next_ch == '/':
                    in_line_comment = True
                    pos += 1
                elif ch == '/' and next_ch == '*':
                    in_block_comment = True
                    pos += 1
                elif ch == "'":
                    in_single_quote = True
                elif ch == '"':
                    in_double_quote = True
                elif ch == '`':
                    in_template = True
                elif ch == '{':
                    depth += 1
                elif ch == '}':
                    depth -= 1
                    if depth == 0:
                        end_pos = pos
                        break
            pos += 1

        block_text = code[brace_pos:end_pos + 1]
        block_start_line = code[:brace_pos].count('\n')
        block_end_line = code[:end_pos + 1].count('\n')
        scopes.append((block_start_line, block_end_line, block_text))
        covered_ranges.append((block_start_line, block_end_line))

    # Build global scope from lines NOT inside any function
    global_lines = []
    for i, line in enumerate(lines):
        inside = any(start <= i <= end for start, end in covered_ranges)
        if not inside:
            global_lines.append(line)
        else:
            global_lines.append('')
    global_text = '\n'.join(global_lines)
    if global_text.strip():
        scopes.append((0, len(lines) - 1, global_text))

    return scopes


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

    def find_functions(self, tree):
        """Extract function scope boundaries from AST.

        Returns list of (start_line, end_line, node) for each function.
        """
        functions = []
        self._walk_functions(tree.root_node, functions)
        return functions

    def _walk_functions(self, node, results):
        """Recursively find function/method/arrow nodes."""
        fn_types = {
            'function_declaration', 'function_expression', 'arrow_function',
            'method_definition', 'generator_function_declaration',
            'generator_function',
        }
        if node.type in fn_types:
            results.append((node.start_point[0], node.end_point[0], node))
        for child in node.children:
            self._walk_functions(child, results)

    def get_node_text(self, node, source_bytes):
        """Get the text content of a node."""
        return source_bytes[node.start_byte:node.end_byte].decode('utf-8', errors='replace')

    def find_sources_in_range(self, tree, source_bytes, start_line, end_line):
        """Find taint source patterns in a line range using AST walking."""
        sources = []
        self._walk_sources(tree.root_node, source_bytes, start_line, end_line, sources)
        return sources

    def _walk_sources(self, node, source_bytes, start_line, end_line, results):
        """Walk AST to find source patterns within line range."""
        if node.start_point[0] > end_line or node.end_point[0] < start_line:
            return

        if node.type == 'member_expression':
            text = self.get_node_text(node, source_bytes)
            for source_name, source_pattern in SOURCES.items():
                if re.search(source_pattern, text, re.IGNORECASE):
                    results.append({
                        "category": source_name,
                        "match": text,
                        "line": node.start_point[0] + 1,
                    })
                    break

        if node.type == 'new_expression':
            text = self.get_node_text(node, source_bytes)
            if re.search(r'\bURLSearchParams\b', text):
                results.append({
                    "category": "URLSearchParams",
                    "match": text[:60],
                    "line": node.start_point[0] + 1,
                })

        if node.type == 'call_expression':
            text = self.get_node_text(node, source_bytes)
            for source_name in ("getItem", "cookie_read"):
                if re.search(SOURCES[source_name], text, re.IGNORECASE):
                    results.append({
                        "category": source_name,
                        "match": text[:60],
                        "line": node.start_point[0] + 1,
                    })
                    break

        for child in node.children:
            self._walk_sources(child, source_bytes, start_line, end_line, results)

    def find_sinks_in_range(self, tree, source_bytes, start_line, end_line):
        """Find taint sink patterns in a line range using AST walking."""
        sinks = []
        self._walk_sinks(tree.root_node, source_bytes, start_line, end_line, sinks)
        return sinks

    def _walk_sinks(self, node, source_bytes, start_line, end_line, results):
        """Walk AST to find sink patterns within line range."""
        if node.start_point[0] > end_line or node.end_point[0] < start_line:
            return

        # Assignment expressions: innerHTML=, outerHTML=, location.href=, document.cookie=
        if node.type == 'assignment_expression':
            left = node.child_by_field_name('left')
            if left and left.type == 'member_expression':
                left_text = self.get_node_text(left, source_bytes)
                for sink_name, sink_info in SINKS.items():
                    if re.search(sink_info["pattern"], left_text + ' =', re.IGNORECASE):
                        # Check for literal-only RHS (false positive filter)
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
                fn_text = self.get_node_text(fn, source_bytes)
                for sink_name, sink_info in SINKS.items():
                    if re.search(sink_info["pattern"], fn_text + '(', re.IGNORECASE):
                        # False positive: eval/Function with only literal args
                        if sink_name == "Eval Injection" and self._has_only_literal_args(node):
                            continue
                        results.append({
                            "category": sink_name,
                            "match": fn_text + '(',
                            "line": node.start_point[0] + 1,
                            "severity": sink_info["severity"],
                        })
                        break

        for child in node.children:
            self._walk_sinks(child, source_bytes, start_line, end_line, results)

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

    def find_postmessage_handlers(self, tree, source_bytes):
        """Find addEventListener('message', ...) without origin check."""
        findings = []
        self._walk_postmessage(tree.root_node, source_bytes, findings)
        return findings

    def _walk_postmessage(self, node, source_bytes, results):
        if node.type == 'call_expression':
            text = self.get_node_text(node, source_bytes)
            if re.search(POSTMESSAGE_HANDLER_PATTERN, text):
                # Check if the handler body contains an origin check
                if not re.search(POSTMESSAGE_ORIGIN_CHECK, text):
                    results.append({
                        "category": "postMessage no origin check",
                        "match": text[:100],
                        "line": node.start_point[0] + 1,
                        "severity": 7,
                        "confidence": "medium",
                    })
        for child in node.children:
            self._walk_postmessage(child, source_bytes, results)

    def find_global_assignments(self, tree, source_bytes):
        """Find window.X = ... assignments for cross-file tracking."""
        assignments = []
        self._walk_global_assigns(tree.root_node, source_bytes, assignments)
        return assignments

    def _walk_global_assigns(self, node, source_bytes, results):
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
                        # Check if RHS is tainted
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
        for child in node.children:
            self._walk_global_assigns(child, source_bytes, results)


# Singleton AST analyzer (created on first use)
_ast_analyzer = None


def get_ast_analyzer():
    """Get or create the singleton AST analyzer."""
    global _ast_analyzer
    if _ast_analyzer is None and TREESITTER_AVAILABLE:
        try:
            _ast_analyzer = ASTAnalyzer()
        except Exception:
            pass
    return _ast_analyzer


# --- Taint Flow Analysis ---

def get_context_lines(js_code, line_number, context_size):
    """Extracts surrounding lines for a finding."""
    lines = js_code.split('\n')
    start = max(0, line_number - context_size - 1)
    end = min(len(lines), line_number + context_size)
    return [lines[i].rstrip() for i in range(start, end) if lines[i].strip()]


def _emit_grouped_findings(findings, script_content, script_hash, url, script_url, method):
    """Emit taint findings, grouping when a single source reaches multiple sinks."""
    context_size = ARGS.context_lines if ARGS and hasattr(ARGS, 'context_lines') else 3

    # Group by (source_category, source_line)
    grouped = {}
    for f in findings:
        key = (f["source_category"], f["source_line"])
        grouped.setdefault(key, []).append(f)

    for (src_cat, src_line), sinks in grouped.items():
        if len(sinks) == 1:
            f = sinks[0]
            finding_key = f"{script_hash}:{f['sink_category']}:{f['sink_line']}:{src_cat}:{src_line}"
            if finding_key in SEEN_FINDINGS:
                continue
            SEEN_FINDINGS.add(finding_key)
            log_message("FINDING", {
                "source_url": url,
                "script_url": script_url or "inline",
                "script_hash": script_hash,
                "finding_type": "taint_flow",
                "sink_category": f["sink_category"],
                "sink_match": f["sink_match"],
                "sink_line": f["sink_line"],
                "source_category": src_cat,
                "source_match": f["source_match"],
                "source_line": src_line,
                "severity": f["severity"],
                "confidence": "high",
                "analysis_method": method,
                "context": get_context_lines(script_content, f["sink_line"], context_size),
            })
        else:
            finding_key = f"{script_hash}:grouped:{src_cat}:{src_line}"
            if finding_key in SEEN_FINDINGS:
                continue
            SEEN_FINDINGS.add(finding_key)
            max_severity = max(f["severity"] for f in sinks)
            log_message("FINDING", {
                "source_url": url,
                "script_url": script_url or "inline",
                "script_hash": script_hash,
                "finding_type": "taint_flow_grouped",
                "source_category": src_cat,
                "source_match": sinks[0]["source_match"],
                "source_line": src_line,
                "sink_count": len(sinks),
                "sinks": [
                    {"category": f["sink_category"], "match": f["sink_match"], "line": f["sink_line"]}
                    for f in sinks
                ],
                "severity": max_severity,
                "confidence": "high",
                "analysis_method": method,
                "context": get_context_lines(script_content, src_line, context_size),
            })


def analyze_taint_flow_regex(script_content, script_hash, url, script_url=None):
    """Regex-based source-to-sink taint analysis within function scopes."""
    context_size = ARGS.context_lines if ARGS and hasattr(ARGS, 'context_lines') else 3
    include_sink_only = ARGS and hasattr(ARGS, 'include_sink_only') and ARGS.include_sink_only
    scopes = split_into_scopes(script_content)
    collected = []

    for scope_start, scope_end, block_text in scopes:
        found_sources = []
        for source_name, source_pattern in SOURCES.items():
            for m in re.finditer(source_pattern, block_text, re.IGNORECASE):
                source_line = scope_start + block_text[:m.start()].count('\n') + 1
                found_sources.append({
                    "category": source_name,
                    "match": m.group(0),
                    "line": source_line,
                })

        for sink_name, sink_info in SINKS.items():
            for m in re.finditer(sink_info["pattern"], block_text, re.IGNORECASE):
                sink_line = scope_start + block_text[:m.start()].count('\n') + 1

                if found_sources:
                    closest_source = min(found_sources, key=lambda s: abs(s["line"] - sink_line))
                    collected.append({
                        "sink_category": sink_name,
                        "sink_match": m.group(0),
                        "sink_line": sink_line,
                        "source_category": closest_source["category"],
                        "source_match": closest_source["match"],
                        "source_line": closest_source["line"],
                        "severity": sink_info["severity"],
                    })
                elif include_sink_only:
                    finding_key = f"{script_hash}:{sink_name}:{sink_line}:none:none"
                    if finding_key in SEEN_FINDINGS:
                        continue
                    SEEN_FINDINGS.add(finding_key)
                    log_message("FINDING", {
                        "source_url": url,
                        "script_url": script_url or "inline",
                        "script_hash": script_hash,
                        "finding_type": "sink_only",
                        "sink_category": sink_name,
                        "sink_match": m.group(0),
                        "sink_line": sink_line,
                        "source_category": None,
                        "source_match": None,
                        "source_line": None,
                        "severity": sink_info["severity"] // 2,
                        "confidence": "low",
                        "analysis_method": "regex",
                        "context": get_context_lines(script_content, sink_line, context_size),
                    })

    _emit_grouped_findings(collected, script_content, script_hash, url, script_url, "regex")


def analyze_taint_flow_ast(script_content, script_hash, url, analyzer, tree, script_url=None):
    """AST-based source-to-sink taint analysis within function scopes."""
    context_size = ARGS.context_lines if ARGS and hasattr(ARGS, 'context_lines') else 3
    include_sink_only = ARGS and hasattr(ARGS, 'include_sink_only') and ARGS.include_sink_only
    source_bytes = script_content.encode('utf-8')
    collected = []

    # Get real function scopes from AST
    functions = analyzer.find_functions(tree)

    # Build scope ranges: each function + global scope (everything outside functions)
    scope_ranges = [(f[0], f[1]) for f in functions]
    total_lines = script_content.count('\n')

    # Add global scope
    scope_ranges.append((0, total_lines))

    for start_line, end_line in scope_ranges:
        sources = analyzer.find_sources_in_range(tree, source_bytes, start_line, end_line)
        sinks = analyzer.find_sinks_in_range(tree, source_bytes, start_line, end_line)

        for sink in sinks:
            if sources:
                closest_source = min(sources, key=lambda s: abs(s["line"] - sink["line"]))
                collected.append({
                    "sink_category": sink["category"],
                    "sink_match": sink["match"],
                    "sink_line": sink["line"],
                    "source_category": closest_source["category"],
                    "source_match": closest_source["match"],
                    "source_line": closest_source["line"],
                    "severity": sink["severity"],
                })
            elif include_sink_only:
                finding_key = f"{script_hash}:{sink['category']}:{sink['line']}:none:none"
                if finding_key in SEEN_FINDINGS:
                    continue
                SEEN_FINDINGS.add(finding_key)
                log_message("FINDING", {
                    "source_url": url,
                    "script_url": script_url or "inline",
                    "script_hash": script_hash,
                    "finding_type": "sink_only",
                    "sink_category": sink["category"],
                    "sink_match": sink["match"],
                    "sink_line": sink["line"],
                    "source_category": None,
                    "source_match": None,
                    "source_line": None,
                    "severity": sink["severity"] // 2,
                    "confidence": "low",
                    "analysis_method": "ast",
                    "context": get_context_lines(script_content, sink["line"], context_size),
                })

    _emit_grouped_findings(collected, script_content, script_hash, url, script_url, "ast")


def analyze_secrets(script_content, script_hash, url, script_url=None):
    """Detect hardcoded secrets and API keys."""
    context_size = ARGS.context_lines if ARGS and hasattr(ARGS, 'context_lines') else 3
    for secret_name, secret_info in SECRET_PATTERNS.items():
        for m in re.finditer(secret_info["pattern"], script_content):
            line = script_content[:m.start()].count('\n') + 1
            finding_key = f"{script_hash}:secret:{secret_name}:{line}"
            if finding_key in SEEN_FINDINGS:
                continue
            SEEN_FINDINGS.add(finding_key)

            finding = {
                "source_url": url,
                "script_url": script_url or "inline",
                "script_hash": script_hash,
                "finding_type": "secret",
                "category": secret_name,
                "matched_text": m.group(0)[:80],
                "line": line,
                "severity": secret_info["severity"],
                "confidence": secret_info["confidence"],
                "analysis_method": "regex",
                "context": get_context_lines(script_content, line, context_size),
            }
            log_message("FINDING", finding)


def analyze_postmessage(script_content, script_hash, url, analyzer, tree, script_url=None):
    """Detect postMessage handlers without origin checks."""
    context_size = ARGS.context_lines if ARGS and hasattr(ARGS, 'context_lines') else 3
    source_bytes = script_content.encode('utf-8')

    findings = analyzer.find_postmessage_handlers(tree, source_bytes)
    for f in findings:
        finding_key = f"{script_hash}:postmessage:{f['line']}"
        if finding_key in SEEN_FINDINGS:
            continue
        SEEN_FINDINGS.add(finding_key)

        finding = {
            "source_url": url,
            "script_url": script_url or "inline",
            "script_hash": script_hash,
            "finding_type": "postmessage_no_origin",
            "category": f["category"],
            "matched_text": f["match"],
            "line": f["line"],
            "severity": f["severity"],
            "confidence": f["confidence"],
            "analysis_method": "ast",
            "context": get_context_lines(script_content, f["line"], context_size),
        }
        log_message("FINDING", finding)


def analyze_proto_pollution(script_content, script_hash, url, script_url=None):
    """Detect prototype pollution patterns."""
    context_size = ARGS.context_lines if ARGS and hasattr(ARGS, 'context_lines') else 3
    for name, info in PROTO_POLLUTION_PATTERNS.items():
        for m in re.finditer(info["pattern"], script_content):
            line = script_content[:m.start()].count('\n') + 1
            finding_key = f"{script_hash}:proto_pollution:{name}:{line}"
            if finding_key in SEEN_FINDINGS:
                continue
            SEEN_FINDINGS.add(finding_key)
            log_message("FINDING", {
                "source_url": url,
                "script_url": script_url or "inline",
                "script_hash": script_hash,
                "finding_type": "prototype_pollution",
                "category": name,
                "matched_text": m.group(0)[:80],
                "line": line,
                "severity": info["severity"],
                "confidence": info["confidence"],
                "analysis_method": "regex",
                "context": get_context_lines(script_content, line, context_size),
            })


def analyze_ssrf(script_content, script_hash, url, script_url=None):
    """Detect potential SSRF patterns (fetch/xhr with dynamic URLs)."""
    context_size = ARGS.context_lines if ARGS and hasattr(ARGS, 'context_lines') else 3
    for name, info in SSRF_PATTERNS.items():
        for m in re.finditer(info["pattern"], script_content):
            line = script_content[:m.start()].count('\n') + 1
            finding_key = f"{script_hash}:ssrf:{name}:{line}"
            if finding_key in SEEN_FINDINGS:
                continue
            SEEN_FINDINGS.add(finding_key)
            log_message("FINDING", {
                "source_url": url,
                "script_url": script_url or "inline",
                "script_hash": script_hash,
                "finding_type": "ssrf",
                "category": name,
                "matched_text": m.group(0)[:80],
                "line": line,
                "severity": info["severity"],
                "confidence": info["confidence"],
                "analysis_method": "regex",
                "context": get_context_lines(script_content, line, context_size),
            })


def analyze_insecure_randomness(script_content, script_hash, url, script_url=None):
    """Detect Math.random() near security-sensitive contexts."""
    context_size = ARGS.context_lines if ARGS and hasattr(ARGS, 'context_lines') else 3
    # Only flag Math.random if near security keywords
    security_ctx = re.compile(
        r'\b(?:token|nonce|secret|csrf|random.*id|session|key|salt|password|otp)\b',
        re.IGNORECASE
    )
    for name, info in INSECURE_RANDOMNESS_PATTERNS.items():
        for m in re.finditer(info["pattern"], script_content):
            line = script_content[:m.start()].count('\n') + 1
            # Check surrounding context for security keywords
            start = max(0, m.start() - 200)
            end = min(len(script_content), m.end() + 200)
            nearby = script_content[start:end]
            if not security_ctx.search(nearby):
                continue
            finding_key = f"{script_hash}:insecure_random:{line}"
            if finding_key in SEEN_FINDINGS:
                continue
            SEEN_FINDINGS.add(finding_key)
            log_message("FINDING", {
                "source_url": url,
                "script_url": script_url or "inline",
                "script_hash": script_hash,
                "finding_type": "insecure_randomness",
                "category": name,
                "matched_text": m.group(0),
                "line": line,
                "severity": info["severity"],
                "confidence": info["confidence"],
                "analysis_method": "regex",
                "context": get_context_lines(script_content, line, context_size),
            })


def analyze_dynamic_scripts(script_content, script_hash, url, script_url=None):
    """Detect dynamic script element creation."""
    context_size = ARGS.context_lines if ARGS and hasattr(ARGS, 'context_lines') else 3
    for name, info in DYNAMIC_SCRIPT_PATTERNS.items():
        for m in re.finditer(info["pattern"], script_content):
            line = script_content[:m.start()].count('\n') + 1
            finding_key = f"{script_hash}:dynamic_script:{line}"
            if finding_key in SEEN_FINDINGS:
                continue
            SEEN_FINDINGS.add(finding_key)
            log_message("FINDING", {
                "source_url": url,
                "script_url": script_url or "inline",
                "script_hash": script_hash,
                "finding_type": "dynamic_script_creation",
                "category": name,
                "matched_text": m.group(0)[:80],
                "line": line,
                "severity": info["severity"],
                "confidence": info["confidence"],
                "analysis_method": "regex",
                "context": get_context_lines(script_content, line, context_size),
            })


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
        """Find the RHS node of a `window.X = ...` assignment."""
        return self._walk_for_rhs(root_node, global_name, source_bytes)

    def _walk_for_rhs(self, node, target_name, source_bytes):
        if node.type == 'assignment_expression':
            left = node.child_by_field_name('left')
            if left and left.type == 'member_expression':
                left_text = source_bytes[left.start_byte:left.end_byte].decode('utf-8', errors='replace')
                if left_text == target_name:
                    return node.child_by_field_name('right')
        for child in node.children:
            result = self._walk_for_rhs(child, target_name, source_bytes)
            if result:
                return result
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
        """Emit findings where tainted globals flow into sinks across scripts."""
        tainted_globals = {w["name"] for w in self.global_writes if w["is_tainted"]}
        if not tainted_globals:
            return

        context_size = ARGS.context_lines if ARGS and hasattr(ARGS, 'context_lines') else 3
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


# --- Main Script Analysis Pipeline ---

def check_script_safety(script_content, script_hash, url, script_url=None):
    """Routes script to appropriate analysis methods."""
    if ARGS and ARGS.link_mode:
        for match in re.finditer(LINK_FINDER_PATTERN, script_content, re.IGNORECASE):
            finding = {
                "source_url": url,
                "script_url": script_url or "inline",
                "script_hash": script_hash,
                "category": "Link Finder",
                "matched_text": match.group(0),
                "line_number": script_content.count('\n', 0, match.start()) + 1,
            }
            hashed_link = get_sha256(match.group(0))
            if hashed_link not in SEEN_LINKS:
                log_message("FINDING", finding)
                SEEN_LINKS.add(hashed_link)
        return

    # Try AST-based analysis first
    analyzer = get_ast_analyzer()
    tree = None
    if analyzer:
        tree = analyzer.parse(script_content)

    if analyzer and tree:
        analyze_taint_flow_ast(script_content, script_hash, url, analyzer, tree, script_url)
        analyze_postmessage(script_content, script_hash, url, analyzer, tree, script_url)
    else:
        analyze_taint_flow_regex(script_content, script_hash, url, script_url)

    # Pattern-based detections (always run, regex-based)
    analyze_secrets(script_content, script_hash, url, script_url)
    analyze_proto_pollution(script_content, script_hash, url, script_url)
    analyze_ssrf(script_content, script_hash, url, script_url)
    analyze_insecure_randomness(script_content, script_hash, url, script_url)
    analyze_dynamic_scripts(script_content, script_hash, url, script_url)

    # Script interestingness scoring
    interest_score, reasons = score_script(script_content, script_url or "")
    if interest_score >= 30:
        finding_key = f"{script_hash}:interesting"
        if finding_key not in SEEN_FINDINGS:
            SEEN_FINDINGS.add(finding_key)
            log_message("FINDING", {
                "source_url": url,
                "script_url": script_url or "inline",
                "script_hash": script_hash,
                "finding_type": "interesting_script",
                "category": "interestingness",
                "severity": min(interest_score // 10, 10),
                "confidence": "heuristic",
                "interestingness_score": interest_score,
                "reasons": reasons,
            })


def _structural_hash(js_code):
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
    structural = _structural_hash(js_code)

    # Check both raw hash (--ignore-hashes compat) and structural hash for dedup
    if raw_hash in IGNORED_HASHES:
        log_message("INFO", f"Skipping ignored script hash: {raw_hash}")
        return
    if raw_hash in SEEN_SCRIPTS or structural in SEEN_SCRIPTS:
        return
    SEEN_SCRIPTS.add(raw_hash)
    SEEN_SCRIPTS.add(structural)

    check_script_safety(js_code, raw_hash, url, script_url)

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
                        check_script_safety(original, original_hash, url, script_url + " (source map)")
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
