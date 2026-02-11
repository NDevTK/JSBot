"""AST parsing, cross-file taint analysis, script safety checks."""
import re
import asyncio
import httpx
from hashlib import sha256
from urllib.parse import urljoin, urlparse

from patterns import SOURCES, SINKS, TAINT_SINKS, JS_PATH_FINDER, ENDPOINT_PATTERNS, INTERESTING_STRING_PATTERNS
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

            # new expressions: new Function(payload) → Eval Injection
            if node.type == 'new_expression':
                constructor = None
                for child in node.children:
                    if child.type == 'identifier':
                        constructor = self.get_node_text(child, source_bytes)
                        break
                if constructor:
                    for sink_name, sink_info in SINKS.items():
                        if re.search(sink_info["pattern"], constructor + '(', re.IGNORECASE):
                            if sink_name == "Eval Injection" and self._has_only_literal_args(node):
                                continue
                            results.append({
                                "category": sink_name,
                                "match": "new " + constructor + '(',
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

    _URL_SINK_PROPERTIES = frozenset({'src', 'href', 'action', 'formAction', 'data'})
    _ATTR_URL_SINKS = frozenset({'href', 'src', 'action', 'formaction', 'data'})

    def find_taint_sinks_in_range(self, tree, source_bytes, start_line, end_line):
        """Find taint-only sinks via AST. Too broad for anomaly, valid for taint.

        Detects: setTimeout/setInterval, window.open, .src/.href/.action/.data
        assignment, setAttribute/setAttributeNS with URL or event handler attrs,
        createContextualFragment, fetch, XHR .open.
        """
        results = []
        stack = [tree.root_node]
        while stack:
            node = stack.pop()
            if node.start_point[0] > end_line or node.end_point[0] < start_line:
                continue

            # Property assignment: el.src = x, el.href = x, el.data = x
            if node.type == 'assignment_expression':
                left = node.child_by_field_name('left')
                if left and left.type == 'member_expression':
                    prop = left.child_by_field_name('property')
                    if prop:
                        prop_name = self.get_node_text(prop, source_bytes)
                        if prop_name in self._URL_SINK_PROPERTIES:
                            # Skip location.href — already Open Redirect in core SINKS
                            obj = left.child_by_field_name('object')
                            if obj and prop_name == 'href':
                                obj_text = self.get_node_text(obj, source_bytes)
                                if obj_text == 'location' or obj_text.endswith('.location'):
                                    stack.extend(node.children)
                                    continue
                            right = node.child_by_field_name('right')
                            if right and not self._is_literal(right):
                                results.append({
                                    'category': 'Script/Link Source',
                                    'match': f'.{prop_name} =',
                                    'line': node.start_point[0] + 1,
                                    'severity': 6,
                                })

            # Call expressions
            if node.type == 'call_expression':
                fn = node.child_by_field_name('function')
                args_node = node.child_by_field_name('arguments')
                if fn:
                    if fn.type == 'identifier':
                        fn_name = self.get_node_text(fn, source_bytes)
                        if fn_name in ('setTimeout', 'setInterval'):
                            results.append({
                                'category': 'setTimeout/setInterval',
                                'match': fn_name + '(',
                                'line': node.start_point[0] + 1,
                                'severity': 7,
                            })
                        elif fn_name == 'fetch':
                            results.append({
                                'category': 'Fetch/XHR',
                                'match': 'fetch(',
                                'line': node.start_point[0] + 1,
                                'severity': 5,
                            })

                    elif fn.type == 'member_expression':
                        mem_prop = fn.child_by_field_name('property')
                        mem_obj = fn.child_by_field_name('object')
                        if mem_prop and mem_obj:
                            pname = self.get_node_text(mem_prop, source_bytes)

                            if pname in ('setTimeout', 'setInterval'):
                                results.append({
                                    'category': 'setTimeout/setInterval',
                                    'match': pname + '(',
                                    'line': node.start_point[0] + 1,
                                    'severity': 7,
                                })
                            elif pname == 'open':
                                obj_text = self.get_node_text(mem_obj, source_bytes)
                                if obj_text in ('window', 'self', 'globalThis'):
                                    results.append({
                                        'category': 'window.open',
                                        'match': 'window.open(',
                                        'line': node.start_point[0] + 1,
                                        'severity': 6,
                                    })
                                else:
                                    results.append({
                                        'category': 'Fetch/XHR',
                                        'match': '.open(',
                                        'line': node.start_point[0] + 1,
                                        'severity': 5,
                                    })
                            elif pname == 'fetch':
                                results.append({
                                    'category': 'Fetch/XHR',
                                    'match': '.fetch(',
                                    'line': node.start_point[0] + 1,
                                    'severity': 5,
                                })
                            elif pname == 'createContextualFragment':
                                results.append({
                                    'category': 'createContextualFragment',
                                    'match': '.createContextualFragment(',
                                    'line': node.start_point[0] + 1,
                                    'severity': 9,
                                })
                            elif pname in ('setAttribute', 'setAttributeNS'):
                                if args_node:
                                    arg_nodes = [c for c in args_node.children
                                                 if c.type not in ('(', ')', ',')]
                                    # setAttribute: 1st arg is attr name
                                    # setAttributeNS: 2nd arg is attr name
                                    attr_idx = 0 if pname == 'setAttribute' else 1
                                    if len(arg_nodes) > attr_idx:
                                        attr_node = arg_nodes[attr_idx]
                                        if attr_node.type == 'string':
                                            attr_val = self.get_node_text(
                                                attr_node, source_bytes
                                            ).strip('\'"` ')
                                            # Strip namespace prefix (xlink:href → href)
                                            bare = attr_val.split(':')[-1] if ':' in attr_val else attr_val
                                            if bare.lower() in self._ATTR_URL_SINKS:
                                                results.append({
                                                    'category': 'Script/Link Source',
                                                    'match': f'.{pname}("{attr_val}", ...)',
                                                    'line': node.start_point[0] + 1,
                                                    'severity': 6,
                                                })
                                            elif bare.lower().startswith('on'):
                                                results.append({
                                                    'category': 'setAttribute Event Handler',
                                                    'match': f'.{pname}("{attr_val}", ...)',
                                                    'line': node.start_point[0] + 1,
                                                    'severity': 8,
                                                })

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

    def _check_tainted(self, text, tainted_vars):
        """Check if text contains a source or references a tainted variable.

        Returns the source name if tainted, None otherwise.
        """
        for source_name, source_pattern in SOURCES.items():
            if re.search(source_pattern, text):
                return source_name
        for var_name, source_name in tainted_vars.items():
            if re.search(r'\b' + re.escape(var_name) + r'\b', text):
                return source_name
        return None

    _SCOPE_TYPES = frozenset({
        'function_declaration', 'function_expression', 'arrow_function',
        'generator_function_declaration', 'generator_function',
        'method_definition',
    })

    def _analyze_return_taint(self, fn_node, source_bytes):
        """Check if a function returns tainted data. Returns source name or None.

        Builds an internal taint map for the function body, then checks if any
        return statement yields a tainted expression.
        """
        tainted = {}
        stack = [fn_node]
        while stack:
            n = stack.pop()
            if n != fn_node and n.type in self._SCOPE_TYPES:
                continue  # skip nested functions

            if n.type == 'variable_declarator':
                name_node = n.child_by_field_name('name')
                value_node = n.child_by_field_name('value')
                if name_node and value_node and name_node.type == 'identifier':
                    var_name = self.get_node_text(name_node, source_bytes)
                    value_text = self.get_node_text(value_node, source_bytes)
                    source = self._check_tainted(value_text, tainted)
                    if source:
                        tainted[var_name] = source
                    elif var_name in tainted:
                        del tainted[var_name]

            elif n.type == 'assignment_expression':
                left = n.child_by_field_name('left')
                right = n.child_by_field_name('right')
                if left and right and left.type == 'identifier':
                    var_name = self.get_node_text(left, source_bytes)
                    value_text = self.get_node_text(right, source_bytes)
                    source = self._check_tainted(value_text, tainted)
                    if source:
                        tainted[var_name] = source

            elif n.type == 'return_statement':
                for child in n.children:
                    if child.type not in ('return', ';'):
                        return_text = self.get_node_text(child, source_bytes)
                        source = self._check_tainted(return_text, tainted)
                        if source:
                            return source

            stack.extend(reversed(n.children))
        return None

    def _check_call_return_taint(self, call_node, scope_root, source_bytes):
        """Check if a function call returns tainted data by analyzing the callee."""
        fn = call_node.child_by_field_name('function')
        if not fn or fn.type != 'identifier':
            return None
        fn_name = self.get_node_text(fn, source_bytes)

        # Walk up to the tree root
        root = scope_root
        while root.parent:
            root = root.parent
        fn_node = self._find_function_by_name(root, fn_name, source_bytes)
        if not fn_node:
            return None
        return self._analyze_return_taint(fn_node, source_bytes)

    def _collect_taint_per_scope(self, node, source_bytes, parent_tainted):
        """Walk a scope, track taint with proper function boundaries.

        Returns list of (tainted_vars_dict, start_line, end_line) for this scope
        and all nested scopes. Each scope inherits from parent but local
        declarations shadow inherited vars.

        Two-phase: first build this scope's complete taint map (skipping child
        functions), then recurse into child functions with the finished map.
        """
        scopes = []
        tainted = dict(parent_tainted)
        start_line = node.start_point[0]
        end_line = node.end_point[0]
        child_functions = []  # deferred — recurse after this scope is complete

        # Phase 1: walk this scope, collect taint, defer child functions
        stack = [node]
        while stack:
            n = stack.pop()

            if n != node and n.type in self._SCOPE_TYPES:
                child_functions.append(n)
                continue

            if n.type == 'variable_declarator':
                name_node = n.child_by_field_name('name')
                value_node = n.child_by_field_name('value')
                if name_node and value_node and name_node.type == 'identifier':
                    var_name = self.get_node_text(name_node, source_bytes)
                    value_text = self.get_node_text(value_node, source_bytes)
                    source = self._check_tainted(value_text, tainted)
                    if not source and value_node.type == 'call_expression':
                        source = self._check_call_return_taint(
                            value_node, node, source_bytes,
                        )
                    if source:
                        tainted[var_name] = source
                    elif var_name in tainted:
                        del tainted[var_name]

            elif n.type == 'assignment_expression':
                left = n.child_by_field_name('left')
                right = n.child_by_field_name('right')
                if left and right and left.type == 'identifier':
                    var_name = self.get_node_text(left, source_bytes)
                    value_text = self.get_node_text(right, source_bytes)
                    source = self._check_tainted(value_text, tainted)
                    if not source and right.type == 'call_expression':
                        source = self._check_call_return_taint(
                            right, node, source_bytes,
                        )
                    if source:
                        tainted[var_name] = source

            elif n.type == 'formal_parameters':
                for child in n.children:
                    if child.type == 'identifier':
                        param_name = self.get_node_text(child, source_bytes)
                        if param_name in tainted:
                            del tainted[param_name]
                continue

            stack.extend(reversed(n.children))

        scopes.append((tainted, start_line, end_line))

        # Phase 2: recurse into child functions with completed taint map
        for child_fn in child_functions:
            scopes.extend(self._collect_taint_per_scope(child_fn, source_bytes, tainted))

        return scopes

    def find_taint_flows(self, tree, source_bytes):
        """Find intra-file dataflows from user-controlled sources to dangerous sinks.

        Two detection modes:
        1. Via variable: var x = location.hash; el.innerHTML = x;
        2. Direct: el.innerHTML = location.hash;  (source directly on sink line)

        Taint tracking is scoped to function boundaries — variable `r` tainted
        in function A does not contaminate a different `r` in function B.

        Also checks taint-only sinks (setTimeout, window.open, .src/.href assignment,
        setAttribute) which are too broad for anomaly detection but valid for taint.
        """
        # Build per-scope taint maps
        scopes = self._collect_taint_per_scope(tree.root_node, source_bytes, {})

        # Collect all sinks: core SINKS + taint-only sinks (both AST-based)
        end_line = tree.root_node.end_point[0]
        sinks = self.find_sinks_in_range(tree, source_bytes, 0, end_line)

        # Add taint-only sinks via AST (too broad for anomaly, valid for taint)
        taint_only = self.find_taint_sinks_in_range(tree, source_bytes, 0, end_line)
        seen_sink_lines = {(s['category'], s['line']) for s in sinks}
        for ts in taint_only:
            if (ts['category'], ts['line']) not in seen_sink_lines:
                seen_sink_lines.add((ts['category'], ts['line']))
                sinks.append(ts)

        if not sinks:
            return []

        text = source_bytes.decode('utf-8', errors='replace')
        lines = text.split('\n')

        # Check each sink line for tainted variables or direct source patterns
        flows = []
        for sink in sinks:
            sink_line_num = sink['line']
            sink_line_idx = sink_line_num - 1  # 0-indexed
            if not (0 <= sink_line_idx < len(lines)):
                continue
            sink_text = lines[sink_line_idx]

            # Find the innermost scope containing this sink line.
            # Children are appended after parents, so last match = deepest.
            tainted_vars = {}
            best_span = float('inf')
            for scope_tainted, scope_start, scope_end in scopes:
                if scope_start <= sink_line_idx <= scope_end:
                    span = scope_end - scope_start
                    if span <= best_span:
                        best_span = span
                        tainted_vars = scope_tainted

            # Mode 1: tainted variable on sink line
            found = False
            for var_name, source_name in tainted_vars.items():
                if re.search(r'\b' + re.escape(var_name) + r'\b', sink_text):
                    flows.append({
                        'source': source_name,
                        'sink': sink['category'],
                        'tainted_var': var_name,
                        'sink_line': sink_line_num,
                        'severity': sink['severity'],
                    })
                    found = True
                    break

            # Mode 2: source pattern directly in sink value (no intermediate variable)
            # Uses AST to extract only the data portion (RHS of assignment, call args)
            # so `location.href = location.href` (self-assignment) doesn't false-positive.
            if not found:
                value_text = self._extract_sink_value(
                    tree, source_bytes, sink_line_idx, sink['category'],
                )
                if value_text:
                    for source_name, source_pattern in SOURCES.items():
                        if re.search(source_pattern, value_text):
                            flows.append({
                                'source': source_name,
                                'sink': sink['category'],
                                'tainted_var': 'direct',
                                'sink_line': sink_line_num,
                                'severity': sink['severity'],
                            })
                            break

        return flows

    def _extract_sink_value(self, tree, source_bytes, line_idx, sink_category):
        """Extract the data-flow value from the specific sink expression at a line.

        Finds the AST node that matches the sink category, then returns just
        the value flowing into it (RHS for assignments, arguments for calls).

        For assignments, self-assignment (LHS == RHS) returns None — no new
        data flows in a no-op like `location.href = location.href`.
        """
        # Determine if this sink is assignment-style or call-style
        sink_pattern = None
        for cat, info in TAINT_SINKS.items():
            if cat == sink_category:
                sink_pattern = info['pattern']
                break

        stack = [tree.root_node]
        while stack:
            node = stack.pop()
            if node.start_point[0] == line_idx:
                if node.type == 'assignment_expression':
                    left = node.child_by_field_name('left')
                    right = node.child_by_field_name('right')
                    if left and right:
                        lhs = self.get_node_text(left, source_bytes)
                        rhs = self.get_node_text(right, source_bytes)
                        # Check this assignment matches the sink
                        node_text = self.get_node_text(node, source_bytes)
                        is_match = False
                        if sink_pattern and re.search(sink_pattern, node_text):
                            is_match = True
                        elif not sink_pattern:
                            for sname, sinfo in SINKS.items():
                                if sname == sink_category and re.search(sinfo['pattern'], node_text):
                                    is_match = True
                                    break
                        if is_match and lhs != rhs:
                            return rhs

                elif node.type in ('call_expression', 'new_expression'):
                    fn = node.child_by_field_name('function')
                    if not fn:
                        # new_expression: constructor is the first identifier child
                        for child in node.children:
                            if child.type == 'identifier':
                                fn = child
                                break
                    args = node.child_by_field_name('arguments')
                    if fn and args:
                        fn_text = self.get_node_text(fn, source_bytes)
                        # Check this call matches the sink
                        is_match = False
                        if sink_pattern and re.search(sink_pattern, fn_text + '('):
                            is_match = True
                        elif not sink_pattern:
                            for sname, sinfo in SINKS.items():
                                if sname == sink_category and re.search(sinfo['pattern'], fn_text + '('):
                                    is_match = True
                                    break
                        if is_match:
                            return self.get_node_text(args, source_bytes)

            if node.start_point[0] <= line_idx <= node.end_point[0]:
                stack.extend(node.children)
        return None

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
        """Analyze a message handler for origin checks and sink usage.

        Origin check classification (AST-based, no regex):
          'valid'                 — .origin compared against a real string/variable
          'unsafe_null'           — .origin compared against the string 'null'
          'unsafe_source_origin'  — uses .source.origin (spoofable, not the real origin)
          'none'                  — no .origin reference found at all
        """
        origin_check = self._classify_origin_check(handler_node, source_bytes)
        sinks = []
        if handler_node.type in ('arrow_function', 'function_expression', 'function'):
            sinks = self.find_sinks_in_range(
                tree, source_bytes,
                handler_node.start_point[0], handler_node.end_point[0]
            )
        return {
            'line': context_node.start_point[0] + 1,
            'origin_check': origin_check,
            'sinks': sinks,
        }

    def _classify_origin_check(self, handler_node, source_bytes):
        """Walk handler AST to classify origin validation.

        Looks for binary expressions (===, ==, !==, !=) or method calls
        (.includes, .match, .startsWith, .indexOf) involving '.origin'.
        Then checks if the comparison target is 'null' string or uses
        .source.origin (both unsafe).
        """
        # Resolve the handler body — follow identifier references if needed
        body = handler_node
        if handler_node.type == 'identifier':
            # Handler is a named function reference — scan entire tree
            body = handler_node  # fall through, we'll find nothing but that's OK
            # Try to find the function declaration/expression
            name = self.get_node_text(handler_node, source_bytes)
            root = handler_node
            while root.parent:
                root = root.parent
            resolved = self._find_function_by_name(root, name, source_bytes)
            if resolved:
                body = resolved

        found_origin_ref = False
        result = 'none'

        stack = [body]
        while stack:
            node = stack.pop()

            # Check for .source.origin pattern (unsafe)
            if node.type == 'member_expression':
                chain = self._get_member_chain(node, source_bytes)
                if chain and chain.endswith('.source.origin'):
                    return 'unsafe_source_origin'

            # Check binary comparisons: x.origin === 'something'
            if node.type == 'binary_expression':
                op = node.child_by_field_name('operator')
                if op and self.get_node_text(op, source_bytes) in ('===', '==', '!==', '!='):
                    left = node.child_by_field_name('left')
                    right = node.child_by_field_name('right')
                    origin_side, other_side = None, None

                    if left and self._is_origin_access(left, source_bytes):
                        origin_side, other_side = left, right
                    elif right and self._is_origin_access(right, source_bytes):
                        origin_side, other_side = right, left

                    if origin_side and other_side:
                        found_origin_ref = True
                        # Check if comparing to 'null' string
                        other_text = self.get_node_text(other_side, source_bytes).strip()
                        if other_text in ("'null'", '"null"', '`null`'):
                            result = 'unsafe_null'
                        elif result != 'unsafe_null':
                            # Real comparison against a string/variable
                            result = 'valid'

            # Check method calls: allowedOrigins.includes(e.origin)
            # or e.origin.startsWith(...)
            if node.type == 'call_expression':
                fn = node.child_by_field_name('function')
                if fn and fn.type == 'member_expression':
                    obj = fn.child_by_field_name('object')
                    prop = fn.child_by_field_name('property')
                    if obj and prop:
                        prop_name = self.get_node_text(prop, source_bytes)
                        if prop_name in ('includes', 'indexOf', 'match',
                                         'startsWith', 'endsWith'):
                            # Check if .origin is the object or an argument
                            if self._is_origin_access(obj, source_bytes):
                                found_origin_ref = True
                                # e.origin.match(...) — check arguments
                                # This is a comparison, treat as valid unless
                                # comparing to 'null'
                                if result != 'unsafe_null':
                                    result = 'valid'
                            else:
                                # Check arguments for .origin
                                args = node.child_by_field_name('arguments')
                                if args:
                                    for arg in args.children:
                                        if self._is_origin_access(arg, source_bytes):
                                            found_origin_ref = True
                                            if result != 'unsafe_null':
                                                result = 'valid'

            # Check if/switch on .origin (even without comparison)
            if node.type in ('if_statement', 'switch_statement'):
                cond = node.child_by_field_name('condition')
                if cond and self._subtree_has_origin(cond, source_bytes):
                    found_origin_ref = True
                    if result == 'none':
                        result = 'valid'

            stack.extend(node.children)

        return result

    def _is_origin_access(self, node, source_bytes):
        """Check if node is a .origin member access (e.g. event.origin)."""
        if node.type != 'member_expression':
            return False
        prop = node.child_by_field_name('property')
        if not prop:
            return False
        prop_name = self.get_node_text(prop, source_bytes)
        if prop_name != 'origin':
            return False
        # Make sure it's NOT .source.origin
        obj = node.child_by_field_name('object')
        if obj and obj.type == 'member_expression':
            obj_prop = obj.child_by_field_name('property')
            if obj_prop and self.get_node_text(obj_prop, source_bytes) == 'source':
                return False  # This is .source.origin — handled separately
        return True

    def _subtree_has_origin(self, node, source_bytes):
        """Check if any node in the subtree is a .origin access."""
        stack = [node]
        while stack:
            n = stack.pop()
            if self._is_origin_access(n, source_bytes):
                return True
            stack.extend(n.children)
        return False

    def _find_function_by_name(self, root, name, source_bytes):
        """Find a function declaration or variable-assigned function by name."""
        stack = [root]
        while stack:
            node = stack.pop()
            # function foo() { ... }
            if node.type == 'function_declaration':
                fn_name = node.child_by_field_name('name')
                if fn_name and self.get_node_text(fn_name, source_bytes) == name:
                    return node
            # const foo = function() { ... }  or  const foo = (...) => { ... }
            if node.type == 'variable_declarator':
                decl_name = node.child_by_field_name('name')
                value = node.child_by_field_name('value')
                if (decl_name and self.get_node_text(decl_name, source_bytes) == name
                        and value and value.type in ('function_expression',
                                                      'arrow_function')):
                    return value
            stack.extend(node.children)
        return None


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
    """Check for postMessage handlers with missing or unsafe origin validation."""
    handlers = analyzer.find_postmessage_handlers(tree, source_bytes)
    for handler in handlers:
        finding_key = f"postmsg:{script_hash}:{handler['line']}"
        if finding_key in SEEN_FINDINGS:
            continue
        SEEN_FINDINGS.add(finding_key)

        origin_check = handler['origin_check']
        has_sinks = bool(handler['sinks'])

        # Classify the issue
        if origin_check == 'none':
            severity = 9 if has_sinks else 7
            issue = 'no_origin_check_with_sink' if has_sinks else 'no_origin_check'
        elif origin_check == 'unsafe_null':
            severity = 9 if has_sinks else 7
            issue = 'unsafe_null_origin_check'
        elif origin_check == 'unsafe_source_origin':
            severity = 9 if has_sinks else 7
            issue = 'unsafe_source_origin_check'
        elif origin_check == 'valid' and has_sinks:
            severity = 6
            issue = 'data_to_sink'
        else:
            continue  # Valid origin check, no sinks — not interesting

        finding = {
            'finding_type': 'postmessage_issue',
            'source_url': url,
            'script_url': script_url or 'inline',
            'script_hash': script_hash,
            'issue': issue,
            'origin_check': origin_check,
            'handler_line': handler['line'],
            'severity': severity,
            'confidence': 'medium',
            'analysis_method': 'ast',
        }
        if has_sinks:
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


def _check_taint_flows(analyzer, tree, source_bytes, script_hash, url, script_url):
    """Check for intra-file taint flows from user input to dangerous sinks. Emits findings."""
    flows = analyzer.find_taint_flows(tree, source_bytes)
    for flow in flows:
        finding_key = f"taint:{script_hash}:{flow['sink']}:{flow['sink_line']}"
        if finding_key in SEEN_FINDINGS:
            continue
        SEEN_FINDINGS.add(finding_key)
        log_message("FINDING", {
            'finding_type': 'taint_flow',
            'source_url': url,
            'script_url': script_url or 'inline',
            'script_hash': script_hash,
            'taint_source': flow['source'],
            'sink_category': flow['sink'],
            'tainted_var': flow['tainted_var'],
            'sink_line': flow['sink_line'],
            'severity': flow['severity'],
            'confidence': 'medium',
            'analysis_method': 'ast',
        })


# --- Main Script Analysis Pipeline ---

def check_script_safety(script_content, script_hash, url, script_url=None,
                        struct_hash=None, anomaly_detector=None):
    """Analyze script: taint flow, anomaly detection, endpoints, strings, postMessage, CVEs."""
    minified = looks_minified(script_content)
    line_count = script_content.count('\n') + 1
    SCRIPT_METADATA[script_hash] = {
        "minified": minified,
        "line_count": line_count,
    }

    # Parse AST once — shared across all analysis passes
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

    # --- Inline findings (always run) ---
    _extract_endpoints(script_content, script_hash, url, script_url)
    _extract_interesting_strings(script_content, script_hash, url, script_url)
    if tree:
        _check_taint_flows(analyzer, tree, source_bytes, script_hash, url, script_url)
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
