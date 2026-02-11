"""AST parsing, cross-file taint analysis, script safety checks."""
import bisect
import re
import asyncio
import httpx
import threading
from hashlib import sha256
from urllib.parse import urljoin, urlparse

from patterns import (SOURCES, CONTEXT_SOURCES, SINKS, TAINT_SINKS, JS_PATH_FINDER,
                      ENDPOINT_PATTERNS, INTERESTING_STRING_PATTERNS,
                      PROTOTYPE_POLLUTION_SINKS)
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

# Pre-compiled regex: matches any backslash-escaped character (\. \/ etc.)
_RE_ESCAPED = re.compile(r'\\.')


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
                                # Fall back to property name for SINKS matching
                                # Catches el.insertAdjacentHTML(), el.postMessage(), etc.
                                # where the base object is a complex expression
                                fn_text = prop_text
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

    _URL_SINK_PROPERTIES = frozenset({'src', 'href', 'action', 'formAction', 'data', 'srcdoc'})
    _ATTR_URL_SINKS = frozenset({'href', 'src', 'action', 'formaction', 'data', 'srcdoc'})

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

            # Property assignment: el.src = x, el.href = x, el.data = x, document.domain = x
            if node.type == 'assignment_expression':
                left = node.child_by_field_name('left')
                if left and left.type == 'member_expression':
                    prop = left.child_by_field_name('property')
                    if prop:
                        prop_name = self.get_node_text(prop, source_bytes)
                        # document.domain = x (SOP relaxation)
                        if prop_name == 'domain':
                            obj = left.child_by_field_name('object')
                            if obj:
                                obj_text = self.get_node_text(obj, source_bytes)
                                if obj_text == 'document':
                                    right = node.child_by_field_name('right')
                                    if right and not self._is_literal(right):
                                        results.append({
                                            'category': 'document.domain',
                                            'match': 'document.domain =',
                                            'line': node.start_point[0] + 1,
                                            'severity': 7,
                                        })
                        # el.style.cssText = x (CSS injection)
                        elif prop_name == 'cssText':
                            right = node.child_by_field_name('right')
                            if right and not self._is_literal(right):
                                results.append({
                                    'category': 'CSS Injection',
                                    'match': '.cssText =',
                                    'line': node.start_point[0] + 1,
                                    'severity': 5,
                                })
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
                                # srcdoc is HTML injection (high sev), others are URL sinks
                                if prop_name == 'srcdoc':
                                    cat, sev = 'iframe srcdoc Injection', 9
                                else:
                                    cat, sev = 'Script/Link Source', 6
                                results.append({
                                    'category': cat,
                                    'match': f'.{prop_name} =',
                                    'line': node.start_point[0] + 1,
                                    'severity': sev,
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
                        elif fn_name in ('$', 'jQuery'):
                            # $(tainted) — HTML injection if arg contains tags
                            if not self._has_only_literal_args(node):
                                results.append({
                                    'category': 'jQuery Selector Injection',
                                    'match': fn_name + '(',
                                    'line': node.start_point[0] + 1,
                                    'severity': 7,
                                })

                    # import(x) — dynamic import, tree-sitter parses as
                    # call_expression with fn type 'import'
                    elif fn.type == 'import':
                        results.append({
                            'category': 'Dynamic Import',
                            'match': 'import(',
                            'line': node.start_point[0] + 1,
                            'severity': 9,
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
                            elif pname == 'register':
                                # navigator.serviceWorker.register(url)
                                chain = self._get_member_chain(fn, source_bytes)
                                if chain and 'serviceWorker' in chain:
                                    results.append({
                                        'category': 'ServiceWorker Registration',
                                        'match': '.register(',
                                        'line': node.start_point[0] + 1,
                                        'severity': 9,
                                    })
                            elif pname in ('getScript', 'globalEval'):
                                # $.getScript(url), $.globalEval(code)
                                obj_text = self.get_node_text(mem_obj, source_bytes)
                                if obj_text in ('$', 'jQuery'):
                                    results.append({
                                        'category': 'jQuery Script Exec',
                                        'match': f'{obj_text}.{pname}(',
                                        'line': node.start_point[0] + 1,
                                        'severity': 8,
                                    })
                            elif pname == 'createObjectURL':
                                results.append({
                                    'category': 'Blob URL',
                                    'match': '.createObjectURL(',
                                    'line': node.start_point[0] + 1,
                                    'severity': 7,
                                })
                            elif pname == 'execCommand':
                                # document.execCommand("insertHTML", ...)
                                if args_node:
                                    arg_nodes = [c for c in args_node.children
                                                 if c.type not in ('(', ')', ',')]
                                    if arg_nodes and arg_nodes[0].type == 'string':
                                        cmd = self.get_node_text(
                                            arg_nodes[0], source_bytes
                                        ).strip('\'"` ')
                                        if cmd == 'insertHTML':
                                            results.append({
                                                'category': 'execCommand insertHTML',
                                                'match': '.execCommand("insertHTML")',
                                                'line': node.start_point[0] + 1,
                                                'severity': 7,
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
                                            elif bare.lower() == 'srcdoc':
                                                results.append({
                                                    'category': 'iframe srcdoc Injection',
                                                    'match': f'.{pname}("{attr_val}", ...)',
                                                    'line': node.start_point[0] + 1,
                                                    'severity': 9,
                                                })
                                            elif bare.lower().startswith('on'):
                                                results.append({
                                                    'category': 'setAttribute Event Handler',
                                                    'match': f'.{pname}("{attr_val}", ...)',
                                                    'line': node.start_point[0] + 1,
                                                    'severity': 8,
                                                })
                                            elif bare.lower() == 'style':
                                                results.append({
                                                    'category': 'CSS Injection',
                                                    'match': f'.{pname}("{attr_val}", ...)',
                                                    'line': node.start_point[0] + 1,
                                                    'severity': 5,
                                                })

            # new Worker(url), new SharedWorker(url)
            if node.type == 'new_expression':
                constructor = None
                for child in node.children:
                    if child.type == 'identifier':
                        constructor = self.get_node_text(child, source_bytes)
                        break
                if constructor in ('Worker', 'SharedWorker'):
                    if not self._has_only_literal_args(node):
                        results.append({
                            'category': 'Worker Constructor',
                            'match': f'new {constructor}(',
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

    def _extract_pattern_identifiers(self, pattern_node, source_bytes):
        """Extract all identifier names from a destructuring pattern.

        Handles object_pattern ({a, b: c}) and array_pattern ([x, , y]).
        Returns a list of bound variable names.
        """
        names = []
        stack = [pattern_node]
        while stack:
            n = stack.pop()
            if n.type == 'identifier' and n.parent != pattern_node.parent:
                names.append(self.get_node_text(n, source_bytes))
            elif n.type == 'shorthand_property_identifier_pattern':
                names.append(self.get_node_text(n, source_bytes))
            elif n.type in ('object_pattern', 'array_pattern', 'pair_pattern',
                            'assignment_pattern', 'rest_pattern'):
                stack.extend(n.children)
        return names

    def _get_shallow_text(self, node, source_bytes):
        """Get the text of a node, excluding nested function/scope bodies.

        Prevents taint leaking from deeply-nested function bodies into the
        containing expression.  `var x = { fn: function() { location.hash } }`
        returns `var x = { fn:  }` — the function body is elided.

        Uses pre-computed _scope_byte_ranges (set by find_taint_flows) for
        O(log N) binary-search overlap detection instead of walking the subtree.
        """
        if node.type in self._SCOPE_TYPES:
            return ''
        # Fast path: single-line expressions almost never contain scopes
        if node.start_point[0] == node.end_point[0]:
            return source_bytes[node.start_byte:node.end_byte].decode(
                'utf-8', errors='replace',
            )
        # Multi-line: find nested scopes to elide
        all_ranges = getattr(self, '_scope_byte_ranges', None)
        if all_ranges is not None:
            # Binary search: scopes starting within [node.start_byte, node.end_byte)
            lo = bisect.bisect_left(all_ranges, (node.start_byte,))
            hi = bisect.bisect_left(all_ranges, (node.end_byte,))
            overlapping = [
                r for r in all_ranges[lo:hi]
                if r[0] >= node.start_byte
            ]
            if not overlapping:
                return source_bytes[node.start_byte:node.end_byte].decode(
                    'utf-8', errors='replace',
                )
            parts = []
            pos = node.start_byte
            for sb, eb in overlapping:
                if sb > pos:
                    parts.append(
                        source_bytes[pos:sb].decode('utf-8', errors='replace')
                    )
                pos = max(pos, eb)
            if node.end_byte > pos:
                parts.append(
                    source_bytes[pos:node.end_byte].decode(
                        'utf-8', errors='replace',
                    )
                )
            return ''.join(parts)

        # Fallback: walk subtree (used when pre-computed ranges unavailable)
        scope_ranges = []
        stack = list(node.children)
        while stack:
            child = stack.pop()
            if child.type in self._SCOPE_TYPES:
                scope_ranges.append((child.start_byte, child.end_byte))
            else:
                stack.extend(child.children)
        if not scope_ranges:
            return source_bytes[node.start_byte:node.end_byte].decode(
                'utf-8', errors='replace',
            )
        scope_ranges.sort()
        parts = []
        pos = node.start_byte
        for sb, eb in scope_ranges:
            if sb > pos:
                parts.append(
                    source_bytes[pos:sb].decode('utf-8', errors='replace')
                )
            pos = eb
        if node.end_byte > pos:
            parts.append(
                source_bytes[pos:node.end_byte].decode(
                    'utf-8', errors='replace',
                )
            )
        return ''.join(parts)

    def _check_tainted(self, text, tainted_vars, is_message_handler=False):
        """Check if text contains a source or references a tainted variable.

        Returns the source name if tainted, None otherwise.

        is_message_handler: when True, also match CONTEXT_SOURCES (e.data,
        evt.data, msg.data) — these are only valid inside message event
        handler scopes to avoid false taint from minified parameter names.
        """
        for source_name, source_pattern in SOURCES.items():
            if re.search(source_pattern, text):
                return source_name
        if is_message_handler:
            for source_name, source_pattern in CONTEXT_SOURCES.items():
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

    def _precompute_scope_ranges(self, root_node):
        """Pre-compute sorted byte ranges of all scope-type nodes in the tree.

        Returns a sorted list of (start_byte, end_byte) tuples.
        Used by _get_shallow_text for O(log N) scope overlap detection.
        """
        ranges = []
        stack = [root_node]
        while stack:
            node = stack.pop()
            if node.type in self._SCOPE_TYPES:
                ranges.append((node.start_byte, node.end_byte))
            stack.extend(node.children)
        ranges.sort()
        return ranges

    def _build_function_map(self, root_node, source_bytes):
        """Build a name -> function-node map for efficient callee lookup.

        Covers function declarations, variable-assigned functions/arrows,
        object property functions, and class methods.
        First match per name wins (DFS order).
        """
        fn_map = {}
        stack = [root_node]
        while stack:
            node = stack.pop()
            if node.type == 'function_declaration':
                fn_name = node.child_by_field_name('name')
                if fn_name:
                    name = self.get_node_text(fn_name, source_bytes)
                    if name not in fn_map:
                        fn_map[name] = node
            elif node.type == 'variable_declarator':
                decl_name = node.child_by_field_name('name')
                value = node.child_by_field_name('value')
                if (decl_name and value
                        and value.type in ('function_expression',
                                           'arrow_function')):
                    name = self.get_node_text(decl_name, source_bytes)
                    if name not in fn_map:
                        fn_map[name] = value
            elif node.type == 'pair':
                key = node.child_by_field_name('key')
                value = node.child_by_field_name('value')
                if (key and value
                        and value.type in ('function_expression',
                                           'arrow_function')):
                    name = self.get_node_text(
                        key, source_bytes,
                    ).strip('\'"')
                    if name not in fn_map:
                        fn_map[name] = value
            elif node.type == 'method_definition':
                method_name = node.child_by_field_name('name')
                if method_name:
                    name = self.get_node_text(method_name, source_bytes)
                    if name not in fn_map:
                        fn_map[name] = node
            stack.extend(node.children)
        return fn_map

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
                if name_node and name_node.type == 'identifier':
                    var_name = self.get_node_text(name_node, source_bytes)
                    if value_node is None:
                        if var_name in tainted:
                            del tainted[var_name]
                    elif value_node.type in self._SCOPE_TYPES:
                        if var_name in tainted:
                            del tainted[var_name]
                    else:
                        value_text = self._get_shallow_text(value_node, source_bytes)
                        source = self._check_tainted(value_text, tainted)
                        if source:
                            tainted[var_name] = source
                        elif var_name in tainted:
                            del tainted[var_name]
                elif (name_node
                      and name_node.type in ('object_pattern', 'array_pattern')
                      and value_node
                      and value_node.type not in self._SCOPE_TYPES):
                    value_text = self._get_shallow_text(value_node, source_bytes)
                    source = self._check_tainted(value_text, tainted)
                    if not source and name_node.type == 'object_pattern':
                        base = value_text.strip()
                        for ident in self._extract_pattern_identifiers(
                                name_node, source_bytes):
                            prop_source = self._check_tainted(
                                f'{base}.{ident}', tainted)
                            if prop_source:
                                tainted[ident] = prop_source
                    elif source:
                        for ident in self._extract_pattern_identifiers(
                                name_node, source_bytes):
                            tainted[ident] = source

            elif n.type == 'assignment_expression':
                left = n.child_by_field_name('left')
                right = n.child_by_field_name('right')
                var_name = None
                if left and right:
                    if left.type == 'identifier':
                        var_name = self.get_node_text(left, source_bytes)
                    elif left.type == 'member_expression':
                        chain = self._get_member_chain(left, source_bytes)
                        if (chain and chain.startswith('this.')
                                and chain.count('.') == 1):
                            var_name = chain
                if var_name:
                    if right.type in self._SCOPE_TYPES:
                        if var_name in tainted:
                            del tainted[var_name]
                    else:
                        value_text = self._get_shallow_text(right, source_bytes)
                        source = self._check_tainted(value_text, tainted)
                        if source:
                            tainted[var_name] = source
                        elif var_name in tainted:
                            del tainted[var_name]

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

        # Look up callee: pre-computed map (O(1)) or tree walk (O(N))
        fn_map = getattr(self, '_fn_map', None)
        if fn_map is not None:
            fn_node = fn_map.get(fn_name)
        else:
            root = scope_root
            while root.parent:
                root = root.parent
            fn_node = self._find_function_by_name(root, fn_name, source_bytes)
        if not fn_node:
            return None

        # Cache return-taint results: same function → same answer
        cache = getattr(self, '_return_taint_cache', None)
        if cache is not None:
            cache_key = (fn_node.start_byte, fn_node.end_byte)
            if cache_key in cache:
                return cache[cache_key]
            result = self._analyze_return_taint(fn_node, source_bytes)
            cache[cache_key] = result
            return result

        return self._analyze_return_taint(fn_node, source_bytes)

    def _collect_taint_per_scope(self, node, source_bytes, parent_tainted,
                                 arg_taint=None, msg_handler_ranges=None):
        """Walk a scope, track taint with proper function boundaries.

        Returns list of (initial_tainted, taint_history, start_line, end_line)
        for this scope and all nested scopes.  initial_tainted is the inherited
        state at scope entry; taint_history is a source-ordered list of
        (line, var_name, source_or_None) events that modify it.

        To find the effective taint at any line, use _taint_at_line().

        Two-phase: first build this scope's complete taint map (skipping child
        functions), then recurse into child functions with the finished map.

        arg_taint: set of var names pre-tainted as function arguments — these
        survive formal_parameters stripping at the top-level function only.
        msg_handler_ranges: set of (start_byte, end_byte) for message handler
        scopes — enables CONTEXT_SOURCES (e.data) matching.
        """
        scopes = []
        initial = dict(parent_tainted)
        tainted = dict(parent_tainted)
        taint_history = []
        start_line = node.start_point[0]
        end_line = node.end_point[0]
        child_functions = []  # deferred — recurse after this scope is complete

        is_msg_handler = bool(
            msg_handler_ranges
            and (node.start_byte, node.end_byte) in msg_handler_ranges
        )

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
                if name_node and name_node.type == 'identifier':
                    var_name = self.get_node_text(name_node, source_bytes)
                    # Don't let local re-declarations overwrite arg-tainted params
                    if arg_taint and var_name in arg_taint:
                        pass
                    # Uninitialized declaration (var x;) clears inherited taint
                    elif value_node is None:
                        if var_name in tainted:
                            del tainted[var_name]
                            taint_history.append((
                                n.start_point[0], var_name, None,
                            ))
                    # Skip function values — their bodies are child scopes,
                    # not data flowing into the variable.
                    elif value_node.type in self._SCOPE_TYPES:
                        if var_name in tainted:
                            del tainted[var_name]
                            taint_history.append((
                                value_node.start_point[0], var_name, None,
                            ))
                    else:
                        value_text = self._get_shallow_text(
                            value_node, source_bytes,
                        )
                        source = self._check_tainted(
                            value_text, tainted, is_msg_handler,
                        )
                        if not source and value_node.type == 'call_expression':
                            source = self._check_call_return_taint(
                                value_node, node, source_bytes,
                            )
                        if source:
                            tainted[var_name] = source
                            taint_history.append((
                                value_node.start_point[0], var_name, source,
                            ))
                        elif var_name in tainted:
                            del tainted[var_name]
                            taint_history.append((
                                value_node.start_point[0], var_name, None,
                            ))
                # Destructuring: var {hash} = location, var [x, y] = arr
                elif (name_node
                      and name_node.type in ('object_pattern', 'array_pattern')
                      and value_node
                      and value_node.type not in self._SCOPE_TYPES):
                    value_text = self._get_shallow_text(
                        value_node, source_bytes,
                    )
                    source = self._check_tainted(
                        value_text, tainted, is_msg_handler,
                    )
                    # For object destructuring from a known base, check
                    # each property: {hash} = location → location.hash
                    if (not source
                            and name_node.type == 'object_pattern'):
                        base = value_text.strip()
                        for ident in self._extract_pattern_identifiers(
                                name_node, source_bytes):
                            synth = f'{base}.{ident}'
                            prop_source = self._check_tainted(
                                synth, tainted, is_msg_handler,
                            )
                            if prop_source:
                                tainted[ident] = prop_source
                                taint_history.append((
                                    value_node.start_point[0], ident,
                                    prop_source,
                                ))
                    elif source:
                        for ident in self._extract_pattern_identifiers(
                                name_node, source_bytes):
                            tainted[ident] = source
                            taint_history.append((
                                value_node.start_point[0], ident, source,
                            ))

            elif n.type == 'assignment_expression':
                left = n.child_by_field_name('left')
                right = n.child_by_field_name('right')
                # Determine the trackable variable name:
                # - Simple identifiers: x = ...
                # - this.X properties: this.foo = ... (within same scope)
                var_name = None
                is_arg = False
                if left and right:
                    if left.type == 'identifier':
                        var_name = self.get_node_text(left, source_bytes)
                        is_arg = bool(arg_taint and var_name in arg_taint)
                    elif left.type == 'member_expression':
                        chain = self._get_member_chain(left, source_bytes)
                        if (chain and chain.startswith('this.')
                                and chain.count('.') == 1):
                            var_name = chain
                if var_name and not is_arg:
                    # Skip function values — their bodies are child scopes
                    if right.type in self._SCOPE_TYPES:
                        if var_name in tainted:
                            del tainted[var_name]
                            taint_history.append((
                                right.start_point[0], var_name, None,
                            ))
                    else:
                        value_text = self._get_shallow_text(
                            right, source_bytes,
                        )
                        source = self._check_tainted(
                            value_text, tainted, is_msg_handler,
                        )
                        if not source and right.type == 'call_expression':
                            source = self._check_call_return_taint(
                                right, node, source_bytes,
                            )
                        if source:
                            tainted[var_name] = source
                            taint_history.append((
                                right.start_point[0], var_name, source,
                            ))
                        elif var_name in tainted:
                            del tainted[var_name]
                            taint_history.append((
                                right.start_point[0], var_name, None,
                            ))

            elif n.type == 'formal_parameters':
                param_line = n.start_point[0]
                for child in n.children:
                    if child.type == 'identifier':
                        param_name = self.get_node_text(child, source_bytes)
                        if arg_taint and param_name in arg_taint:
                            continue  # keep argument-tainted params
                        if param_name in tainted:
                            del tainted[param_name]
                            taint_history.append((param_line, param_name, None))
                continue

            stack.extend(reversed(n.children))

        scopes.append((initial, taint_history, start_line, end_line))

        # Phase 2: recurse into child functions with taint state at
        # their definition point (not the final state — a variable
        # tainted after a function is defined shouldn't leak into it).
        for child_fn in child_functions:
            parent_at_child = self._taint_at_line(
                initial, taint_history, child_fn.start_point[0],
            )
            scopes.extend(self._collect_taint_per_scope(
                child_fn, source_bytes, parent_at_child,
                msg_handler_ranges=msg_handler_ranges,
            ))

        return scopes

    def _taint_at_line(self, initial, history, target_line):
        """Compute effective taint state at target_line by replaying history.

        Starts from the inherited initial state and applies events up to
        (and including) the target line.
        """
        state = dict(initial)
        for line, var_name, source in history:
            if line > target_line:
                break
            if source is not None:
                state[var_name] = source
            elif var_name in state:
                del state[var_name]
        return state

    @staticmethod
    def _line_in_handler_range(tree, line_idx, msg_handler_ranges):
        """Check if a line falls inside any message handler function range."""
        if not msg_handler_ranges:
            return False
        # Walk tree to find function nodes covering this line that are handlers
        stack = [tree.root_node]
        while stack:
            node = stack.pop()
            if (node.start_point[0] <= line_idx <= node.end_point[0]
                    and (node.start_byte, node.end_byte)
                    in msg_handler_ranges):
                return True
            if node.start_point[0] <= line_idx <= node.end_point[0]:
                stack.extend(node.children)
        return False

    def _find_message_handler_ranges(self, tree, source_bytes):
        """Identify function nodes that are message event handler callbacks.

        Returns a set of (start_byte, end_byte) tuples for handler functions,
        used by _collect_taint_per_scope to enable CONTEXT_SOURCES matching.
        """
        handler_ranges = set()
        _HANDLER_TYPES = frozenset({
            'arrow_function', 'function_expression', 'function',
        })
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
                                evt = self.get_node_text(
                                    arg_nodes[0], source_bytes,
                                ).strip('\'"` ')
                                if evt == 'message':
                                    handler = arg_nodes[1]
                                    if handler.type in _HANDLER_TYPES:
                                        handler_ranges.add((
                                            handler.start_byte,
                                            handler.end_byte,
                                        ))

            # window.onmessage = handler  OR  bc.onmessage = handler
            # (BroadcastChannel, MessagePort, Worker all use onmessage)
            if node.type == 'assignment_expression':
                left = node.child_by_field_name('left')
                if left and left.type == 'member_expression':
                    prop = left.child_by_field_name('property')
                    if (prop
                            and self.get_node_text(prop, source_bytes)
                            == 'onmessage'):
                        right = node.child_by_field_name('right')
                        if right and right.type in _HANDLER_TYPES:
                            handler_ranges.add((
                                right.start_byte, right.end_byte,
                            ))

            stack.extend(node.children)
        return handler_ranges

    def find_taint_flows(self, tree, source_bytes):
        """Find intra-file dataflows from user-controlled sources to dangerous sinks.

        Two detection modes:
        1. Via variable: var x = location.hash; el.innerHTML = x;
        2. Direct: el.innerHTML = location.hash;  (source directly on sink line)

        Taint tracking is scoped to function boundaries — variable `r` tainted
        in function A does not contaminate a different `r` in function B.
        Taint state is line-aware — a variable reassigned clean before a sink
        won't false-positive.

        Also checks taint-only sinks (setTimeout, window.open, .src/.href assignment,
        setAttribute) which are too broad for anomaly detection but valid for taint.
        """
        # Pre-compute data structures for efficient analysis of large files:
        # - scope byte ranges: O(log N) nested-scope detection in _get_shallow_text
        # - function name map: O(1) callee lookup in _check_call_return_taint
        # - return taint cache: avoid re-analyzing the same function body
        self._scope_byte_ranges = self._precompute_scope_ranges(tree.root_node)
        self._fn_map = self._build_function_map(tree.root_node, source_bytes)
        self._return_taint_cache = {}
        try:
            return self._find_taint_flows_inner(tree, source_bytes)
        finally:
            self._scope_byte_ranges = None
            self._fn_map = None
            self._return_taint_cache = None

    def _find_taint_flows_inner(self, tree, source_bytes):
        """Inner implementation of find_taint_flows (pre-computed data already set)."""
        # Pre-compute message handler ranges for context-aware source matching
        msg_handler_ranges = self._find_message_handler_ranges(tree, source_bytes)

        # Build per-scope taint maps (line-aware: initial + history per scope)
        scopes = self._collect_taint_per_scope(
            tree.root_node, source_bytes, {},
            msg_handler_ranges=msg_handler_ranges,
        )

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

            # For multi-line expressions, get the full AST expression text
            full_expr = self._get_expression_text_at_line(
                tree, source_bytes, sink_line_idx,
            )
            check_text = full_expr if full_expr else sink_text

            # Find the innermost scope containing this sink line.
            # Children are appended after parents, so last match = deepest.
            best_initial = {}
            best_history = []
            best_span = float('inf')
            for scope_initial, scope_history, scope_start, scope_end in scopes:
                if scope_start <= sink_line_idx <= scope_end:
                    span = scope_end - scope_start
                    if span <= best_span:
                        best_span = span
                        best_initial = scope_initial
                        best_history = scope_history

            # Line-aware: compute taint state at the sink line, not final state
            tainted_vars = self._taint_at_line(
                best_initial, best_history, sink_line_idx,
            )

            # Mode 1: tainted variable in sink expression
            # Report all distinct sources — each source→sink path is a
            # separate vulnerability (e.g. cookie XSS vs referrer XSS).
            found = False
            seen_sources = set()
            for var_name, source_name in tainted_vars.items():
                if source_name in seen_sources:
                    continue
                if re.search(r'\b' + re.escape(var_name) + r'\b', check_text):
                    flows.append({
                        'source': source_name,
                        'sink': sink['category'],
                        'tainted_var': var_name,
                        'sink_line': sink_line_num,
                        'severity': sink['severity'],
                    })
                    seen_sources.add(source_name)
                    found = True

            # Mode 2: source pattern directly in sink value (no intermediate variable)
            # Uses AST to extract only the data portion (RHS of assignment, call args)
            # so `location.href = location.href` (self-assignment) doesn't false-positive.
            if not found:
                value_text = self._extract_sink_value(
                    tree, source_bytes, sink_line_idx, sink['category'],
                )
                if value_text:
                    # Check if sink is in a message handler (for CONTEXT_SOURCES)
                    sink_in_handler = self._line_in_handler_range(
                        tree, sink_line_idx, msg_handler_ranges,
                    )
                    # Check always-match sources
                    for source_name, source_pattern in SOURCES.items():
                        if re.search(source_pattern, value_text):
                            flows.append({
                                'source': source_name,
                                'sink': sink['category'],
                                'tainted_var': 'direct',
                                'sink_line': sink_line_num,
                                'severity': sink['severity'],
                            })
                            found = True
                            break
                    # Check context-dependent sources if in handler
                    if not found and sink_in_handler:
                        for source_name, source_pattern in \
                                CONTEXT_SOURCES.items():
                            if re.search(source_pattern, value_text):
                                flows.append({
                                    'source': source_name,
                                    'sink': sink['category'],
                                    'tainted_var': 'direct',
                                    'sink_line': sink_line_num,
                                    'severity': sink['severity'],
                                })
                                break

        # Mode 3: taint through function arguments
        # When foo(taintedVar) is called, check if foo uses its parameter
        # in a sink (e.g. eval(x) where x came from top.name at call site).
        arg_flows = self._find_argument_taint_flows(
            tree, source_bytes, scopes, msg_handler_ranges,
        )
        seen_flow_keys = {
            (f['source'], f['sink'], f['sink_line']) for f in flows
        }
        for af in arg_flows:
            key = (af['source'], af['sink'], af['sink_line'])
            if key not in seen_flow_keys:
                seen_flow_keys.add(key)
                flows.append(af)

        return flows

    def _get_expression_text_at_line(self, tree, source_bytes, line_idx):
        """Get full text of the expression node starting at a given line.

        For multi-line expressions like `el.src =\\n  tainted + value;`,
        returns the complete text so tainted variable checks aren't limited
        to the single sink line.
        """
        best = None
        stack = [tree.root_node]
        while stack:
            node = stack.pop()
            if node.start_point[0] == line_idx and node.type in (
                'assignment_expression', 'call_expression', 'new_expression',
            ):
                if best is None or node.end_point[0] >= best.end_point[0]:
                    best = node
            if node.start_point[0] <= line_idx <= node.end_point[0]:
                stack.extend(node.children)
        if best and best.end_point[0] > line_idx:
            return self.get_node_text(best, source_bytes)
        return None

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

    def find_prototype_pollution_sinks(self, tree, source_bytes):
        """Find calls to known deep-merge/extend functions (prototype pollution risk).

        Returns list of {category, match, line, severity} for each vulnerable call.
        """
        results = []
        text = source_bytes.decode('utf-8', errors='replace')
        for pattern in PROTOTYPE_POLLUTION_SINKS:
            for m in re.finditer(pattern, text):
                line = text[:m.start()].count('\n') + 1
                results.append({
                    'category': 'Prototype Pollution Sink',
                    'match': m.group(0).rstrip('('),
                    'line': line,
                    'severity': 7,
                })
        return results

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

            # window.onmessage = handler (not WebSocket.onmessage)
            if node.type == 'assignment_expression':
                left = node.child_by_field_name('left')
                if left and left.type == 'member_expression':
                    prop = left.child_by_field_name('property')
                    obj = left.child_by_field_name('object')
                    if prop and self.get_node_text(prop, source_bytes) == 'onmessage':
                        # Only flag if object is a window-like global or 'this'
                        # at top level — skip ws.onmessage, socket.onmessage, etc.
                        obj_text = self.get_node_text(obj, source_bytes)
                        if obj_text in ('window', 'self', 'globalThis', 'this'):
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
                        other_text = self.get_node_text(other_side, source_bytes).strip()
                        # Check if comparing to 'null' string
                        if other_text in ("'null'", '"null"', '`null`'):
                            result = 'unsafe_null'
                        # e.origin === window.origin — both can be 'null'
                        # from sandboxed iframes (bypass via srcdoc)
                        elif other_text in ('window.origin', 'self.origin',
                                            'globalThis.origin'):
                            if result not in ('unsafe_null',):
                                result = 'unsafe_null'
                        elif result != 'unsafe_null':
                            # Real comparison against a string/variable
                            result = 'valid'

            # Check method calls: allowedOrigins.includes(e.origin)
            # or e.origin.startsWith(...)
            #
            # Classification:
            #   indexOf/includes — substring match, bypassable (attacker-trusted.com)
            #   match without ^ and $ anchors — partial regex, bypassable
            #   startsWith/endsWith — may be valid if checking full origin
            #   === / == — strict comparison, valid
            if node.type == 'call_expression':
                fn = node.child_by_field_name('function')
                if fn and fn.type == 'member_expression':
                    obj = fn.child_by_field_name('object')
                    prop = fn.child_by_field_name('property')
                    if obj and prop:
                        prop_name = self.get_node_text(prop, source_bytes)
                        if prop_name in ('includes', 'indexOf', 'match',
                                         'search', 'test',
                                         'startsWith', 'endsWith'):
                            has_origin = False
                            if self._is_origin_access(obj, source_bytes):
                                has_origin = True
                            else:
                                args = node.child_by_field_name('arguments')
                                if args:
                                    for arg in args.children:
                                        if self._is_origin_access(arg, source_bytes):
                                            has_origin = True
                                            break
                            if has_origin:
                                found_origin_ref = True
                                # indexOf/includes are always bypassable
                                if prop_name in ('indexOf', 'includes'):
                                    if result not in ('unsafe_null',):
                                        result = 'unsafe_partial_match'
                                elif prop_name in ('match', 'search', 'test'):
                                    # Get regex text — for test() the regex
                                    # is the object, for match/search it's
                                    # the first argument
                                    regex_text = ''
                                    args = node.child_by_field_name('arguments')
                                    if prop_name == 'test':
                                        regex_text = self.get_node_text(
                                            obj, source_bytes)
                                    elif args:
                                        arg_nodes = [
                                            c for c in args.children
                                            if c.type not in ('(', ')', ',')]
                                        if arg_nodes:
                                            regex_text = self.get_node_text(
                                                arg_nodes[0], source_bytes)

                                    anchored = False
                                    has_unescaped_dot = False

                                    if regex_text:
                                        if '^' in regex_text and '$' in regex_text:
                                            anchored = True
                                        # Extract inner pattern from /regex/
                                        # or "string" delimiters
                                        inner = regex_text
                                        if inner.startswith('/'):
                                            inner = inner[1:]
                                            ls = inner.rfind('/')
                                            if ls > 0:
                                                inner = inner[:ls]
                                        elif inner[0:1] in ('"', "'", '`'):
                                            inner = inner[1:]
                                            if inner and inner[-1] in ('"', "'", '`'):
                                                inner = inner[:-1]
                                        # Strip escaped chars, then check
                                        # for remaining raw dots
                                        cleaned = _RE_ESCAPED.sub('', inner)
                                        if '.' in cleaned:
                                            has_unescaped_dot = True

                                    if not anchored or has_unescaped_dot:
                                        if result not in ('unsafe_null',):
                                            result = 'unsafe_partial_match'
                                    elif result not in ('unsafe_null',
                                                        'unsafe_partial_match'):
                                        result = 'valid'
                                else:
                                    # startsWith/endsWith — treat as valid
                                    if result not in ('unsafe_null',
                                                      'unsafe_partial_match'):
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
        """Find a function declaration, variable-assigned function, or object
        property function by name."""
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
            # { foo: function(x) { ... } }  (object property)
            if node.type == 'pair':
                key = node.child_by_field_name('key')
                value = node.child_by_field_name('value')
                if (key and value
                        and self.get_node_text(key, source_bytes).strip('\'"') == name
                        and value.type in ('function_expression',
                                           'arrow_function')):
                    return value
            # class Foo { bar(x) { ... } }  (class method)
            if node.type == 'method_definition':
                method_name = node.child_by_field_name('name')
                if (method_name
                        and self.get_node_text(method_name, source_bytes) == name):
                    return node
            stack.extend(node.children)
        return None

    def _find_argument_taint_flows(self, tree, source_bytes, scopes,
                                    msg_handler_ranges=None):
        """Find taint flows through function arguments.

        When foo(taintedVar) is called and foo uses its parameter in a sink,
        reports the source→sink flow. Handles both simple calls (foo(x)) and
        member calls (obj.foo(x)) by resolving the callee by property name.
        """
        flows = []
        text = source_bytes.decode('utf-8', errors='replace')
        lines = text.split('\n')
        root = tree.root_node

        # Pre-compute merged tainted line intervals for quick rejection.
        # Only call expressions within tainted scopes need full analysis.
        tainted_intervals = sorted(
            (ss, se) for si, sh, ss, se in scopes
            if si or any(src is not None for _, _, src in sh)
        )
        merged = []
        for ss, se in tainted_intervals:
            if merged and merged[-1][1] >= ss - 1:
                merged[-1][1] = max(merged[-1][1], se)
            else:
                merged.append([ss, se])
        if not merged:
            return flows

        stack = [root]
        while stack:
            node = stack.pop()
            if node.type != 'call_expression':
                stack.extend(node.children)
                continue

            fn = node.child_by_field_name('function')
            args = node.child_by_field_name('arguments')
            if not fn or not args:
                stack.extend(node.children)
                continue

            # Quick rejection: skip calls outside tainted scopes
            call_line = node.start_point[0]
            idx = bisect.bisect_right(merged, [call_line, float('inf')]) - 1
            if idx < 0 or merged[idx][1] < call_line:
                stack.extend(node.children)
                continue

            # Resolve callee name (simple identifier or member property)
            if fn.type == 'identifier':
                callee_name = self.get_node_text(fn, source_bytes)
            elif fn.type == 'member_expression':
                prop = fn.child_by_field_name('property')
                callee_name = self.get_node_text(prop, source_bytes) if prop else None
            else:
                stack.extend(node.children)
                continue

            if not callee_name:
                stack.extend(node.children)
                continue

            # Get tainted vars at the call site (line-aware)
            best_initial = {}
            best_history = []
            best_span = float('inf')
            for scope_initial, scope_history, scope_start, scope_end in scopes:
                if scope_start <= call_line <= scope_end:
                    span = scope_end - scope_start
                    if span <= best_span:
                        best_span = span
                        best_initial = scope_initial
                        best_history = scope_history

            call_tainted = self._taint_at_line(
                best_initial, best_history, call_line,
            )

            # Check which arguments are tainted
            arg_nodes = [c for c in args.children
                         if c.type not in ('(', ')', ',')]
            tainted_params = {}
            for i, arg in enumerate(arg_nodes):
                arg_text = self.get_node_text(arg, source_bytes)
                source = self._check_tainted(arg_text, call_tainted)
                if source:
                    tainted_params[i] = source

            if not tainted_params:
                stack.extend(node.children)
                continue

            # Find the callee function definition
            fn_map = getattr(self, '_fn_map', None)
            if fn_map is not None:
                callee = fn_map.get(callee_name)
            else:
                callee = self._find_function_by_name(root, callee_name, source_bytes)
            if not callee:
                stack.extend(node.children)
                continue

            # Map tainted argument indices to parameter names
            params_node = callee.child_by_field_name('parameters')
            if not params_node:
                stack.extend(node.children)
                continue
            param_names = [
                self.get_node_text(c, source_bytes)
                for c in params_node.children
                if c.type in ('identifier', 'shorthand_property_identifier')
            ]

            pre_taint = {}
            for idx, source in tainted_params.items():
                if idx < len(param_names):
                    pre_taint[param_names[idx]] = source

            if not pre_taint:
                stack.extend(node.children)
                continue

            # Build taint map for callee with pre-tainted params
            callee_scopes = self._collect_taint_per_scope(
                callee, source_bytes, pre_taint,
                arg_taint=set(pre_taint.keys()),
                msg_handler_ranges=msg_handler_ranges,
            )

            # Find sinks in callee
            callee_start = callee.start_point[0]
            callee_end = callee.end_point[0]
            callee_sinks = self.find_sinks_in_range(
                tree, source_bytes, callee_start, callee_end,
            )
            callee_taint_sinks = self.find_taint_sinks_in_range(
                tree, source_bytes, callee_start, callee_end,
            )
            seen = {(s['category'], s['line']) for s in callee_sinks}
            for ts in callee_taint_sinks:
                if (ts['category'], ts['line']) not in seen:
                    callee_sinks.append(ts)

            # Check each callee sink for tainted params (line-aware)
            for sink in callee_sinks:
                sink_line_idx = sink['line'] - 1
                if not (0 <= sink_line_idx < len(lines)):
                    continue
                sink_text = lines[sink_line_idx]
                full_expr = self._get_expression_text_at_line(
                    tree, source_bytes, sink_line_idx,
                )
                check_text = full_expr if full_expr else sink_text

                # Find innermost callee scope and compute taint at sink line
                callee_best_init = {}
                callee_best_hist = []
                best = float('inf')
                for si, sh, ss, se in callee_scopes:
                    if ss <= sink_line_idx <= se:
                        span = se - ss
                        if span <= best:
                            best = span
                            callee_best_init = si
                            callee_best_hist = sh

                callee_tainted = self._taint_at_line(
                    callee_best_init, callee_best_hist, sink_line_idx,
                )

                seen_sources = set()
                for var_name, source_name in callee_tainted.items():
                    if source_name in seen_sources:
                        continue
                    if re.search(r'\b' + re.escape(var_name) + r'\b',
                                 check_text):
                        flows.append({
                            'source': source_name,
                            'sink': sink['category'],
                            'tainted_var': var_name,
                            'sink_line': sink['line'],
                            'severity': sink['severity'],
                        })
                        seen_sources.add(source_name)

            stack.extend(node.children)
        return flows


# Per-thread AST analyzer (Parser is not thread-safe)
_thread_local = threading.local()


def get_ast_analyzer():
    """Get or create a per-thread AST analyzer."""
    analyzer = getattr(_thread_local, 'ast_analyzer', None)
    if analyzer is None:
        analyzer = ASTAnalyzer()
        _thread_local.ast_analyzer = analyzer
    return analyzer


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
        elif origin_check == 'unsafe_partial_match':
            severity = 8 if has_sinks else 6
            issue = 'unsafe_partial_origin_check'
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
        finding_key = f"taint:{script_hash}:{flow['source']}:{flow['sink']}:{flow['sink_line']}"
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


def _check_prototype_pollution(analyzer, tree, source_bytes, script_hash, url, script_url):
    """Check for prototype pollution sinks (deep merge/extend calls). Emits findings."""
    sinks = analyzer.find_prototype_pollution_sinks(tree, source_bytes)
    for sink in sinks:
        finding_key = f"protopoll:{script_hash}:{sink['match']}:{sink['line']}"
        if finding_key in SEEN_FINDINGS:
            continue
        SEEN_FINDINGS.add(finding_key)
        log_message("FINDING", {
            'finding_type': 'prototype_pollution',
            'source_url': url,
            'script_url': script_url or 'inline',
            'script_hash': script_hash,
            'sink_category': sink['category'],
            'match': sink['match'],
            'sink_line': sink['line'],
            'severity': sink['severity'],
            'confidence': 'low',
            'analysis_method': 'pattern',
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
        _check_prototype_pollution(analyzer, tree, source_bytes, script_hash, url, script_url)
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
    await find_and_process_template_urls(js_code, url, client)


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


# --- Template URL patterns for SPA frameworks ---
# Matches: templateUrl: '/path.html', templateUrl: "/path.html", templateUrl: `path.html`
_TEMPLATE_URL_DIRECT = re.compile(
    r"""templateUrl\s*:\s*['"`]([^'"`\n]+\.html?)['"`]""",
    re.IGNORECASE,
)
# Matches helper calls: templateUrl: getPartialUrl('name'), templateUrl: helper("name")
_TEMPLATE_URL_HELPER = re.compile(
    r"""templateUrl\s*:\s*(\w+)\s*\(\s*['"`]([^'"`\n]+)['"`]\s*\)""",
)
# Matches simple string-returning functions:
# function foo(x) { return "/prefix/" + x + ".html"; }
_HELPER_FUNC = re.compile(
    r"""function\s+(\w+)\s*\(\s*\w+\s*\)\s*\{[^}]*?return\s+['"`]([^'"`]*?)['"`]\s*\+\s*\w+\s*\+\s*['"`]([^'"`]*?)['"`]""",
)


def _extract_template_urls(content, base_url):
    """Extract HTML template URLs from SPA framework route configurations.

    Handles:
    - Direct: templateUrl: '/views/page.html'
    - Helper: templateUrl: getUrl('page') where getUrl builds a path
    """
    urls = set()

    # Resolve helper functions: function name(x) { return prefix + x + suffix; }
    helpers = {}
    for m in _HELPER_FUNC.finditer(content):
        func_name, prefix, suffix = m.group(1), m.group(2), m.group(3)
        helpers[func_name] = (prefix, suffix)

    # Direct templateUrl strings
    for m in _TEMPLATE_URL_DIRECT.finditer(content):
        path = m.group(1)
        urls.add(urljoin(base_url, path))

    # Helper-based templateUrl: resolve using detected helpers
    for m in _TEMPLATE_URL_HELPER.finditer(content):
        func_name, arg = m.group(1), m.group(2)
        if func_name in helpers:
            prefix, suffix = helpers[func_name]
            path = prefix + arg + suffix
            urls.add(urljoin(base_url, path))

    return urls


async def find_and_process_template_urls(content, base_url, client):
    """Find SPA template URLs in JS and analyze their inline scripts."""
    urls = _extract_template_urls(content, base_url)
    if not urls:
        return

    tasks = []
    for template_url in urls:
        hashed = get_sha256(template_url)
        if hashed in CHECKED_JS_URLS:
            continue
        CHECKED_JS_URLS.add(hashed)

        log_message("INFO", f"Discovered template URL: {template_url}")
        try:
            resp = await client.get(template_url, timeout=10)
            if resp.status_code >= 400:
                continue
            html = resp.text
            # Extract inline scripts from the template
            for m in re.finditer(
                r'<script[^>]*>(.*?)</script>', html, re.DOTALL | re.IGNORECASE,
            ):
                js = m.group(1).strip()
                if js:
                    tasks.append(process_javascript(
                        js, base_url, client, script_url=template_url,
                    ))
        except httpx.RequestError as e:
            log_message("ERROR", f"Failed to fetch template {template_url}: {e}")

    if tasks:
        await asyncio.gather(*tasks)
