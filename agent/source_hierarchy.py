"""Stream a source hierarchy index without storing leaf-cell connection graphs.

Only literal, supported module instances become hierarchy edges. Incomplete HDL
is represented explicitly; absence from this index never proves an object absent
when the corresponding source scope is unknown. This is not an elaborator.
"""
from __future__ import annotations

from collections import defaultdict
import json
from pathlib import Path
import re
from typing import Any


_IDENTIFIER = r"(?:\\[^\s]+|[A-Za-z_$][\w$]*)"
_MODULE = re.compile(rf"^module\s+({_IDENTIFIER})(?=\s|\(|#|$)")
_MODULE_START = re.compile(r'^module\b')
_SCOPE_END = re.compile(r'^endmodule\b')
_INSTANCE = re.compile(rf"^({_IDENTIFIER})\s+({_IDENTIFIER})\s*\(")
_SIMPLE_NAMED_CONNECTIONS = re.compile(r"\(\s*(?:\.[A-Za-z_$][\w$]*\s*\([^()]*\)\s*(?:,\s*)?)*\)")
_WORD = re.compile(r"[A-Za-z_$][A-Za-z0-9_$]*")
_DECLARATION = re.compile(r"^(input|output|inout|wire|tri|reg|logic|integer|genvar|parameter|localparam)\b")
_PORT = re.compile(rf"(?:(?:input|output|inout|wire|reg|logic|tri|signed|unsigned)\s+)*"
                   rf"(?:\[\s*\d+\s*:\s*\d+\s*\]\s*)?{_IDENTIFIER}\s*$")
_CONTROL = re.compile(r"^(generate|endgenerate|for|if|case|casex|casez|function|task|always|initial|defparam|bind)\b")
_SAFE_DIRECTIVES = {"timescale", "default_nettype", "celldefine", "endcelldefine"}
_KEYWORD_ROLES = (
    (r"\bJTAG\b|JTAG|\bTAP\b", ("jtag", "tap")),
    (r"门控|\bICG\b|clock[ _-]*gat", ("gate", "gated", "icg", "clk", "clock")),
    (r"闩锁|锁存|latch", ("latch", "clock", "clk")),
    (r"黑盒|wrapper|\bCTL\b", ("wrapper", "wrap", "core")),
    (r"移位寄存器|shift[ _-]*register", ("shift", "register", "reg")),
)


def _name(value: str) -> str:
    return value.removeprefix("\\")


def _clean_line(raw: str, state: dict[str, bool]) -> str:
    """Remove comments and mask strings; escaped Verilog names remain literal."""
    if not state["block"] and not state["string"] and "/" not in raw and '"' not in raw:
        return raw
    pieces = []
    index = 0
    while index < len(raw):
        if state["block"]:
            end = raw.find("*/", index)
            if end < 0:
                break
            state["block"] = False
            pieces.append(" ")
            index = end + 2
        elif state["string"]:
            character = raw[index]
            if character == "\\" and index + 1 < len(raw):
                pieces.append("  ")
                index += 2
            else:
                pieces.append('"' if character == '"' else "\n" if character == "\n" else " ")
                if character == '"':
                    state["string"] = False
                index += 1
        elif raw[index] == "\\":
            end = index + 1
            while end < len(raw) and not raw[end].isspace():
                end += 1
            pieces.append(raw[index:end])
            index = end
        elif raw.startswith("//", index):
            break
        elif raw.startswith("/*", index):
            state["block"] = True
            pieces.append(" ")
            index += 2
        else:
            character = raw[index]
            pieces.append(character)
            if character == '"':
                state["string"] = True
            index += 1
    return "".join(pieces)


def _parts(line: str) -> list[tuple[str, bool]]:
    """Split statement terminators, excluding quoted strings and escaped names."""
    # _clean_line already masks quoted string contents. An escaped identifier
    # only needs the slow scanner when it actually contains a semicolon.
    if "\\" not in line or not re.search(r"\\\S*;", line):
        pieces = line.split(";")
        return [(piece, index < len(pieces) - 1) for index, piece in enumerate(pieces)]
    parts = []
    start = index = 0
    quoted = False
    while index < len(line):
        character = line[index]
        if character == "\\" and not quoted:
            index += 1
            while index < len(line) and not line[index].isspace():
                index += 1
            continue
        if character == '"':
            quoted = not quoted
        elif character == ";" and not quoted:
            parts.append((line[start:index], True))
            start = index + 1
        index += 1
    parts.append((line[start:], False))
    return parts


def _records(path: Path, max_statement_chars: int, leaf_cells: set[str] | None = None, *,
             headers_only: bool = False):
    """Yield bounded statements and scope markers with original line numbers.

    The definition pass needs only headers/scope/directive/lexical markers. A
    complete single-line non-header statement can be skipped without recognizing
    its cell type or parsing any connections. The full reference pass stays exact.
    """
    state = {"block": False, "string": False}
    pending = ""
    first_line = 0
    with path.open(encoding="utf-8", errors="replace") as stream:
        for number, raw in enumerate(stream, 1):
            line = _clean_line(raw, state)
            stripped = line.strip()
            if not stripped:
                continue
            if (headers_only and not pending and stripped.endswith(';') and stripped.count(';') == 1 and
                    not stripped.startswith(('module', 'endmodule', '`')) and
                    ('\\' not in stripped or not re.search(r'\\\S*;', stripped))):
                # Only a real final terminator ends this statement. Escaped
                # identifiers containing semicolons must use the original lexer.
                # _clean_line has already updated comment/string state.
                continue
            if leaf_cells and not pending and stripped.endswith(';') and stripped.count(';') == 1:
                instance = _INSTANCE.match(stripped)
                if (instance and _name(instance[1]) in leaf_cells and len(stripped) - 1 <= max_statement_chars and
                        _SIMPLE_NAMED_CONNECTIONS.fullmatch(stripped[instance.end() - 1:-1].strip())):
                    if not headers_only or _MODULE_START.match(stripped):
                        yield stripped[:-1], number, 'library_leaf'
                    continue
            if stripped.startswith("`"):
                if pending.strip():
                    if not headers_only or _MODULE_START.match(pending):
                        yield pending.strip(), first_line, "unterminated_statement"
                    pending = ""
                yield stripped, number, "directive"
                continue
            if stripped.startswith('endmodule') and _SCOPE_END.match(stripped) and pending.strip():
                if not headers_only or _MODULE_START.match(pending):
                    yield pending.strip(), first_line, "unterminated_statement"
                pending = ""
            for piece, terminated in _parts(line):
                piece = piece.strip()
                if not piece and not pending:
                    continue
                if not pending:
                    while piece.startswith('endmodule') and _SCOPE_END.match(piece):
                        yield "endmodule", number, "scope_end"
                        piece = piece[len("endmodule"):].strip()
                    if not piece:
                        continue
                    first_line = number
                pending += (" " if pending else "") + piece
                if len(pending) > max_statement_chars:
                    if not headers_only or _MODULE_START.match(pending[:max_statement_chars]):
                        yield pending[:max_statement_chars], first_line, "statement_limit"
                    pending = ""
                elif terminated:
                    if not headers_only or _MODULE_START.match(pending):
                        yield pending.strip(), first_line, "statement"
                    pending = ""
    if pending.strip():
        if not headers_only or _MODULE_START.match(pending):
            yield pending.strip(), first_line, "unterminated_statement"
    if state["block"] or state["string"]:
        if headers_only:
            # Legacy lexical diagnostics use the last non-leaf statement's
            # first_line. Recover that exact line only on an incomplete lexical
            # scope instead of classifying every ordinary instance in valid HDL.
            for _, original_line, status in _records(path, max_statement_chars, leaf_cells):
                if status == "unterminated_comment_or_string":
                    first_line = original_line
        yield "", first_line, "unterminated_comment_or_string"


def source_hierarchy_hints(paths: list[Path], library_cells: set[str] | None = None, *,
                           max_edges: int = 100000, max_issues: int = 128,
                           max_statement_chars: int = 65536,
                           max_undefined_types: int = 256) -> dict[str, Any]:
    """Index all module names and referenced module types across all input files.

    Two streaming passes distinguish defined modules from arbitrary library cell
    names. Leaf instances never retain pins or connections. Display/storage limits
    cannot change the complete referenced-module set used to calculate roots.
    Unsupported scopes and undefined types disable conclusions about absence.
    """
    libraries = set(library_cells or ())
    modules: dict[str, dict[str, Any]] = {}
    issues: list[dict[str, Any]] = []
    issue_counts: dict[str, int] = defaultdict(int)
    incomplete_modules: set[str] = set()
    headers_complete = True
    hierarchy_complete = True
    edges_complete = True
    edges: list[dict[str, Any]] = []
    child_types: set[str] = set()
    undefined: dict[str, dict[str, Any]] = {}
    undefined_overflow_instances = 0
    leaf_instance_count = 0

    def issue(code: str, path: Path, line: int, module: str = "", detail: str = "") -> None:
        issue_counts[code] += 1
        if module:
            incomplete_modules.add(module)
        if len(issues) < max_issues:
            issues.append({"code": code, "source": str(path), "line": line,
                           "module": module, "detail": detail[:240]})

    for path in paths:
        current = ""
        for text, number, status in _records(path, max_statement_chars, libraries, headers_only=True):
            if status == "scope_end":
                current = ""
            elif text.startswith('module') and _MODULE_START.match(text):
                found = _MODULE.match(text)
                if not found:
                    headers_complete = False
                    issue("unparsed_module_declaration", path, number, detail=text)
                    current = ""
                    continue
                if current:
                    headers_complete = False
                    hierarchy_complete = False
                    issue("unclosed_module_scope", path, number, current)
                current = _name(found.group(1))
                if current in modules:
                    headers_complete = False
                    modules[current]["definition_count"] += 1
                    issue("duplicate_module", path, number, current)
                else:
                    modules[current] = {"name": current, "source": str(path), "line": number,
                                        "definition_count": 1, "complete": True}
                if status != "statement" or "#" in text[found.end():]:
                    issue("unsupported_module_header", path, number, current, text)
            elif status == "directive":
                directive = text[1:].split(None, 1)[0]
                if directive not in _SAFE_DIRECTIVES:
                    headers_complete = False
                    issue("conditional_or_macro_source", path, number, current, directive)
            elif status == "unterminated_comment_or_string":
                headers_complete = False
                issue(status, path, number, current)
        if current:
            headers_complete = False
            hierarchy_complete = False
            issue("missing_endmodule", path, modules[current]["line"], current)

    if not modules:
        headers_complete = False
        hierarchy_complete = False
        issue("no_module_declarations", paths[0] if paths else Path("."), 1)

    for path in paths:
        current = ""
        for text, number, status in _records(path, max_statement_chars, libraries - set(modules)):
            found = _MODULE.match(text)
            if found:
                current = _name(found.group(1))
                header = text[found.end():].strip()
                if header.startswith("(") and header.endswith(")"):
                    body = header[1:-1].strip()
                    if body and not all(_PORT.fullmatch(entry.strip()) for entry in body.split(",")):
                        issue("unparsed_port_declaration", path, number, current, body)
                elif header:
                    issue("unparsed_port_declaration", path, number, current, header)
                continue
            if status == "scope_end":
                current = ""
                continue
            if status == "directive":
                continue
            if not current:
                if text and status != "unterminated_comment_or_string":
                    hierarchy_complete = False
                    issue("statement_outside_module", path, number, detail=text)
                continue
            if status == 'library_leaf':
                leaf_instance_count += 1
                continue
            if status != "statement":
                hierarchy_complete = False
                issue(status, path, number, current, text)
                continue
            declaration = _DECLARATION.match(text)
            if declaration:
                if declaration.group(1) in {"input", "output", "inout"}:
                    if not all(_PORT.fullmatch(entry.strip()) for entry in text.split(",")):
                        issue("unparsed_port_declaration", path, number, current, text)
                continue
            if text.startswith("assign "):
                continue
            if _CONTROL.search(text):
                hierarchy_complete = False
                issue("unsupported_hierarchy_construct", path, number, current, text)
                continue
            instance = _INSTANCE.match(text)
            if not instance:
                hierarchy_complete = False
                issue("unparsed_instance_statement", path, number, current, text)
                continue
            kind, name = _name(instance.group(1)), _name(instance.group(2))
            if kind in libraries and kind not in modules and _SIMPLE_NAMED_CONNECTIONS.fullmatch(text[instance.end() - 1:]):
                leaf_instance_count += 1
                continue
            # A second instance after the closing connection list is not silently
            # accepted as the first one. Parentheses must close at statement end.
            body = text[instance.end() - 1:]
            depth = 0
            closing = -1
            for index, character in enumerate(body):
                if character == "(":
                    depth += 1
                elif character == ")":
                    depth -= 1
                    if depth == 0:
                        closing = index
                        break
            if closing < 0 or body[closing + 1:].strip():
                hierarchy_complete = False
                issue("multiple_or_unparsed_instances", path, number, current, text)
                continue
            if kind in modules:
                child_types.add(kind)
                if len(edges) < max_edges:
                    edges.append({"parent": current, "type": kind, "instance": name,
                                  "escaped": instance.group(2).startswith("\\"),
                                  "source": str(path), "line": number})
                else:
                    edges_complete = False
                if kind in libraries:
                    hierarchy_complete = False
                    issue("module_library_name_collision", path, number, current, kind)
            elif kind in libraries:
                leaf_instance_count += 1
            else:
                hierarchy_complete = False
                if kind not in undefined:
                    if len(undefined) < max_undefined_types:
                        undefined[kind] = {"type": kind, "count": 0, "source": str(path), "line": number}
                        issue("undefined_instance_type", path, number, current, kind)
                    else:
                        undefined_overflow_instances += 1
                if kind in undefined:
                    undefined[kind]["count"] += 1
                incomplete_modules.add(current)
    if not edges_complete:
        issue_counts["edge_storage_limit"] += 1
    for name in incomplete_modules:
        if name in modules:
            modules[name]["complete"] = False
    # Type-level cycles need no flattened leaf graph and must not produce an
    # apparently complete empty root set. Use an iterative walk for deep HDL.
    adjacency: dict[str, set[str]] = defaultdict(set)
    for edge in edges:
        adjacency[edge["parent"]].add(edge["type"])
    state: dict[str, int] = {}
    for start in modules:
        if state.get(start):
            continue
        state[start] = 1
        stack = [(start, iter(sorted(adjacency[start])))]
        while stack:
            parent, children = stack[-1]
            child = next(children, None)
            if child is None:
                state[parent] = 2
                stack.pop()
            elif state.get(child) == 1:
                hierarchy_complete = False
                modules[parent]["complete"] = False
                item = modules[parent]
                issue("cyclic_module_hierarchy", Path(item["source"]), item["line"], parent, child)
            elif not state.get(child):
                state[child] = 1
                stack.append((child, iter(sorted(adjacency[child]))))
    roots = sorted(modules.keys() - child_types)
    roots_complete = headers_complete and hierarchy_complete
    return {"input_file_count": len(paths), "modules": [modules[name] for name in sorted(modules)], "roots": roots,
            "roots_complete": roots_complete, "module_headers_complete": headers_complete,
            "hierarchy_complete": hierarchy_complete, "edges_complete": edges_complete,
            "complete": roots_complete and edges_complete and not incomplete_modules,
            "module_instances": edges, "referenced_module_types": sorted(child_types),
            "undefined_instance_types": [undefined[name] for name in sorted(undefined)],
            "undefined_type_details_complete": not undefined_overflow_instances,
            "undefined_type_overflow_instances": undefined_overflow_instances,
            "library_leaf_instance_count": leaf_instance_count,
            "issues": issues, "issue_counts": dict(sorted(issue_counts.items()))}


def source_hierarchy_context(paths: list[Path], task_spec: str = "", *, hints: dict[str, Any] | None = None,
                             library_cells: set[str] | None = None, max_paths: int = 128,
                             max_visits: int = 20000, max_depth: int = 64,
                             limit: int = 16000) -> str:
    """Show bounded, task-relevant full paths without truncating root analysis."""
    index = source_hierarchy_hints(paths, library_cells) if hints is None else hints
    by_parent: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for edge in index["module_instances"]:
        by_parent[edge["parent"]].append(edge)
    words = {word.lower() for word in _WORD.findall(task_spec)}
    role_words = set()
    for pattern, values in _KEYWORD_ROLES:
        if re.search(pattern, task_spec, re.I):
            role_words.update(values)
    selected = []
    fallback = []
    visits = 0
    traversal_complete = index["roots_complete"] and index["edges_complete"]
    stack = [(root, root, [], frozenset()) for root in reversed(index["roots"])]
    while stack and visits < max_visits:
        root, module, prefix, ancestors = stack.pop()
        if module in ancestors:
            traversal_complete = False
            continue
        if len(prefix) >= max_depth and by_parent[module]:
            traversal_complete = False
            continue
        for edge in reversed(by_parent[module]):
            visits += 1
            if visits > max_visits:
                traversal_complete = False
                break
            segments = prefix + [edge["instance"]]
            row = {"root": root, "path": "/".join(segments), "segments": segments,
                   "path_literal_unambiguous": all("/" not in segment for segment in segments),
                   "escaped": edge["escaped"], "type": edge["type"],
                   "source": edge["source"], "line": edge["line"]}
            names = {edge["type"].lower(), edge["instance"].lower()}
            relevant = bool(names & words) or any(term in name for term in role_words for name in names)
            if relevant and len(selected) < max_paths:
                selected.append(row)
            elif len(fallback) < max_paths:
                fallback.append(row)
            stack.append((root, edge["type"], segments, ancestors | {module}))
    if stack:
        traversal_complete = False
    rows = selected + fallback[:max(0, max_paths - len(selected))]
    display = {"roots": index["roots"][:40], "root_count": len(index["roots"]),
               "roots_display_complete": len(index["roots"]) <= 40,
               "roots_complete": index["roots_complete"],
               "complete": index["complete"], "module_count": len(index["modules"]),
               "module_instances": rows, "path_traversal_complete": traversal_complete,
               "paths_display_complete": traversal_complete and len(rows) == visits,
               "paths_shown": len(rows), "issues": index["issues"][:24],
               "issue_counts": index["issue_counts"]}
    prefix = ("Literal source module hierarchy. Root analysis uses all files and all parsed module references, "
              "independent of the bounded path display. Paths are structural candidates, not elaboration, pin validity, "
              "clock semantics or DRC proof. Incomplete/unknown source must not justify rejecting an unseen object or "
              "shortening, substituting or guessing a hierarchy. Use the actual tool when static source is uncertain.\n")
    # Keep JSON complete under a character budget; never cut a candidate/source
    # record midway or turn the displayed subset into a claimed complete graph.
    while True:
        rendered = json.dumps(display, ensure_ascii=False, indent=2)
        if len(prefix) + len(rendered) <= limit:
            break
        if display["module_instances"]:
            display["module_instances"].pop()
            display["paths_shown"] = len(display["module_instances"])
            display["paths_display_complete"] = False
        elif display["issues"]:
            display["issues"].pop()
        elif display["roots"]:
            display["roots"].pop()
            display["roots_display_complete"] = False
        else:
            break  # A tiny budget cannot fit even the completeness metadata.
    return prefix + rendered
