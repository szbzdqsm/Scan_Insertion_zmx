"""Task-grounded structural validation of literal, replacement-only netlists.

No tool PASS or report count is substituted for source/final connectivity.  This
reader supports named-pin structural Verilog, literal buses/concatenations, and
Liberty scalar FFs and buffer/inverter/constant functions. Unsupported reachable
HDL or ambiguous drivers yield ``unknown`` and cannot produce a passing proof.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from itertools import product
from pathlib import Path
import re
from typing import Any

from source_hierarchy import _records
from report_validation import report_rows


_ID = r"(?:\\[^\s]+|[A-Za-z_$][\w$]*)"
_NAME = re.compile(r"[A-Za-z_$][\w$./\[\]-]*")
_LIB_EVENT = re.compile(
    r'(?P<group>[A-Za-z_]\w*)\s*\((?P<args>[^{};]*?)\)\s*\{'
    r'|(?P<prop>[A-Za-z_]\w*)\s*:\s*(?P<value>"(?:\\.|[^"\\])*"|[^;{}]+)\s*;'
    r'|(?P<close>\})|(?P<open>\{)|"(?:\\.|[^"\\])*"', re.S)
_FUNCTION_FIELDS = {"clocked_on", "next_state", "clear", "preset"}


def partial_insertion_requirements(spec: str) -> dict[str, Any]:
    """Extract only explicit requirements; names are never case constants."""
    partial = bool(re.search(r"不构建扫描链|不涉及扫描链|不插链|without.{0,30}scan.chain|"
                             r"(?:no|not).{0,15}(?:build|construct|insert).{0,20}scan.chain", spec, re.I))
    result: dict[str, Any] = {"applicable": partial, "top": None, "control_port": None,
                              "icg_excluded_scopes": [], "unscan_scopes": [], "ff_pairs": {},
                              "final_netlist_names": [], "replacement_netlist_names": []}
    if not partial:
        return result
    in_outputs = False
    for line in spec.splitlines():
        if re.match(r"\s*#{1,6}\s+.*(?:输出|outputs?|deliverables)", line, re.I):
            in_outputs = True
        if in_outputs:
            netlists = re.findall(r"`([^`\n]+\.(?:v|vg))`", line, re.I)
            role = ("final_netlist_names" if re.search(r"最终|final|SFF\s*(?:→|->|=>)\s*DFF|反向.{0,15}回替|back.replace", line, re.I)
                    else "replacement_netlist_names" if re.search(r"DFF\s*(?:→|->|=>)\s*SFF|replace.only", line, re.I) else None)
            if role:
                result[role].extend(Path(name).name for name in netlists if Path(name).name == name)
        named = re.findall(r"`([^`\n]+)`|\*\*([^*\n]+)\*\*", line)
        names = [a or b for a, b in named if _NAME.fullmatch(a or b)]
        top = re.search(r"(?:Top\s*模块|顶层模块(?:名)?|top\s*(?:module|design))\s*(?:\*\*)?\s*[:：]\s*`?([A-Za-z_$][\w$]*)", line, re.I)
        if top:
            result["top"] = top[1]
        if "ICG" in line.upper() and re.search(r"scan_enable|扫描控制端|重连|顶层端口|top(?:-level)?\s+(?:input\s+)?port", line, re.I):
            control = re.search(r"(?:顶层端口|top(?:-level)?\s+(?:input\s+)?port)\s*`([^`]+)`", line, re.I)
            if control:
                result["control_port"] = control[1]
            elif line.lstrip().startswith("|") and len(names) == 1 and "scan_enable" in line:
                result["control_port"] = names[0]
        if "ICG" in line.upper() and re.search(r"除外|不需要|不参与|不在|except|exclud", line, re.I):
            matches = re.findall(r"`([A-Za-z_$][\w$./]*)`\s*(?:实例)?下|"
                                 r"\*\*([A-Za-z_$][\w$./]*)\*\*\s*[:：]|"
                                 r"\b([A-Za-z_$][\w$./]*)\s*下的除外|"
                                 r"(?:except|excluding)\s+`([A-Za-z_$][\w$./]*)`", line, re.I)
            result["icg_excluded_scopes"].extend(next(x for x in match if x) for match in matches)
        if re.search(r"回替|普通\s*DFF|ordinary\s+DFF|non.scan", line, re.I) and "ICG" not in line.upper():
            for name in names:
                if re.search(r"实例内部|模块|不可扫描|回替|under|subtree|inside", line, re.I):
                    result["unscan_scopes"].append(name)
        # A module description may mention both ICG absence and SFF back-replacement.
        if re.search(r"不可扫描|nonscannable", line, re.I) and re.search(r"回替|ordinary\s+DFF", line, re.I):
            result["unscan_scopes"].extend(names)
        if line.lstrip().startswith("|"):
            columns = [x.strip() for x in line.strip().strip("|").split("|")]
            if len(columns) >= 2:
                pair = [re.fullmatch(r"`([A-Za-z_$][\w$]*)`", x) for x in columns[:2]]
                if all(pair):
                    result["ff_pairs"][pair[0][1]] = pair[1][1]
    for key in ("icg_excluded_scopes", "unscan_scopes"):
        result[key] = sorted({name for name in result[key] if not re.search(r"\.(?:v|vg|lib|dofile|log)$", name, re.I)})
    for key in ("final_netlist_names", "replacement_netlist_names"):
        result[key] = sorted(set(result[key]))
    return result


def partial_flow_artifact_paths(run_dir: Path, spec: str) -> tuple[list[Path], list[Path]]:
    """Find task-named stage outputs, preferring deliverables over reports.

    Missing or ambiguous names return an empty role list, which validation treats
    as incomplete evidence. No case name or artifact filename is built in.
    """
    requirements = partial_insertion_requirements(spec)
    selected = []
    for role in ("final_netlist_names", "replacement_netlist_names"):
        names = requirements[role]
        if len(names) != 1:
            selected.append([]); continue
        found = []
        for folder in (run_dir / "deliverables", run_dir / "reports"):
            candidates = [path for path in folder.rglob(names[0]) if path.is_file() and not path.is_symlink()]
            if candidates:
                found = candidates; break
        selected.append(found if len(found) == 1 else [])
    return selected[0], selected[1]


def _libraries(paths: list[Path]) -> tuple[dict[str, dict[str, Any]], list[str]]:
    cells, unknown = {}, []
    for path in paths:
        text = path.read_text(encoding="utf-8", errors="replace")
        text = re.sub(r"/\*.*?\*/|//[^\n]*", "", text, flags=re.S)
        stack: list[tuple[str, str]] = []
        cell = None
        for event in _LIB_EVENT.finditer(text):
            if event["group"]:
                name = event["group"]
                args = event["args"].strip().strip('"').split('"', 1)[0]
                stack.append((name, args))
                if name == "cell":
                    cell = {"pins": {}, "ffs": [], "icg": False, "scan": False}
                    if args in cells:
                        unknown.append("Duplicate Liberty cell definition: " + args)
                    cells[args] = cell
                elif cell is not None and name == "pin":
                    cell["pins"].setdefault(args, {})
                elif cell is not None and name == "ff" and not any(g == "test_cell" for g, _ in stack):
                    cell["ffs"].append({"states": re.findall(r'"([^"\n]+)"|([A-Za-z_$][\w$]*)', event["args"]),
                                        "properties": {}})
            elif event["open"]:
                stack.append(("unknown", ""))
            elif event["close"]:
                if not stack:
                    unknown.append("Unbalanced Liberty groups: " + str(path))
                    continue
                name, _ = stack.pop()
                if name == "cell":
                    cell = None
            elif event["prop"] and cell is not None and stack:
                key, value = event["prop"], event["value"].strip().strip('"')
                if key == "clock_gating_integrated_cell" and stack[-1][0] == "cell":
                    cell["icg"] = True
                if stack[-1][0] == "pin":
                    pin = cell["pins"][stack[-1][1]]
                    if key in {"direction", "function", "signal_type", "clock_gate_clock_pin", "clock_gate_enable_pin",
                               "clock_gate_test_pin", "clock_gate_out_pin"}:
                        pin[key] = value
                    if key == "signal_type" and value.startswith("test_scan_"):
                        cell["scan"] = True
                elif stack[-1][0] == "ff" and not any(g == "test_cell" for g, _ in stack):
                    if key in _FUNCTION_FIELDS | {"clear_preset_var1", "clear_preset_var2"}:
                        cell["ffs"][-1]["properties"][key] = value
        if stack:
            unknown.append("Unclosed Liberty groups: " + str(path))
    return cells, unknown


def _boolean(expression: str, fixed: dict[str, int] | None = None) -> tuple | None:
    """Canonical truth table for a small literal Liberty Boolean expression."""
    tokens = re.findall(r"[A-Za-z_$][\w$]*|[01]|[!~'&*+|^()]", expression)
    if re.sub(r"\s+", "", "".join(tokens)) != re.sub(r"\s+", "", expression):
        return None
    position = 0
    def atom():
        nonlocal position
        if position >= len(tokens):
            raise ValueError
        value = tokens[position]; position += 1
        if value in {"!", "~"}:
            node = ("not", atom())
        elif value == "(":
            node = disjunction()
            if position >= len(tokens) or tokens[position] != ")":
                raise ValueError
            position += 1
        elif value in {"0", "1"} or _NAME.fullmatch(value):
            node = ("name", value)
        else:
            raise ValueError
        while position < len(tokens) and tokens[position] == "'":
            position += 1; node = ("not", node)
        return node
    def conjunction():
        nonlocal position
        node = atom()
        while position < len(tokens) and tokens[position] in {"&", "*"}:
            position += 1; node = ("and", node, atom())
        return node
    def disjunction():
        nonlocal position
        node = conjunction()
        while position < len(tokens) and tokens[position] in {"+", "|", "^"}:
            op = tokens[position]; position += 1
            node = ("xor" if op == "^" else "or", node, conjunction())
        return node
    try:
        tree = disjunction()
        if position != len(tokens):
            return None
    except ValueError:
        return None
    fixed = fixed or {}
    names = sorted(set(re.findall(r"[A-Za-z_$][\w$]*", expression)) - fixed.keys())
    if len(names) > 8:
        return None
    def evaluate(node, values):
        if node[0] == "name":
            return int(node[1]) if node[1] in {"0", "1"} else values[node[1]]
        if node[0] == "not":
            return 1 - evaluate(node[1], values)
        left, right = evaluate(node[1], values), evaluate(node[2], values)
        return left & right if node[0] == "and" else left ^ right if node[0] == "xor" else left | right
    rows = list(product((0, 1), repeat=len(names)))
    values = [evaluate(tree, {**fixed, **dict(zip(names, row))}) for row in rows]
    # Remove variables that do not affect the result (e.g. inactive scan data).
    relevant = [i for i in range(len(names)) if any(values[j] != values[j ^ (1 << (len(names)-i-1))]
                                                  for j in range(len(rows)))]
    reduced = {}
    for row, value in zip(rows, values):
        reduced[tuple(row[i] for i in relevant)] = value
    return tuple(names[i] for i in relevant), tuple(reduced[key] for key in sorted(reduced))


def _compatible(ordinary: dict, scan: dict) -> bool | None:
    if len(ordinary["ffs"]) != 1 or len(scan["ffs"]) != 1 or ordinary["scan"] or not scan["scan"]:
        return False
    a, b = ordinary["ffs"][0]["properties"], scan["ffs"][0]["properties"]
    enables = [name for name, pin in scan["pins"].items() if pin.get("signal_type") == "test_scan_enable"]
    if len(enables) != 1:
        return None
    unknown = False
    for off in (0, 1):
        good = True
        for key in _FUNCTION_FIELDS:
            if (key in a) != (key in b):
                good = False; break
            if key in a:
                first, last = _boolean(a[key]), _boolean(b[key], {enables[0]: off})
                if first is None or last is None:
                    unknown = True; good = False; break
                if first != last:
                    good = False; break
        for key in {"clear_preset_var1", "clear_preset_var2"}:
            if a.get(key) != b.get(key):
                good = False
        # Output polarity is a part of the functional cell mapping.
        first_outputs = {p: v.get("function") for p, v in ordinary["pins"].items() if v.get("direction") == "output"}
        last_outputs = {p: v.get("function") for p, v in scan["pins"].items() if v.get("direction") == "output"}
        if good and all(last_outputs.get(pin) == value for pin, value in first_outputs.items()):
            return True
    return None if unknown else False


def _modules(paths: list[Path], library: dict) -> tuple[dict, list[str]]:
    modules, unknown, current = {}, [], None
    for path in paths:
        current = None
        for text, line, status in _records(path, 262144):
            module = re.match(rf"module\s+({_ID})\s*\((.*)\)\s*$", text)
            if module:
                name = module[1].removeprefix("\\")
                if name in modules:
                    unknown.append("Duplicate module: " + name)
                current = {"ports": {}, "widths": {}, "cells": [], "assigns": [], "unknown": [], "source": str(path)}
                modules[name] = current
                header = module[2]
                if re.search(r"\b(?:input|output|inout)\b", header):
                    direction, width = None, None
                    for item in header.split(","):
                        found = re.match(r"\s*(input|output|inout)\s+(.*)", item)
                        if found:
                            direction, item, width = found[1], found[2], None
                        width_match = re.match(r"\s*(?:wire\s+|logic\s+|reg\s+)?\[\s*(\d+)\s*:\s*(\d+)\s*\]\s*(.*)", item)
                        if width_match:
                            width = (int(width_match[1]), int(width_match[2])); item = width_match[3]
                        item = re.sub(r"^(?:wire|reg|logic)\s+", "", item.strip())
                        if direction and re.fullmatch(_ID, item):
                            current["ports"][item] = direction; current["widths"][item] = width
                        else:
                            current["unknown"].append(f"Unsupported ANSI port at {path}:L{line}")
                continue
            if status == "scope_end":
                current = None; continue
            if current is None:
                if status == "directive" and re.match(r"`(?:timescale|default_nettype|celldefine|endcelldefine)\b", text):
                    continue
                if text or status != "statement":
                    unknown.append(f"Unparsed source scope at {path}:L{line} ({status})")
                continue
            def unclear(detail):
                current["unknown"].append(f"{detail} at {path}:L{line}")
            if status != "statement":
                unclear("Unsupported Verilog " + status); continue
            declaration = re.fullmatch(r"(input|output|inout|wire|tri|reg|logic)\s+(.+)", text)
            if declaration:
                rest = re.sub(r"^(?:wire|reg|logic|signed|unsigned)\s+", "", declaration[2])
                match = re.match(r"\[\s*(\d+)\s*:\s*(\d+)\s*\]\s*(.*)", rest)
                width = (int(match[1]), int(match[2])) if match else None
                rest = match[3] if match else rest
                for name in rest.split(","):
                    name = name.strip()
                    if not re.fullmatch(_ID, name):
                        unclear("Unsupported declaration"); continue
                    current["widths"][name] = width
                    if declaration[1] in {"input", "output", "inout"}:
                        current["ports"][name] = declaration[1]
                continue
            assignment = re.fullmatch(r"assign\s+(.+?)\s*=\s*(.+)", text)
            if assignment:
                current["assigns"].append((assignment[1].strip(), assignment[2].strip(), line)); continue
            instance = re.fullmatch(rf"({_ID})\s+({_ID})\s*\((.*)\)\s*", text)
            if instance:
                pins, remainder = {}, instance[3]
                pattern = re.compile(rf"\.({_ID})\s*\(([^()]*)\)\s*(?:,\s*|$)")
                while remainder.strip():
                    match = pattern.match(remainder.strip())
                    if not match or match[1].removeprefix("\\") in pins:
                        unclear("Unsupported instance connections"); break
                    pins[match[1].removeprefix("\\")] = match[2].strip()
                    remainder = remainder.strip()[match.end():]
                else:
                    current["cells"].append({"type": instance[1].removeprefix("\\"),
                                             "instance": instance[2].removeprefix("\\"), "pins": pins,
                                             "source": str(path), "line": line})
                continue
            unclear("Unsupported Verilog statement")
    return modules, unknown


def _bits(expression: str, widths: dict) -> list[str] | None:
    value = expression.strip()
    if not value:
        return []
    if value.startswith("{") and value.endswith("}"):
        result = []
        for item in value[1:-1].split(","):
            bits = _bits(item, widths)
            if bits is None:
                return None
            result.extend(bits)
        return result
    constant = re.fullmatch(r"(\d+)'[sS]?([bBoOdDhH])([0-9a-fA-F_]+)", value)
    if constant:
        width = int(constant[1])
        if width > 4096:
            return None
        try:
            number = int(constant[3].replace("_", ""), {"b": 2, "o": 8, "d": 10, "h": 16}[constant[2].lower()])
        except ValueError:
            return None
        return ["$" + str((number >> i) & 1) for i in reversed(range(width))]
    if value in {"0", "1", "'0", "'1"}:
        return ["$" + value[-1]]
    if value.startswith("\\") and re.fullmatch(_ID, value):
        return [value]
    ranged = re.fullmatch(r"([A-Za-z_$][\w$]*)\s*\[\s*(\d+)\s*(?::\s*(\d+)\s*)?\]", value)
    if ranged:
        left, right = int(ranged[2]), int(ranged[3] or ranged[2])
        if abs(left - right) > 4096:
            return None
        return [ranged[1] + f"[{i}]" for i in range(left, right + (-1 if left > right else 1), -1 if left > right else 1)]
    if re.fullmatch(r"[A-Za-z_$][\w$]*", value):
        width = widths.get(value)
        if width is None:
            return [value]
        if abs(width[0] - width[1]) > 4096:
            return None
        return [value + f"[{i}]" for i in range(width[0], width[1] + (-1 if width[0] > width[1] else 1), -1 if width[0] > width[1] else 1)]
    return None


class _Graph:
    def __init__(self):
        self.parent, self.parity, self.rank = {}, {}, {}
        self.drivers = defaultdict(set)
        self.unknown_nodes = set()
        self.contradictions = []

    def find(self, node):
        if node not in self.parent:
            self.parent[node], self.parity[node], self.rank[node] = node, 0, 0
        if self.parent[node] != node:
            parent, inversion = self.find(self.parent[node])
            self.parity[node] ^= inversion; self.parent[node] = parent
        return self.parent[node], self.parity[node]

    def join(self, a, b, inversion=0):
        x, p = self.find(a); y, q = self.find(b)
        if x == y:
            if p ^ q != inversion:
                self.contradictions.append(a)
            return
        if self.rank[x] < self.rank[y]:
            x, y = y, x
        self.parent[y], self.parity[y] = x, p ^ q ^ inversion
        if self.rank[x] == self.rank[y]:
            self.rank[x] += 1

    def finish(self):
        self.sources, self.bad, self.members = defaultdict(set), set(), defaultdict(set)
        for node in self.parent:
            root, parity = self.find(node)
            self.members[root].add((node, parity))
        for node, drivers in self.drivers.items():
            root, parity = self.find(node)
            self.sources[root].update((driver, parity) for driver in drivers)
        for node in self.unknown_nodes | set(self.contradictions):
            self.bad.add(self.find(node)[0])

    def resolve(self, node):
        if node is None:
            return None
        root, parity = self.find(node)
        sources = self.sources.get(root, set())
        # Identical constant drivers are harmless; distinct physical drivers are not.
        normalized = {(source, p ^ parity) for source, p in sources}
        if root in self.bad or len(normalized) > 1:
            return None
        if normalized:
            source, inverted = next(iter(normalized))
            if source in {"$0", "$1"}:
                return ("$" + str(int(source[1]) ^ inverted), 0)
            return source, inverted
        return None  # An undriven declared port/wire never proves connectivity.


def _flatten(modules: dict, library: dict, top: str) -> tuple[dict, _Graph, list[str], set[str]]:
    graph, leaves, unknown, scopes = _Graph(), {}, [], set()
    def walk(kind, prefix, ancestors):
        if kind in ancestors:
            unknown.append("Recursive hierarchy: " + prefix); return
        module = modules[kind]
        unknown.extend(module["unknown"])
        widths = module["widths"]
        def node(bit):
            if bit in {"$0", "$1"}:
                graph.drivers[bit].add(bit); graph.find(bit); return bit
            value = top + "::" + prefix + bit
            graph.find(value); return value
        def signals(expression):
            bits = _bits(expression, widths)
            return [node(bit) for bit in bits] if bits is not None else None
        if not prefix:
            for port, direction in module["ports"].items():
                for bit in _bits(port, widths) or []:
                    if direction == "input":
                        graph.drivers[node(bit)].add(top + "::" + bit)
                    elif direction == "inout":
                        graph.unknown_nodes.add(node(bit))
        for left, right, line in module["assigns"]:
            inversion = int(right.startswith(("!", "~")))
            value = right[1:].strip() if inversion else right
            a, b = signals(left), signals(value)
            if a is None or b is None or len(a) != len(b):
                if a is not None:
                    graph.unknown_nodes.update(a)
                else:
                    unknown.append(f"Unsupported assignment target in {kind}:L{line}")
                continue
            for first, last in zip(a, b):
                graph.join(first, last, inversion)
        instances = set()
        for cell in module["cells"]:
            full = prefix + cell["instance"]
            if cell["instance"] in instances:
                unknown.append("Duplicate instance: " + full); continue
            instances.add(cell["instance"])
            if cell["type"] in modules:
                child = modules[cell["type"]]
                scopes.add(full)
                for port, expression in cell["pins"].items():
                    child_port = port if port in child["ports"] else "\\" + port
                    if child_port not in child["ports"]:
                        unknown.append("Unknown hierarchy port: " + full + "/" + port); continue
                    parent_bits = signals(expression)
                    child_bits = _bits(child_port, child["widths"])
                    if parent_bits is None or child_bits is None or len(parent_bits) != len(child_bits):
                        for bit in child_bits or []:
                            graph.unknown_nodes.add(top + "::" + full + "/" + bit)
                        continue
                    for first, last in zip(parent_bits, child_bits):
                        graph.join(first, top + "::" + full + "/" + last)
                for port, direction in child["ports"].items():
                    if direction in {"input", "inout"} and port.removeprefix("\\") not in cell["pins"]:
                        graph.unknown_nodes.update(top + "::" + full + "/" + bit for bit in _bits(port, child["widths"]) or [])
                walk(cell["type"], full + "/", ancestors | {kind})
                continue
            shape = library.get(cell["type"])
            if shape is None:
                unknown.append("Leaf type absent from actual Liberty: " + cell["type"] + " at " + full)
                continue
            pins = {}
            for pin, expression in cell["pins"].items():
                bits = signals(expression)
                pins[pin] = bits[0] if bits is not None and len(bits) == 1 else None
            leaves[full] = {**cell, "pins": pins}
            for pin, properties in shape["pins"].items():
                if properties.get("direction") != "output" or not pins.get(pin):
                    continue
                output = pins[pin]
                function = re.sub(r"[()\s]", "", properties.get("function", ""))
                simple = re.fullmatch(r"([!~]?)([A-Za-z_$][\w$]*)('?)", function)
                if (not shape["ffs"] and not shape["icg"] and simple and
                      shape["pins"].get(simple[2], {}).get("direction") == "input"):
                    if pins.get(simple[2]):
                        graph.join(output, pins[simple[2]], bool(simple[1]) ^ bool(simple[3]))
                    else:
                        graph.unknown_nodes.add(output)
                else:
                    graph.drivers[output].add(top + "::" + full + "." + pin)
    if top not in modules:
        unknown.append("Required top module missing: " + top)
    else:
        walk(top, "", set())
    graph.finish()
    return leaves, graph, unknown, scopes


def _scope_names(requested: list[str], scopes: set[str], top: str) -> tuple[list[str], list[str]]:
    resolved, unknown = [], []
    for name in requested:
        name = name.removeprefix(top + "/").strip("/")
        found = [scope for scope in scopes if scope == name or ("/" not in name and scope.rsplit("/", 1)[-1] == name)]
        if len(found) != 1:
            unknown.append("Task scope is missing or ambiguous in source: " + name)
        else:
            resolved.append(found[0])
    return resolved, unknown


def partial_insertion_validation(source_paths: list[Path], final_paths: list[Path], libraries: list[Path],
                                 spec: str, *, top: str | None = None,
                                 report_paths: list[Path] | None = None,
                                 replacement_paths: list[Path] | None = None) -> dict[str, Any]:
    """Return JSON-safe proof; ``status`` is pass/fail/unknown/not_applicable.

    Call with the actual pre-scan input and the required final back-replacement
    netlist. ``replacement_paths`` is the actual successful replace-only output;
    its per-instance transitions establish which replacements must survive final
    back-replacement. A missing final file is unknown. Reports can establish an
    analyzed unreplaceable cell; arbitrary user exclusions cannot.
    """
    requirements = partial_insertion_requirements(spec)
    result = {"applicable": requirements["applicable"], "status": "not_applicable", "problems": [],
              "unknown": [], "requirements": requirements, "counts": {}, "evidence": {}}
    if not result["applicable"]:
        return result
    problems, unknown = result["problems"], result["unknown"]
    if requirements["replacement_netlist_names"] and replacement_paths == []:
        unknown.append("Task-declared replace-only output is missing or ambiguous")
    if any(not path.is_file() for path in source_paths + final_paths + libraries + (replacement_paths or [])) or not source_paths or not final_paths or not libraries:
        unknown.append("Actual source, final netlist and Liberty files are required")
        result["status"] = "unknown"; return result
    library, issues = _libraries(libraries); unknown.extend(issues)
    before_modules, issues = _modules(source_paths, library); unknown.extend(issues)
    after_modules, issues = _modules(final_paths, library); unknown.extend(issues)
    selected_top = top or requirements["top"]
    if selected_top is None:
        child_types = {cell["type"] for module in before_modules.values() for cell in module["cells"]}
        roots = sorted(set(before_modules) - child_types)
        if len(roots) == 1:
            selected_top = roots[0]
    if selected_top is None:
        unknown.append("Task/source does not identify one top module")
        result["status"] = "unknown"; return result
    requirements["top"] = selected_top
    before, old_graph, issues, scopes = _flatten(before_modules, library, selected_top); unknown.extend(issues)
    after, new_graph, issues, new_scopes = _flatten(after_modules, library, selected_top); unknown.extend(issues)
    middle_ff = None
    if replacement_paths:
        middle_modules, issues = _modules(replacement_paths, library); unknown.extend(issues)
        middle, _, issues, _ = _flatten(middle_modules, library, selected_top); unknown.extend(issues)
        middle_ff = {name: cell for name, cell in middle.items() if library[cell["type"]]["ffs"]}
    excluded, issues = _scope_names(requirements["icg_excluded_scopes"], scopes, selected_top); unknown.extend(issues)
    unscan, issues = _scope_names(requirements["unscan_scopes"], scopes, selected_top); unknown.extend(issues)
    requirements["resolved_icg_excluded_scopes"], requirements["resolved_unscan_scopes"] = excluded, unscan
    if not set(unscan) <= new_scopes:
        problems.append("Required non-scan hierarchy scopes disappeared from final netlist")
    def inside(identity, prefixes):
        return any(identity.startswith(prefix + "/") for prefix in prefixes)
    def select(cells, key):
        return {name: cell for name, cell in cells.items() if library[cell["type"]][key]}
    old_gates, new_gates = select(before, "icg"), select(after, "icg")
    old_ff = {name: cell for name, cell in before.items() if library[cell["type"]]["ffs"]}
    new_ff = {name: cell for name, cell in after.items() if library[cell["type"]]["ffs"]}
    result["counts"] = {"source_icg": len(old_gates), "final_icg": len(new_gates), "source_ff": len(old_ff),
                        "final_ff": len(new_ff), "final_scan_ff": sum(library[cell["type"]]["scan"] for cell in new_ff.values()),
                        "required_icg_reconnections": 0, "preserved_icg": 0,
                        "source_unscan_ff": sum(inside(name, unscan) for name in old_ff),
                        "final_unscan_ff": sum(inside(name, unscan) for name in new_ff)}
    if set(old_gates) != set(new_gates):
        problems.append("Source/final ICG instance identities or count changed")
    control = requirements["control_port"]
    if old_gates and not control:
        unknown.append("Task does not unambiguously identify the ICG control port")
    expected = old_graph.resolve(selected_top + "::" + control) if control else None
    final_expected = new_graph.resolve(selected_top + "::" + control) if control else None
    if control and (before_modules.get(selected_top, {}).get("ports", {}).get(control) != "input" or
                    after_modules.get(selected_top, {}).get("ports", {}).get(control) != "input" or
                    expected != (selected_top + "::" + control, 0) or final_expected != expected):
        unknown.append("Required ICG control is not proved to be a unique top input driver: " + control)
    examples = []
    for identity in sorted(set(old_gates) & set(new_gates)):
        old, new = old_gates[identity], new_gates[identity]
        if old["type"] != new["type"]:
            problems.append("ICG type changed: " + identity); continue
        shape = library[old["type"]]
        tests = [pin for pin, prop in shape["pins"].items() if prop.get("clock_gate_test_pin") == "true"]
        if len(tests) != 1:
            unknown.append("Liberty does not identify one ICG test pin: " + old["type"]); continue
        test = tests[0]
        old_control, new_control = old_graph.resolve(old["pins"].get(test)), new_graph.resolve(new["pins"].get(test))
        targeted = old_control == ("$0", 0) and not inside(identity, excluded)
        result["counts"]["required_icg_reconnections" if targeted else "preserved_icg"] += 1
        if old_control is None or new_control is None:
            unknown.append("ICG test driver cannot be proved: " + identity + "/" + test)
        elif targeted:
            if final_expected is None or new_control[0] != final_expected[0]:
                problems.append("ICG test pin lacks the task-required top input driver: " + identity + "/" + test)
        elif old_control != new_control:
            problems.append("ICG outside reconnect targets changed its test connection: " + identity + "/" + test)
        for pin, properties in shape["pins"].items():
            if pin == test or properties.get("direction") not in {"input", "output"}:
                continue
            first, last = old_graph.resolve(old["pins"].get(pin)), new_graph.resolve(new["pins"].get(pin))
            if first is None or last is None:
                unknown.append("ICG original/final input cannot be proved: " + identity + "/" + pin)
            elif first != last:
                problems.append("ICG functional input changed: " + identity + "/" + pin)
            elif properties.get("direction") == "output":
                # The cell output driver has the same identity even when it was
                # reconnected to another wire. Prove its original terminal still
                # belongs to the final output component as well.
                old_terminal = old["pins"].get(pin)
                if old_terminal not in new_graph.parent:
                    problems.append("ICG output connection changed: " + identity + "/" + pin)
                elif new_graph.resolve(old_terminal) != last:
                    problems.append("ICG output connection changed: " + identity + "/" + pin)
        if len(examples) < 8 or inside(identity, excluded) and not any(item["excluded"] for item in examples):
            examples.append({"instance": identity, "source": old["source"], "source_line": old["line"],
                             "final_source": new["source"], "final_line": new["line"], "excluded": inside(identity, excluded),
                             "targeted": targeted, "old_test_driver": old_control, "final_test_driver": new_control})
    result["evidence"]["icg_examples"] = examples
    if set(old_ff) != set(new_ff):
        problems.append("Source/final FF instance identities or total count changed")
    if middle_ff is not None and set(old_ff) != set(middle_ff):
        problems.append("Actual replace-only output changed source FF identities or total count")
    if any(len(library[cell["type"]]["ffs"]) != 1 for cell in list(old_ff.values()) + list(new_ff.values())):
        unknown.append("Multi-bit Liberty FFs require a bit-level elaborator")
    mappings = requirements["ff_pairs"]
    for ordinary, scanned in mappings.items():
        if ordinary not in library or scanned not in library or _compatible(library[ordinary], library[scanned]) is not True:
            unknown.append("Task FF mapping lacks actual Liberty functional proof: " + ordinary + " -> " + scanned)
    state_rows = {}
    for path in report_paths or []:
        if "element" not in path.name.lower():
            continue
        for row in report_rows(path, {"InstanceName", "ObjState", "Type"}):
            identity = row["InstanceName"].lstrip("/").removeprefix(selected_top + "/")
            state_rows.setdefault(identity, set()).add(row["ObjState"])
    compatibility = {}
    ordinary_types = {cell["type"] for cell in old_ff.values() if not library[cell["type"]]["scan"]}
    scan_types = {kind for kind, cell in library.items() if cell["scan"] and cell["ffs"]}
    for kind in ordinary_types:
        # The tool may select an equivalent variant with an additional unused
        # inverted output. Actual Liberty behavior proves the variant, not names.
        candidates = scan_types
        compatibility[kind] = {candidate for candidate in candidates if candidate in library and
                               _compatible(library[kind], library[candidate]) is True}
    ff_violations = []
    for identity in sorted(set(old_ff) & set(new_ff)):
        old, new = old_ff[identity], new_ff[identity]
        first, last = library[old["type"]], library[new["type"]]
        issue = None
        if inside(identity, unscan):
            if last["scan"]:
                issue = "Required non-scan subtree still contains a scan FF"
            elif first["scan"] and _compatible(last, first) is not True:
                issue = "Back-replaced FF lacks equivalent Liberty behavior"
            elif not first["scan"] and old["type"] != new["type"]:
                issue = "Ordinary FF in non-scan subtree changed type"
        elif first["scan"]:
            if not last["scan"]:
                issue = "Existing scan FF outside back-replacement scopes became ordinary"
            elif old["type"] != new["type"]:
                unknown.append("Existing scan FF changed type outside requested scopes: " + identity)
        elif last["scan"]:
            if new["type"] not in compatibility.get(old["type"], set()):
                issue = "FF replacement does not match task/Liberty functional mapping"
        else:
            observed = state_rows.get(identity, set())
            justified = len(observed) == 1 and bool(re.search(r"unreplaceable|not_replaceable|no_scan_equivalent", next(iter(observed), ""), re.I))
            middle_cell = middle_ff.get(identity) if middle_ff is not None else None
            actually_replaced = middle_cell is not None and library[middle_cell["type"]]["scan"]
            unchanged_in_replacement = middle_cell is not None and middle_cell["type"] == old["type"]
            if actually_replaced or compatibility.get(old["type"]) and not justified and not unchanged_in_replacement:
                issue = "Replaceable FF outside back-replacement scopes remained ordinary"
            elif old["type"] != new["type"]:
                issue = "Unreplaced ordinary FF changed type"
            elif not compatibility.get(old["type"]) and not justified and not unchanged_in_replacement:
                unknown.append("Actual tool eligibility not proved for unmapped ordinary FF: " + identity)
        if issue:
            ff_violations.append({"instance": identity, "source_type": old["type"], "final_type": new["type"],
                                  "source": old["source"], "source_line": old["line"], "final_source": new["source"],
                                  "final_line": new["line"], "reason": issue})
        for pin, properties in first["pins"].items():
            if properties.get("direction") != "input" or properties.get("signal_type", "").startswith("test_scan_"):
                continue
            original_signal = old_graph.resolve(old["pins"].get(pin))
            final_signal = new_graph.resolve(new["pins"].get(pin))
            if original_signal is None or final_signal is None:
                # Existing floating functional inputs can remain physically
                # connected to the identical original net. This proves the
                # requested preservation, without claiming that it has a driver.
                if not old["pins"].get(pin) or old["pins"].get(pin) != new["pins"].get(pin):
                    unknown.append("FF functional input cannot be proved: " + identity + "/" + pin)
            elif original_signal != final_signal:
                ff_violations.append({"instance": identity, "source_type": old["type"], "final_type": new["type"],
                                      "source": old["source"], "source_line": old["line"], "final_source": new["source"],
                                      "final_line": new["line"], "reason": "FF functional input changed: " + pin})
    if ff_violations:
        for reason, count in Counter(item["reason"] for item in ff_violations).items():
            problems.append(f"{reason}: {count} instance(s)")
    result["evidence"]["ff_violation_count"] = len(ff_violations)
    result["evidence"]["ff_violation_examples"] = ff_violations[:12]
    result["evidence"]["eligibility_basis"] = ("Actual successful replace-only per-instance output; retained ordinary FFs were not replaced by that tool stage"
                                               if middle_ff is not None else "Actual Liberty mappings and available analyzed element-state reports")
    if middle_ff is not None:
        result["counts"]["replace_only_scan_ff"] = sum(library[cell["type"]]["scan"] for cell in middle_ff.values())
    def chain_edges(cells, graph):
        outputs = defaultdict(set)
        for identity, cell in cells.items():
            for pin, properties in library[cell["type"]]["pins"].items():
                if properties.get("direction") == "output":
                    signal = graph.resolve(cell["pins"].get(pin))
                    if signal:
                        outputs[signal[0]].add(identity)
        edges = set()
        for identity, cell in cells.items():
            for pin, properties in library[cell["type"]]["pins"].items():
                if properties.get("signal_type") == "test_scan_in":
                    signal = graph.resolve(cell["pins"].get(pin))
                    if signal:
                        edges.update((source, identity) for source in outputs.get(signal[0], set()))
                    else:
                        unknown.append("Scan data input cannot be proved free of a chain: " + identity + "/" + pin)
        return edges
    added_edges = chain_edges(new_ff, new_graph) - chain_edges(old_ff, old_graph)
    if added_edges:
        problems.append("Replacement-only flow introduced FF-to-scan-input chain connections")
    result["evidence"]["new_scan_chain_edges"] = sorted(added_edges)[:12]
    if selected_top in before_modules and selected_top in after_modules:
        added_ports = set(after_modules[selected_top]["ports"]) - set(before_modules[selected_top]["ports"])
        data_signals = set()
        for cell in new_ff.values():
            for pin, properties in library[cell["type"]]["pins"].items():
                if properties.get("signal_type") in {"test_scan_in", "test_scan_out", "test_scan_out_inverted"}:
                    signal = new_graph.resolve(cell["pins"].get(pin))
                    if signal:
                        data_signals.add(signal)
        new_scan_ports = []
        for port in sorted(added_ports):
            bits = _bits(port, after_modules[selected_top]["widths"]) or []
            if any(new_graph.resolve(selected_top + "::" + bit) in data_signals for bit in bits):
                new_scan_ports.append(port)
        if new_scan_ports:
            problems.append("Replacement-only flow introduced top scan data ports: " + ", ".join(new_scan_ports))
        result["evidence"]["new_top_ports"] = sorted(added_ports)
    # Deduplicate diagnostics while preserving evidence order and bound display.
    result["unknown_count"] = len(set(unknown))
    result["unknown"] = list(dict.fromkeys(unknown))[:128]
    result["problems"] = list(dict.fromkeys(problems))
    result["status"] = "fail" if problems else "unknown" if unknown else "pass"
    return result


def partial_insertion_problems(*args, **kwargs) -> list[str]:
    """Admission helper: both a disproved and an incomplete proof block PASS."""
    result = partial_insertion_validation(*args, **kwargs)
    return result["problems"] + ["Partial-flow structural proof incomplete: " + item for item in result["unknown"]]
