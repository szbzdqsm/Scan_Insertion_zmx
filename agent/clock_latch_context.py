"""Bounded, source-only hints for simple latch-based clock-gating modules."""
from __future__ import annotations

import json
from pathlib import Path
import re
from typing import Any


_IDENTIFIER = r"[A-Za-z_$][\w$]*"
_NET = re.compile(rf"{_IDENTIFIER}(?:\[\d+\])?\Z")
_CELL = re.compile(r"\s*([\w$]+)\s+(\\\S+|[\w$\[\].]+)\s*\(")
_RESERVED = {"input", "output", "inout", "wire", "reg", "logic", "signed", "unsigned", "tri"}


def _scalar(value: str) -> str | None:
    value = value.strip().removeprefix("\\")
    return value if _NET.fullmatch(value) else None


def _source_line(raw: str, blocked: bool) -> tuple[str, bool]:
    parts = []
    while raw:
        if blocked:
            end = raw.find("*/")
            if end < 0:
                break
            raw = raw[end + 2:]
            blocked = False
        start = raw.find("/*")
        comment = raw.find("//")
        if comment >= 0 and (start < 0 or comment < start):
            parts.append(raw[:comment])
            break
        if start < 0:
            parts.append(raw)
            break
        parts.append(raw[:start])
        raw = raw[start + 2:]
        blocked = True
    return "".join(parts), blocked


def _library_shapes(paths: list[Path]) -> dict[str, dict[str, Any]]:
    """Keep only literal pin functions and one-latch definitions, not timing data."""
    result = {}
    current = None
    depth = 0
    pin = ""
    pin_depth = 0
    latch_depth = 0
    for path in paths:
        with path.open(encoding="utf-8", errors="replace") as stream:
            for line in stream:
                cell = re.match(r'\s*cell\s*\(\s*"?([^"\s)]+)', line)
                if cell:
                    current = {"name": cell.group(1), "pins": {}, "latches": []}
                    depth = 0
                if current is None:
                    continue
                depth += line.count("{") - line.count("}")
                found_pin = re.match(r'\s*pin\s*\(\s*"?([^"\s)]+)', line)
                if found_pin:
                    pin = found_pin.group(1)
                    pin_depth = depth
                    current["pins"][pin] = {}
                latch = re.match(r'\s*latch\s*\(\s*"?([^",\s)]+)', line)
                if latch:
                    current["latches"].append({"state": latch.group(1)})
                    latch_depth = depth
                if pin:
                    prop = re.match(r'\s*(direction|function)\s*:\s*"([^"\n]+)"', line)
                    if prop:
                        current["pins"][pin][prop.group(1)] = prop.group(2)
                if latch_depth:
                    prop = re.match(r'\s*(enable|data_in)\s*:\s*"([^"\n]+)"', line)
                    if prop:
                        current["latches"][-1][prop.group(1)] = prop.group(2)
                if depth < pin_depth:
                    pin = ""
                if depth < latch_depth:
                    latch_depth = 0
                if depth == 0:
                    name = current.pop("name")
                    if name in result:
                        result[name] = {"pins": {}, "latches": []}
                    else:
                        result[name] = current
                    current = None
                    pin = ""
                    pin_depth = latch_depth = 0
    return result


def _modules(paths: list[Path], library: dict[str, Any], maximum_cells: int = 32,
             selected: set[str] | None = None) -> dict[str, dict[str, Any]]:
    modules = {}
    current = None
    pending = None
    discarding = False
    hierarchy_count = 0
    names = set()
    buffers = {}
    for kind, shape in library.items():
        pairs = [(output, pin["function"]) for output, pin in shape["pins"].items()
                 if pin.get("direction") == "output" and pin.get("function") in shape["pins"] and
                 shape["pins"][pin["function"]].get("direction") == "input"]
        if len(pairs) == 1 and not shape["latches"]:
            buffers[kind] = pairs[0]
    for path in paths:
        blocked = False
        with path.open(encoding="utf-8", errors="replace") as stream:
            for number, raw in enumerate(stream, 1):
                if not blocked and raw.lstrip().startswith("//"):
                    continue
                line, blocked = _source_line(raw, blocked)
                module = re.match(r"\s*module\s+([\w$]+)", line)
                if module:
                    name = module.group(1)
                    if name in names or len(names) >= 100000:
                        return {}
                    names.add(name)
                    if selected is not None and name not in selected:
                        current = None
                        pending = None
                        discarding = False
                        continue
                    small = bool(re.search(r"clk|clock|gate|buf", name, re.I))
                    current = {"name": name, "inputs": set(), "outputs": set(), "aliases": {},
                               "hierarchy": [], "children": set(), "cells": [], "ambiguous": False,
                               "small": small, "detailed": selected is not None or small}
                    if not current["detailed"]:
                        current = {"name": name, "children": set(), "small": False, "detailed": False}
                    modules[name] = current
                    pending = None
                    discarding = False
                if current is None:
                    continue
                if not current["detailed"]:
                    found = _CELL.match(line)
                    if found and found.group(1) != "module" and found.group(1) not in library and not found.group(1).startswith("sky130_fd_sc_"):
                        current["children"].add(found.group(1))
                    if line.lstrip().startswith("endmodule"):
                        current = None
                    continue
                if discarding:
                    if ";" in line:
                        discarding = False
                    continue
                if pending is None and line.lstrip().startswith("."):
                    continue
                for direction in ("input", "output"):
                    for declaration in re.finditer(rf"\b{direction}\s+([^;)]*)", line):
                        text = re.split(r"\b(?:input|output|inout)\b", declaration.group(1))[0]
                        ports = re.findall(_IDENTIFIER, re.sub(r"\[[^]]*\]", "", text))
                        current[direction + "s"].update(port for port in ports if port not in _RESERVED)
                    if len(current[direction + "s"]) > 512:
                        current["ambiguous"] = True
                        current[direction + "s"].clear()
                alias = re.fullmatch(r"\s*assign\s+(\S+)\s*=\s*(\S+)\s*;\s*", line)
                if alias and len(current["aliases"]) < 512:
                    left, right = (_scalar(part) for part in alias.groups())
                    if left and right:
                        if left in current["aliases"] and current["aliases"][left] != right:
                            current["ambiguous"] = True
                        current["aliases"][left] = right
                if pending is None:
                    found = _CELL.match(line)
                    if found and found.group(1) != "module":
                        kind = found.group(1)
                        standard = kind in library or kind.startswith("sky130_fd_sc_")
                        if not standard:
                            current["children"].add(kind)
                        if not standard or current["small"] or kind in buffers:
                            pending = {"type": kind, "instance": found.group(2).removeprefix("\\"),
                                       "literal": line, "line": number, "source": str(path), "standard": standard}
                else:
                    pending["literal"] += line
                if pending is not None and len(pending["literal"]) > 16384:
                    current["small"] = False
                    current["cells"].clear()
                    pending = None
                    discarding = ";" not in line
                if pending is not None and ";" in line:
                    pairs = re.findall(r"\.([\w$]+)\s*\(([^()]*)\)", pending.pop("literal"))
                    if not pairs or len({pin for pin, _ in pairs}) != len(pairs):
                        current["ambiguous"] = True
                    pending["pins"] = {pin: value for pin, raw_value in pairs if (value := _scalar(raw_value))}
                    if pending["type"] in buffers:
                        output, source = buffers[pending["type"]]
                        if {output, source} <= pending["pins"].keys():
                            left, right = pending["pins"][output], pending["pins"][source]
                            if left in current["aliases"] and current["aliases"][left] != right:
                                current["ambiguous"] = True
                            if len(current["aliases"]) < 512:
                                current["aliases"][left] = right
                    if not pending.pop("standard"):
                        hierarchy_count += 1
                        if hierarchy_count > 50000:
                            return {}
                        current["hierarchy"].append(pending)
                    if current["small"]:
                        current["cells"].append(pending)
                        if len(current["cells"]) > maximum_cells:
                            current["cells"].clear()
                            current["small"] = False
                            if selected is None:
                                name, children = current["name"], current["children"]
                                current.clear()
                                current.update(name=name, children=children, small=False, detailed=False)
                    pending = None
                if re.match(r"\s*endmodule\b", line):
                    if selected is None and not _patterns(current, library):
                        name, children = current["name"], current["children"]
                        current.clear()
                        current.update(name=name, children=children, small=False, detailed=False)
                    current = None
                    pending = None
    return modules


def _alias(module: dict[str, Any], net: str) -> str | None:
    visited = set()
    while net in module["aliases"]:
        if net in visited:
            return None
        visited.add(net)
        net = module["aliases"][net]
    return net


def _patterns(module: dict[str, Any], library: dict[str, Any]) -> list[dict[str, Any]]:
    if not module["small"] or module["ambiguous"]:
        return []
    if any(cell["type"] not in library for cell in module["cells"]):
        return []
    drivers = {}
    for cell in module["cells"]:
        for name, pin in library[cell["type"]]["pins"].items():
            if pin.get("direction") == "output" and name in cell["pins"]:
                net = cell["pins"][name]
                drivers[net] = drivers.get(net, 0) + 1
    if any(count != 1 for count in drivers.values()):
        return []
    found = []
    for latch in module["cells"]:
        shape = library.get(latch["type"], {})
        if len(shape.get("latches", [])) != 1:
            continue
        definition = shape["latches"][0]
        enable = re.fullmatch(rf"(!?)({_IDENTIFIER})", definition.get("enable", "").replace(" ", ""))
        data_pin = definition.get("data_in", "")
        if not enable or not re.fullmatch(_IDENTIFIER, data_pin):
            continue
        outputs = [name for name, pin in shape["pins"].items() if pin.get("direction") == "output" and
                   pin.get("function", "").replace(" ", "") == definition["state"]]
        if len(outputs) != 1:
            continue
        q_pin, gate_pin = outputs[0], enable.group(2)
        if not {q_pin, gate_pin, data_pin} <= latch["pins"].keys():
            continue
        clock = _alias(module, latch["pins"][gate_pin])
        q_net = _alias(module, latch["pins"][q_pin])
        if clock not in module["inputs"] or clock == q_net:
            continue
        matches = []
        for cell in module["cells"]:
            for output, pin in library.get(cell["type"], {}).get("pins", {}).items():
                expression = re.sub(r"[()\s]", "", pin.get("function", ""))
                conjunction = re.fullmatch(rf"({_IDENTIFIER})[&*]({_IDENTIFIER})", expression)
                if pin.get("direction") != "output" or not conjunction:
                    continue
                operands = conjunction.groups()
                if not {output, *operands} <= cell["pins"].keys():
                    continue
                nets = {_alias(module, cell["pins"][operand]) for operand in operands}
                output_net = _alias(module, cell["pins"][output])
                exported = [name for name in module["outputs"] if _alias(module, name) == output_net]
                if nets == {clock, q_net} and len(exported) == 1:
                    matches.append((cell, output, exported[0]))
        if len(matches) != 1:
            continue
        cell, output, port = matches[0]
        found.append({"clock_input": clock, "clock_output": port, "latch": latch,
                      "latch_data_pin": data_pin, "latch_gate_pin": gate_pin, "latch_q_pin": q_pin,
                      "latch_transparent_clock_level": 0 if enable.group(1) else 1,
                      "and_cell": cell, "and_output_pin": output})
    return found


def clock_latch_hints(paths: list[Path], libraries: list[Path], maximum_hints: int = 12) -> list[dict[str, Any]]:
    """Trace only unambiguous scalar named-port gate shapes to a root input."""
    library = _library_shapes(libraries)
    if not library:
        return []
    modules = _modules(paths, library)
    children = {kind for module in modules.values() for kind in module["children"]}
    selected = {name for name, module in modules.items() if _patterns(module, library)}
    if not selected:
        return []
    roots = sorted(set(modules) - children)
    parents = {}
    for name, module in modules.items():
        for child in module["children"]:
            parents.setdefault(child, set()).add(name)
    pending = list(selected)
    while pending:
        child = pending.pop()
        for parent in parents.get(child, set()) - selected:
            selected.add(parent)
            pending.append(parent)
    modules = _modules(paths, library, selected=selected)
    patterns = {name: _patterns(module, library) for name, module in modules.items()}
    hints = []
    visits = 0

    def walk(name: str, prefix: str, inputs: dict[str, str], exposures: dict[str, list[str]],
             ancestors: set[str], root: str, placement: dict[str, Any] | None = None) -> None:
        nonlocal visits
        visits += 1
        if name in ancestors or visits > 100000 or len(hints) >= maximum_hints:
            return
        module = modules[name]
        if module["ambiguous"]:
            return
        for pattern in patterns[name]:
            primary = inputs.get(pattern["clock_input"])
            if not primary:
                continue
            latch, conjunction = pattern["latch"], pattern["and_cell"]
            hints.append({"root": root, "module": name, "instance": prefix.rstrip("/"),
                          "root_primary_clock_candidate": primary,
                          "clock_input_pin": prefix + pattern["clock_input"],
                          "clock_output_candidates": [prefix + pattern["clock_output"]] + exposures.get(pattern["clock_output"], []),
                          "enable_data_pin": prefix + latch["instance"] + "/" + pattern["latch_data_pin"],
                          "enable_data_net": latch["pins"][pattern["latch_data_pin"]],
                          "enable_latch_q_pin": prefix + latch["instance"] + "/" + pattern["latch_q_pin"],
                          "and_clock_output_pin": prefix + conjunction["instance"] + "/" + pattern["and_output_pin"],
                          "latch_transparent_clock_level": pattern["latch_transparent_clock_level"],
                          "module_instance_connections": placement,
                          "literal_cells": [{"type": item["type"], "instance": prefix + item["instance"],
                                             "pins": item["pins"], "source": item["source"], "line": item["line"]}
                                            for item in (latch, conjunction)]})
            if len(hints) >= maximum_hints:
                return
        for cell in module["hierarchy"]:
            if cell["type"] not in modules:
                continue
            child = modules[cell["type"]]
            bound = {pin: inputs[net] for pin, value in cell["pins"].items()
                     if pin in child["inputs"] and (net := _alias(module, value)) in inputs}
            exported = {}
            for pin in child["outputs"]:
                value = cell["pins"].get(pin)
                if not value:
                    continue
                net = _alias(module, value)
                ports = [port for port in module["outputs"] if _alias(module, port) == net]
                if len(ports) == 1:
                    port = ports[0]
                    exported[pin] = [prefix + port] + exposures.get(port, [])
            placement = {"parent_module": name, "instance": prefix + cell["instance"], "pins": cell["pins"],
                         "source": cell["source"], "line": cell["line"]}
            walk(cell["type"], prefix + cell["instance"] + "/", bound, exported, ancestors | {name}, root, placement)

    for root in roots:
        if root not in modules:
            continue
        walk(root, "", {port: port for port in modules[root]["inputs"]}, {}, set(), root)
    return hints


def clock_latch_context(paths: list[Path], libraries: list[Path], limit: int = 5000) -> str:
    hints = clock_latch_hints(paths, libraries)
    if not hints:
        return ""
    header = ("Source-only candidates for simple latch-based clock gates; verify with actual tool reports. "
              "The latch D/CE and Q carry ENABLE DATA, not a clock waveform. Its gate input and AND clock operand "
              "trace to the listed root primary input; the AND output/hierarchy output are clock-output candidates. "
              "No configuration command or proven DRC fix is inferred. Complex mappings are omitted.\n")
    retained = []
    for hint in hints:
        candidate = header + json.dumps(retained + [hint], ensure_ascii=False)
        if len(candidate) > limit:
            break
        retained.append(hint)
    return header + json.dumps(retained, ensure_ascii=False) if retained else ""
