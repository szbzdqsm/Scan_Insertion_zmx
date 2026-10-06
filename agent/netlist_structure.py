"""Read-only structural hints for gate-level shift registers; no synthesized artifacts."""
from __future__ import annotations

from collections import defaultdict
import json
from pathlib import Path
import re
from typing import Any


def normalized_net(value: str) -> str:
    return re.sub(r"\s+", "", value).removeprefix("\\")


def shift_register_groups(paths: list[Path], minimum: int = 10,
                          libraries: list[Path] | None = None,
                          reset_hints: dict[str, Any] | None = None,
                          instance_map: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    """Find unbranched Q-to-D chains starting with actual scan FFs within a module."""
    if sum(path.stat().st_size for path in paths) > 64 * 1024 * 1024:
        return []
    modules: dict[str, list[dict[str, Any]]] = defaultdict(list)
    aliases: dict[str, dict[str, str]] = defaultdict(dict)
    clock_inversions: dict[str, dict[str, str]] = defaultdict(dict)
    library_pins: dict[str, set[str]] = defaultdict(set)
    library_resets: dict[str, dict[str, int]] = defaultdict(dict)
    input_ports: dict[str, set[str]] = defaultdict(set)
    for library in libraries or []:
        kind = ""
        with library.open(encoding="utf-8", errors="replace") as stream:
            for line in stream:
                cell = re.match(r'\s*cell\s*\(\s*"?([^"\s)]+)', line)
                if cell:
                    kind = cell.group(1)
                pin = re.match(r'\s*pin\s*\(\s*"?([^"\s)]+)', line)
                if pin and "__sdf" in kind:
                    library_pins[kind].add(pin.group(1))
                reset = re.match(r'\s*(?:clear|preset)\s*:\s*"([^"\n]+)"', line)
                if reset:
                    expression = re.sub(r"[()\s]", "", reset.group(1))
                    simple = re.fullmatch(r"(!?)([A-Za-z_][\w$]*)", expression)
                    if simple:
                        library_resets[kind][simple.group(2)] = 1 if simple.group(1) else 0
    current = ""
    pending: tuple[str, str, str] | None = None
    for path in paths:
        with path.open(encoding="utf-8", errors="replace") as stream:
            for raw in stream:
                line = raw.split("//", 1)[0]
                module = re.match(r"\s*module\s+([\w$]+)", line)
                if module:
                    current = module.group(1)
                    modules[current]
                if not current:
                    continue
                for declaration in re.finditer(r"\binput\s+([^;)]*)", line):
                    words = re.findall(r"[A-Za-z_][\w$]*", re.split(r"\b(?:output|inout)\b", declaration.group(1))[0])
                    input_ports[current].update(word for word in words if word not in {"input", "wire", "reg", "logic", "signed", "unsigned", "tri"})
                assignment = re.match(r"\s*assign\s+(\\?[^\s=]+)\s*=\s*(\\?[^;\s]+)\s*;", line)
                if assignment:
                    aliases[current][normalized_net(assignment.group(1))] = normalized_net(assignment.group(2))
                if pending is None:
                    cell = re.match(r"\s*([\w$]+)\s+(\\\S+|[\w$\[\].]+)\s*\(", line)
                    if cell and cell.group(1) != "module" and (not cell.group(1).startswith("sky130_fd_sc_") or
                            any(marker in cell.group(1) for marker in ("__df", "__sdf", "__dl", "__sdl", "__buf_", "__clkbuf_", "__inv_", "__clkinv_"))):
                        pending = (cell.group(1), cell.group(2).removeprefix("\\"), line)
                else:
                    pending = (pending[0], pending[1], pending[2] + line)
                if pending and ";" in line:
                    kind, instance, text = pending
                    pins = dict((name, normalized_net(net)) for name, net in
                                re.findall(r"\.([\w$]+)\s*\(\s*([^()]*)\)", text))
                    if instance_map is not None:
                        instance_map.setdefault(current, {})[instance] = {"type": kind, "pins": sorted(pins)}
                    if any(marker in kind for marker in ("__buf_", "__clkbuf_")) and "X" in pins and "A" in pins:
                        aliases[current][pins["X"]] = pins["A"]
                    elif any(marker in kind for marker in ("__inv_", "__clkinv_")) and "Y" in pins and "A" in pins:
                        clock_inversions[current][pins["Y"]] = pins["A"]
                    else:
                        modules[current].append({"kind": kind, "instance": instance, "pins": pins})
                    pending = None
                if re.match(r"\s*endmodule\b", line):
                    current = ""
                    pending = None
    child_types = {cell["kind"] for cells in modules.values() for cell in cells if cell["kind"] in modules}
    roots = sorted(set(modules) - child_types)
    flattened: dict[str, list[dict[str, Any]]] = defaultdict(list)
    inverted_clocks: dict[str, str] = {}
    def walk(module: str, prefix: str, bindings: dict[str, str], ancestors: set[str], top: str) -> None:
        if module in ancestors or len(flattened[top]) > 200000:
            return
        def qualified(net: str) -> str:
            seen = set()
            while net not in seen:
                seen.add(net)
                base = re.sub(r"(?:\[\d+\])+$", "", net)
                suffix = net[len(base):]
                if net in aliases[module]:
                    net = aliases[module][net]
                elif base in aliases[module] and suffix:
                    net = aliases[module][base] + suffix
                else:
                    break
            if net in bindings:
                return bindings[net]
            base = re.sub(r"(?:\[\d+\])+$", "", net)
            suffix = net[len(base):]
            if base in bindings and suffix and not re.search(r"[:{},()]", bindings[base].split("::", 1)[-1]):
                return bindings[base] + suffix
            return top + "::" + prefix + net
        for output, source in clock_inversions[module].items():
            inverted_clocks[qualified(output)] = qualified(source)
        for cell in modules[module]:
            pins = {pin: qualified(net) for pin, net in cell["pins"].items()}
            if cell["kind"] in modules:
                walk(cell["kind"], prefix + cell["instance"] + "/", pins, ancestors | {module}, top)
            elif re.search(r"__(?:s?df)", cell["kind"]):
                flattened[top].append({**cell, "instance": prefix + cell["instance"], "pins": pins})
    for root in roots:
        walk(root, "", {}, set(), root)
    def clock(net: str) -> tuple[str, bool]:
        parity = False
        visited = set()
        while net in inverted_clocks and net not in visited:
            visited.add(net)
            net = inverted_clocks[net]
            parity = not parity
        return net, parity
    if reset_hints is not None:
        for root, cells in flattened.items():
            levels: dict[str, set[int]] = defaultdict(set)
            targets: dict[str, list[str]] = defaultdict(list)
            for cell in cells:
                for pin, inactive in library_resets[cell["kind"]].items():
                    if pin not in cell["pins"]:
                        continue
                    driver, inverted = clock(cell["pins"][pin])
                    name = driver.removeprefix(root + "::")
                    if name not in input_ports[root]:
                        continue
                    levels[name].add(inactive ^ int(inverted))
                    targets[name].append(cell["instance"] + "/" + pin)
            reset_hints[root] = {name: {"inactive_level": next(iter(values)), "traced_targets": len(targets[name]),
                                      "example_pins": targets[name][:3]}
                                 for name, values in levels.items() if len(values) == 1}
    found = []
    for name, cells in flattened.items():
        sequential = [cell for cell in cells if "D" in cell["pins"] and "Q" in cell["pins"]
                      and re.search(r"__(?:s?df)", cell["kind"])]
        consumers: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for cell in sequential:
            consumers[cell["pins"]["D"]].append(cell)
        for seed in sequential:
            pin_names = set(seed["pins"]) | library_pins[seed["kind"]]
            scan_in = next((pin for pin in ("SCD", "SI") if pin in pin_names), None)
            scan_enable = next((pin for pin in ("SCE", "SE") if pin in pin_names), None)
            if "__sdf" not in seed["kind"] or not scan_in or not scan_enable:
                continue
            chain = [seed]
            visited = {seed["instance"]}
            while len(chain) <= 4096:
                next_cells = consumers.get(chain[-1]["pins"]["Q"], [])
                if len(next_cells) != 1:
                    break
                cell = next_cells[0]
                if cell["instance"] in visited or "__sdf" in cell["kind"]:
                    break
                if not cell["pins"].get("CLK") or clock(cell["pins"]["CLK"]) != clock(seed["pins"].get("CLK", "")):
                    break
                visited.add(cell["instance"])
                chain.append(cell)
            if len(chain) >= minimum and len(chain) <= 4096:
                found.append({"root": name, "start": seed["instance"], "end": chain[-1]["instance"],
                                    "length": len(chain), "si_pin": scan_in, "se_pin": scan_enable, "so_pin": "Q"})
    groups: dict[tuple, list[dict[str, Any]]] = defaultdict(list)
    for row in found:
        signature = (row["root"], re.sub(r"\[\d+\]", "[*]", row["start"]), re.sub(r"\[\d+\]", "[*]", row["end"]),
                     row["length"], row["si_pin"], row["se_pin"], row["so_pin"])
        groups[signature].append(row)
    hints = []
    for signature, rows in groups.items():
        starts = [re.findall(r"\[(\d+)\]", row["start"]) for row in rows]
        ends = [re.findall(r"\[(\d+)\]", row["end"]) for row in rows]
        variable = [index for index in range(len(starts[0])) if len({values[index] for values in starts}) > 1]
        start_replacements = {index: "{i" + str(number) + "}" for number, index in enumerate(variable)}
        end_replacements = {}
        for index in range(len(ends[0])):
            values = [value[index] for value in ends]
            if len(set(values)) <= 1:
                continue
            matching = next((start_index for start_index in variable
                             if [value[start_index] for value in starts] == values), None)
            if matching is None:
                break
            end_replacements[index] = start_replacements[matching]
        else:
            def template(text: str, replacements: dict[int, str]) -> str:
                counter = iter(range(1000))
                return re.sub(r"\[(\d+)\]", lambda match: "[" + replacements.get(next(counter), match.group(1)) + "]", text)
            hints.append({"root": signature[0], "start_template": template(rows[0]["start"], start_replacements),
                          "end_template": template(rows[0]["end"], end_replacements),
                          "length": signature[3], "scan_data_in_pin": signature[4],
                          "scan_enable_pin": signature[5], "scan_data_out_pin": signature[6],
                          "index_tuples": [[int(values[index]) for index in variable] for values in starts],
                          "count": len(rows)})
    return hints


def shift_register_context(paths: list[Path], minimum: int = 10, limit: int = 16000,
                           libraries: list[Path] | None = None) -> str:
    if sum(path.stat().st_size for path in paths) > 64 * 1024 * 1024:
        return "Shift-register structural scan omitted for inputs larger than 64 MiB; use real tool evidence."
    hints = shift_register_groups(paths, minimum=minimum, libraries=libraries)
    return ("Best-effort unbranched shift-register candidates from actual input connections. "
            "Templates include concrete hierarchy and correlated indices; preserve existing scan enables and verify with the tool. "
            "This scan does not cover branched paths, concatenated/sliced bus bindings or arbitrary HDL.\n" +
            json.dumps(hints, ensure_ascii=False, indent=2))[:limit]


def reset_polarity_hints(paths: list[Path], libraries: list[Path]) -> dict[str, Any]:
    hints: dict[str, Any] = {}
    shift_register_groups(paths, libraries=libraries, reset_hints=hints)
    return {root: values for root, values in hints.items() if values}


def source_instance_map(paths: list[Path]) -> dict[str, Any]:
    instances: dict[str, Any] = {}
    shift_register_groups(paths, instance_map=instances)
    return instances
