"""Find gate clock outputs whose clock inputs are literally disconnected."""
from __future__ import annotations

from collections import defaultdict
from pathlib import Path
import re
from typing import Any


def floating_clock_outputs(paths: list[Path]) -> dict[str, list[str]]:
    modules: dict[str, list[dict[str, Any]]] = defaultdict(list)
    inputs: dict[str, set[str]] = defaultdict(set)
    outputs: dict[str, set[str]] = defaultdict(set)
    current = ""
    pending = None
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
                    inputs[current].update(word for word in words if word not in {"input", "wire", "reg", "logic", "signed", "unsigned", "tri"})
                for declaration in re.finditer(r"\boutput\s+([^;)]*)", line):
                    words = re.findall(r"[A-Za-z_][\w$]*", re.split(r"\b(?:input|inout)\b", declaration.group(1))[0])
                    outputs[current].update(word for word in words if word not in {"output", "wire", "reg", "logic", "signed", "unsigned", "tri"})
                if pending is None:
                    cell = re.match(r"\s*([\w$]+)\s+(\\\S+|[\w$\[\].]+)\s*\(", line)
                    if cell and cell.group(1) != "module" and not cell.group(1).startswith("sky130_fd_sc_"):
                        pending = (cell.group(1), cell.group(2).removeprefix("\\"), line)
                else:
                    pending = (pending[0], pending[1], pending[2] + line)
                if pending and ";" in line:
                    kind, name, text = pending
                    pins = dict((pin, value.strip()) for pin, value in re.findall(r"\.([\w$]+)\s*\(([^()]*)\)", text))
                    modules[current].append({"type": kind, "name": name, "pins": pins})
                    pending = None
                if re.match(r"\s*endmodule\b", line):
                    current = ""
                    pending = None
    child_types = {cell["type"] for values in modules.values() for cell in values}
    result = {}
    def walk(module: str, prefix: str, ancestors: set[str], found: list[str]) -> None:
        if module in ancestors:
            return
        for cell in modules[module]:
            path = prefix + cell["name"] + "/"
            if re.search(r"clock|clk|gated|icg", cell["type"], re.I):
                disconnected = any(not connection and pin in inputs[cell["type"]] and re.search(r"clock|clk|^ck$", pin, re.I)
                                   for pin, connection in cell["pins"].items())
                if disconnected:
                    for pin in outputs[cell["type"]]:
                        if cell["pins"].get(pin) and re.search(r"clock|clk|^ck$", pin, re.I):
                            found.append(path + pin)
            if cell["type"] in modules:
                walk(cell["type"], path, ancestors | {module}, found)
    for root in sorted(set(modules) - child_types):
        found = []
        walk(root, "", set(), found)
        if found:
            result[root] = sorted(set(found))
    return result
