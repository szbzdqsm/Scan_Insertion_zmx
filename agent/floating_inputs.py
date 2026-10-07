"""Find gate clock outputs whose clock inputs are literally disconnected."""
from __future__ import annotations

from collections import defaultdict
from pathlib import Path
import re
from typing import Any


_MODULE = re.compile(r"\s*module\s+([\w$]+)")
_INPUT = re.compile(r"\binput\s+([^;)]*)")
_OUTPUT = re.compile(r"\boutput\s+([^;)]*)")
_AFTER_INPUT = re.compile(r"\b(?:output|inout)\b")
_AFTER_OUTPUT = re.compile(r"\b(?:input|inout)\b")
_PORT_WORD = re.compile(r"[A-Za-z_][\w$]*")
_PORT_TYPES = {"input", "output", "wire", "reg", "logic", "signed", "unsigned", "tri"}
_CELL = re.compile(r"\s*([\w$]+)\s+(\\\S+|[\w$\[\].]+)\s*\(")
_PIN = re.compile(r"\.([\w$]+)\s*\(([^()]*)\)")
_ENDMODULE = re.compile(r"\s*endmodule\b")
_CLOCK_CELL = re.compile(r"clock|clk|gated|icg", re.I)
_CLOCK_PIN = re.compile(r"clock|clk|^ck$", re.I)


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
                stripped = line.lstrip()
                module = _MODULE.match(stripped) if stripped.startswith("module") else None
                if module:
                    current = module.group(1)
                    modules[current]
                if not current:
                    continue
                # Necessary substring gates avoid regex work on cell/net lines;
                # the patterns still decide boundaries and ANSI directions.
                if "input" in line:
                    for declaration in _INPUT.finditer(line):
                        words = _PORT_WORD.findall(_AFTER_INPUT.split(declaration.group(1), 1)[0])
                        inputs[current].update(word for word in words if word not in _PORT_TYPES)
                if "output" in line:
                    for declaration in _OUTPUT.finditer(line):
                        words = _PORT_WORD.findall(_AFTER_OUTPUT.split(declaration.group(1), 1)[0])
                        outputs[current].update(word for word in words if word not in _PORT_TYPES)
                if pending is None:
                    # These primitive instances were already excluded after
                    # matching. Pin continuations cannot start an instance.
                    cell = (_CELL.match(stripped) if "(" in line and not stripped.startswith(("sky130_fd_sc_", "."))
                            else None)
                    if cell and cell.group(1) != "module" and not cell.group(1).startswith("sky130_fd_sc_"):
                        pending = (cell.group(1), cell.group(2).removeprefix("\\"), line)
                else:
                    pending = (pending[0], pending[1], pending[2] + line)
                if pending and ";" in line:
                    kind, name, text = pending
                    pins = dict((pin, value.strip()) for pin, value in _PIN.findall(text))
                    modules[current].append({"type": kind, "name": name, "pins": pins})
                    pending = None
                if stripped.startswith("endmodule") and _ENDMODULE.match(stripped):
                    current = ""
                    pending = None
    child_types = {cell["type"] for values in modules.values() for cell in values}
    result = {}
    def walk(module: str, prefix: str, ancestors: set[str], found: list[str]) -> None:
        if module in ancestors:
            return
        for cell in modules[module]:
            path = prefix + cell["name"] + "/"
            if _CLOCK_CELL.search(cell["type"]):
                disconnected = any(not connection and pin in inputs[cell["type"]] and _CLOCK_PIN.search(pin)
                                   for pin, connection in cell["pins"].items())
                if disconnected:
                    for pin in outputs[cell["type"]]:
                        if cell["pins"].get(pin) and _CLOCK_PIN.search(pin):
                            found.append(path + pin)
            if cell["type"] in modules:
                walk(cell["type"], path, ancestors | {module}, found)
    for root in sorted(set(modules) - child_types):
        found = []
        walk(root, "", set(), found)
        if found:
            result[root] = sorted(set(found))
    return result
