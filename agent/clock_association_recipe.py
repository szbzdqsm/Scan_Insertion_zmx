"""Compile literal source-backed CE-latch clock propagation requested by the task."""
from __future__ import annotations

from collections import defaultdict
import re
from typing import Callable
from pathlib import Path

from report_validation import report_rows


def propagation_requested(spec: str) -> bool:
    return any(re.search(r"\bCE\b|使能", line, re.I) and
               re.search(r"latch|闩锁|锁存", line, re.I) and
               re.search(r"(?:时钟|clock).{0,30}(?:传播|propagat)", line, re.I)
               for line in spec.splitlines())


def configure_clock_associations(script: str, hints: list[dict], spec: str,
                                 words_for: Callable[[str], list[str]]) -> tuple[str, list[str]]:
    """Extend one unambiguous literal primary clock with its proven source-shaped output.

    The relation comes from the input graph, not from a case name or a solution.
    Its scan semantics still require actual DRC and final signal-report validation.
    """
    if not hints or not propagation_requested(spec):
        return script, []
    wanted = defaultdict(set)
    for hint in hints:
        candidates = [value for value in hint.get("clock_output_candidates", [])
                      if "/" in value and not re.search(r"[$\[\]\\;\s]", value)]
        source = hint.get("root_primary_clock_candidate", "")
        root = hint.get("root", "")
        if candidates and re.fullmatch(r"[A-Za-z_][\w$]*", source) and re.fullmatch(r"[A-Za-z_][\w$]*", root):
            wanted[(root, source)].add(candidates[-1])
    if not wanted:
        return script, []
    lines = script.splitlines()
    declarations = defaultdict(list)
    design = ""
    for index, line in enumerate(lines):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if "\\" in line or ";" in line or re.search(r"^\s*(?:if|foreach|for|while|proc|eval|source|uplevel)\b", line):
            # Multiline/dynamic ownership cannot be safely scoped by this narrow recipe.
            return script, []
        words = words_for(line.strip())
        if not words or words[0].startswith("#"):
            continue
        if words[0] == "present_design" and len(words) == 2:
            design = words[1].strip('"{}')
        if words[0] != "set_scan_signal" or len(words[1:]) % 2:
            continue
        options = {key: value.strip('"{}') for key, value in zip(words[1::2], words[2::2])}
        if options.get("-type") == "clock" and (design, options.get("-port")) in wanted:
            declarations[(design, options["-port"])].append((index, words))
    references = []
    for key, outputs in wanted.items():
        declared = declarations[key]
        if len(declared) != 1:
            continue
        index, words = declared[0]
        if "-associated_internal_clocks" in words:
            value_index = words.index("-associated_internal_clocks") + 1
            if value_index >= len(words) or re.search(r"[$\[\]\\;]", words[value_index]):
                continue
            outputs = outputs | set(words[value_index].strip('"{}').split())
            enable_data = {hint.get("enable_latch_q_pin") for hint in hints
                           if hint.get("root") == key[0] and hint.get("root_primary_clock_candidate") == key[1]}
            if outputs & enable_data:
                raise ValueError("The CE latch Q is enable data; associate the source-derived clock output, not its enable Q")
            words[value_index] = "{" + " ".join(sorted(outputs)) + "}"
        else:
            words.extend(["-associated_internal_clocks", "{" + " ".join(sorted(outputs)) + "}"])
        lines[index] = " ".join(words)
        references.append(lines[index])
    return "\n".join(lines) + ("\n" if script.endswith("\n") else ""), references


def clock_association_problems(paths: list[Path], script: str, hints: list[dict], spec: str,
                               words_for: Callable[[str], list[str]]) -> list[str]:
    _, references = configure_clock_associations(script, hints, spec, words_for)
    problems = []
    for reference in references:
        words = words_for(reference)
        options = {key: value.strip('"{}') for key, value in zip(words[1::2], words[2::2])}
        port = options["-port"]
        expected = set(options["-associated_internal_clocks"].split())
        proven = False
        for path in paths:
            if "signal" not in path.name.lower():
                continue
            for row in report_rows(path, {"Port", "SignalType", "AssociatedInternal"}):
                actual = set(re.split(r"[,\s]+", row["AssociatedInternal"]))
                if row["Port"] == port and row["SignalType"].split("(")[0] == "clock" and expected <= actual:
                    proven = True
        if not proven:
            problems.append(f"Actual signal reports do not prove source-derived clock propagation for {port}: " + ", ".join(sorted(expected)))
    return problems
