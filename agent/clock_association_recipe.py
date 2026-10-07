"""Compile literal source-backed CE-latch clock propagation requested by the task."""
from __future__ import annotations

from collections import defaultdict
import re
from typing import Callable
from pathlib import Path

from report_validation import report_rows
from dofile_recipe import tcl_chunks


_READ_ONLY = {"list", "format", "lindex", "llength", "concat", "get_cells", "get_obj_insts",
              "get_pins", "get_obj_pins", "get_ports", "get_obj_ports", "get_nets",
              "get_obj_nets", "get_property", "get_attribute", "list_properties",
              "sizeof_collection", "cluster_length"}
_FILE_READ_ONLY = {"join", "dirname", "normalize", "tail", "rootname", "exists", "isdirectory"}
_TOOL_CONFIGURATION = {"load_lib", "load_netlist", "load_ctl", "present_design", "set_scan_signal",
                       "set_scan_cell_mapping", "set_scan_cfg", "set_scan_drc_rule_handling",
                       "set_scan_drc_cfg", "set_dft_clock_gating_cfg", "set_scan_segment",
                       "set_wrapper_cfg", "set_dwc_cfg", "set_scan_partition", "add_scan_partition",
                       "add_dedicated_wrapper_cell_type", "set_scan_element",
                       "set_current_scan_partition", "examine_scan_drc", "examine_scan_chain",
                       "insert_dft_logic", "add_pseudo_pi", "exit"}
_NON_SCOPE = {"set", "incr", "lappend", "puts", "continue", "break", "add_pseudo_pi", "set_scan_segment",
              "set_scan_element"}


def _chunks(script: str) -> list[str]:
    """Preserve chunks while splitting command separators outside Tcl groups.

    No Tcl is evaluated. Backslash-newline normalization is only used when
    inspecting a chunk; untouched original output/control text remains intact.
    """
    result = []
    for chunk in tcl_chunks(script):
        if chunk.lstrip().startswith("#"):
            result.append(chunk)
            continue
        braces = brackets = 0
        quoted = escaped = False
        start = 0
        for index, character in enumerate(chunk):
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"' and not braces:
                quoted = not quoted
            elif not quoted:
                if character == "{":
                    braces += 1
                elif character == "}":
                    braces -= 1
                elif character == "[":
                    brackets += 1
                elif character == "]":
                    brackets -= 1
                elif character == ";" and not (braces or brackets):
                    result.append(chunk[start:index + 1])
                    start = index + 1
        if chunk[start:]:
            result.append(chunk[start:])
    return result


def _text(chunk: str) -> str:
    return re.sub(r"\\\r?\n[ \t]*", " ", chunk).strip().removesuffix(";").strip()


def _literal(word: str) -> str | None:
    if word.startswith("{") and word.endswith("}"):
        return word[1:-1]
    if word.startswith('"') and word.endswith('"'):
        word = word[1:-1]
    return None if re.search(r"[$\[\]\\;\n]", word) else word


def _readonly_word(word: str, words_for: Callable[[str], list[str]]) -> bool:
    if word.startswith("{") and word.endswith("}"):
        return True  # Literal API argument; structured command bodies are checked separately.
    if word.startswith('"') and word.endswith('"'):
        word = word[1:-1]
    if "\\" in word:
        return False
    index = 0
    while index < len(word):
        if word[index] == "]":
            return False
        if word[index] != "[":
            index += 1
            continue
        depth = 1
        end = index + 1
        while end < len(word) and depth:
            depth += (word[end] == "[") - (word[end] == "]")
            end += 1
        if depth:
            return False
        try:
            commands = [_text(chunk) for chunk in _chunks(word[index + 1:end - 1]) if _text(chunk)]
        except ValueError:
            return False
        if len(commands) != 1:
            return False
        words = words_for(commands[0])
        if not words:
            return False
        if words[0] == "file":
            if len(words) < 2 or words[1] not in _FILE_READ_ONLY:
                return False
            arguments = words[2:]
        elif words[0] in _READ_ONLY:
            arguments = words[1:]
        else:
            return False
        if not all(_readonly_word(argument, words_for) for argument in arguments):
            return False
        index = end
    return True


def _safe_body(word: str, words_for: Callable[[str], list[str]]) -> bool:
    if not (word.startswith("{") and word.endswith("}")):
        return False
    try:
        return all(_safe_non_scope(words_for(_text(chunk)), words_for)
                   for chunk in _chunks(word[1:-1]) if _text(chunk) and not _text(chunk).startswith("#"))
    except ValueError:
        return False


def _safe_condition(word: str, words_for: Callable[[str], list[str]]) -> bool:
    # A variable containing an expression could introduce new executable Tcl.
    # Only a literal condition with known readonly substitutions is recognized.
    return (word.startswith("{") and word.endswith("}") and
            not re.search(r"\b[\w:]+\s*\(", word[1:-1]) and
            _readonly_word(word[1:-1], words_for))


def _safe_non_scope(words: list[str], words_for: Callable[[str], list[str]]) -> bool:
    """Recognize output control and runtime recipes that cannot redeclare clocks/designs."""
    if not words:
        return False
    name = words[0]
    if name == "if":
        index = 1
        while index < len(words):
            if words[index] == "else":
                return index + 2 == len(words) and _safe_body(words[index + 1], words_for)
            if words[index] == "elseif":
                index += 1
            if index >= len(words) or not _safe_condition(words[index], words_for):
                return False
            index += 1
            if index < len(words) and words[index] == "then":
                index += 1
            if index >= len(words) or not _safe_body(words[index], words_for):
                return False
            index += 1
        return True
    if name in {"foreach", "foreach_in_collection", "cluster_foreach"}:
        return (len(words) >= 4 and not len(words[1:-1]) % 2 and
                all(_literal(word) is not None for word in words[1:-1:2]) and
                all(_readonly_word(word, words_for) for word in words[2:-1:2]) and
                _safe_body(words[-1], words_for))
    if name == "for":
        return (len(words) == 5 and _safe_body(words[1], words_for) and
                _safe_condition(words[2], words_for) and _safe_body(words[3], words_for) and
                _safe_body(words[4], words_for))
    if name == "file":
        return (len(words) >= 2 and words[1] in _FILE_READ_ONLY | {"mkdir"} and
                all(_readonly_word(word, words_for) for word in words[2:]))
    return ((name in _NON_SCOPE or name in _READ_ONLY or name.startswith(("rpt_", "dump_"))) and
            all(_readonly_word(word, words_for) for word in words[1:]))


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
    try:
        chunks = _chunks(script)
    except ValueError:
        return script, []
    declarations = defaultdict(list)
    design = ""
    selected_designs = set()
    for index, chunk in enumerate(chunks):
        text = _text(chunk)
        if not text or text.startswith("#"):
            continue
        words = words_for(text)
        if not words:
            return script, []
        if _safe_non_scope(words, words_for):
            continue
        if words[0] not in _TOOL_CONFIGURATION or not all(_readonly_word(word, words_for) for word in words[1:]):
            return script, []
        if words[0] == "load_netlist" and "-top" in words:
            if words.count("-top") != 1 or words.index("-top") + 1 >= len(words):
                return script, []
            design = _literal(words[words.index("-top") + 1])
            if not design:
                return script, []
            selected_designs.add(design)
        if words[0] == "present_design":
            if len(words) != 2 or not (design := _literal(words[1])):
                return script, []
            selected_designs.add(design)
        if words[0] != "set_scan_signal":
            continue
        if len(words[1:]) % 2 or len(set(words[1::2])) != len(words[1::2]):
            return script, []
        options = {key: _literal(value) for key, value in zip(words[1::2], words[2::2])}
        if any(value is None for value in options.values()):
            return script, []
        if (design, options.get("-port")) in wanted:
            declarations[(design, options["-port"])].append((index, words))
    if len(selected_designs) > 1:
        return script, []
    references = []
    for key, outputs in wanted.items():
        declared = declarations[key]
        if len(declared) != 1:
            continue
        index, words = declared[0]
        if dict(zip(words[1::2], words[2::2])).get("-type") not in {"clock", "{clock}", '"clock"'}:
            continue
        if "-associated_internal_clocks" in words:
            value_index = words.index("-associated_internal_clocks") + 1
            if value_index >= len(words) or re.search(r"[$\[\]\\;]", words[value_index]):
                continue
            outputs = outputs | set(words[value_index].strip('"{}').split())
            words[value_index] = "{" + " ".join(sorted(outputs)) + "}"
        else:
            words.extend(["-associated_internal_clocks", "{" + " ".join(sorted(outputs)) + "}"])
        enable_data = {hint.get("enable_latch_q_pin") for hint in hints
                       if hint.get("root") == key[0] and hint.get("root_primary_clock_candidate") == key[1]}
        if outputs & enable_data:
            raise ValueError("The CE latch Q is enable data; associate the source-derived clock output, not its enable Q")
        statement = " ".join(words)
        suffix = ";" if chunks[index].rstrip().endswith(";") else ""
        suffix += "\n" if chunks[index].endswith("\n") else ""
        indentation = chunks[index][:len(chunks[index]) - len(chunks[index].lstrip())]
        chunks[index] = indentation + statement + suffix
        references.append(statement)
    return "".join(chunks), references


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
