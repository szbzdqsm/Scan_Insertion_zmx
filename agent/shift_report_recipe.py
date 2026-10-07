"""Write and validate the tool's native natural shift-register report.

The official manual (printed pages 56-57) and installed verbose help identify
``rpt_shift_register -file``. ``rpt_scan_segment`` describes explicit segments
and is not a substitute for naturally identified ShiftReg membership.
No report data is synthesized or extracted from another report here.
"""
from __future__ import annotations

from pathlib import Path
import re
from typing import Callable

from clock_association_recipe import (
    _TOOL_CONFIGURATION, _chunks, _literal, _readonly_word, _safe_non_scope, _text,
)


def requested_shift_reports(spec: str) -> set[str]:
    """Infer filenames from explicit output/report roles, never a case identity."""
    reports = set()
    for line in spec.splitlines():
        if not re.search(r"移位寄存器|shift[ _-]*(?:register|reg)\b", line, re.I):
            continue
        if re.search(r"scan\s+segment|扫描段", line, re.I) and not re.search(r"自然|识别|natural|identified", line, re.I):
            continue
        for name in re.findall(r"(?<![\w./-])([\w./-]+\.(?:rpt|report|txt))(?![\w./-])", line, re.I):
            if not Path(name).is_absolute() and ".." not in Path(name).parts:
                reports.add(Path(name).name)
    return reports


def _file_argument(words: list[str]) -> str | None:
    positions = [index for index, word in enumerate(words) if word in {"-file", ">", ">>"}]
    if len(positions) != 1 or positions[0] + 1 >= len(words):
        return None
    return _literal(words[positions[0] + 1])


def configure(script: str, spec: str, words_for: Callable[[str], list[str]]) -> tuple[str, list[str]]:
    """Bind requested natural-shift report roles to a native command after analysis.

    Literal reports are retained at their existing output paths. Report-only
    control and input-derived runtime recipes are inspected, never evaluated.
    Unknown Tcl, dynamically selected output paths and design switches abstain.
    The caller must leave the supplied Task 2 original diagnostic R1 unchanged.
    """
    wanted = requested_shift_reports(spec)
    if not wanted:
        return script, []
    try:
        chunks = _chunks(script)
    except ValueError:
        return script, []
    bindings: dict[str, list[tuple[int, str]]] = {name: [] for name in wanted}
    analysis = insertion = -1
    exit_index = len(chunks)
    selected_designs = set()
    for index, chunk in enumerate(chunks):
        text = _text(chunk)
        if not text or text.startswith("#"):
            continue
        words = words_for(text)
        if not words:
            return script, []
        name = words[0]
        if exit_index != len(chunks):
            return script, []  # Commands after exit are not actual report producers.
        if name == "exit":
            if len(words) != 1:
                return script, []
            exit_index = index
            continue
        if name in {"if", "foreach", "for", "foreach_in_collection", "cluster_foreach"}:
            if any(report in text for report in wanted) or not _safe_non_scope(words, words_for):
                return script, []
            continue
        if not (_safe_non_scope(words, words_for) or
                name in _TOOL_CONFIGURATION | {"set_parameter"} and
                all(_readonly_word(word, words_for) for word in words[1:])):
            return script, []
        if name == "present_design":
            design = _literal(words[1]) if len(words) == 2 else None
            if not design:
                return script, []
            selected_designs.add(design)
        if name == "load_netlist" and "-top" in words:
            position = words.index("-top") + 1
            design = _literal(words[position]) if position < len(words) and words.count("-top") == 1 else None
            if not design:
                return script, []
            selected_designs.add(design)
        if name == "examine_scan_chain":
            if len(words) != 1 or insertion >= 0:
                return script, []
            analysis = index
        elif name == "insert_dft_logic":
            if analysis < 0 or len(words) != 1 or insertion >= 0:
                return script, []
            insertion = index
        if name.startswith(("rpt_", "dump_")):
            has_destination = any(word in {"-file", ">", ">>"} for word in words)
            destination = _file_argument(words) if has_destination else None
            if has_destination and destination is None:
                return script, []
            if destination is None or Path(destination).name not in wanted:
                continue
            if name not in {"rpt_scan_segment", "rpt_shift_register"} or any(character in destination for character in "{}\\"):
                return script, []
            bindings[Path(destination).name].append((index, destination))
    if analysis < 0 or insertion < 0 or len(selected_designs) != 1:
        return script, []
    commands = []
    remove = set()
    for name in sorted(wanted):
        entries = bindings[name]
        destinations = {destination for _, destination in entries}
        if len(destinations) > 1:
            return script, []
        destination = next(iter(destinations), "reports/" + name)
        statement = "rpt_shift_register -file {" + destination + "}"
        if len(entries) == 1 and entries[0][0] > insertion and _text(chunks[entries[0][0]]) == statement:
            continue
        remove.update(index for index, _ in entries)
        commands.append(statement)
    if not commands:
        return script, ["rpt_shift_register -file {" + bindings[name][0][1] + "}" for name in sorted(wanted)]
    result = []
    for index, chunk in enumerate(chunks):
        if index == exit_index:
            result.extend(command + "\n" for command in commands)
        if index not in remove:
            result.append(chunk)
    if exit_index == len(chunks):
        if result and not result[-1].endswith("\n"):
            result.append("\n")
        result.extend(command + "\n" for command in commands)
    references = ["rpt_shift_register -file {" +
                  (bindings[name][0][1] if bindings[name] else "reports/" + name) + "}" for name in sorted(wanted)]
    return "".join(result), references


def _members(path: Path) -> tuple[bool, set[tuple[str, str, str]]]:
    """Stream actual typed membership tables, preserving each Design scope."""
    columns = []
    design = ""
    typed = False
    members = set()
    with path.open(encoding="utf-8", errors="replace") as stream:
        for line in stream:
            found = re.fullmatch(r"\s*Design\s*:\s*(\S+)\s*", line)
            if found:
                design = found.group(1)
                columns = []
                continue
            headers = [(match.group(), match.start()) for match in re.finditer(r"\S+", line)]
            if {"InstanceName", "ShiftRegID/CellNo"} <= {name for name, _ in headers}:
                columns = headers
                typed = True
                continue
            if not columns or not line.strip() or line.lstrip().startswith("-"):
                continue
            row = {name: line[start:columns[index + 1][1] if index + 1 < len(columns) else None].strip()
                   for index, (name, start) in enumerate(columns)}
            identity = row["ShiftRegID/CellNo"]
            if design and row["InstanceName"] and re.fullmatch(r"\d+/\d+", identity):
                members.add((design, row["InstanceName"], identity))
    return typed, members


def natural_shift_report_problems(paths: list[Path], spec: str) -> list[str]:
    """Require real native membership when other actual outputs identify ShiftRegs.

    This verifies report membership against tool-produced chain-cell tables and
    native Examine Chain output. It does not independently prove FF eligibility
    or functional equivalence, and does not make an empty segment table evidence.
    """
    wanted = requested_shift_reports(spec)
    if not wanted:
        return []
    existing = list(dict.fromkeys(path for path in paths if path.is_file()))
    expected = set()
    identified = set()
    for path in existing:
        if path.name in wanted:
            continue
        if path.suffix.lower() in {".rpt", ".report", ".txt"}:
            _, members = _members(path)
            expected.update(members)
        if path.suffix.lower() == ".log":
            design = ""
            latest_groups = set()
            with path.open(encoding="utf-8", errors="replace") as stream:
                for line in stream:
                    if line.strip() == "Examine Chain Report":
                        # Reanalysis can change or split groups. Earlier previews
                        # must not masquerade as membership of the final preview.
                        latest_groups.clear()
                        design = ""
                        continue
                    found = re.fullmatch(r"\s*Design\s*:\s*(\S+)\s*", line)
                    if found:
                        design = found.group(1)
                    group = re.match(r"\s*ShiftReg(\d+)\s+\(s\)(?:\s|$)", line)
                    if group and design:
                        latest_groups.add((design, group.group(1)))
            identified.update(latest_groups)
    if not expected and not identified:
        return []
    problems = []
    for name in sorted(wanted):
        reports = [path for path in existing if path.name == name]
        typed = False
        actual = set()
        for path in reports:
            has_header, members = _members(path)
            typed |= has_header
            actual.update(members)
        actual_ids = {(design, identity.split("/")[0]) for design, _, identity in actual}
        missing_members = expected - actual
        missing_ids = identified - actual_ids
        if not typed or not actual or missing_members or missing_ids:
            problems.append(f"Requested natural shift-register report {name} does not prove actual identified ShiftRegs: "
                            f"typed membership header={typed}, members={len(actual)}, "
                            f"missing chain-cell members={len(missing_members)}, missing identified groups={len(missing_ids)}. "
                            "Use the real rpt_shift_register output; rpt_scan_segment is a different report.")
    return problems
