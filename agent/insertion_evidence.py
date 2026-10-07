"""Bind a zero-replacement discovery to actual later insertion evidence.

This deliberately supports literal full-insertion flows with one current design
and unambiguous per-partition scan enables. Dynamic Tcl and CTL assembly abstain.
The insertion-summary reader is the existing private report parser; its FF-bit
identities prove the tool's accounting, not independently inferred eligibility.
The caller must additionally require that the whole tool round passed.
"""
from __future__ import annotations

from pathlib import Path
import re
from typing import Any, Callable

from dofile_recipe import tcl_chunks
from report_validation import _COVERAGE_FIELDS, _insertion_summary_blocks, report_rows


_REPLACEMENT = re.compile(
    r"\s*\[INFO\]\s+\[\s*SCAN-7600\]\s+There were (\d+) 'D' flip-flops "
    r"that have been replaced\.\s*"
)
_IDENTIFIER = re.compile(r"[A-Za-z_][\w$]*")
_SCOPE_COMMAND = re.compile(
    r"\b(?:load_netlist|load_ctl|present_design|set_scan_signal|set_current_scan_partition|"
    r"add_scan_partition|insert_dft_logic)\b"
)
_DYNAMIC_COMMAND = re.compile(r"\b(?:source|eval|uplevel|namespace|rename|interp|apply|exec|load_ctl|proc)\b")


def _literal(word: str) -> str | None:
    if word.startswith("{") and word.endswith("}"):
        return word[1:-1] if not re.search(r"[{}\\]", word[1:-1]) else None
    if word.startswith('"') and word.endswith('"'):
        word = word[1:-1]
    return None if re.search(r"[$\[\]\\;\n]", word) else word


def _options(words: list[str]) -> dict[str, str] | None:
    if len(words) % 2:
        return None
    result = {}
    for option, raw in zip(words[::2], words[1::2]):
        value = _literal(raw)
        if not re.fullmatch(r"-[a-z_]+", option) or value is None or option in result:
            return None
        result[option] = value
    return result


def _load_top(words: list[str]) -> str:
    if words.count("-top") != 1:
        return ""
    index = words.index("-top")
    top = _literal(words[index + 1]) if index + 1 < len(words) else None
    return top if top is not None and _IDENTIFIER.fullmatch(top) else ""


def _scope(dofile: str, words_for: Callable[[str], list[str]]) -> tuple[str, dict[str, str]] | None:
    try:
        chunks = tcl_chunks(dofile.replace("\\\n", " "))
    except ValueError:
        return None
    top, partition = "", "Default_Partition"
    enables: dict[str, tuple[str, str]] = {}
    declared_partitions = {"Default_Partition"}
    insertion = None
    for chunk in chunks:
        text = chunk.strip()
        if not text or text.startswith("#"):
            continue
        words = words_for(text)
        if not words:
            return None
        name = words[0]
        if name in {"source", "eval", "uplevel", "namespace", "rename", "interp", "apply", "exec", "load_ctl", "proc"}:
            return None
        if name in {"if", "foreach", "for", "while", "proc", "cluster_foreach", "foreach_in_collection"}:
            if _SCOPE_COMMAND.search(text) or _DYNAMIC_COMMAND.search(text):
                return None
            continue
        if ";" in text and _SCOPE_COMMAND.search(text):
            return None
        if name == "exit":
            break
        if name not in {
            "load_netlist", "present_design", "set_scan_signal", "set_current_scan_partition",
            "add_scan_partition", "insert_dft_logic",
        }:
            # A nested command substitution must not change the analyzed scope.
            if _SCOPE_COMMAND.search(text) or _DYNAMIC_COMMAND.search(text):
                return None
            continue
        if insertion is not None:
            return None
        if name == "load_netlist":
            top = _load_top(words)
            partition = "Default_Partition"
        elif name == "present_design":
            selected = _literal(words[1]) if len(words) == 2 else None
            if selected is None or not _IDENTIFIER.fullmatch(selected):
                return None
            top, partition = selected, "Default_Partition"
        elif name == "add_scan_partition":
            selected = _literal(words[1]) if len(words) >= 2 else None
            if selected is None or not _IDENTIFIER.fullmatch(selected) or selected in declared_partitions:
                return None
            declared_partitions.add(selected)
        elif name == "set_current_scan_partition":
            selected = _literal(words[1]) if len(words) == 2 else None
            if selected not in declared_partitions:
                return None
            partition = selected
        elif name == "set_scan_signal":
            options = _options(words[1:])
            if options is None or not top:
                return None
            if options.get("-type") != "scan_enable" or options.get("-usage") == "clock_gating":
                continue
            port = options.get("-port", "")
            if not _IDENTIFIER.fullmatch(port) or options.get("-off_state") not in {"0", "1"}:
                return None
            if options.get("-usage", "all") not in {"all", "scan"}:
                return None
            setting = (top, port)
            if partition in enables and enables[partition] != setting:
                return None
            enables[partition] = setting
        elif name == "insert_dft_logic":
            # Partial insertion, repeated insertion and unknown options are not
            # enough to establish this deliberately narrow full-insertion proof.
            if len(words) != 1 or not top or not enables:
                return None
            if any(design != top for design, _ in enables.values()):
                return None
            insertion = (top, {name: port for name, (_, port) in enables.items()})
    return insertion


def _replacement_lines(path: Path, words_for: Callable[[str], list[str]]) -> list[dict[str, Any]]:
    design = ""
    command: list[str] = []
    events = []
    with path.open(encoding="utf-8", errors="replace") as stream:
        for number, line in enumerate(stream, 1):
            echo = re.search(r"\bCMD-0034\]\s+@\d+:\s*(.*)", line)
            if echo:
                text = echo.group(1).strip()
                if text and not text.startswith("#"):
                    command = words_for(text)
                    if command and command[0] == "load_netlist":
                        design = _load_top(command)
                    elif command and command[0] == "present_design":
                        selected = _literal(command[1]) if len(command) == 2 else None
                        design = selected if selected is not None and _IDENTIFIER.fullmatch(selected) else ""
                continue
            match = _REPLACEMENT.fullmatch(line)
            if match and command == ["insert_dft_logic"]:
                events.append({"line": number, "excerpt": line.strip(), "count": int(match.group(1)),
                               "design": design})
    return events


def _discovery(issue: dict[str, Any], output_dir: Path,
               words_for: Callable[[str], list[str]]) -> int | None:
    found = issue.get("found", {})
    excerpt = str(found.get("excerpt", ""))
    match = _REPLACEMENT.fullmatch(excerpt)
    run = re.fullmatch(r"R(\d+)", str(found.get("run_ref", "")))
    locator = re.fullmatch(r"L(\d+)", str(found.get("locator", "")))
    relative = Path(str(found.get("source", "")))
    if not found.get("verified") or not match or int(match.group(1)) != 0 or not run or not locator:
        return None
    path = output_dir / relative
    expected = output_dir / "runs" / run.group() / f"{run.group()}.log"
    if (relative.parts != ("runs", run.group(), f"{run.group()}.log") or relative.is_absolute() or
            path.resolve() != expected.resolve() or path.is_symlink() or not path.is_file()):
        return None
    if not expected.resolve().is_relative_to((output_dir / "runs").resolve()):
        return None
    events = _replacement_lines(path, words_for)
    if not any(event["line"] == int(locator.group(1)) and event["excerpt"] == excerpt and event["count"] == 0
               for event in events):
        return None
    return int(run.group(1))


def _current_files(files: list[Path], output_dir: Path, previous: int) -> tuple[list[Path], str] | None:
    accepted = []
    runs = set()
    for path in files:
        if path.suffix.lower() not in {".log", ".rpt", ".report", ".txt"}:
            continue
        relative = path.resolve().relative_to(output_dir.resolve())
        if len(relative.parts) < 3 or relative.parts[0] != "runs":
            return None
        run = re.fullmatch(r"R(\d+)", relative.parts[1])
        if not run or int(run.group(1)) <= previous or path.is_symlink() or not path.is_file():
            return None
        if path.suffix.lower() == ".log":
            if relative.parts[2:] != (f"{run.group()}.log",):
                return None
        elif len(relative.parts) < 4 or relative.parts[2] != "reports":
            return None
        runs.add(run.group())
        accepted.append(path)
    return (accepted, next(iter(runs))) if len(runs) == 1 else None


def _designs(path: Path) -> set[str]:
    designs = set()
    with path.open(encoding="utf-8", errors="replace") as stream:
        for line in stream:
            match = re.fullmatch(r"\s*Design\s*:\s*(\S+)\s*", line)
            if match:
                designs.add(match.group(1))
    return designs


def _coverage(paths: list[Path], top: str) -> int | None:
    signatures = set()
    for path in paths:
        if path.suffix.lower() == ".log":
            continue
        # Tool insertion summaries have a short standard header. Avoid scanning
        # every large cell report just to establish that its type is different.
        with path.open(encoding="utf-8", errors="replace") as stream:
            head = stream.read(8192)
        if not re.search(r"(?mi)^\s*NO\.?\s+Item\s+Quantity\s*$", head):
            continue
        if _designs(path) != {top}:
            return None
        for block in _insertion_summary_blocks(path):
            if not block["values"] and not block["invalid"]:
                continue
            values = block["values"]
            if (block["design"] != top or set(values) != set(_COVERAGE_FIELDS) or
                    block["conflicts"] or block["invalid"]):
                return None
            if values["Scannable FF Bit Count"] <= 0 or values["Scan Chain Cell Bit Count"] <= 0:
                return None
            for total, left, right in (
                ("Scannable FF Bit Count", "Scan Chain Cell Bit Count", "Wrapper Chain Cell Bit Count"),
                ("Total FF Bit Count", "Scannable FF Bit Count", "Nonscannable FF Bit Count"),
                ("Wrapper Chain Cell Bit Count", "Shared Wrapper Cell Bit Count", "Dedicated Wrapper Cell Bit Count"),
            ):
                if values[total] != values[left] + values[right]:
                    return None
            signatures.add(tuple(values[name] for name in _COVERAGE_FIELDS))
    if len(signatures) != 1:
        return None
    return next(iter(signatures))[_COVERAGE_FIELDS.index("Scannable FF Bit Count")]


def _chains(paths: list[Path], top: str, enables: dict[str, str]) -> bool:
    seen = False
    signatures = {}
    for path in paths:
        if path.suffix.lower() == ".log" or "chain" not in path.name.lower() or "cell" in path.name.lower():
            continue
        if _designs(path) != {top}:
            return False
        rows = list(report_rows(path, {"Chain", "Length", "Input", "Output", "ScanEnable", "Clocks", "Partition"}))
        if not rows:
            return False
        for row in rows:
            if (not re.fullmatch(r"I\s+\S+|\d+", row["Chain"]) or not row["Length"].isdigit() or
                    int(row["Length"]) <= 0 or not row["Input"] or not row["Output"] or not row["Clocks"] or
                    row["Partition"] not in enables or row["ScanEnable"] != enables[row["Partition"]]):
                return False
            key = (row["Chain"], row["Partition"])
            signature = tuple(row[name] for name in ("Length", "Input", "Output", "ScanEnable", "Clocks"))
            if key in signatures and signatures[key] != signature:
                return False
            signatures[key] = signature
            seen = True
    return seen


def insertion_replacement_evidence(issue: dict[str, Any], files: list[Path], output_dir: Path,
                                   dofile: str, words_for: Callable[[str], list[str]]) -> dict[str, str] | None:
    """Prove a literal zero-replacement defect was followed by real full insertion.

    Wrapper-only/CTL/dynamic flows are outside this narrow proof. The returned
    SCAN-7600 line is actual tool evidence; its accompanying reports must also
    demonstrate nonempty chains, declared scan enables, and closed FF accounting.
    """
    try:
        previous = _discovery(issue, output_dir, words_for)
        scope = _scope(dofile, words_for)
        if previous is None or scope is None:
            return None
        selected = _current_files(files, output_dir, previous)
        if selected is None:
            return None
        paths, run = selected
        top, enables = scope
        logs = [path for path in paths if path.suffix.lower() == ".log"]
        if len(logs) != 1 or logs[0].name != f"{run}.log":
            return None
        events = _replacement_lines(logs[0], words_for)
        if len(events) != 1 or events[0]["count"] <= 0 or events[0]["design"] != top:
            return None
        scannable = _coverage(paths, top)
        if scannable is None or events[0]["count"] > scannable or not _chains(paths, top, enables):
            return None
        event = events[0]
        return {"source": logs[0].relative_to(output_dir).as_posix(),
                "locator": f"L{event['line']}", "excerpt": event["excerpt"]}
    except (OSError, ValueError, KeyError, TypeError):
        return None
