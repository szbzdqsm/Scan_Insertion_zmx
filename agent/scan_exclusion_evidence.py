"""Conservative evidence that a formerly empty set_scan_element collection was repaired."""
from __future__ import annotations

from fnmatch import fnmatchcase
from pathlib import Path
import re
from typing import Any, Callable

from dofile_recipe import tcl_chunks
from report_validation import report_rows


def _scope(query: str, words_for: Callable[[str], list[str]]) -> dict[str, Any] | None:
    if not query.startswith("[") or not query.endswith("]") or "$" in query:
        return None
    words = words_for(query[1:-1].strip())
    if not words or words[0] not in {"get_obj_insts", "get_cells"}:
        return None
    options = words[1:]
    if options and options[0] in {"-hier", "-hierarchical"}:
        options = options[1:]
    if len(options) != 2 or options[0] != "-filter":
        return None
    expression = options[1]
    if expression[:1] in {'"', "{"}:
        expression = expression[1:-1]
    includes, excludes = [], []
    sequential_only = False
    for clause in expression.split("&&"):
        if re.fullmatch(r"\s*is_(?:sequential|scannable)\s*==\s*true\s*", clause):
            sequential_only |= bool(re.fullmatch(r"\s*is_sequential\s*==\s*true\s*", clause))
            continue
        match = re.fullmatch(r'\s*full_name\s*(=~|!~|==|!=)\s*("[^"\n]+"|\{[^}\n]+\}|[^\s]+)\s*', clause)
        if not match:
            return None
        operator, pattern = match.groups()
        pattern = pattern.strip('"{}').lstrip("/")
        if not pattern or "$" in pattern or "\\" in pattern:
            return None
        (excludes if operator in {"!~", "!="} else includes).append((operator, pattern))
    return {"includes": includes, "excludes": excludes, "endpoints": None,
            "sequential_only": sequential_only} if includes else None


def _matches(name: str, terms: list[tuple[str, str]]) -> bool:
    name = name.lstrip("/")
    return all(name == pattern if operator in {"==", "!="} else fnmatchcase(name, pattern)
               for operator, pattern in terms)


def _included(name: str, scope: dict[str, Any]) -> bool:
    endpoints = scope["endpoints"]
    return name.lstrip("/") in endpoints if endpoints is not None else _matches(name, scope["includes"])


def _exempt(name: str, scope: dict[str, Any]) -> bool:
    return _included(name, scope) and any(_matches(name, [term]) for term in scope["excludes"])


def _selected(name: str, scope: dict[str, Any]) -> bool:
    return _included(name, scope) and not _exempt(name, scope)


def _selectors(dofile: str, words_for: Callable[[str], list[str]]) -> list[dict[str, Any]]:
    bindings: dict[str, dict[str, Any]] = {}
    selectors = []
    try:
        chunks = tcl_chunks(dofile.replace("\\\n", " "))
    except ValueError:
        return []
    for chunk in chunks:
        command = chunk.strip()
        if not command or command.startswith("#"):
            continue
        words = words_for(command)
        if words and words[0] == "set" and len(words) == 3:
            name = words[1]
            bindings.pop(name, None)
            scope = _scope(words[2], words_for)
            if scope:
                bindings[name] = scope
            continue
        if not re.search(r"\bset_scan_element\s+(?:false|0|no|off)\b", command, re.I):
            continue
        guard = re.fullmatch(r"if\s+\{\[cluster_length\s+\$(\w+)\]\s*>\s*0\}\s*"
                             r"\{\s*set_scan_element\s+false\s+\$\1\s*\}", command)
        if guard:
            scope = bindings.get(guard.group(1))
        elif words and len(words) == 3 and words[:2] == ["set_scan_element", "false"]:
            target = words[2]
            if re.fullmatch(r"\$\w+", target):
                scope = bindings.get(target[1:])
            elif target.startswith("["):
                scope = _scope(target, words_for)
            else:
                endpoints = target.strip('"{}').split()
                scope = ({"endpoints": {name.lstrip("/") for name in endpoints}, "includes": [], "excludes": []}
                         if endpoints and all(re.fullmatch(r"[\w./\[\]-]+", name) for name in endpoints) else None)
        else:
            scope = None
        if scope is None:
            # Do not prove a partial interpretation of dynamic exclusion statements.
            return []
        selectors.append(scope)
    return selectors


def _failed_exclusion(issue: dict[str, Any], output_dir: Path) -> bool:
    found = issue.get("found", {})
    excerpt = str(found.get("excerpt", ""))
    if not re.search(r"\[ERROR\].*CMD-(?:0067|0074).*No valid value for 'instance_list'", excerpt):
        return False
    source = Path(str(found.get("source", "")))
    locator = re.fullmatch(r"L(\d+)", str(found.get("locator", "")))
    run_ref = str(found.get("run_ref", ""))
    path = (output_dir / source).resolve()
    if source.is_absolute() or source.suffix != ".log" or not locator or not re.fullmatch(r"R\d+", run_ref):
        return False
    if not path.is_relative_to((output_dir / "runs" / run_ref).resolve()) or not path.is_file():
        return False
    target = int(locator.group(1))
    active_command = ""
    error_matches = failed = False
    with path.open(encoding="utf-8", errors="replace") as stream:
        for number, line in enumerate(stream, 1):
            if number > target + 3:
                break
            echo = re.search(r"\bCMD-0034\]\s+@\d+:\s*(.*)", line)
            if echo and number <= target:
                command = echo.group(1).strip()
                # Source echo prints closing braces before executing a Tcl block.
                if command and not command.startswith("#") and not re.fullmatch(r"\}+(?:\s*;)?", command):
                    active_command = command
            if number == target:
                error_matches = excerpt in line and bool(re.match(r"set_scan_element\s+false\b", active_command))
            elif number > target and "Command 'set_scan_element' execution failed" in line:
                failed = True
    return error_matches and failed


def _fragment(path: Path, output_dir: Path, first: int, last: int) -> dict[str, str]:
    lines = []
    with path.open(encoding="utf-8", errors="replace") as stream:
        for number, line in enumerate(stream, 1):
            if number > last:
                break
            if number >= first:
                lines.append(line.rstrip("\r\n"))
    return {"source": path.relative_to(output_dir).as_posix(),
            "locator": f"L{first}" if first == last else f"L{first}-L{last}", "excerpt": "\n".join(lines)}


def exclusion_command_evidence(issue: dict[str, Any], files: list[Path], output_dir: Path,
                               dofile: str, words_for: Callable[[str], list[str]]) -> dict[str, str] | None:
    """Prove only the concrete empty-collection execution fault, with literal scope and actual states."""
    if not _failed_exclusion(issue, output_dir):
        return None
    selectors = _selectors(dofile, words_for)
    if not selectors:
        return None
    element_files = [path for path in files if "element" in path.name.lower() and
                     path.suffix.lower() in {".rpt", ".report", ".txt"}]
    all_rows = []
    for path in element_files:
        rows = [row for row in report_rows(path, {"InstanceName", "ObjState", "Type"})
                if row["InstanceName"] and row["Type"] in {"dff", "sff"}]
        all_rows.extend(rows)
        selected, exceptions = [], []
        proven = True
        for scope in selectors:
            targets = [row for row in rows if _selected(row["InstanceName"], scope)]
            kept = [row for row in rows if _exempt(row["InstanceName"], scope)]
            if (not targets or any(row["ObjState"] != "user_defined_nonscannable" for row in targets) or
                    scope["excludes"] and (not kept or any(row["ObjState"] != "scannable" for row in kept)) or
                    scope["endpoints"] is not None and scope["endpoints"] != {row["InstanceName"].lstrip("/") for row in targets}):
                proven = False
                break
            selected.extend(targets)
            exceptions.extend(kept)
        if proven:
            evidence_rows = selected + exceptions
            return _fragment(path, output_dir, min(row["line"] for row in evidence_rows),
                             max(row["line"] for row in evidence_rows))
    # Older scripts may report only scannable cells. Actual DFTDRC-7006/7007
    # still establishes a nonempty exclusion, not independently enumerated FF eligibility.
    for scope in selectors:
        kept = [row for row in all_rows if _exempt(row["InstanceName"], scope)]
        if scope["excludes"] and (not kept or any(row["ObjState"] != "scannable" for row in kept)):
            return None
        if any(_selected(row["InstanceName"], scope) and row["ObjState"] != "user_defined_nonscannable"
               for row in all_rows):
            return None
    for path in files:
        if path.suffix != ".log":
            continue
        blocks = []
        active_block = None
        with path.open(encoding="utf-8", errors="replace") as stream:
            for number, line in enumerate(stream, 1):
                if "CMD-0034" in line:
                    active_block = None
                    continue
                start = re.search(r"\[DFTDRC-7006\].*Cannot make cell '([^']+)' scannable due to 'set_scan_element' command", line)
                if start:
                    active_block = {"first": number, "last": number, "names": {start.group(1).lstrip("/")}}
                    blocks.append(active_block)
                elif active_block and "[DFTDRC-7007]" in line and "Cells with the same violation:" in line:
                    names = line.split("Cells with the same violation:", 1)[1].strip().removesuffix(".")
                    active_block["names"].update(name.strip().lstrip("/") for name in names.split(",") if name.strip())
                    active_block["last"] = number
                else:
                    active_block = None
        names = set().union(*(block["names"] for block in blocks)) if blocks else set()
        if (not names or any(not any(_selected(name, scope) for scope in selectors) for name in names) or
                any(not any(_selected(name, scope) for name in names) for scope in selectors) or
                any(scope["endpoints"] is not None and not scope["endpoints"] <= names for scope in selectors)):
            continue
        return _fragment(path, output_dir, blocks[0]["first"], blocks[-1]["last"])
    return None
