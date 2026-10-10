"""Close a proved partial-flow scope repair without claiming DRC was cleared."""
from __future__ import annotations

import difflib
import json
from pathlib import Path
import re
from typing import Any

from partial_insertion_validation import partial_insertion_requirements


def _artifact(root: Path, relative: str) -> Path | None:
    path = Path(relative)
    if path.is_absolute() or ".." in path.parts:
        return None
    candidate = root / path
    if not candidate.is_file() or candidate.is_symlink():
        return None
    try:
        candidate.resolve().relative_to(root.resolve())
    except ValueError:
        return None
    return candidate


def _commands(script: str, name: str) -> list[str]:
    # This admission rule intentionally abstains on compound/dynamic commands.
    return [line.strip() for line in script.splitlines()
            if re.match(r"^\s*" + re.escape(name) + r"(?:\s|$)", line)
            and not re.search(r"[;$\[\\]", line)]


def partial_issue_positive_evidence(
        issue: dict[str, Any], output_dir: Path, current_run: str, task_spec: str,
        structural_check: dict[str, Any] | None, changes: list[dict[str, Any]],
) -> dict[str, str] | None:
    """Accept only actual old scope failure plus an admitted, now-proved repair.

    The return value points to saved independent structural evidence. It does not
    assert a clean DRC result. DRC-bearing task specifications, unknown proofs,
    unrelated diagnostics, and missing/mismatched actual changes all abstain.
    """
    requirements = partial_insertion_requirements(task_spec)
    if (not requirements["applicable"] or not requirements["unscan_scopes"] or
            re.search(r"\bDRC\b|违例", task_spec, re.I) or not structural_check or
            not re.fullmatch(r"R[1-9]\d*", current_run)):
        return None
    previous_run = issue.get("found", {}).get("run_ref", "")
    if (not re.fullmatch(r"R[1-9]\d*", str(previous_run)) or previous_run == current_run or
            not issue.get("found", {}).get("verified")):
        return None
    attempts = issue.get("attempts", [])
    if not attempts or attempts[-1].get("verify", {}).get("resolved"):
        return None
    diagnosis = issue.get("diagnosis", {})
    description = " ".join(str(diagnosis.get(field, ""))
                           for field in ("summary", "located_object", "root_cause", "violated_requirement"))
    fix = str(attempts[-1].get("fix", {}).get("action", ""))
    if not re.search(r"replace_unscan|回替|revert|reversion|back.replace", description, re.I):
        return None
    drc_removal = (bool(re.search(r"examine_scan_drc", description + " " + fix)) and
                   bool(re.search(r"remove|removed|unnecessary|unrequested|不需要|移除|删除", fix, re.I)))
    scope_repair = (bool(re.search(r"scope|subtree|范围|选择|set_scan_element", description + " " + fix, re.I)) and
                    bool(re.search(r"correct|fix|narrow|limit|修|纠|缩", fix, re.I)))
    if not (drc_removal or scope_repair):
        return None
    previous_path = _artifact(output_dir, f"structural_checks/{previous_run}.json")
    current_path = _artifact(output_dir, f"structural_checks/{current_run}.json")
    if not previous_path or not current_path:
        return None
    try:
        previous = json.loads(previous_path.read_text(encoding="utf-8"))
        current_text = current_path.read_text(encoding="utf-8")
        current = json.loads(current_text)
        # Structural drivers are tuples in memory and JSON arrays on disk. The
        # proof must match its exact serializable representation, not Python's
        # tuple/list distinction introduced by saving the same result.
        expected_current = json.loads(json.dumps(structural_check))
    except (OSError, ValueError):
        return None
    if (current != expected_current or current.get("status") != "pass" or
            current.get("problems") != [] or current.get("unknown") != [] or
            current.get("unknown_count", 0) != 0 or previous.get("status") != "fail" or
            previous.get("unknown") != [] or previous.get("unknown_count", 0) != 0):
        return None
    failure = "Replaceable FF outside back-replacement scopes remained ordinary: "
    if (not any(str(problem).startswith(failure) for problem in previous.get("problems", [])) or
            previous.get("evidence", {}).get("ff_violation_count", 0) <= 0 or
            current.get("evidence", {}).get("ff_violation_count") != 0):
        return None
    for proof in (previous, current):
        declared = proof.get("requirements", {})
        if (declared.get("applicable") is not True or
                set(declared.get("unscan_scopes", [])) != set(requirements["unscan_scopes"])):
            return None
    old_requirements, new_requirements = previous["requirements"], current["requirements"]
    for field in ("top", "resolved_unscan_scopes"):
        if not new_requirements.get(field) or new_requirements.get(field) != old_requirements.get(field):
            return None
    # Partial tasks may rely on tool/library mappings rather than declaring a
    # mapping table. Empty mapping dictionaries are valid when both proofs agree.
    if (not isinstance(new_requirements.get("ff_pairs"), dict) or
            new_requirements.get("ff_pairs") != old_requirements.get("ff_pairs")):
        return None
    counts = current.get("counts", {})
    old_counts = previous.get("counts", {})
    required_counts = ("source_ff", "final_ff", "final_scan_ff", "source_unscan_ff", "final_unscan_ff")
    if any(type(counts.get(key)) is not int or counts[key] <= 0 for key in required_counts):
        return None
    if (counts["source_ff"] != counts["final_ff"] or counts["source_ff"] != old_counts.get("source_ff") or
            counts["source_unscan_ff"] != counts["final_unscan_ff"] or
            counts["source_unscan_ff"] != old_counts.get("source_unscan_ff")):
        return None
    old_script_path = _artifact(output_dir, f"runs/{previous_run}/deliverables/{previous_run}.dofile")
    actual_script_path = _artifact(output_dir, f"runs/{current_run}/deliverables/{current_run}.dofile")
    if not old_script_path or not actual_script_path:
        return None
    old_script = old_script_path.read_text(encoding="utf-8")
    actual_script = actual_script_path.read_text(encoding="utf-8")
    if not any("-replace_unscan" in command for command in _commands(actual_script, "insert_dft_logic")):
        return None
    change_ids = attempts[-1].get("fix", {}).get("artifact_ref", [])
    if not change_ids or not all(isinstance(item, str) for item in change_ids):
        return None
    referenced = [change for change in changes if change.get("change_id") in change_ids]
    if len(referenced) != len(set(change_ids)):
        return None
    admitted = False
    for change in referenced:
        if change.get("type") != "dofile":
            continue
        changed_path = _artifact(output_dir, str(change.get("path", "")))
        diff_path = _artifact(output_dir, str(change.get("diff_path", "")))
        if not changed_path or not diff_path:
            continue
        match = re.fullmatch(r"runs/(R[1-9]\d*)/deliverables/\1\.dofile", str(change.get("path", "")))
        if not match:
            continue
        changed_run = match[1]
        changed_script = changed_path.read_text(encoding="utf-8")
        expected_diff = "".join(difflib.unified_diff(
            old_script.splitlines(keepends=True), changed_script.splitlines(keepends=True),
            fromfile=previous_run, tofile=changed_run))
        if not expected_diff or diff_path.read_text(encoding="utf-8") != expected_diff:
            continue
        old_drc, changed_drc, actual_drc = (_commands(script, "examine_scan_drc")
                                           for script in (old_script, changed_script, actual_script))
        removed = drc_removal and bool(old_drc) and not changed_drc and not actual_drc
        changed_scope = (scope_repair and changed_script != old_script and
                         any(re.search(r"^[+-](?![+-]).*\bset_scan_element\b|"
                                       r"^[+-](?![+-]).*\b(?:get_cells|get_obj_insts)\b.*full_name", line)
                             for line in expected_diff.splitlines()))
        if removed or changed_scope:
            admitted = True
            break
    if not admitted:
        return None
    # Locate literal saved counts, preserving actual JSON line numbers and text.
    lines = current_text.splitlines()
    starts = [index for index, line in enumerate(lines) if line.strip() == '"counts": {']
    if len(starts) != 1:
        return None
    first = starts[0]
    last = next((index for index in range(first + 1, len(lines))
                 if lines[index].strip() in ("},", "}")), None)
    if last is None:
        return None
    return {"source": current_path.relative_to(output_dir).as_posix(),
            "locator": f"L{first + 1}-L{last + 1}", "excerpt": "\n".join(lines[first:last + 1]),
            "structural_check_ref": current_path.relative_to(output_dir).as_posix()}
