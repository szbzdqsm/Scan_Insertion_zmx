"""Localized private netlist edits admitted only after a fixed, real EQY proof."""
from __future__ import annotations

import json
import hashlib
import os
from pathlib import Path
import re
import signal
import subprocess
import time
from typing import Any


class RepairRejected(RuntimeError):
    pass


def fingerprint_paths(paths: list[Path]) -> dict[str, dict[str, str]]:
    """Bind the retained candidate and proof artifacts to their exact bytes."""
    result = {}
    for path in sorted(set(paths)):
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            while chunk := stream.read(1024 * 1024):
                digest.update(chunk)
        result[str(path)] = {"resolved": str(path.resolve()), "sha256": digest.hexdigest()}
    return result


def changed_paths(snapshot: dict[str, dict[str, str]]) -> list[str]:
    changes = []
    for name, before in snapshot.items():
        try:
            after = fingerprint_paths([Path(name)])[name]
        except OSError:
            changes.append(name)
            continue
        if before != after:
            changes.append(name)
    return changes


def edits_allowed(task: str, spec: str) -> bool:
    if task != "task2":
        return False
    return not re.search(
        r"(?:不允许|禁止|不得|不能).{0,40}(?:修改|编辑).{0,40}(?:网表|netlist)|"
        r"(?:do not|must not|forbid|not allow|no).{0,40}(?:edit|modif).{0,40}(?:netlist|pre.scan)",
        spec, re.I)


def patch_unique(source: Path, destination: Path, old: str, new: str) -> None:
    """Replace one literal byte span, streaming large files and rejecting ambiguity."""
    if not old or old == new or max(len(old), len(new)) > 16384:
        raise RepairRejected("Each edit needs a distinct, nonempty old span and at most 16384 characters")
    if max(old.count("\n"), new.count("\n")) > 32:
        raise RepairRejected("Edits are limited to 32 lines each")
    if re.search(r"\b(?:module|endmodule|input|output|inout|parameter)\b", old + "\n" + new):
        raise RepairRejected("Automatic edits cannot change module interfaces or parameters")
    needle, replacement = old.encode(), new.encode()
    # Count first, so a rejected edit never leaves a partially accepted version.
    count = 0
    buffer = b""
    with source.open("rb") as stream:
        while chunk := stream.read(65536):
            buffer += chunk
            while (position := buffer.find(needle)) >= 0:
                count += 1
                buffer = buffer[position + 1:]
                if count > 1:
                    raise RepairRejected("Edit old span is not unique in the current netlist")
            buffer = buffer[-(len(needle) - 1):] if len(needle) > 1 else b""
    if count != 1:
        raise RepairRejected("Edit old span was not found in the current netlist")
    destination.parent.mkdir(parents=True, exist_ok=True)
    buffer = b""
    changed = False
    with source.open("rb") as stream, destination.open("wb") as output:
        while chunk := stream.read(65536):
            buffer += chunk
            if not changed and (position := buffer.find(needle)) >= 0:
                output.write(buffer[:position] + replacement)
                buffer = buffer[position + len(needle):]
                changed = True
            keep = 0 if changed else len(needle) - 1
            length = max(0, len(buffer) - keep)
            output.write(buffer[:length])
            buffer = buffer[length:]
        output.write(buffer)


def proof_top(spec: str, original_dofile: str, netlists: list[Path]) -> str:
    candidates = []
    for line in spec.splitlines():
        if re.search(r"顶层模块|Top\s*模块|top\s*module|设计名称", line, re.I):
            candidates.extend(re.findall(r"`([A-Za-z_][\w$]*)`", line))
    candidates.extend(re.findall(r"(?m)^\s*present_design\s+([A-Za-z_][\w$]*)\s*$", original_dofile))
    names = set()
    for path in netlists:
        with path.open(encoding="utf-8", errors="replace") as stream:
            for line in stream:
                match = re.match(r"\s*module\s+([A-Za-z_][\w$]*)\b", line)
                if match:
                    names.add(match.group(1))
    for name in candidates:
        if name in names:
            return name
    raise RepairRejected("Cannot determine a proof top from task specification and the supplied original Dofile")


def containing_module(path: Path, excerpt: str) -> str:
    module = ""
    buffer = ""
    with path.open(encoding="utf-8", errors="replace") as stream:
        for line in stream:
            declaration = re.match(r"\s*module\s+([A-Za-z_][\w$]*)", line)
            if declaration:
                module = declaration.group(1)
            buffer += line
            if excerpt in buffer:
                if not module:
                    raise RepairRejected("Every changed span must belong to a concrete module")
                return module
            buffer = buffer[-max(1, len(excerpt)-1):]
            if re.match(r"\s*endmodule\b", line):
                module = ""
    raise RepairRejected("Cannot locate the changed module for proof coverage")


def eqy_configuration(originals: list[Path], candidates: list[Path], libs: list[Path], top: str) -> str:
    if not re.fullmatch(r"[A-Za-z_][\w$]*", top):
        raise RepairRejected("Invalid proof top identifier")
    def section(paths: list[Path]) -> str:
        # Functional Liberty models; no -lib, blackbox assumptions or model-provided constraints.
        # Skip unsupported *unused* library cells. Any such cell used by the actual
        # design makes hierarchy -check fail; no blackbox replacement is admitted.
        lines = ["read_liberty -ignore_miss_func -ignore_miss_dir " + json.dumps(str(path)) for path in libs]
        lines += ["read_verilog " + " ".join(json.dumps(str(path)) for path in paths),
                  f"hierarchy -check -top {top}", "select -assert-none A:blackbox",
                  f"prep -top {top} -flatten", "memory_map"]
        return "\n".join(lines) + "\n"
    return ("[gold]\n" + section(originals) + "\n[gate]\n" + section(candidates) +
            "\n[strategy sat]\nuse sat\ndepth 10\n")


def run_proof(originals: list[Path], candidates: list[Path], libs: list[Path], top: str,
              proof_root: Path, deadline: float) -> dict[str, Any]:
    proof_root.mkdir(parents=True, exist_ok=False)
    config = proof_root / "check.eqy"
    config.write_text(eqy_configuration(originals, candidates, libs, top))
    log = proof_root / "eqy.log"
    budget = min(float(os.environ.get("AGENT_EQY_TIMEOUT", "180")), deadline - time.monotonic())
    if budget <= 1:
        raise RepairRejected("Insufficient remaining case time for EQY")
    started = time.monotonic()
    with log.open("w") as stream:
        process = subprocess.Popen(["eqy", "-d", str(proof_root / "proof"), str(config)],
                                   cwd=proof_root, stdout=stream, stderr=subprocess.STDOUT,
                                   start_new_session=True)
        try:
            code = process.wait(timeout=budget)
            marker = next((name for name in ("PASS", "FAIL", "UNPROVEN", "ERROR")
                           if (proof_root / "proof" / name).is_file()), "MISSING")
            if marker == "MISSING" and code != 0:
                marker = "ERROR"
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
            stream.write("\n[agent] EQY process group terminated at proof deadline\n")
            code, marker = None, "TIMEOUT"
        except BaseException:
            if process.poll() is None:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            process.wait()
            stream.write("\n[agent] EQY process group terminated during case interruption\n")
            raise
    result = {"passed": code == 0 and marker == "PASS", "returncode": code, "result": marker,
              "elapsed_seconds": round(time.monotonic() - started, 3), "top": top,
              "log": str(log), "original_netlists": [str(path) for path in originals],
              "candidate_netlists": [str(path) for path in candidates]}
    (proof_root / "summary.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


def prepare_repair(task: str, spec: str, original_dofile: str, input_dir: Path,
                   originals: list[Path], active: dict[Path, Path], libs: list[Path],
                   edits: list[dict[str, Any]], output_dir: Path, run_id: str,
                   deadline: float) -> tuple[dict[Path, Path], list[dict[str, Any]]]:
    if not edits_allowed(task, spec):
        raise RepairRejected("Task or case explicitly forbids Pre-scan netlist editing")
    if not 1 <= len(edits) <= 4:
        raise RepairRejected("A proposal must contain one to four localized edits")
    candidate_root = output_dir / "netlist_versions" / run_id
    candidate_root.mkdir(parents=True, exist_ok=False)
    candidate_map = dict(active)
    changed: set[Path] = set()
    affected_modules: set[str] = set()
    for index, edit in enumerate(edits):
        path = Path(str(edit.get("file", "")))
        source = (path if path.is_absolute() else input_dir / path).resolve()
        if source not in originals:
            raise RepairRejected("Netlist edit file must identify an original input .v, not a library or external path")
        if not str(edit.get("reason", "")).strip():
            raise RepairRejected("Every edit must explain why Dofile settings alone are insufficient")
        relative = source.relative_to(input_dir / "netlist")
        affected_modules.add(containing_module(candidate_map[source], str(edit.get("old", ""))))
        intermediate = candidate_root / ".patches" / f"{index}.v"
        patch_unique(candidate_map[source], intermediate, str(edit.get("old", "")), str(edit.get("new", "")))
        target = candidate_root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        os.replace(intermediate, target)
        candidate_map[source] = target
        changed.add(source)
    # Include unchanged files so directory-relative Dofile paths also refer to this version.
    for source in originals:
        target = candidate_root / source.relative_to(input_dir / "netlist")
        if source not in changed:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.symlink_to(active[source])
            candidate_map[source] = target
    top = proof_top(spec, original_dofile, originals)
    proof_root = output_dir / "lec" / run_id
    aggregate = proof_root / "aggregate.log"
    proof_logs = []
    for index, module in enumerate([top] + sorted(affected_modules - {top})):
        directory = proof_root if index == 0 else proof_root / f"affected_{index}"
        proof = run_proof(originals, [candidate_map[path] for path in originals], libs, module, directory, deadline)
        actual_log = directory / "eqy.log"
        if actual_log.is_file():
            proof_logs.append(actual_log.relative_to(output_dir).as_posix())
            with aggregate.open("a") as output, actual_log.open() as source_log:
                output.write(f"\n[agent] Actual EQY log for module {module}: {actual_log}\n")
                while chunk := source_log.read(65536):
                    output.write(chunk)
        if not proof["passed"] or not actual_log.is_file():
            raise RepairRejected(f"EQY did not prove module {module} equivalent to original: {proof['result']}; candidate not adopted")
    changes = []
    diff_root = output_dir / "diffs"
    diff_root.mkdir(exist_ok=True)
    for index, source in enumerate(sorted(changed)):
        diff = diff_root / f"netlist_{run_id}_{index}.diff"
        with diff.open("w") as stream:
            result = subprocess.run(["diff", "-u", "--", str(source), str(candidate_map[source])],
                                    stdout=stream, stderr=subprocess.STDOUT,
                                    timeout=max(1, min(20, deadline - time.monotonic())))
        if result.returncode != 1:
            raise RepairRejected("Could not retain a real nonempty original-to-candidate netlist diff")
        changes.append({"type": "netlist", "path": candidate_map[source].relative_to(output_dir).as_posix(),
                        "diff_path": diff.relative_to(output_dir).as_posix(),
                        "lec_ref": aggregate.relative_to(output_dir).as_posix(), "lec_refs": proof_logs})
    return candidate_map, changes
