"""Run the live agent against Public inputs; withhold answer files and retain all attempts."""
from __future__ import annotations

import argparse
from contextlib import contextmanager
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import re
import subprocess
import sys
import threading
import time
import tempfile

ROOT = Path(__file__).resolve().parents[1]
LARGE_CASE_LOCK = threading.Lock()
sys.path.insert(0, str(ROOT / "agent"))
from scan_agent import parse_limit_seconds  # noqa: E402


def _case_tag(case: Path) -> str:
    return f"{case.parent.name}_{case.name}"


def _stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")


def _resume_path(path: Path) -> Path:
    batch = path.expanduser().resolve()
    outputs = (ROOT / "outputs").resolve()
    if not batch.is_dir() or batch == outputs or not batch.is_relative_to(outputs):
        raise ValueError("Resume batch must be an existing directory under ROOT/outputs")
    if (batch / "summary.json").is_symlink():
        raise ValueError("Resume summary must not be a symbolic link")
    return batch


def _resume_selection(batch: Path, image_id: str, thinking: str, all_cases: list[Path],
                      selected: list[Path]) -> tuple[dict, bytes, list[Path]]:
    """Read recorded results without modifying them or trusting an image tag."""
    raw = (batch / "summary.json").read_bytes()
    summary = json.loads(raw)
    if not isinstance(summary, dict):
        raise ValueError("Resume summary must be a JSON object")
    required = {"mode": "live_model", "answers_exposed": False,
                "model": "deepseek-v4-pro", "image_id": image_id, "thinking": thinking}
    for key, value in required.items():
        if key not in summary or summary[key] != value or type(summary[key]) is not type(value):
            raise ValueError(f"Resume summary {key} does not match this live run")
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", image_id):
        raise ValueError("Docker inspect did not return an immutable image ID")
    records = summary.get("cases")
    count = summary.get("case_count")
    if not isinstance(records, list) or type(count) is not int or count < len(records):
        raise ValueError("Resume summary has invalid recorded cases or case_count")
    known = {_case_tag(case) for case in all_cases}
    recorded = set()
    for result in records:
        if (not isinstance(result, dict) or not isinstance(result.get("case"), str) or
                result["case"] not in known or result["case"] in recorded or
                type(result.get("agent_passed")) is not bool):
            raise ValueError("Resume summary has duplicate, unknown, or invalid case results")
        recorded.add(result["case"])
        if "output_directory" in result:
            expected = batch / result["case"]
            if Path(result["output_directory"]).resolve() != expected.resolve():
                raise ValueError("Recorded output directory does not belong to this batch")
            if not expected.resolve().is_relative_to(batch):
                raise ValueError("Recorded output directory escapes this batch")
    if "agent_pass_count" in summary:
        if (type(summary["agent_pass_count"]) is not int or
                summary["agent_pass_count"] != sum(row["agent_passed"] for row in records)):
            raise ValueError("Resume summary pass count disagrees with its case results")
    if "resume_history" in summary and not isinstance(summary["resume_history"], list):
        raise ValueError("Resume history must be a list")
    if "run_status" in summary:
        if summary["run_status"] not in {"in_progress", "complete"}:
            raise ValueError("Resume summary has an invalid run_status")
        if summary["run_status"] == "complete" and count != len(records):
            raise ValueError("Completed summary still has unrecorded planned cases")
    # The previous runner has no batch lock. Its last case_count is a complete
    # plan, so refuse to merge a legacy batch while it still has pending cases.
    if "run_status" not in summary and count != len(records):
        raise ValueError("Legacy batch has not finished recording its original plan")
    remaining = [case for case in selected if _case_tag(case) not in recorded]
    for case in remaining:
        tag = _case_tag(case)
        paths = (batch / tag, batch / ".inputs" / tag)
        if any(path.exists() or path.is_symlink() for path in paths):
            raise ValueError(f"Unrecorded case directory already exists: {tag}; refusing to overwrite it")
    return summary, raw, remaining


def _backup_summary(batch: Path, raw: bytes) -> str:
    stem = f"summary.before-resume-{_stamp()}"
    suffix = 0
    while True:
        name = stem + (f"-{suffix}" if suffix else "") + ".json"
        try:
            with (batch / name).open("xb") as stream:
                stream.write(raw)
            return name
        except FileExistsError:
            suffix += 1


def _progress(summary: dict) -> None:
    summary["agent_pass_count"] = sum(result["agent_passed"] for result in summary["cases"])
    summary["completed_case_count"] = len(summary["cases"])
    recorded = {result["case"] for result in summary["cases"]}
    summary["pending_cases"] = sorted(set(summary["planned_cases"]) - recorded)
    summary["run_status"] = "in_progress" if summary["pending_cases"] else "complete"
    if summary.get("resume_history"):
        current = summary["resume_history"][-1]
        current["recorded_new_cases"] = sorted(set(current["remaining_cases"]) & recorded)
        current["run_status"] = summary["run_status"]


def _write_summary(batch: Path, summary: dict) -> None:
    """Replace one complete JSON snapshot atomically, including the pending plan."""
    path = None
    try:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=batch,
                                         prefix=".summary-", suffix=".tmp", delete=False) as stream:
            path = Path(stream.name)
            stream.write(json.dumps(summary, ensure_ascii=False, indent=2) + "\n")
        path.replace(batch / "summary.json")
    finally:
        if path is not None and path.exists():
            path.unlink()


@contextmanager
def _batch_lock(batch: Path):
    path = batch / ".public-runner.lock"
    if path.is_symlink():
        raise ValueError("Batch lock must not be a symbolic link")
    with path.open("a") as stream:
        fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        try:
            yield
        finally:
            fcntl.flock(stream, fcntl.LOCK_UN)


def run_case(case: Path, batch: Path, image: str, env_file: Path, thinking: str | None = None) -> dict:
    large = sum(path.stat().st_size for path in (case / "input/netlist").rglob("*.v")) > 64 * 1024 * 1024
    # Measured large designs use several GiB each on this WSL host; serialize them.
    if not large:
        return execute_case(case, batch, image, env_file, thinking)
    with LARGE_CASE_LOCK, (batch.parent / ".public-large.lock").open("a") as lock:
        # flock also coordinates separate batches launched from other terminals.
        fcntl.flock(lock, fcntl.LOCK_EX)
        try:
            return execute_case(case, batch, image, env_file, thinking)
        finally:
            fcntl.flock(lock, fcntl.LOCK_UN)


def execute_case(case: Path, batch: Path, image: str, env_file: Path, thinking: str | None = None) -> dict:
    tag = f"{case.parent.name}_{case.name}"
    source = case / "input"
    output = batch / tag
    output.mkdir()
    staged = batch / ".inputs" / tag
    staged.mkdir(parents=True)
    # The agent only receives platform input files, never Public answers or expected issues.
    for name in ("task_spec.md", "limitations.md", "original.dofile"):
        path = source / name
        if path.is_file():
            shutil.copyfile(path, staged / name)
    mounts = ["--mount", f"type=bind,source={staged},target=/input,readonly"]
    for name in ("netlist", "lib", "ctl"):
        path = source / name
        if path.is_dir():
            (staged / name).mkdir()
            mounts += ["--mount", f"type=bind,source={path},target=/input/{name},readonly"]
    limit = parse_limit_seconds((staged / "limitations.md").read_text()
                                if (staged / "limitations.md").is_file() else "")
    container = f"scan-public-{batch.name.lower()}-{tag}"
    command = ["docker", "run", "--rm", "--name", container,
               "--user", f"{os.getuid()}:{os.getgid()}", "--env-file", str(env_file),
               "-e", f"CASE_ID={tag}", *mounts,
               "--mount", f"type=bind,source={output},target=/output",
               image, "-input", "/input", "-output", "/output"]
    if thinking is not None:
        command[2:2] = ["-e", "LLM_ENABLE_THINKING=" + ("true" if thinking == "on" else "false")]
    started = time.monotonic()
    print(f"START {tag} (case limit {limit}s)", flush=True)
    timed_out = False
    cleanup_error = None
    with (output / "agent-console.log").open("w") as log:
        try:
            code = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT,
                                  timeout=limit + 10).returncode
        except subprocess.TimeoutExpired:
            timed_out = True
            try:
                cleanup = subprocess.run(["docker", "rm", "-f", container], capture_output=True, timeout=15)
                if cleanup.returncode:
                    cleanup_error = "DockerCleanupFailed"
            except subprocess.TimeoutExpired:
                cleanup_error = "DockerCleanupTimeout"
            code = 124
    elapsed = round(time.monotonic() - started, 2)
    decision_path = output / "decision_log.json"
    decision = json.loads(decision_path.read_text()) if decision_path.is_file() else {}
    result = {"case": tag, "exit_code": code, "elapsed_seconds": elapsed,
              "limit_seconds": limit, "deadline_exceeded": timed_out or elapsed > limit,
              "tool_checks_passed": decision.get("tool_checks_passed", False),
              "issue_audit_complete": decision.get("issue_audit_complete", False),
              "tool_calls": len(decision.get("tool_runs", [])),
              "summary": decision.get("summary", "Agent produced no decision log"),
              "output_directory": str(output)}
    if cleanup_error:
        result["cleanup_error"] = cleanup_error
    result["agent_passed"] = bool(code == 0 and not result["deadline_exceeded"]
                                  and result["tool_checks_passed"] and result["issue_audit_complete"])
    print(f"DONE {tag}: {'PASS' if result['agent_passed'] else 'FAIL'} ({elapsed}s, exit {code})", flush=True)
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--cases", type=Path, default=ROOT / "public_cases")
    parser.add_argument("--image", default="scan-agent-dev:local")
    parser.add_argument("--jobs", type=int, choices=(1, 2), default=1)
    parser.add_argument("--select", nargs="+", help="Optional task_1/case1 style subset")
    parser.add_argument("--thinking", choices=("on", "off"), help="Optional model reasoning-mode experiment")
    parser.add_argument("--resume-batch", type=Path,
                        help="Retain a finished batch and run only unrecorded matching cases with the same image")
    args = parser.parse_args()
    env_file = ROOT / "agent/.env"
    cases_root = args.cases.expanduser().resolve()
    all_cases = sorted(path.parent.parent for path in cases_root.glob("task_*/case*/input/task_spec.md"))
    if len({_case_tag(case) for case in all_cases}) != len(all_cases):
        parser.error("Case names must have unique task/case tags")
    cases = all_cases
    if args.select:
        cases = [case for case in cases if str(case.relative_to(cases_root)) in args.select]
    if not cases:
        parser.error("No matching cases found")
    image_id = subprocess.run(["docker", "image", "inspect", "--format", "{{.Id}}", args.image],
                              check=True, capture_output=True, text=True).stdout.strip()
    thinking = args.thinking or "runtime_default"
    try:
        if args.resume_batch:
            batch = _resume_path(args.resume_batch)
            summary, raw, remaining = _resume_selection(batch, image_id, thinking, all_cases, cases)
            if not remaining:
                print(f"No unrecorded matching cases; summary unchanged: {batch}", flush=True)
                return 0 if sum(row["agent_passed"] for row in summary["cases"]) == summary["case_count"] else 2
        if not env_file.is_file():
            parser.error("Configure agent/.env locally first")
        if not args.resume_batch:
            batch = ROOT / "outputs" / f"public-live-{_stamp()}"
            batch.mkdir(parents=True)
            summary = {"image": args.image, "image_id": image_id, "model": "deepseek-v4-pro",
                       "mode": "live_model", "answers_exposed": False, "thinking": thinking,
                       "case_count": len(cases), "cases": [], "cases_root": str(cases_root),
                       "selected_cases": [case.relative_to(cases_root).as_posix() for case in cases]}
        with _batch_lock(batch):
            if args.resume_batch:
                # Re-read after acquiring the lock; never race a second resumer.
                summary, raw, cases = _resume_selection(batch, image_id, thinking, all_cases, cases)
                if not cases:
                    return 0 if sum(row["agent_passed"] for row in summary["cases"]) == summary["case_count"] else 2
                backup = _backup_summary(batch, raw)
                if "original_subset" not in summary:
                    summary["original_subset"] = {"case_count": summary["case_count"],
                                                   "recorded_cases": [row["case"] for row in summary["cases"]],
                                                   "cases_root": summary.get("cases_root"),
                                                   "selected_cases": summary.get("selected_cases")}
                summary.setdefault("resume_history", []).append({
                    "started_at_utc": datetime.now(timezone.utc).isoformat(), "summary_backup": backup,
                    "source_summary_sha256": hashlib.sha256(raw).hexdigest(),
                    "requested_image": args.image, "image_id": image_id, "thinking": thinking,
                    "cases_root": str(cases_root), "preserved_cases": [row["case"] for row in summary["cases"]],
                    "remaining_cases": [_case_tag(case) for case in cases],
                    "remaining_sources": [{"case": _case_tag(case), "input_directory": str(case / "input")}
                                          for case in cases]})
            summary["case_count"] = len(summary["cases"]) + len(cases)
            summary["planned_cases"] = sorted([row["case"] for row in summary["cases"]] + [_case_tag(case) for case in cases])
            _progress(summary)
            _write_summary(batch, summary)
            print(f"Batch directory: {batch}", flush=True)
            with ThreadPoolExecutor(max_workers=args.jobs) as workers:
                futures = {workers.submit(run_case, case, batch, image_id, env_file, args.thinking): case for case in cases}
                for future in as_completed(futures):
                    try:
                        summary["cases"].append(future.result())
                    except Exception as error:
                        case = futures[future]
                        summary["cases"].append({"case": _case_tag(case), "agent_passed": False,
                                                 "runner_error": type(error).__name__})
                    summary["cases"].sort(key=lambda result: result["case"])
                    _progress(summary)
                    _write_summary(batch, summary)
    except (OSError, ValueError, TypeError) as error:
        parser.error(str(error))
    print(f"Agent-reported pass count: {summary['agent_pass_count']}/{summary['case_count']}", flush=True)
    print("Full contest conformance still requires independent semantic review.", flush=True)
    return 0 if summary["agent_pass_count"] == summary["case_count"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
