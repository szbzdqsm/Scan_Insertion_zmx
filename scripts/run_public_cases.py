"""Run the live agent against Public inputs; withhold answer files and retain all attempts."""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
import fcntl
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
LARGE_CASE_LOCK = threading.Lock()
sys.path.insert(0, str(ROOT / "agent"))
from scan_agent import parse_limit_seconds  # noqa: E402


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
    args = parser.parse_args()
    env_file = ROOT / "agent/.env"
    if not env_file.is_file():
        parser.error("Configure agent/.env locally first")
    cases_root = args.cases.expanduser().resolve()
    cases = sorted(path.parent.parent for path in cases_root.glob("task_*/case*/input/task_spec.md"))
    if args.select:
        cases = [case for case in cases if str(case.relative_to(cases_root)) in args.select]
    if not cases:
        parser.error("No matching cases found")
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    batch = ROOT / "outputs" / f"public-live-{stamp}"
    batch.mkdir(parents=True)
    image_id = subprocess.run(["docker", "image", "inspect", "--format", "{{.Id}}", args.image],
                              check=True, capture_output=True, text=True).stdout.strip()
    summary = {"image": args.image, "image_id": image_id, "model": "deepseek-v4-pro",
               "mode": "live_model", "answers_exposed": False,
               "thinking": args.thinking or "runtime_default",
               "case_count": len(cases), "cases": []}
    print(f"Batch directory: {batch}", flush=True)
    with ThreadPoolExecutor(max_workers=args.jobs) as workers:
        futures = {workers.submit(run_case, case, batch, image_id, env_file, args.thinking): case for case in cases}
        for future in as_completed(futures):
            try:
                summary["cases"].append(future.result())
            except Exception as error:
                case = futures[future]
                summary["cases"].append({"case": f"{case.parent.name}_{case.name}",
                                         "agent_passed": False, "runner_error": type(error).__name__})
            summary["cases"].sort(key=lambda result: result["case"])
            summary["agent_pass_count"] = sum(result["agent_passed"] for result in summary["cases"])
            (batch / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n")
    print(f"Agent-reported pass count: {summary['agent_pass_count']}/{len(cases)}", flush=True)
    print("Full contest conformance still requires independent semantic review.", flush=True)
    return 0 if summary["agent_pass_count"] == len(cases) else 2


if __name__ == "__main__":
    raise SystemExit(main())
