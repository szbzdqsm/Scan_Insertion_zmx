"""Run one case in Docker with read-only input and a fresh output directory."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("case", type=Path, help="Case folder or its input folder")
    parser.add_argument("--image", default="scan-agent-dev:local")
    args = parser.parse_args()
    case = args.case.expanduser().resolve()
    input_dir = case if (case / "task_spec.md").is_file() else case / "input"
    if not (input_dir / "task_spec.md").is_file():
        parser.error("Case must contain input/task_spec.md or task_spec.md")
    env_file = ROOT / "agent/.env"
    if not env_file.is_file():
        parser.error("Copy agent/.env.example to agent/.env and configure it locally")
    case_id = input_dir.parent.name if input_dir.name == "input" else input_dir.name
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    output_dir = ROOT / "outputs" / f"{case_id}-{stamp}"
    output_dir.mkdir(parents=True, exist_ok=False)
    print(f"Actual output directory: {output_dir}", flush=True)
    # No shell interpolation; Docker injects credentials without displaying their contents.
    command = ["docker", "run", "--rm", "--user", f"{os.getuid()}:{os.getgid()}",
               "--env-file", str(env_file),
               "-e", f"CASE_ID={case_id}",
               "--mount", f"type=bind,source={input_dir},target=/input,readonly",
               "--mount", f"type=bind,source={output_dir},target=/output",
               args.image, "-input", "/input", "-output", "/output"]
    try:
        return subprocess.call(command)
    except FileNotFoundError:
        parser.error("Docker CLI is unavailable; run this task from WSL")


if __name__ == "__main__":
    raise SystemExit(main())
