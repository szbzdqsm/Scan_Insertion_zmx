"""Report local development requirements without printing credentials."""
from __future__ import annotations

import importlib.metadata
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    inside = Path("/opt/dftexp_scan/bin/dftexp_scan").is_file()
    required = ["git", "make", "yosys", "eqy", "dftexp_scan"] if inside else ["git", "docker"]
    commands = {name: shutil.which(name) for name in required}
    modules = {}
    for name in ("openai", "pypdf", "ruff"):
        try:
            modules[name] = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            modules[name] = None
    config = {}
    env_file = ROOT / "agent/.env"
    if env_file.is_file():
        for line in env_file.read_text().splitlines():
            if line.strip() and not line.lstrip().startswith("#") and "=" in line:
                key, value = line.split("=", 1)
                config[key.strip()] = value.strip().strip("\"'")
    config.update({key: value for key, value in os.environ.items()
                   if key in {"LLM_API_KEY", "LLM_MODEL", "SCANINSERTION_LICENSE_SERVER"}})
    missing = [name for name, path in commands.items() if not path]
    missing += [name for name, version in modules.items() if not version]
    docker_ready = None
    if not inside and commands.get("docker"):
        try:
            result = subprocess.run(["docker", "info", "--format", "{{.ServerVersion}}"],
                                    capture_output=True, text=True, timeout=10)
            docker_ready = result.returncode == 0
        except (OSError, subprocess.TimeoutExpired):
            docker_ready = False
        if not docker_ready:
            missing.append("docker_daemon_access")
    print(json.dumps({
        "environment": "official_dev_container" if inside else "WSL_development",
        "python": sys.version.split()[0], "commands": commands, "packages": modules,
        "docker_ready": docker_ready, "missing": missing,
        "env_file_present": env_file.is_file(),
        "llm_key_configured": bool(config.get("LLM_API_KEY")),
        "license_configured": bool(config.get("SCANINSERTION_LICENSE_SERVER")),
        "contest_model_configured": config.get("LLM_MODEL", "deepseek-v4-pro") == "deepseek-v4-pro",
    }, ensure_ascii=False, indent=2))
    return 1 if missing else 0


if __name__ == "__main__":
    raise SystemExit(main())
