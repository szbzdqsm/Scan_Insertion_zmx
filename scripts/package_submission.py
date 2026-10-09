#!/usr/bin/env python3
"""Build a local official-layout source ZIP without reading private .env files."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import stat
import zipfile


_COPY = re.compile(r"^(\s*COPY\s+)([^\s]+)(\s+)([^\s]+)(\s*)$", re.I)
_FORBIDDEN_PARTS = {".git", ".venv", "public_cases", "outputs", "reference_submission", "reference_official"}
_FORBIDDEN_NAMES = {"golden.dofile", "preset_issues.json"}
_ENV = ("LLM_API_KEY=\nLLM_BASE_URL=https://dashscope.aliyuncs.com/compatible-mode/v1\n"
        "LLM_MODEL=deepseek-v4-pro\nSCANINSERTION_LICENSE_SERVER=8273@121.40.209.111\n")
_DOCKERIGNORE = "**\n!Dockerfile\n!submission/\n!submission/**\n"
_README = """# Scan Insertion local source submission

This local ZIP has not been uploaded to the evaluation platform.
Build from the extracted ZIP root using its Dockerfile and the official
scan-agent-base:ubuntu24 base image. The executable entry is:

    /submission/agent_system -input /input -output /output

The root .env contains an intentionally empty LLM_API_KEY. Configure the actual
key privately at runtime; never commit it or bake it into the image. The official
evaluation supplies its model API URL, key and License settings. .dockerignore
excludes .env, README and the source manifest from the Docker build context.

SOURCE_MANIFEST.json records the actual source SHA-256 values and the staged
Dockerfile. This package records source contents, not a new validation result
or a claim that Hidden cases passed.
"""


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _read_source(path: Path) -> bytes:
    before = path.stat()
    data = path.read_bytes()
    after = path.stat()
    attributes = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
    if any(getattr(before, name) != getattr(after, name) for name in attributes):
        raise ValueError(f"Source changed while packaging: {path.name}")
    return data


def build_submission(output_dir: Path | str, repo_root: Path | str | None = None) -> dict[str, Path]:
    """Return zip_path/stage_path in a newly created, never overwritten directory."""
    repo = Path(repo_root) if repo_root is not None else Path(__file__).resolve().parents[1]
    agent = repo / "agent"
    output = Path(output_dir)
    if output.exists() or output.is_symlink():
        raise FileExistsError(f"Output directory already exists: {output}")
    docker_source = agent / "Dockerfile"
    docker_bytes = _read_source(docker_source)
    sources: dict[str, bytes] = {}
    rewritten = []
    for line in docker_bytes.decode("utf-8").splitlines(keepends=True):
        if not re.match(r"\s*COPY\b", line, re.I):
            rewritten.append(line)
            continue
        match = _COPY.fullmatch(line)
        if not match:
            raise ValueError("Only simple single-source COPY declarations are supported")
        name = match[2]
        relative = PurePosixPath(name)
        if (relative.is_absolute() or ".." in relative.parts or re.search(r"[\"'$*?\[\]{}\\]", name)
                or any(part.lower() in _FORBIDDEN_PARTS for part in relative.parts)
                or relative.name.lower() in _FORBIDDEN_NAMES or relative.name.lower().startswith(".env")
                or relative.suffix.lower() in {".env", ".docx", ".pptx", ".log", ".v", ".vg", ".lib"}):
            raise ValueError(f"COPY source is outside the runtime package scope: {name}")
        source = agent / relative
        if (source.is_symlink() or not source.is_file() or
                not source.resolve().is_relative_to(agent.resolve())):
            raise ValueError(f"COPY source must be a regular file inside agent/: {name}")
        if name not in sources:
            sources[name] = _read_source(source)
        rewritten.append(match[1] + "submission/" + name + match[3] + match[4] + match[5])
    if "agent_system" not in sources or "requirements.txt" not in sources:
        raise ValueError("Runtime COPY whitelist must include agent_system and requirements.txt")
    docker_staged = "".join(rewritten).encode()
    generated = {"Dockerfile": docker_staged, ".env": _ENV.encode(),
                 ".dockerignore": _DOCKERIGNORE.encode(), "README.md": _README.encode()}
    source_manifest = {
        "format": "official-layout-local-source-zip",
        "source_files": [{"source": "agent/Dockerfile", "sha256": _sha(docker_bytes)}] +
                        [{"source": "agent/" + name, "archive_path": "submission/" + name,
                          "bytes": len(data), "sha256": _sha(data)} for name, data in sorted(sources.items())],
        "generated_files": {name: {"bytes": len(data), "sha256": _sha(data)}
                            for name, data in generated.items()},
        "credentials": "private .env never read; generated LLM_API_KEY is empty",
        "uploaded": False,
    }
    generated["SOURCE_MANIFEST.json"] = (json.dumps(source_manifest, ensure_ascii=False, indent=2) + "\n").encode()
    files = generated | {"submission/" + name: data for name, data in sources.items()}
    output.mkdir(parents=True, exist_ok=False)
    stage = output / "submission-stage"
    stage.mkdir()
    zip_path = output / "submission.zip"
    with zipfile.ZipFile(zip_path, "x", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, data in sorted(files.items()):
            mode = 0o600 if name == ".env" else 0o755 if name == "submission/agent_system" else 0o644
            target = stage / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
            target.chmod(mode)
            info = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | mode) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, data)
    return {"zip_path": zip_path, "stage_path": stage}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args(argv)
    result = build_submission(args.output_dir)
    print(json.dumps({key: str(path) for key, path in result.items()}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
