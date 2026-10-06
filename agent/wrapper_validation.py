"""Verify explicit port wrapper requirements using actual implementation rows."""
from __future__ import annotations

from pathlib import Path
import re

from report_validation import report_rows


def wrapper_targets(spec: str) -> dict[str, tuple[str, str | None]]:
    if "wrapper" not in spec.lower():
        return {}
    targets = {}
    for line in spec.splitlines():
        port = re.search(r"(?:端口|\bport)\s+`([A-Za-z_][\w$]*)`", line, re.I)
        if not port:
            continue
        if re.search(r"不参与扫描路径|不参与.{0,15}wrapper|\bno wrapper\b", line, re.I):
            targets[port.group(1)] = ("none", None)
        elif re.search(r"dedicated|专用.{0,10}wrapper", line, re.I):
            custom = "user_defined" if re.search(r"输入中提供|用户自定义|user.?defined|provided", line, re.I) else None
            targets[port.group(1)] = ("dedicated", custom)
        elif re.search(r"shared|共享.{0,10}wrapper", line, re.I):
            targets[port.group(1)] = ("shared", None)
    return targets


def port_wrapper_rows(paths: list[Path], port: str) -> list[dict]:
    matched = {}
    pattern = re.compile(re.escape(port) + r"(?:\[\d+\])?(?:\s+\([IO]\))?$")
    for path in paths:
        if not re.search(r"wrapper.*implementation", path.name, re.I):
            continue
        for row in report_rows(path, {"PortName(I/O)", "WrapperStyle"}):
            if pattern.fullmatch(row["PortName(I/O)"]):
                key = (row["PortName(I/O)"], row["WrapperStyle"], row.get("DWCType", ""))
                matched[key] = row
    return list(matched.values())


def wrapper_problems(paths: list[Path], spec: str) -> list[str]:
    problems = []
    for port, (style, custom) in wrapper_targets(spec).items():
        rows = port_wrapper_rows(paths, port)
        if not rows:
            problems.append(f"No actual wrapper implementation rows prove requested port {port}")
        elif any(row["WrapperStyle"].lower() != style or custom and row.get("DWCType", "").lower() != custom
                 for row in rows):
            problems.append(f"Actual wrapper implementation for {port} must be {style}" +
                            (f" with DWCType {custom}" if custom else ""))
    return problems


def wrapper_style_evidence(paths: list[Path], output_dir: Path, port: str, style: str) -> dict | None:
    rows = port_wrapper_rows(paths, port)
    if not rows or any(row["WrapperStyle"].lower() != style for row in rows):
        return None
    path = Path(rows[0]["source"])
    selected = [row for row in rows if Path(row["source"]) == path]
    first, last = min(row["line"] for row in selected), max(row["line"] for row in selected)
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    return {"source": path.relative_to(output_dir).as_posix(),
            "locator": f"L{first}" if first == last else f"L{first}-L{last}",
            "excerpt": "\n".join(lines[first - 1:last])}
