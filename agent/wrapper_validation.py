"""Verify explicit port wrapper requirements using actual implementation rows."""
from __future__ import annotations

from pathlib import Path
import re

from report_validation import report_rows


def global_wrapper_style(spec: str) -> str | None:
    styles = set()
    for line in spec.splitlines():
        if re.search(r"端口|\bport\b|不启用|不得|例如|example|\bif\b", line, re.I):
            continue
        match = re.search(r"(?:启用|enable|configure).{0,20}\bwrapper\b.{0,16}(dedicated|shared)(?![A-Za-z_])", line, re.I)
        if match:
            styles.add(match[1].lower())
    return next(iter(styles)) if len(styles) == 1 else None


def wrapper_style_configuration_problems(script: str, spec: str, words_for) -> list[str]:
    wanted = global_wrapper_style(spec)
    required = bool(wanted or any(style != 'none' for style, _ in wrapper_targets(spec).values()))
    problems = []
    enabled = False
    actual = None
    for line in script.splitlines():
        words = words_for(line.strip())
        if not words or words[0] != "set_wrapper_cfg":
            continue
        if any(re.search(r"[$\[\\]", word) for word in words):
            return problems
        if any(word in {'enable', 'disable'} for word in words[1:]) and '-port' in words:
            problems.append('Wrapper enable/disable is global and cannot be combined with -port; use a separate set_wrapper_cfg enable, then per-port style commands')
        if '-port' in words:
            continue
        if 'enable' in words[1:]:
            enabled = True
        if 'disable' in words[1:]:
            enabled = False
        if "-style" in words and words.index("-style") + 1 < len(words):
            actual = words[words.index("-style") + 1].strip('"{}')
    dynamic = re.search(r'(?m)^\s*(?:proc|source|eval|namespace)\b', script)
    if required and not enabled and not dynamic:
        problems.append('Task requires Wrapper insertion; add a global set_wrapper_cfg enable without -port')
    if wanted and actual != wanted and not dynamic:
        problems.append(f"Task explicitly requires global Wrapper style {wanted}; configure set_wrapper_cfg -style {wanted}")
    return problems


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
    wanted = global_wrapper_style(spec)
    required = bool(wanted or any(style != 'none' for style, _ in wrapper_targets(spec).values()))
    cfgs = [path for path in paths if 'wrapper_cfg' in path.name.lower()]
    canonical = [path for path in cfgs if path.name == 'rpt_wrapper_cfg.audit.rpt']
    cfgs = canonical or cfgs
    if required:
        enabled = [value for path in cfgs for value in re.findall(r'(?m)^\s*enable\s+([YN])\s*$', path.read_text(errors='replace'))]
        if not enabled or any(value != 'Y' for value in enabled):
            problems.append('Task requires Wrapper insertion but actual global Wrapper configuration is not enabled (enable must be Y); use separate global enable and per-port style commands')
    if wanted:
        observed = []
        for path in cfgs:
            if "wrapper_cfg" in path.name.lower():
                observed.extend(re.findall(r"(?m)^\s*style\s+(dedicated|shared)\s*$", path.read_text(errors="replace")))
        if not observed or any(value != wanted for value in observed):
            problems.append(f"Actual Wrapper configuration does not prove task-required global style {wanted}")
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
