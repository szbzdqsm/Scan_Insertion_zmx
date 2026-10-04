#!/usr/bin/env python3
"""Auditable ScanInsertion agent starter for the contest container."""
from __future__ import annotations

import argparse
from collections import deque
import difflib
import functools
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from openai import OpenAI


TOOL = os.environ.get("DFTEXP_SCAN", "/opt/dftexp_scan/bin/dftexp_scan")
MANUAL = Path("/opt/dftexp_scan/doc/Scan_User_Manual.pdf")


def read_text(path: Path, limit: int = 30000) -> str:
    if not path.is_file():
        return ""
    with path.open("r", encoding="utf-8", errors="replace") as f:
        return f.read(limit)


def case_id_for(input_dir: Path) -> str:
    """Use the enclosing case directory, not the commonly named `input` folder."""
    configured = os.environ.get("CASE_ID", "").strip()
    if configured:
        return configured
    for parent in (input_dir, *input_dir.parents):
        if re.fullmatch(r"(?:(?:hidden|public)_)?case\w+", parent.name, re.I):
            return parent.name
    return "unknown" if input_dir.name.lower() == "input" else input_dir.name


def discover_files(input_dir: Path, suffix: str) -> list[Path]:
    return sorted(p for p in input_dir.rglob(f"*{suffix}") if p.is_file())


def netlist_summary(paths: list[Path]) -> str:
    """Bound context size; never load a multi-hundred-MB gate netlist into the LLM prompt."""
    out: list[str] = []
    for p in paths:
        out.append(f"FILE {p.name} ({p.stat().st_size} bytes)")
        modules: list[str] = []
        ports: list[str] = []
        cells: dict[str, int] = {}
        try:
            with p.open("r", encoding="utf-8", errors="replace") as f:
                for i, line in enumerate(f):
                    if i > 4_000_000:
                        break
                    m = re.search(r"\bmodule\s+([\w$]+)\s*(?:\((.*?)\))?\s*;", line)
                    if m and len(modules) < 80:
                        modules.append(m.group(1))
                        if m.group(2) and len(ports) < 160:
                            ports.extend(re.findall(r"[\w$]+", m.group(2)))
                    c = re.match(r"\s*([\w$]+)\s+(?:\\[^\s]+|[\w$]+)\s*\(", line)
                    if c and ("df" in c.group(1).lower() or "sdf" in c.group(1).lower() or "dl" in c.group(1).lower() or "latch" in c.group(1).lower() or "clk" in c.group(1).lower()):
                        cells[c.group(1)] = cells.get(c.group(1), 0) + 1
        except OSError as e:
            out.append(f"Could not scan file: {e}")
            continue
        out.append("Modules (first 80): " + ", ".join(modules))
        out.append("Top-level port identifiers (best-effort): " + ", ".join(dict.fromkeys(ports[:160])))
        out.append("Sequential/clock cell type counts (best-effort): " + json.dumps(cells, ensure_ascii=False))
    return "\n".join(out)


@functools.lru_cache(maxsize=1)
def manual_text() -> str:
    if not MANUAL.exists():
        return ""
    try:
        from pypdf import PdfReader
        chunks: list[str] = []
        for page_no, page in enumerate(PdfReader(str(MANUAL)).pages, 1):
            text = page.extract_text() or ""
            if text:
                chunks.append(f"[manual page {page_no}]\n{text}")
        return "\n\n".join(chunks)
    except Exception:
        return ""


def manual_context(query: str, max_chars: int = 12000) -> str:
    text = manual_text()
    if not text:
        return "Manual PDF is unavailable or not text-searchable. Use case Dofiles as syntax evidence; do not invent unsupported commands."
    terms = set(re.findall(r"[A-Za-z][A-Za-z0-9_]+", query.lower()))
    pages = re.split(r"(?=\[manual page \d+\])", text)
    ranked = sorted(pages, key=lambda p: sum(p.lower().count(term) for term in terms), reverse=True)
    selected: list[str] = []
    size = 0
    for page in ranked:
        if len(selected) >= 12:
            break
        if size + len(page) > max_chars:
            continue
        selected.append(page)
        size += len(page)
    return "\n\n".join(selected) or text[:max_chars]


def parse_limit_seconds(text: str) -> int:
    vals = re.findall(r"(?:wall\s*time|执行总时间|总时间|时间限制)[^\d]{0,40}(\d+)\s*(秒|seconds?|s\b|分钟|minutes?|min\b)?", text, re.I)
    if not vals:
        return int(os.environ.get("AGENT_CASE_TIMEOUT", "1500"))
    n, unit = vals[0]
    return int(n) * (60 if unit and ("分" in unit or "min" in unit.lower()) else 1)


def parse_tool_limit(text: str) -> int:
    patterns = [r"(?:工具调用次数|调用次数)[^\d]{0,30}(\d+)", r"(?:最多|不超过)[^\d]{0,20}(\d+)\s*(?:次|calls?)"]
    for pat in patterns:
        m = re.search(pat, text, re.I)
        if m:
            return max(1, int(m.group(1)))
    return max(1, int(os.environ.get("AGENT_MAX_TOOL_CALLS", "4")))


def contest_model() -> str:
    model = os.environ.get("LLM_MODEL", "deepseek-v4-pro").strip()
    if model != "deepseek-v4-pro":
        raise RuntimeError("Contest requires DeepSeek V4 Pro: LLM_MODEL must be deepseek-v4-pro")
    return model


def get_client() -> OpenAI:
    contest_model()
    key = os.environ.get("LLM_API_KEY", "").strip()
    if not key:
        raise RuntimeError("LLM_API_KEY is required; inject it at runtime and never bake it into the image.")
    return OpenAI(api_key=key, base_url=os.environ.get("LLM_BASE_URL", "https://dashscope.aliyuncs.com/compatible-mode/v1"), timeout=45.0, max_retries=0)


def ask(client: OpenAI, system: str, user: str, max_tokens: int = 7000) -> str:
    response = client.chat.completions.create(
        model=contest_model(),
        messages=[{"role": "system", "content": system}, {"role": "user", "content": user}],
        max_tokens=max_tokens,
        temperature=0.1,
    )
    content = response.choices[0].message.content
    if not content:
        raise RuntimeError("LLM returned an empty response")
    return content.strip()


def strip_fence(text: str) -> str:
    text = text.strip()
    text = re.sub(r"^```(?:tcl|text)?\s*", "", text, flags=re.I)
    text = re.sub(r"\s*```$", "", text)
    return text.strip() + "\n"


def json_from_response(text: str) -> dict[str, Any]:
    text = text.strip()
    text = re.sub(r"^```(?:json)?\s*|\s*```$", "", text, flags=re.I)
    start, end = text.find("{"), text.rfind("}")
    if start < 0 or end <= start:
        raise ValueError("LLM response did not contain a JSON object")
    value = json.loads(text[start:end + 1])
    if not isinstance(value, dict):
        raise ValueError("LLM JSON response was not an object")
    return value


def get_task_artifacts(input_dir: Path) -> tuple[str, str, list[Path], list[Path], Path | None]:
    task_spec_path = input_dir / "task_spec.md"
    if not task_spec_path.exists():
        raise FileNotFoundError("Missing task_spec.md")
    task_spec = read_text(task_spec_path, 60000)
    netlists = discover_files(input_dir / "netlist", ".v")
    libs = discover_files(input_dir / "lib", ".lib")
    if not netlists or not libs:
        raise FileNotFoundError("Expected at least one .v under netlist/ and one .lib under lib/")
    original = input_dir / "original.dofile"
    task = "task2" if original.is_file() else "task1"
    return task, task_spec, netlists, libs, original if original.is_file() else None


def context_for_run(input_dir: Path, task_spec: str, limits: str, netlists: list[Path], libs: list[Path], dofile: str, log: str = "", reports: str = "") -> str:
    lib_names = [str(p) for p in libs]
    lib_summary = []
    for p in libs:
        # Read only cell names; liberty files in public cases can be very large.
        names = re.findall(r"\bcell\s*\(\s*([^\)]+)\s*\)", read_text(p, 8_000_000))
        lib_summary.append(f"{p.name}: {len(names)} cells; sample={', '.join(names[:50])}")
    return f"""# Natural-language task specification
{task_spec}

# Runtime limits
{limits or 'Not supplied'}

# Input files
Input directory: {input_dir}
Netlists: {[str(p) for p in netlists]}
Liberty files: {lib_names}
{chr(10).join(lib_summary)}

# Best-effort structural netlist scan
{netlist_summary(netlists)}

# ScanInsertion manual excerpts (authoritative syntax reference)
{manual_context(task_spec)}

# Current Dofile
{dofile}

# Most recent tool log / diagnostics
{log[-18000:] if log else '(no run yet)'}

# Most recent tool reports
{reports[-18000:] if reports else '(no reports captured yet)'}
"""


def call_for_dofile(client: OpenAI, task: str, context: str, original: str | None,
                    input_dir: Path, run_dir: Path) -> tuple[str, dict[str, Any]]:
    mode = "Generate a Dofile from the task requirements." if task == "task1" else "Repair the supplied original Dofile while preserving valid intent."
    if task == "task2" and original:
        context += "\n# Original Dofile (repair starting point)\n" + original
    netlist_rule = ("Task 1 strictly forbids modifying any Pre-scan input netlist."
                    if task == "task1" else
                    "This runtime supports Dofile repairs only; it has no netlist-edit/EQY workflow. "
                    "Do not modify Pre-scan netlists. If netlist repair is necessary, leave the issue unresolved.")
    system = f"""You are an expert operator of the ScanInsertion tool `dftexp_scan` for the contest.
Follow the task specification exactly. Use only commands and options supported by the supplied manual excerpts and evidence from existing Dofiles. Never disable DRC to hide a violation. {netlist_rule} Never modify Liberty libraries, the tool, License configuration, or protected evaluation scripts.
Return exactly one JSON object with keys: dofile (complete Tcl script as a string), summary (brief), requirement_mapping (array of objects with requirement and dft_config), and issue_resolutions (array; each item has issue_id, phenomenon, evidence_excerpt, located_object, diagnosis, root_cause, violated_requirement, fix, and optional verification). Each evidence_excerpt must be an exact short excerpt copied from the supplied PREVIOUS run's tool log or report. Describe a concrete object and root cause; use an empty array when no issue is directly evidenced. For verification you may provide an object with source (a report filename or relative report path) and expected_excerpt (a specific positive tool report value or completion message expected after the fix). This is a verification plan, not a claim that verification already occurred. Do not use disappearance of a diagnostic as positive evidence. Do not claim a requirement is met unless the script configures it.
The actual read-only input directory is {input_dir}. The current run directory and tool working directory are {run_dir}. Use the supplied absolute input file paths. Write reports under {run_dir / 'reports'} and deliverables under {run_dir / 'deliverables'}, or use paths relative to the current working directory. Add `exit` at the end. No markdown fences."""
    user = f"{mode}\n\n{context}\n\nReturn the JSON object now."
    result = json_from_response(ask(client, system, user))
    dofile = result.get("dofile")
    if not isinstance(dofile, str) or not dofile.strip():
        raise ValueError("LLM JSON is missing a non-empty dofile")
    return strip_fence(dofile), result


def _is_inside(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def collect_tool_outputs(run_dir: Path, run_id: str) -> list[Path]:
    """Copy real tool artifacts into stable run folders without flattening collisions."""
    delivery = run_dir / "deliverables"
    reports = run_dir / "reports"
    delivery.mkdir(parents=True, exist_ok=True)
    reports.mkdir(parents=True, exist_ok=True)
    log_path = run_dir / f"{run_id}.log"
    dofile_path = delivery / f"{run_id}.dofile"
    copied: list[Path] = []
    for source in sorted(run_dir.rglob("*")):
        if not source.is_file() or source.is_symlink() or source == log_path or source == dofile_path:
            continue
        if _is_inside(source, delivery) or _is_inside(source, reports):
            continue
        rel = source.relative_to(run_dir)
        if rel.parts and rel.parts[0] == "input":
            continue
        if source.name.endswith(".dofile") or source.suffix.lower() == ".log":
            continue

        parts = list(rel.parts)
        lower_parts = [part.lower() for part in parts]
        report_at = next((i for i in range(len(lower_parts) - 1, -1, -1) if lower_parts[i] in {"report", "reports"}), None)
        output_at = next((i for i in range(len(lower_parts) - 1, -1, -1) if lower_parts[i] in {"output", "deliverable", "deliverables"}), None)
        if report_at is not None:
            destination_root, subparts = reports, parts[report_at + 1:]
        elif output_at is not None:
            destination_root, subparts = delivery, parts[output_at + 1:]
        elif source.suffix.lower() in {".rpt", ".report", ".txt"}:
            destination_root, subparts = reports, parts
        else:
            destination_root, subparts = delivery, parts
        if not subparts:
            subparts = [source.name]
        target = destination_root.joinpath(*subparts)
        if source.resolve() == target.resolve():
            copied.append(target)
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        try:
            if not target.exists():
                shutil.copy2(source, target)
            copied.append(target)
        except OSError:
            continue
    return copied


def tool_run(dofile: str, run_dir: Path, run_id: str, timeout: int, execute_path: Path | None = None) -> dict[str, Any]:
    delivery = run_dir / "deliverables"
    reports = run_dir / "reports"
    delivery.mkdir(parents=True, exist_ok=True)
    reports.mkdir(parents=True, exist_ok=True)
    dofile_path = delivery / f"{run_id}.dofile"
    dofile_path.write_text(dofile, encoding="utf-8")
    if execute_path is None:
        # Keep [info script] rooted at the run directory so common script_dir-relative
        # output conventions stay inside this round's isolated workspace.
        execute_path = run_dir / f"{run_id}.dofile"
        execute_path.write_text(dofile, encoding="utf-8")
    log_path = run_dir / f"{run_id}.log"
    cmd = [TOOL, "-f", str(execute_path)]
    started = time.monotonic()
    try:
        proc = subprocess.run(cmd, cwd=run_dir, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                              text=True, errors="replace", timeout=max(1, timeout), check=False)
        log_path.write_text(proc.stdout, encoding="utf-8")
        status = "completed" if proc.returncode == 0 else "error"
        error = None
        code = proc.returncode
    except subprocess.TimeoutExpired as e:
        output = e.stdout or ""
        if isinstance(output, bytes):
            output = output.decode("utf-8", "replace")
        log_path.write_text(str(output) + "\n[agent] tool timeout\n", encoding="utf-8")
        status, error, code = "aborted", "timeout", None
    elapsed = time.monotonic() - started
    # Collect only actual tool outputs. Preserve subdirectories and never fabricate reports.
    output_files = collect_tool_outputs(run_dir, run_id)
    return {"run_id": run_id, "status": status, "returncode": code, "error": error,
            "elapsed_seconds": round(elapsed, 3), "log_path": log_path,
            "artifacts": [p.relative_to(run_dir).as_posix() for p in output_files]}


def check_output(run_dir: Path, task_spec: str, task: str, dofile: str, status: str) -> tuple[bool, list[str]]:
    problems: list[str] = []
    log = read_text(run_dir / f"{run_dir.name}.log", 100000)
    if status != "completed":
        problems.append("ScanInsertion tool did not exit successfully")
    diagnostic_files = [p for p in (run_dir / "reports").rglob("*") if p.is_file()]
    diagnostic_files += [p for p in run_dir.rglob("*") if p.is_file() and p.suffix.lower() in {".rpt", ".report"}]
    diagnostic_files = list(dict.fromkeys(diagnostic_files))
    diagnostics = "\n".join(read_text(p, 100000) for p in diagnostic_files)
    diagnostic_text = log + "\n" + diagnostics
    if re.search(r"\[(?:ERROR|FATAL)\]", diagnostic_text, re.I):
        problems.append("Tool log or DRC report contains an ERROR/FATAL diagnostic")
    allowed_codes: set[str] = set()
    for line in task_spec.splitlines():
        if re.search(r"忽略|允许|无需处理|不需要处理", line):
            allowed_codes.update(re.sub(r"[-_ ]", "", code).upper()
                                 for code in re.findall(r"DFTR[-_ ]?(?:TIE[01]|\d+)", line, re.I))
    violation_total = re.search(r"Total violations:\s*(\d+)", diagnostic_text, re.I)
    if violation_total and int(violation_total.group(1)) > 0:
        found_codes = {re.sub(r"[-_ ]", "", c).upper()
                       for c in re.findall(r"DFTR[-_ ]?(?:TIE[01]|\d+)", diagnostic_text, re.I)}
        blocking_codes = found_codes - allowed_codes
        strict_zero = bool(re.search(r"DRC.{0,50}(?:无[^\n]{0,12}违例|必须清零|zero\s+violations|no\s+violations)|(?:无违例|必须清零).{0,40}DRC|(?:其余|其他).{0,12}(?:违例|violation).{0,20}(?:清零|zero)", task_spec, re.I))
        warning_only = bool(re.search(r"\[WARNING\].*DFTDRC", diagnostic_text, re.I)) and not re.search(r"\[(?:ERROR|FATAL)\].*DFTDRC", diagnostic_text, re.I)
        if not found_codes or blocking_codes and (strict_zero or not warning_only):
            problems.append("DRC report has nonzero violations" +
                            (f" (unallowed codes: {', '.join(sorted(blocking_codes))})" if blocking_codes else " whose codes could not be verified"))
    actual_files = [p for p in run_dir.rglob("*") if p.is_file() and p.suffix.lower() not in {".dofile", ".log"} and not _is_inside(p, run_dir / "input")]
    if not any(p.suffix.lower() in {".v", ".vg"} for p in actual_files):
        problems.append("No actual Verilog deliverable was produced")
    report_files = [p for p in actual_files if p.suffix.lower() in {".rpt", ".report", ".txt"}]
    report_text = "\n".join(read_text(p, 50000) for p in report_files)
    desired = re.search(r"(?:共\s*)\*{0,2}(\d+)\*{0,2}\s*条\s*(?:扫描)?链", task_spec)
    if desired is None:
        desired = re.search(r"(?:scan\s*chain(?:s)?\s*(?:count|number)?|chain_count)\s*(?:is|=|:|：|为|应为)?\s*(\d+)", task_spec, re.I)
    desired_count = int(desired.group(1)) if desired else None
    if desired_count is None:
        lines = task_spec.splitlines()
        for idx, line in enumerate(lines):
            if "|" not in line or "chain_count" not in line.lower():
                continue
            headers = [cell.strip().lower().strip("`*") for cell in line.strip().strip("|").split("|")]
            if "chain_count" not in headers:
                continue
            col = headers.index("chain_count")
            counts: list[int] = []
            for row in lines[idx + 1:]:
                if "|" not in row:
                    break
                cells = [cell.strip().strip("`*") for cell in row.strip().strip("|").split("|")]
                if col < len(cells) and cells[col].isdigit():
                    counts.append(int(cells[col]))
            if counts:
                desired_count = sum(counts)
                break
    no_chain = re.search(r"(?:不涉及|无需|不需要|不要求|不构建|不插入|不生成|no\s+chain|no\s+scan\s+chain).{0,40}(?:扫描链|scan\s*chain)|(?:扫描链|scan\s*chain).{0,40}(?:不涉及|无需|不需要|不要求|不构建|不插入|不生成)", task_spec, re.I)
    requires_chain = task == "task2" or (not no_chain and bool(re.search(r"(?:scan\s*chain|扫描链).{0,30}(?:构建|插入|数量|条|chain|chain_count)", task_spec, re.I)))
    if requires_chain:
        if not any("chain" in p.name.lower() or "链" in p.name for p in report_files):
            problems.append("No scan-chain report found for a task that requests scan-chain evidence")
        if desired_count is not None:
            actual = re.search(r"(?:total\s+(?:scan\s+)?chains?(?:\s+checked)?|number\s+of\s+chains|scan\s+chains?)\s*[:=：]?\s*(\d+)", report_text + "\n" + log, re.I)
            if actual is None:
                chain_names = set(re.findall(r"(?:Sub)?ScanChain[_-]?\d+", report_text + "\n" + log, re.I))
                if chain_names:
                    actual_count = len(chain_names)
                else:
                    actual_count = None
            else:
                actual_count = int(actual.group(1))
            if actual_count is not None and actual_count != desired_count:
                default_partition = bool(re.search(r"默认分区|default[_ ]partition", task_spec, re.I))
                default_rows = bool(re.search(r"Default[_ ]Partition", report_text, re.I))
                one_implicit_default_chain = actual_count == desired_count + 1 and default_partition and default_rows
                if not one_implicit_default_chain:
                    problems.append(f"Scan-chain count mismatch: requested {desired_count}, tool report shows {actual_count}")
            elif actual_count is None:
                problems.append(f"Could not verify requested scan-chain count {desired_count} from reports")
        max_length = re.search(r"(?:最大链长|最大长度|最大链长度|链最大长度)[^\d]{0,40}(\d+)|maximum\s+(?:chain\s+)?length\s*(?:is|of|:|=)?\s*(\d+)|max_length\s*(?:is|:|=)\s*(\d+)", task_spec, re.I)
        max_length_value = int(next(group for group in max_length.groups() if group)) if max_length else None
        # Public specs also express per-partition limits in Markdown tables.
        spec_lines = task_spec.splitlines()
        for idx, line in enumerate(spec_lines):
            if "|" not in line or "max_length" not in line.lower():
                continue
            headers = [cell.strip().lower().strip("`*") for cell in line.strip().strip("|").split("|")]
            if "max_length" not in headers:
                continue
            col = headers.index("max_length")
            for row in spec_lines[idx + 1:]:
                if "|" not in row:
                    break
                cells = [cell.strip().strip("`*") for cell in row.strip().strip("|").split("|")]
                if col < len(cells) and cells[col].isdigit():
                    value = int(cells[col])
                    max_length_value = max(max_length_value or 0, value)
        if max_length_value is not None:
            lengths = [int(value) for value in re.findall(r"(?im)^\s*(?:I\s*)?\d+\s+(\d+)\s+\S+\s+\S+", report_text)]
            lengths.extend(int(value) for value in re.findall(r"Scan chain\s+['\"]?\w+['\"]?[^\n]*?includes\s+(\d+)\s+cells", log, re.I))
            if not lengths:
                problems.append(f"Could not verify scan-chain maximum length {max_length_value} from reports")
            elif max_length_value is not None and max(lengths) > max_length_value:
                problems.append(f"Scan-chain length {max(lengths)} exceeds the specified maximum {max_length_value}")

    if re.search(r"DRC.{0,40}(?:报告|report|零|无|清零|zero|no\s+violation)|(?:零|无|清零).{0,30}DRC", task_spec, re.I):
        drc_reports = [p for p in report_files if "drc" in p.name.lower() or "violation" in p.name.lower()]
        if not drc_reports and not re.search(r"Total violations:\s*\d+", log, re.I):
            problems.append("Task requires DRC evidence, but no DRC report or violation summary was produced")
    # Check explicitly named output artifacts when the task specification lists them.
    output_section = re.search(r"(?:##\s*(?:输出文件|输出要求)|输出文件|输出要求)(.*?)(?=\n##\s|\Z)", task_spec, re.S)
    if output_section:
        listed = set(re.findall(r"`([^`]+\.(?:v|vg|ctl|def|rpt))`", output_section.group(1), re.I))
        produced_names = {p.name.lower() for p in actual_files}
        missing = [name for name in sorted(listed) if not any(fnmatch_name(name.lower(), produced) for produced in produced_names)]
        if missing:
            problems.append("Missing task-listed output artifacts: " + ", ".join(missing[:12]))
    return not problems, problems


def fnmatch_name(pattern: str, name: str) -> bool:
    """Match a task-listed artifact name; allow documented wildcard suffixes."""
    if "*" not in pattern:
        return pattern == name
    return re.fullmatch(re.escape(pattern).replace(r"\*", ".*"), name) is not None


def copy_tree_contents(source: Path, target: Path) -> None:
    target.mkdir(parents=True, exist_ok=True)
    for p in source.rglob("*"):
        if not p.is_file():
            continue
        rel = p.relative_to(source)
        # Keep the report/deliverable tree and prevent same-name reports from overwriting.
        dest = target / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        if not dest.exists():
            shutil.copy2(p, dest)


def write_diff(out: Path, old: str, new: str, old_name: str, new_name: str) -> str:
    diffs = out / "diffs"
    diffs.mkdir(parents=True, exist_ok=True)
    path = diffs / f"dofile_{old_name}_to_{new_name}.diff"
    lines = difflib.unified_diff(old.splitlines(True), new.splitlines(True), fromfile=old_name, tofile=new_name)
    path.write_text("".join(lines), encoding="utf-8")
    return str(path.relative_to(out))


def run_evidence_files(run_dir: Path) -> list[Path]:
    """Enumerate real evidence without loading large logs into memory."""
    reports = sorted(p for p in (run_dir / "reports").rglob("*")
                     if p.is_file() and p.suffix.lower() in {".rpt", ".report", ".txt"})
    log = run_dir / f"{run_dir.name}.log"
    return reports + ([log] if log.is_file() else [])


def locate_evidence(files: list[Path], output_dir: Path, excerpt: str,
                    positive: bool = False) -> dict[str, str] | None:
    """Locate an exact excerpt, retaining real line numbers even in long logs."""
    if not excerpt:
        return None
    line_count = excerpt.count("\n") + 1
    for path in files:
        window: deque[str] = deque(maxlen=line_count)
        with path.open("r", encoding="utf-8", errors="replace") as stream:
            for last_line, line in enumerate(stream, 1):
                window.append(line)
                content = "".join(window)
                if excerpt not in content:
                    continue
                # A Tcl echo/comment is not evidence that the tool performed an action.
                if (re.search(r"CMD-0034|SOURCE TCL FILE", content, re.I)
                        or any(part.lstrip().startswith("#") for part in window)):
                    continue
                if positive and re.search(r"\[(?:ERROR|FATAL|WARNING)\]", content, re.I):
                    continue
                after = content[content.index(excerpt) + len(excerpt):]
                if positive and excerpt[-1].isdigit() and after[:1].isdigit():
                    continue
                before = content[:content.index(excerpt)]
                first = last_line - len(window) + 1 + before.count("\n")
                last = first + line_count - 1
                return {"source": path.relative_to(output_dir).as_posix(),
                        "locator": f"L{first}" if first == last else f"L{first}-L{last}",
                        "excerpt": excerpt}
    return None


def record_issue_fixes(meta: dict[str, Any], issues: list[dict[str, Any]],
                       verification_plans: dict[str, dict[str, Any]], output_dir: Path,
                       previous_run: str, current_run: str, change_id: str) -> None:
    """Bind a proposed fix to the previous run that actually exposed the issue."""
    if not previous_run or not change_id:
        return
    files = run_evidence_files(output_dir / "runs" / previous_run)
    for item in meta.get("issue_resolutions", []):
        if not isinstance(item, dict):
            continue
        cited = str(item.get("evidence_excerpt", item.get("excerpt", ""))).strip()
        evidence = locate_evidence(files, output_dir, cited)
        if not evidence:
            continue
        diagnosis = {"summary": str(item.get("diagnosis", "")),
                     "located_object": str(item.get("located_object", "")),
                     "root_cause": str(item.get("root_cause", "")),
                     "violated_requirement": str(item.get("violated_requirement", ""))}
        existing = next((issue for issue in issues
                         if (issue["found"]["source"] == evidence["source"] and
                             issue["found"]["excerpt"] == cited) or
                         (diagnosis["located_object"] and diagnosis["root_cause"] and
                          issue["diagnosis"]["located_object"] == diagnosis["located_object"] and
                          issue["diagnosis"]["root_cause"] == diagnosis["root_cause"])), None)
        if existing is None:
            existing = {"issue_id": f"I{len(issues) + 1}",
                        "phenomenon": str(item.get("phenomenon", "")),
                        "found": {"run_ref": previous_run, **evidence, "verified": True},
                        "diagnosis": diagnosis, "attempts": []}
            issues.append(existing)
        else:
            existing["diagnosis"] = diagnosis
        existing["attempts"].append({
            "fix": {"action": str(item.get("fix", "")), "artifact_ref": [change_id]},
            "verify": {"run_ref": current_run, "source": f"runs/{current_run}/{current_run}.log",
                       "resolved": False, "locator": "", "excerpt": ""}})
        plan = item.get("verification", {})
        verification_plans[existing["issue_id"]] = plan if isinstance(plan, dict) else {}


def positive_issue_evidence(issue: dict[str, Any], plan: dict[str, Any],
                           files: list[Path], output_dir: Path) -> dict[str, str] | None:
    """Accept conservative, issue-specific positive evidence from a real rerun."""
    found = issue["found"]["excerpt"]
    diagnosis = issue["diagnosis"]
    # A zero DRC summary proves a DRC condition only; it says nothing about configuration.
    if re.search(r"\bDFTR[-_ ]?(?:\d+|TIE[01]|L[12])\b|Total violations:\s*[1-9]\d*", found, re.I):
        drc_files = [p for p in files if "drc" in p.name.lower() or "violation" in p.name.lower()]
        return locate_evidence(drc_files, output_dir, "Total violations: 0", positive=True)
    expected = str(plan.get("expected_excerpt", "")).strip()
    source = str(plan.get("source", "")).strip().replace("\\", "/")
    if len(expected) < 8 or "\n" in expected or not source or expected == found:
        return None
    # Report paths may be nested; compare them relative to their run without accepting arbitrary paths.
    candidates = [p for p in files if p.name == source or p.relative_to(output_dir).as_posix() == source or
                  p.relative_to(output_dir).as_posix().endswith("/" + source)]
    description = " ".join(str(value) for value in diagnosis.values())
    required = diagnosis.get("violated_requirement", "")
    if required and re.search(r"chain[_ -]?count|链数|扫描链数量|scan\s+chains?.{0,20}(?:count|number)", description, re.I):
        wanted = re.search(r"(\d+)\s*条|(?:chain[_ -]?count|(?:number|total)\s+of\s+(?:scan\s+)?chains?)\s*[:=：]?\s*(\d+)", required, re.I)
        actual = re.search(r"(?:number\s+of\s+chains|total\s+(?:scan\s+)?chains|scan\s+chains?)\s*[:=：]?\s*(\d+)", expected, re.I)
        if wanted and actual and int(next(value for value in wanted.groups() if value)) == int(actual.group(1)):
            candidates = [p for p in candidates if p.suffix.lower() in {".rpt", ".report", ".txt"}
                          and "chain" in p.name.lower()]
            return locate_evidence(candidates, output_dir, expected, positive=True)
        return None
    if re.search(r"ERROR|FATAL|unknown|invalid", found, re.I) and not required:
        commands = re.findall(r"\b(?:set|load|write|rpt|examine|insert|add)_[A-Za-z0-9_]+\b", diagnosis["located_object"])
        if any(command in expected for command in commands) and re.search(r"completed|successfully|passed", expected, re.I):
            return locate_evidence(candidates, output_dir, expected, positive=True)
    # Wrapper, signal, and other conditions need a dedicated semantic verifier.
    return None


def verify_issue_fixes(issues: list[dict[str, Any]], verification_plans: dict[str, dict[str, Any]],
                       output_dir: Path, current_run: str, tool_checks_passed: bool) -> None:
    if not tool_checks_passed:
        return
    files = run_evidence_files(output_dir / "runs" / current_run)
    for issue in issues:
        attempts = issue.get("attempts", [])
        if not attempts or issue["found"]["run_ref"] == current_run:
            continue
        verify = attempts[-1]["verify"]
        if verify["run_ref"] != current_run or verify["resolved"]:
            continue
        evidence = positive_issue_evidence(issue, verification_plans.get(issue["issue_id"], {}), files, output_dir)
        if evidence:
            verify.update({"run_ref": current_run, **evidence, "resolved": True})


def issue_audit_problems(task: str, issues: list[dict[str, Any]], changes: list[dict[str, Any]]) -> list[str]:
    problems = []
    if task == "task2" and not issues:
        problems.append("Task 2 has no evidence-backed issue diagnosis; audit closure is incomplete")
    change_ids = {change["change_id"] for change in changes}
    for issue in issues:
        diagnosis = issue.get("diagnosis", {})
        if not all(str(diagnosis.get(key, "")).strip() for key in ("summary", "located_object", "root_cause")):
            problems.append(f"{issue['issue_id']} lacks a concrete object or root-cause diagnosis")
        attempts = issue.get("attempts", [])
        if not attempts or not attempts[-1]["verify"].get("resolved"):
            problems.append(f"{issue['issue_id']} lacks positive verification evidence from a later tool run")
        for attempt in attempts:
            if not attempt["fix"].get("action") or not attempt["fix"].get("artifact_ref") or any(
                    ref not in change_ids for ref in attempt["fix"].get("artifact_ref", [])):
                problems.append(f"{issue['issue_id']} has an incomplete fix or a non-closing change reference")
    return problems


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("-input", "--input", required=True)
    parser.add_argument("-output", "--output", required=True)
    args = parser.parse_args()
    input_dir, output_dir = Path(args.input).resolve(), Path(args.output).resolve()
    # Accept both the platform's case directory (`case/input/task_spec.md`) and a
    # direct mount of the case input directory (`/input/task_spec.md`).
    if not (input_dir / "task_spec.md").is_file() and (input_dir / "input" / "task_spec.md").is_file():
        input_dir = input_dir / "input"
    output_dir.mkdir(parents=True, exist_ok=True)
    runs_root = output_dir / "runs"
    runs_root.mkdir(exist_ok=True)
    run_records: list[dict[str, Any]] = []
    changes: list[dict[str, Any]] = []
    issue_records: list[dict[str, Any]] = []
    verification_plans: dict[str, dict[str, Any]] = {}
    requirement_mapping: list[dict[str, Any]] = []
    final_dofile = ""
    task = "task1"
    error_message = None
    start = time.monotonic()
    final_run_dir: Path | None = None
    try:
        if not input_dir.is_dir():
            raise FileNotFoundError(f"Input directory does not exist: {input_dir}")
        if not os.environ.get("SCANINSERTION_LICENSE_SERVER"):
            raise RuntimeError("SCANINSERTION_LICENSE_SERVER is required")
        task, task_spec, netlists, libs, original_path = get_task_artifacts(input_dir)
        limits = read_text(input_dir / "limitations.md", 8000)
        timeout_total = parse_limit_seconds(limits)
        finalize_reserve = 30
        max_calls = parse_tool_limit(limits)
        # Contest tool-call ceiling always includes a strict local cap.
        max_calls = min(max_calls, int(os.environ.get("AGENT_MAX_TOOL_CALLS", str(max_calls))))
        client: OpenAI | None = None
        original = read_text(original_path, 50000) if original_path else None
        previous = original or ""
        last_log = ""
        generation_error = ""
        static_context = context_for_run(input_dir, task_spec, limits, netlists, libs, "")
        for index in range(1, max_calls + 1):
            remaining = timeout_total - (time.monotonic() - start)
            if remaining <= finalize_reserve + 1:
                break
            rid = f"R{index}"
            run_dir = runs_root / rid
            run_dir.mkdir(parents=True, exist_ok=False)
            previous_reports = ""
            if run_records:
                previous_dir = runs_root / run_records[-1]["run_id"]
                excerpts = []
                for rp in previous_dir.rglob("*"):
                    if rp.is_file() and rp.suffix.lower() in {".rpt", ".report", ".txt"}:
                        excerpts.append(f"### {rp.relative_to(previous_dir)}\n{read_text(rp, 12000)}")
                previous_reports = "\n\n".join(excerpts)[:18000]
            context = (static_context + f"\n# Current Dofile\n{previous}\n\n"
                       f"# Most recent tool log / diagnostics\n{last_log[-18000:] if last_log else '(no run yet)'}\n\n"
                       f"# Most recent tool reports\n{previous_reports[-18000:] if previous_reports else '(no reports captured yet)'}\n")
            if task == "task2" and index == 1 and original is not None:
                # R1 is a faithful diagnostic run of the supplied Dofile. Preserve the original as evidence.
                dofile, meta = original, {"summary": "Run the supplied original Dofile to gather diagnostic evidence.", "requirement_mapping": [], "issue_resolutions": []}
                script_root = run_dir / "input"
                script_root.mkdir(parents=True, exist_ok=True)
                (script_root / "original.dofile").write_text(original, encoding="utf-8")
                for dirname in ("netlist", "lib", "ctl"):
                    source = input_dir / dirname
                    if source.exists():
                        (script_root / dirname).symlink_to(source, target_is_directory=True)
                execution_path = script_root / "original.dofile"
            else:
                try:
                    if client is None:
                        client = get_client()
                    remaining = timeout_total - (time.monotonic() - start)
                    if remaining <= finalize_reserve + 1:
                        generation_error = f"Insufficient time for Dofile generation before {rid}; finalization reserve retained"
                        break
                    request_client = client.with_options(timeout=max(1.0, min(45.0, remaining - finalize_reserve - 1)), max_retries=0)
                    dofile, meta = call_for_dofile(request_client, task, context, original if task == "task2" else None,
                                                 input_dir, run_dir)
                except Exception as e:
                    generation_error = f"LLM Dofile generation failed before R{index}: {type(e).__name__}: {e}"
                    if run_records:
                        break
                    raise
                execution_path = None
            # Generation and report-context reads consumed time; never reuse the pre-LLM budget.
            remaining = timeout_total - (time.monotonic() - start)
            if remaining <= finalize_reserve + 1:
                generation_error = f"Insufficient time for tool call {rid}; finalization reserve retained"
                break
            previous_run = run_records[-1]["run_id"] if run_records else ""
            change_id = ""
            if index > 1:
                prior = run_records[-1]
                diff_path = write_diff(output_dir, previous, dofile, prior["run_id"], rid)
                change_id = f"F{len(changes)+1}"
                changes.append({"change_id": change_id, "type": "dofile",
                                "path": f"runs/{rid}/deliverables/{rid}.dofile", "diff_path": diff_path, "lec_ref": ""})
            final_dofile = dofile
            remaining = timeout_total - (time.monotonic() - start)
            per_run_timeout = max(1, min(900, int(remaining - finalize_reserve)))
            result = tool_run(dofile, run_dir, rid, per_run_timeout, execution_path)
            record = {k: v for k, v in result.items() if k != "log_path"}
            record["log_file"] = str((run_dir / f"{rid}.log").relative_to(output_dir)).replace("\\", "/")
            record["exit_status"] = result["status"]
            run_records.append(record)
            last_log = read_text(run_dir / f"{rid}.log", 50000)
            previous = dofile
            final_run_dir = run_dir
            ok, problems = check_output(run_dir, task_spec, task, dofile, result["status"])
            if meta.get("requirement_mapping"):
                requirement_mapping = []
                for item in meta.get("requirement_mapping", []):
                    if isinstance(item, dict):
                        requirement_mapping.append({"requirement": str(item.get("requirement", "")),
                                                    "dft_config": str(item.get("dft_config", "")),
                                                    "config_ref": {"source": "final_results/deliverables/final.dofile", "locator": ""}})
            record_issue_fixes(meta, issue_records, verification_plans, output_dir, previous_run, rid, change_id)
            verify_issue_fixes(issue_records, verification_plans, output_dir, rid, ok)
            unresolved = any(issue.get("found", {}).get("verified") and
                             not (issue.get("attempts") and issue["attempts"][-1].get("verify", {}).get("resolved"))
                             for issue in issue_records)
            if ok and not unresolved:
                break
            if index < max_calls:
                continue
        if not run_records:
            raise RuntimeError("No ScanInsertion tool call was made within the time budget")
        final_run_dir = runs_root / run_records[-1]["run_id"]
        final_results = output_dir / "final_results"
        final_results.mkdir(exist_ok=True)
        shutil.copy2(final_run_dir / f"{run_records[-1]['run_id']}.log", final_results / "final.log")
        deliverables = final_results / "deliverables"
        reports = final_results / "reports"
        deliverables.mkdir(exist_ok=True)
        reports.mkdir(exist_ok=True)
        (deliverables / "final.dofile").write_text(final_dofile, encoding="utf-8")
        # Copy actual tool-created products only.
        copy_tree_contents(final_run_dir / "reports", reports)
        copy_tree_contents(final_run_dir / "deliverables", deliverables)
        tool_checks_passed, final_problems = check_output(final_run_dir, task_spec, task, final_dofile, run_records[-1]["exit_status"])
        audit_problems = issue_audit_problems(task, issue_records, changes)
        audit_complete = not audit_problems
        passed = tool_checks_passed and audit_complete
        for mapping in requirement_mapping:
            config = mapping.get("dft_config", "")
            locator = ""
            if config:
                for line_no, line in enumerate(final_dofile.splitlines(), 1):
                    if config.strip() and config.strip() in line:
                        locator = f"L{line_no}"
                        break
            mapping.setdefault("config_ref", {})["locator"] = locator
        decision = {
            "case_id": case_id_for(input_dir),
            "task": task,
            "final_run": run_records[-1]["run_id"],
            "summary": f"Tool calls: {len(run_records)}; wall time: {time.monotonic() - start:.1f}s. Verified artifact checks: {'passed' if tool_checks_passed else 'incomplete'}; issue audit: {'complete' if audit_complete else 'incomplete'}. " + ("; ".join(final_problems + audit_problems) if final_problems or audit_problems else "") + (f"; {generation_error}" if generation_error else ""),
            "tool_checks_passed": tool_checks_passed,
            "issue_audit_complete": audit_complete,
            "audit_problems": audit_problems,
            "requirement_mapping": requirement_mapping,
            "issue_resolutions": issue_records,
            "tool_runs": [{"tool_call_id": r["run_id"], "log_file": r["log_file"],
                           "exit_status": r["exit_status"], "returncode": r.get("returncode"),
                           "elapsed_seconds": r.get("elapsed_seconds"), "artifacts": r.get("artifacts", [])}
                          for r in run_records],
            "file_changes": changes,
        }
        (output_dir / "decision_log.json").write_text(json.dumps(decision, ensure_ascii=False, indent=2), encoding="utf-8")
        print(json.dumps({"status": "completed" if passed else "incomplete", "task": task,
                          "tool_calls": len(run_records), "tool_checks_passed": tool_checks_passed,
                          "issue_audit_complete": audit_complete,
                          "problems": final_problems + audit_problems}, ensure_ascii=False))
        return 0 if passed else 2
    except Exception as e:
        error_message = f"{type(e).__name__}: {e}"
        print(error_message, file=sys.stderr)
        if not (output_dir / "decision_log.json").exists():
            (output_dir / "decision_log.json").write_text(json.dumps({"case_id": case_id_for(input_dir), "task": task,
                "final_run": run_records[-1]["run_id"] if run_records else "", "summary": "Agent failed: " + error_message,
                "requirement_mapping": requirement_mapping, "issue_resolutions": issue_records,
                "tool_runs": run_records, "file_changes": changes}, ensure_ascii=False, indent=2), encoding="utf-8")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
