#!/usr/bin/env python3
"""Auditable ScanInsertion agent runtime for the contest container."""
from __future__ import annotations

import argparse
from collections import deque
import difflib
import functools
import itertools
import json
import os
import re
import signal
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from openai import OpenAI
from netlist_repair import RepairRejected, changed_paths, edits_allowed, fingerprint_paths, prepare_repair
from netlist_structure import reset_polarity_hints, shift_register_context, shift_register_groups, source_instance_map
from report_validation import chain_problems, chain_rows, coverage_problems, ctl_overlength_exceptions, pseudo_clock_problems, segment_problems
from report_validation import report_rows as typed_report_rows
from dofile_recipe import configure_floating_inputs, configure_shift_segments, normalize_unrequested_counts
from floating_inputs import floating_clock_outputs
from clock_latch_context import clock_latch_context
from model_script_view import model_owned_script
from drc_retry_preflight import unchanged_control_retry_problems
from wrapper_validation import port_wrapper_rows, wrapper_problems, wrapper_style_evidence, wrapper_targets
from contest_rules import QA_READ_DATE, QA_URL, qa_context, qa_residual_codes
from drc_validation import drc_summaries, excluded_scan_cells, redirected_drc_codes, residual_positive_evidence, rule_codes, summary_permitted
from scan_exclusion_evidence import exclusion_command_evidence


TOOL = os.environ.get("DFTEXP_SCAN", "/opt/dftexp_scan/bin/dftexp_scan")
MANUAL = Path("/opt/dftexp_scan/doc/Scan_User_Manual.pdf")


def read_text(path: Path, limit: int = 30000) -> str:
    if not path.is_file():
        return ""
    with path.open("r", encoding="utf-8", errors="replace") as f:
        return f.read(limit)


def diagnostic_excerpt(path: Path, limit: int = 18000) -> str:
    """Keep early errors as well as the end of a large log for the next model request."""
    if not path.is_file():
        return ""
    errors: list[str] = []
    seen: set[str] = set()
    error_size = 0
    tail: deque[str] = deque()
    tail_size = 0
    drc_samples: dict[str, int] = {}
    with path.open(encoding="utf-8", errors="replace") as stream:
        for line in stream:
            drc = re.search(r"\b(DFTR[-_]?(?:\d+|TIE[01]))\b", line, re.I)
            if re.search(r"\[(?:ERROR|FATAL)\]|unknown (?:option|command)|invalid command", line, re.I) or drc:
                sample_ok = not drc or drc_samples.get(drc.group(1), 0) < 3
                if line not in seen and sample_ok and error_size + len(line) <= limit // 2:
                    errors.append(line)
                    seen.add(line)
                    error_size += len(line)
                    if drc:
                        drc_samples[drc.group(1)] = drc_samples.get(drc.group(1), 0) + 1
            tail.append(line)
            tail_size += len(line)
            while tail_size > limit // 2 and tail:
                tail_size -= len(tail.popleft())
    return ("# Earlier tool errors\n" + "".join(errors) + "\n# End of tool log\n" + "".join(tail))[:limit]


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


def netlist_summary(paths: list[Path], query: str = "") -> str:
    """Bound context size; never load a multi-hundred-MB gate netlist into the LLM prompt."""
    out: list[str] = []
    for p in paths:
        out.append(f"FILE {p.name} ({p.stat().st_size} bytes)")
        modules: list[str] = []
        ports: list[str] = []
        cells: dict[str, int] = {}
        module_names: set[str] = set()
        hierarchy: dict[str, list[tuple[str, str]]] = {}
        control_ports: dict[str, list[str]] = {}
        current_module = ""
        mentioned = set(re.findall(r"`([\w$]+)`", query))
        special_instances = []
        special_remaining = 0
        try:
            with p.open("r", encoding="utf-8", errors="replace") as f:
                for i, line in enumerate(f):
                    m = re.match(r"\s*module\s+([\w$]+)", line)
                    if m:
                        current_module = m.group(1)
                        module_names.add(current_module)
                        if len(modules) < 80:
                            modules.append(current_module)
                    if special_remaining:
                        special_instances[-1]["literal"] += line
                        special_remaining = 0 if ";" in line else special_remaining - 1
                    if current_module and re.match(r"\s*(?:input|output|inout)\b", line):
                        if re.search(r"clk|clock|rst|reset|test|scan|mode|mbist|jtag", line, re.I):
                            entries = control_ports.setdefault(current_module, [])
                            if len(entries) < 24:
                                entries.append(line.strip()[:240])
                        if len(ports) < 160:
                            ports.extend(re.findall(r"[\w$]+", line))
                    c = re.match(r"\s*([\w$]+)\s+(?:\\[^\s]+|[\w$]+)\s*\(", line)
                    if c and c.group(1) != "module" and current_module and len(special_instances) < 12:
                        inst = re.match(r"\s*[\w$]+\s+(\\[^\s]+|[\w$]+)\s*\(", line)
                        if inst and inst.group(1).removeprefix("\\") in mentioned:
                            special_instances.append({"module": current_module, "instance": inst.group(1),
                                                      "source": f"{p}:L{i+1}", "literal": line})
                            special_remaining = 0 if ";" in line else 8
                    if c and any(term in c.group(1).lower() for term in ("df", "dl", "latch", "clk", "clock")):
                        kind = c.group(1)
                        if not kind.startswith("sky130_fd_sc_"):
                            kind = re.sub(r"\d+$", "*", kind)
                        cells[kind] = cells.get(kind, 0) + 1
                    if c and current_module and not c.group(1).startswith("sky130_fd_sc_"):
                        entries = hierarchy.setdefault(current_module, [])
                        instance = re.match(r"\s*[\w$]+\s+(\\[^\s]+|[\w$]+)\s*\(", line)
                        if instance and len(entries) < 64:
                            entries.append((instance.group(1), c.group(1)))
                    if re.match(r"\s*endmodule\b", line):
                        current_module = ""
        except OSError as e:
            out.append(f"Could not scan file: {e}")
            continue
        out.append("Modules (first 80): " + ", ".join(modules))
        out.append("Top-level port identifiers (best-effort): " + ", ".join(dict.fromkeys(ports[:160])))
        out.append("Sequential/clock cell type counts (numeric module variants grouped; first 100): " +
                   json.dumps(dict(sorted(cells.items(), key=lambda item: -item[1])[:100]), ensure_ascii=False))
        links = {name: [f"{instance}:{kind}" for instance, kind in entries if kind in module_names]
                 for name, entries in hierarchy.items()}
        child_modules = {kind for entries in hierarchy.values() for _, kind in entries}
        roots = sorted(module_names - child_modules)
        preferred = sorted(module_names.intersection(re.findall(r"[A-Za-z_][\w$]*", query)))
        preferred_roots = [name for name in preferred if name in roots]
        order = list(dict.fromkeys(preferred_roots + preferred + roots + list(links)))
        shown_roots = list(dict.fromkeys(preferred_roots + roots))[:40]
        out.append("Root modules (not instantiated by another module in this file): " + ", ".join(shown_roots))
        if len(roots) > 40:
            out.append(f"Root module candidates total: {len(roots)}; only 40 names shown.")
        out.append("Hierarchy (module -> child-instance:module): " +
                   json.dumps({name: links.get(name, []) for name in order[:40]}, ensure_ascii=False)[:8000])
        out.append("Clock/reset/test port declarations by module: " +
                   json.dumps({name: control_ports.get(name, []) for name in order[:12]}, ensure_ascii=False)[:5000])
        out.append("Actual module and literal connections for task-mentioned instances: " +
                   json.dumps(special_instances, ensure_ascii=False)[:7000])
    return "\n".join(out)[:50000]


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
    critical = []
    for pattern, commands in (
        (r"悬空|浮空|伪|pseudo", ["add_pseudo_pi", "rpt_pseudo_pi"]),
        (r"分区|partition", ["add_scan_partition", "set_current_scan_partition"]),
        (r"ICG|时钟门控|clock.gating", ["set_dft_clock_gating_cfg", "clock_gating_init_cycles"]),
        (r"Wrapper|黑盒|CTL", ["load_ctl", "set_wrapper_cfg", "add_dedicated_wrapper_cell_type"]),
        (r"替换|回替|replacement", ["set_scan_cell_mapping", "replace_unscan"]),
        (r"闩锁|latch|内部时钟|关联关系", ["associated_internal_clocks"]),
        (r"移位寄存器|segment", ["set_scan_segment", "rpt_scan_segment"]),
    ):
        if re.search(pattern, query, re.I):
            critical.extend(commands)
    pages = re.split(r"(?=\[manual page \d+\])", text)
    ranked = sorted(pages, key=lambda p: sum(p.lower().count(term) for term in terms) +
                    sum(p.lower().count(command) * 40 for command in critical), reverse=True)
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


def command_syntax(query: str, max_chars: int = 30000) -> str:
    path = Path(__file__).with_name("tool_help.json")
    if not path.is_file():
        return "No build-time command syntax cache; consult the manual excerpts."
    syntax = json.loads(path.read_text())
    names = ["__cell_properties", "load_lib", "load_netlist", "present_design", "set_scan_signal", "set_scan_cfg",
             "set_scan_cell_mapping", "set_scan_element", "set_dft_clock_gating_cfg", "insert_dft_logic",
             "examine_scan_drc", "examine_scan_chain", "set_scan_drc_cfg", "dump_netlist", "dump_ctl",
             "dump_def", "rpt_scan_chain", "rpt_scan_chain_cell", "rpt_scan_element", "rpt_scan_cfg",
             "rpt_scan_signal", "rpt_scan_drc_violation", "rpt_insertion_info", "get_cells",
             "get_pins", "get_ports", "get_nets", "get_obj_insts", "get_attribute", "get_property",
             "list_properties", "rpt_property", "foreach_in_collection", "sizeof_collection"]
    if re.search(r"悬空|浮空|伪|pseudo", query, re.I):
        names = ["add_pseudo_pi", "rpt_pseudo_pi"] + names
    if re.search(r"partition|分区", query, re.I):
        names = ["add_scan_partition", "set_current_scan_partition", "rpt_scan_partition"] + names
    if re.search(r"wrapper|CTL|黑盒", query, re.I):
        names = ["load_ctl", "set_wrapper_cfg", "add_dedicated_wrapper_cell_type", "rpt_dedicated_wrapper_cell_type",
                 "rpt_wrapper_cfg", "rpt_wrapper_implementation"] + names
    if re.search(r"移位寄存器|segment", query, re.I):
        names = ["set_scan_segment", "rpt_scan_segment"] + names
    if re.search(r"忽略|允许|无需处理", query):
        names = ["set_scan_drc_rule_handling", "rpt_scan_drc_rule_handling"] + names
    chunks = []
    size = 0
    for name in dict.fromkeys(names):
        text = syntax.get(name, "")
        if text and size + len(text) <= max_chars:
            chunks.append(text)
            size += len(text)
    return "\n\n".join(chunks)


def allowed_drc_codes(spec: str) -> set[str]:
    allowed = set()
    for sentence in re.split(r"[\n;；。]", spec):
        pending = set()
        for clause in re.split(r"[，,]", sentence):
            codes = rule_codes(clause)
            negative = re.search(r"不允许|不得|禁止|不忽略|not allowed|must not|do not ignore", clause, re.I)
            positive = re.search(r"忽略|允许|无需处理|不需要处理|\ballow|\bignore|\bpermit", clause, re.I)
            if negative:
                pending = set()
                continue
            if positive:
                allowed.update(codes or pending)
            if codes:
                pending = codes
    return allowed


def permitted_residual_drc_codes(task: str, spec: str) -> set[str]:
    return allowed_drc_codes(spec) | qa_residual_codes(task, spec)


def unsupported_options(dofile: str, task_spec: str | None = None, *,
                        known_reset_ports: set[str] | None = None,
                        permit_reset_inference: bool = False) -> list[str]:
    """Check literal options on simple commands against the installed tool's help."""
    path = Path(__file__).with_name("tool_help.json")
    if not path.is_file():
        return []
    syntax = json.loads(path.read_text())
    problems = []
    if (task_spec is not None and qa_residual_codes("task2", task_spec) and
            re.search(r"(?m)^\s*set_scan_element\s+(?:false|0|no|off)\b", dofile, re.I)):
        problems.append("Q19 permits visible DFTR10, not exclusion of scan FFs; remove set_scan_element false")
    if re.search(r"set_dft_clock_gating_cfg[^\n]*-exclude_elements\s+(?:\{\s*\}|\"\")", dofile):
        problems.append("Empty -exclude_elements is invalid; omit this option when no objects are excluded")
    design = ""
    inserted = set()
    declared_signals = {}
    for line in dofile.replace("\\\n", " ").splitlines():
        present = re.match(r"\s*present_design\s+([\w$]+)\s*$", line)
        if present:
            design = present.group(1)
        if re.match(r"\s*insert_dft_logic\b", line) and not re.search(r"-(?:\w+_only|replace_unscan)\b", line):
            inserted.add(design)
        examination = re.match(r"\s*(examine_scan_drc|examine_scan_chain)\b", line)
        if examination and design in inserted:
            problems.append(f"{examination.group(1)} must precede full insert_dft_logic; use rpt_scan_drc_violation for reporting afterwards")
        if re.match(r"\s*set_wrapper_cfg\b", line) and re.search(r"-style\s+none\b", line):
            if not re.search(r"\s-port\s+(?!\{\s*\}|\"\")(?:\S)", line):
                problems.append("set_wrapper_cfg -style none requires actual -port objects; use set_wrapper_cfg disable for global disable")
        rules_command = re.match(r"\s*set_scan_drc_rule_handling\s+(\{[^}]+\}|\S+)\s+(Error|Warning|Info|Ignore)\b", line)
        if rules_command:
            invalid = [rule for rule in rules_command.group(1).strip("{}").split()
                       if not re.fullmatch(r"DFTR(?:[1-9]|1[0-7]|-(?:TIE[01]|L[12]))", rule)]
            if invalid:
                problems.append("Invalid DRC IDs; spell each actual rule individually, without ranges: " + ", ".join(invalid))
        level = re.match(r"\s*set_scan_drc_rule_handling\s+(\{[^}]+\}|DFTR[\w-]+)\s+(Info|Ignore)\b", line)
        if level:
            rules = re.findall(r"DFTR\d+\b", level.group(1))
            forbidden = [rule for rule in rules if rule not in {"DFTR7", "DFTR17"}]
            if forbidden:
                problems.append("These DRC rules only support Error/Warning, never Info/Ignore: " + ", ".join(forbidden))
            if task_spec is not None:
                changed = {re.sub(r"[-_ ]", "", rule).upper() for rule in re.findall(r"DFTR[-_ ]?(?:TIE[01]|\d+)", level.group(1))}
                disallowed = changed - allowed_drc_codes(task_spec)
                if disallowed:
                    problems.append("Task does not authorize suppressing these DRC rules: " + ", ".join(sorted(disallowed)))
        if not re.match(r"\s*set_scan_signal\b", line):
            continue
        signal_type = re.search(r"-type\s+(\w+)", line)
        if signal_type and signal_type.group(1) == "reset" and task_spec is not None:
            reset_port = re.search(r"-port\s+(\{[^}]+\}|\"[^\"]+\"|\S+)", line)
            traced = bool(reset_port and reset_port.group(1).strip('"{}') in (known_reset_ports or set()))
            if re.search(r"没有复位端口|不作为.{0,20}(?:reset|复位)|no reset port", task_spec, re.I):
                problems.append("Task explicitly says no reset declaration is required; preserve ordinary functional inputs")
            elif not re.search(r"复位|reset|rst", task_spec, re.I) and not traced and not permit_reset_inference:
                problems.append("Task does not request a reset signal; remove the invented reset declaration")
        port = re.search(r"-port\s+([A-Za-z_][\w]*)\b", line)
        if signal_type and port:
            key, kind = (design, port.group(1)), signal_type.group(1)
            previous_type = declared_signals.get(key)
            if previous_type and (previous_type != kind or kind in {"clock", "reset", "wrapper_clock", "wrp_in_shift_en", "wrp_out_shift_en", "wrp_in_capture_en", "wrp_out_capture_en"}):
                problems.append(f"Port {port.group(1)} has conflicting or duplicate declarations ({previous_type}, {kind}); combine clock options and use separate wrapper control ports")
            declared_signals[key] = kind
        if signal_type and signal_type.group(1) != "scan_enable" and re.search(r"\s-usage\s", line):
            problems.append("set_scan_signal -usage is valid only for -type scan_enable")
        off = re.search(r"-off_state\s+([\w+-]+)(?:\s|$)", line)
        if off and off.group(1) not in {"0", "1"}:
            problems.append("set_scan_signal -off_state must be literal 0/1 or a validated Tcl variable")
    properties = set(re.findall(r"(?m)^\s*(\w+)\s+cell\s+", syntax.get("__cell_properties", "")))
    if properties:
        for match in re.finditer(r'-filter\s+(?:"([^"\n]+)"|\{([^}\n]+)\})', dofile):
            prefix = dofile[:match.start()].rsplit("\n", 1)[-1]
            queries = re.findall(r"\b(get_cells|get_obj_insts|get_pins|get_obj_pins|get_ports|get_nets)\b", prefix)
            if not queries or queries[-1] not in {"get_cells", "get_obj_insts"}:
                continue
            expression = match.group(1) or match.group(2)
            for name in re.findall(r"\b([A-Za-z_]\w*)\s*(?:==|!=|=~|!~|<=|>=|<|>)", expression):
                if name not in properties:
                    problems.append(f"Cell filter uses undefined property {name}; use the actual cell property table")
    for line in dofile.replace("\\\n", " ").splitlines():
        match = re.match(r"\s*([a-z_]+)\s+(.*)", line)
        if not match or match.group(1) not in syntax:
            continue
        command, args = match.groups()
        # Skip groups/substitutions; only literal options directly on this command are checked.
        args = re.sub(r'\[[^\]]*\]|"[^"\n]*"|\{[^}]*\}', "", args)
        args = args.split(";", 1)[0].split(" #", 1)[0]
        allowed = set(re.findall(r"(?<![\w-])-([a-z_]+)\b", syntax[command]))
        for option in re.findall(r"(?:^|\s)-([a-z_]+)\b", args):
            if not any(name.startswith(option) for name in allowed):
                problems.append(f"{command}: unsupported -{option}; supported options: " +
                                ", ".join("-" + name for name in sorted(allowed)))
    return list(dict.fromkeys(problems))[:10]


def normalize_report_redirection(dofile: str) -> str:
    """Adapt unsupported report -file to the official shell's equivalent redirection."""
    path = Path(__file__).with_name("tool_help.json")
    if not path.is_file():
        return dofile
    syntax = json.loads(path.read_text())
    lines = []
    for line in dofile.splitlines():
        match = re.match(r"(\s*)(rpt_[a-z_]+)(\s+.*)", line)
        if match and match.group(2) in syntax:
            indent, command, args = match.groups()
            if not re.search(r"(?<![\w-])-file\b", syntax[command]) and ">" not in args and ";" not in args:
                words = literal_tcl_words(args)
                if "-file" in words:
                    index = words.index("-file")
                    if index + 1 < len(words):
                        target = words[index + 1]
                        del words[index:index+2]
                        line = indent + command + (" " + " ".join(words) if words else "") + " > " + target
        lines.append(line)
    return "\n".join(lines) + "\n"


def parse_limit_seconds(text: str) -> int:
    vals = re.findall(r"(?:wall\s*time|执行总时间|总时间|时间限制)[^\d]{0,40}(\d+)\s*(秒|seconds?|s\b|分钟|minutes?|min\b)?", text, re.I)
    if not vals:
        return int(os.environ.get("AGENT_CASE_TIMEOUT", "1500"))
    n, unit = vals[0]
    return int(n) * (60 if unit and ("分" in unit or "min" in unit.lower()) else 1)


def parse_tool_limit(text: str) -> int | None:
    """Q15/A16 cancels old case call limits; an explicit local budget remains optional."""
    configured = os.environ.get("AGENT_MAX_TOOL_CALLS", "").strip()
    return max(1, int(configured)) if configured else None


def model_request_timeout(remaining: float) -> float:
    default = 120 if remaining >= 180 else 90
    return max(1.0, min(float(os.environ.get("AGENT_LLM_TIMEOUT", str(default))), remaining))


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


def ask(client: OpenAI, system: str, user: str, max_tokens: int = 7000,
        request_log: Path | None = None) -> str:
    started = time.monotonic()
    thinking = os.environ.get("LLM_ENABLE_THINKING", "false").lower() == "true"
    response = client.chat.completions.create(
        model=contest_model(),
        messages=[{"role": "system", "content": system}, {"role": "user", "content": user}],
        max_tokens=max(16000, max_tokens) if thinking else max_tokens,
        temperature=0.1,
        response_format={"type": "json_object"},
        extra_body={"enable_thinking": thinking},
    )
    if request_log is not None:
        usage = getattr(response, "usage", None)
        request_log.write_text(json.dumps({
            "model": contest_model(), "response_model": getattr(response, "model", None),
            "response_id": getattr(response, "id", None),
            "elapsed_seconds": round(time.monotonic() - started, 3),
            "finish_reason": getattr(response.choices[0], "finish_reason", None),
            "thinking_enabled": thinking,
            "reasoning_content": getattr(response.choices[0].message, "reasoning_content", None),
            "usage": usage.model_dump() if usage is not None else None,
            "content": response.choices[0].message.content,
        }, ensure_ascii=False, indent=2), encoding="utf-8")
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


def liberty_summary(path: Path) -> str:
    """Read actual sequential/clock cell pins without sending timing tables to the model."""
    names = []
    pin_map: dict[str, list[str]] = {}
    current = ""
    with path.open(encoding="utf-8", errors="replace") as stream:
        for line in stream:
            cell = re.match(r'\s*cell\s*\(\s*"?([^"\s)]+)', line)
            if cell:
                current = cell.group(1)
                names.append(current)
                if re.search(r"df|sdf|latch|clk|dl", current, re.I) and len(pin_map) < 128:
                    pin_map[current] = []
            pin = re.match(r'\s*pin\s*\(\s*"?([^"\s)]+)', line)
            if pin and current in pin_map and len(pin_map[current]) < 24:
                pin_map[current].append(pin.group(1))
    pins = dict(sorted(pin_map.items(), key=lambda item: ("sdf" not in item[0], item[0]))[:80])
    return (f"{path.name}: {len(names)} cells; sample={', '.join(names[:30])}\n"
            "Actual sequential/clock cell pin names (scan cells first): " + json.dumps(pins))[:8000]


def netlist_diagnostic_context(active: dict[Path, Path], diagnostic: str, limit: int = 6000) -> str:
    """Provide literal localized source evidence around diagnosed instances for a repair proposal."""
    tokens = re.findall(r"'([^'\n]{3,120})'", diagnostic)
    needles = list(dict.fromkeys(token.split("/")[-1] for token in tokens
                                if re.fullmatch(r"[\w$\[\]\\/.-]+", token)))[:24]
    if not needles:
        return ""
    result = []
    size = 0
    for original, current in active.items():
        before: deque[tuple[int, str]] = deque(maxlen=2)
        remaining = 0
        seen: set[str] = set()
        with current.open(encoding="utf-8", errors="replace") as stream:
            for number, line in enumerate(stream, 1):
                match = next((needle for needle in needles if needle not in seen and needle in line), None)
                if match:
                    seen.add(match)
                    header = f"\n# Netlist literal excerpt: original file {original}, current version {current}, L{max(1, number-2)}\n"
                    result.append(header)
                    result.extend(text for _, text in before)
                    size += len(header) + sum(len(text) for _, text in before)
                    remaining = 10
                if remaining:
                    result.append(line)
                    size += len(line)
                    remaining -= 1
                before.append((number, line))
                if size >= limit:
                    return "".join(result)[:limit]
    return "".join(result)[:limit]


def append_audit_reports(dofile: str, run_dir: Path) -> str:
    """Request real configuration evidence; never change the supplied Task 2 R1 script."""
    cache = Path(__file__).with_name("tool_help.json")
    if not cache.is_file():
        return dofile
    known = json.loads(cache.read_text())
    commands = [name for name in ("rpt_scan_signal", "rpt_scan_cfg", "rpt_scan_drc_rule_handling", "rpt_wrapper_cfg", "rpt_pseudo_pi")
                if name in known]
    # Incremental repairs inherit the preceding script. Replace our own report
    # block so each round records its current state once, in its own directory.
    dofile = re.sub(r"(?m)^\n?# Agent audit reports from actual tool state\n"
                    r"(?:rpt_(?:scan_(?:signal|cfg|drc_rule_handling|element)|wrapper_(?:cfg|implementation)|pseudo_pi)(?: -type all)? > [^\n]+\.audit\.rpt\"?\n)+"
                    r"(?:# End agent audit reports\n)?", "", dofile)
    reports = [(name, "") for name in commands]
    if "rpt_scan_element" in known and re.search(r"\bset_scan_element\b", dofile):
        reports.append(("rpt_scan_element", " -type all"))
    if "rpt_wrapper_implementation" in known and re.search(r"\bset_wrapper_cfg\b", dofile):
        reports.append(("rpt_wrapper_implementation", ""))
    extra = "\n# Agent audit reports from actual tool state\n" + "\n".join(
        f'{name}{options} > "{run_dir / "reports" / (name + ".audit.rpt")}"' for name, options in reports) + "\n# End agent audit reports\n"
    if not reports:
        return dofile
    exits = list(re.finditer(r"(?m)^\s*exit\s*$", dofile))
    if exits:
        position = exits[-1].start()
        return dofile[:position] + extra + dofile[position:]
    return dofile.rstrip() + extra + "exit\n"


def rebase_round(dofile: str, mapping: list[dict[str, Any]], previous_dir: Path,
                 run_dir: Path) -> tuple[str, list[dict[str, Any]]]:
    """Move inherited output references without changing earlier evidence files."""
    before, after = str(previous_dir), str(run_dir)
    copied = [dict(item) for item in mapping]
    for item in copied:
        if isinstance(item.get("dft_config"), str):
            item["dft_config"] = item["dft_config"].replace(before, after)
        item.pop("dofile_ref", None)
    return dofile.replace(before, after), copied


def literal_tcl_words(text: str) -> list[str]:
    words = []
    word = ""
    braces = brackets = 0
    quoted = escaped = False
    for character in text:
        if character.isspace() and not (braces or brackets or quoted or escaped):
            if word:
                words.append(word)
                word = ""
            continue
        word += character
        if escaped:
            escaped = False
            continue
        if character == "\\":
            escaped = True
        elif character == '"' and not braces:
            quoted = not quoted
        elif not quoted:
            if character == "{":
                braces += 1
            elif character == "}":
                braces -= 1
            elif character == "[":
                brackets += 1
            elif character == "]":
                brackets -= 1
    if braces or brackets or quoted:
        return []
    if word:
        words.append(word)
    return words


def normalize_load_file_lists(dofile: str) -> str:
    """Pack multiple literal input filenames into the official API's single Tcl list."""
    result = []
    for line in dofile.replace("\\\n", " ").splitlines():
        words = literal_tcl_words(line.strip())
        if words and words[0] in {"load_lib", "load_netlist"} and ";" not in line:
            suffix = r"\.lib[\"}\]]*$" if words[0] == "load_lib" else r"\.(?:v|sv)[\"}\]]*$"
            positions = [index for index in range(1, len(words)) if re.search(suffix, words[index], re.I)
                         and not words[index-1].startswith("-")]
            simple = all(not words[index].startswith("[list") and
                         not (words[index].startswith("{") and len(literal_tcl_words(words[index][1:-1])) > 1)
                         for index in positions)
            if len(positions) > 1 and simple and positions == list(range(positions[0], positions[-1]+1)):
                words[positions[0]:positions[-1]+1] = ["[list " + " ".join(words[index] for index in positions) + "]"]
                line = line[:len(line)-len(line.lstrip())] + " ".join(words)
        result.append(line)
    return "\n".join(result) + "\n"


def normalize_scan_port_formats(dofile: str) -> str:
    """Use the documented format API for indexed scan data port creation."""
    result = []
    for line in dofile.splitlines():
        words = literal_tcl_words(line.strip())
        if len(words) == 5 and words[0] == "set_scan_signal":
            options = dict(zip(words[1::2], words[2::2]))
            kind, name = options.get("-type"), options.get("-port", "")
            if set(options) == {"-type", "-port"} and kind in {"scan_data_in", "scan_data_out"} and "%d" in name:
                option = "si_port_format" if kind == "scan_data_in" else "so_port_format"
                line = line[:len(line)-len(line.lstrip())] + f"set_scan_cfg -{option} {name}"
        result.append(line)
    return "\n".join(result) + "\n"


def normalize_wrapper_roots(dofile: str, configuration: str | None = None) -> str:
    """Keep separately registered wrapper designs available when loading roots."""
    source = dofile if configuration is None else configuration
    wrappers = set(re.findall(r"add_dedicated_wrapper_cell_type\s+[^\n]*?-design_name\s+([\w$]+)", source))
    designs = set(re.findall(r"(?m)^\s*present_design\s+([\w$]+)\s*$", source))
    result = []
    for line in dofile.splitlines():
        words = literal_tcl_words(line.strip())
        if words and words[0] == "load_netlist" and "-top" in words and ";" not in line:
            index = words.index("-top")
            if index + 1 < len(words) and words[index+1] in designs and wrappers - {words[index+1]}:
                del words[index:index+2]
                line = line[:len(line)-len(line.lstrip())] + " ".join(words)
        result.append(line)
    return "\n".join(result) + "\n"


def normalize_reset_levels(dofile: str, hints: dict[str, Any], configuration: str | None = None) -> str:
    """Set reset inactivity from actual simple Liberty clear/preset paths."""
    designs = re.findall(r"(?m)^\s*present_design\s+([\w$]+)\s*$", configuration or "")
    current = designs[0] if len(set(designs)) == 1 else ""
    result = []
    for line in dofile.splitlines():
        present = re.match(r"\s*present_design\s+([\w$]+)\s*$", line)
        if present:
            current = present.group(1)
        if re.match(r"\s*set_scan_signal\b", line) and re.search(r"-type\s+reset\b", line):
            port = re.search(r"-port\s+([A-Za-z_][\w$]*)\b", line)
            hint = hints.get(current, {}).get(port.group(1)) if port else None
            if hint:
                level = str(hint["inactive_level"])
                if re.search(r"-off_state\s+[01]\b", line):
                    line = re.sub(r"(-off_state\s+)[01]\b", lambda match: match.group(1) + level, line)
                elif "-off_state" not in line:
                    line = line.rstrip() + " -off_state " + level
        result.append(line)
    return "\n".join(result) + "\n"


def normalize_associated_pin_paths(dofile: str, instances: dict[str, Any], configuration: str | None = None) -> str:
    """Correct a nonexistent prefix only when the exact pin exists directly at top."""
    designs = re.findall(r"(?m)^\s*present_design\s+([\w$]+)\s*$", configuration or "")
    current = designs[0] if len(set(designs)) == 1 else ""
    result = []
    for line in dofile.splitlines():
        present = re.match(r"\s*present_design\s+([\w$]+)\s*$", line)
        if present:
            current = present.group(1)
        words = literal_tcl_words(line.strip())
        if words and words[0] == "set_scan_signal" and "-associated_internal_clocks" in words:
            index = words.index("-associated_internal_clocks")
            if index + 1 < len(words):
                path = words[index+1].strip('"{}').lstrip("/").removeprefix(current + "/")
                pieces = path.split("/")
                if len(pieces) >= 2 and "$" not in path and not re.search(r"\s", path):
                    module = current
                    target = None
                    for name in pieces[:-1]:
                        target = instances.get(module, {}).get(name)
                        if not target:
                            break
                        module = target["type"]
                    valid = target and pieces[-1] in target["pins"]
                    direct = instances.get(current, {}).get(pieces[-2])
                    if not valid and direct and pieces[-1] in direct["pins"]:
                        words[index+1] = "{" + pieces[-2] + "/" + pieces[-1] + "}"
                        line = line[:len(line)-len(line.lstrip())] + " ".join(words)
        result.append(line)
    return "\n".join(result) + "\n"


def apply_dofile_edits(base: str, edits: Any) -> str:
    """Validate unique, disjoint spans against the same original round, then apply."""
    if not isinstance(edits, list) or not 0 <= len(edits) <= 12:
        raise ValueError("dofile_edits must contain 0 to 12 localized replacements")
    replacements = []
    for edit in edits:
        if not isinstance(edit, dict) or not isinstance(edit.get("old"), str) or not isinstance(edit.get("new"), str):
            raise ValueError("Each Dofile edit needs literal old/new Tcl strings")
        old, new = edit["old"], edit["new"]
        position = base.find(old)
        if not old or max(len(old), len(new)) > 20000 or position < 0 or base.find(old, position + 1) >= 0:
            raise ValueError("Dofile edit old span must be nonempty, unique and no larger than 20000 characters")
        replacements.append((position, position + len(old), new))
    replacements.sort()
    if any(end > start for (_, end, _), (start, _, _) in zip(replacements, replacements[1:])):
        raise ValueError("Dofile edits overlap; combine related changes into one replacement of the complete original block")
    result = base
    for start, end, new in reversed(replacements):
        result = result[:start] + new + result[end:]
    return result


def option_subset_matches(expected: str, actual: str) -> bool:
    left, right = literal_tcl_words(expected), literal_tcl_words(actual)
    if not left or not right or left[0] != right[0] or left[0] not in {
            "set_scan_cfg", "set_scan_signal", "set_wrapper_cfg", "set_scan_drc_cfg", "set_dft_clock_gating_cfg"}:
        return False
    def options(words: list[str]) -> dict[str, str] | None:
        if len(words) % 2 != 1:
            return None
        result = {}
        for index in range(1, len(words), 2):
            if not re.fullmatch(r"-[a-z_]+", words[index]) or words[index] in result:
                return None
            value = words[index+1]
            result[words[index]] = value[1:-1] if value.startswith('"') and value.endswith('"') else value
        return result
    wanted, configured = options(left), options(right)
    return bool(wanted and configured and all(configured.get(key) == value for key, value in wanted.items()))


def config_reference(dofile: str, configuration: str) -> str:
    """Resolve literal configuration statements, including continued and grouped commands."""
    records = []
    current = ""
    first = 0
    for number, line in enumerate(dofile.splitlines(), 1):
        if not current and (not line.strip() or line.lstrip().startswith("#")):
            continue
        if not current:
            first = number
        current += " " + line.rstrip().removesuffix("\\")
        if line.rstrip().endswith("\\"):
            continue
        records.append((first, number, re.sub(r"\s+", " ", current).strip()))
        current = ""
    parts = re.split(r";\s*(?=[A-Za-z_]+\b)|\n", configuration.replace("\\\n", " "))
    locations = []
    for part in parts:
        normalized = re.sub(r"\s+", " ", part).strip()
        if not normalized:
            continue
        matches = [(start, end) for start, end, text in records
                   if re.search(re.escape(normalized) + r"(?=$|[\s;])", text) or option_subset_matches(normalized, text)]
        if not matches:
            return ""
        locations.append(matches[0])
    if not locations:
        return ""
    first, last = min(start for start, _ in locations), max(end for _, end in locations)
    return f"L{first}" if first == last else f"L{first}-L{last}"


def normalize_mapping_annotation(dofile: str, configuration: str) -> str:
    """Remove trailing prose only when the remaining complete Tcl already exists."""
    if config_reference(dofile, configuration):
        return configuration
    candidate = re.sub(r"\s+[（(][^()（）]*[）)]\s*$", "", configuration)
    words = literal_tcl_words(candidate)
    if not words or words[0] not in {"set_scan_cfg", "set_scan_signal", "set_wrapper_cfg", "set_scan_drc_cfg", "set_dft_clock_gating_cfg"}:
        return configuration
    options = words[1:]
    if words[0] == "set_wrapper_cfg" and options and options[0] in {"enable", "disable"}:
        options = options[1:]
    if len(options) % 2 or any(not re.fullmatch(r"-[a-z_]+", value) for value in options[::2]):
        return configuration
    return candidate if config_reference(dofile, candidate) else configuration


def context_for_run(input_dir: Path, task_spec: str, limits: str, netlists: list[Path], libs: list[Path], dofile: str, log: str = "", reports: str = "") -> str:
    lib_names = [str(p) for p in libs]
    lib_summary = [liberty_summary(p) for p in libs]
    shift_summary = shift_register_context(netlists, libraries=libs) if re.search(r"移位寄存器|scan\s+segment", task_spec, re.I) else "Not requested"
    return f"""# Natural-language task specification
{task_spec}

# Runtime limits
{limits or 'Not supplied'}

# Reviewed organizer clarifications
{qa_context('task2' if (input_dir / 'original.dofile').is_file() else 'task1', task_spec)}

# Input files
Input directory: {input_dir}
Netlists: {[str(p) for p in netlists]}
Liberty files: {lib_names}
{chr(10).join(lib_summary)}

# Best-effort structural netlist scan
{netlist_summary(netlists, task_spec)}

# Shift-register structures requested by the task
{shift_summary}

# Literal clock-buffer and enable-latch connections (structural candidates, not proof)
{clock_latch_context(netlists, libs) if re.search(r'ICG|门控|缓冲|latch|闩锁', task_spec, re.I) else 'Not requested'}

# ScanInsertion manual excerpts (authoritative syntax reference)
{manual_context(task_spec)}

# Command syntax from this installed tool's built-in verbose help
{command_syntax(task_spec)}

# Current Dofile
{dofile}

# Most recent tool log / diagnostics
{log[-18000:] if log else '(no run yet)'}

# Most recent tool reports
{reports[-18000:] if reports else '(no reports captured yet)'}
"""


def call_for_dofile(client: OpenAI, task: str, context: str, original: str | None,
                    input_dir: Path, run_dir: Path, deadline: float | None = None,
                    base_dofile: str | None = None,
                    previous_mapping: list[dict[str, Any]] | None = None,
                    catalog: dict[str, dict[str, str]] | None = None,
                    segments: list[dict[str, Any]] | None = None,
                    control_hints: dict[str, Any] | None = None,
                    instances: dict[str, Any] | None = None,
                    floating: dict[str, list[str]] | None = None,
                    previous_actual_dofile: str | None = None,
                    previous_unallowed_codes: set[str] | None = None) -> tuple[str, dict[str, Any]]:
    mode = ("Repair the CURRENT Dofile from actual diagnostics and task requirements; preserve already valid settings."
            if base_dofile is not None else "Generate a Dofile from the task requirements.")
    if task == "task2" and original:
        context += "\n# Original Dofile (diagnostic baseline; patch the CURRENT Dofile)\n" + original
    if previous_mapping:
        context += "\n# Previous requirement mapping (may be inherited if unchanged)\n" + json.dumps(previous_mapping, ensure_ascii=False)
    if catalog:
        context += "\n# Exact evidence catalog from the preceding actual tool run\n" + json.dumps(catalog, ensure_ascii=False)
        (run_dir / "llm_evidence_catalog.json").write_text(json.dumps(catalog, ensure_ascii=False, indent=2))
    if control_hints:
        context += "\n# Reset inactive levels traced from actual Liberty clear/preset functions and input connections\n" + json.dumps(control_hints, ensure_ascii=False)
    if floating:
        context += "\n# Clock outputs of gates whose input clocks are literally disconnected in original source\n" + json.dumps(floating, ensure_ascii=False)
    if previous_unallowed_codes:
        context += ("\n# Actual blocking DRC rules from the preceding tool result\n" +
                    ", ".join(sorted(previous_unallowed_codes)) +
                    "\nThe displayed current Dofile contains the editable model code. Runtime-owned recipes "
                    "and audit reports are restored automatically; removing their former text cannot repair these rules.")
    spec = read_text(input_dir / "task_spec.md", 60000)
    netlist_rule = (("Task 1 strictly forbids modifying Pre-scan input netlists. Return no netlist_edits."
                     if task == "task1" else "This case strictly forbids modifying Pre-scan input netlists. Return no netlist_edits.")
                    if not edits_allowed(task, spec) else
                    "Prefer Dofile repairs. Only if an evidence-backed structural problem cannot be fixed by Dofile settings, "
                    "you may additionally return netlist_edits: an array of at most four objects with file (original input .v path), "
                    "old (unique literal span from the actual input), new (replacement), reason (why settings are insufficient), "
                    "and evidence_excerpt (a real preceding tool diagnostic). Each edit is limited to 32 lines and cannot change "
                    "module interfaces. Input files remain read-only. The runtime patches a private copy and admits it only after "
                    "a fixed EQY proof against the original netlist returns PASS; failed or unproven candidates are not adopted. "
                    "Do not provide proof scripts or assumptions, and do not claim EQY ran before it actually runs.")
    system = f"""You are an expert operator of the ScanInsertion tool `dftexp_scan` for the contest.
Follow the task specification exactly. Use only commands and options supported by the supplied manual excerpts, this tool's built-in help and evidence from existing Dofiles. Built-in help determines valid command options; do not use options from another EDA product. Correct every earlier ERROR before retrying. Use the actual Liberty pin names, never guess SE/SI/CLK. Choose the requested top module from root-module evidence, rather than an internal module whose name appears first. For reset signals, -off_state is the INACTIVE level: active-low reset means -off_state 1; active-high reset means -off_state 0. get_cells/get_pins return tool collections; use foreach_in_collection to iterate them. Declare wrapper control signals with set_scan_signal before referring to them in set_wrapper_cfg. Complete examine_scan_drc/examine_scan_chain before insert_dft_logic; do not call examine_scan_chain after insertion. For a clock passed through a latch, use the documented associated_internal_clocks option and exclude that latch from scan elements as required. Group repeated diagnostics by concrete root cause, rather than one issue per cell. Keep each diagnosis and summary short. Never disable DRC to hide a violation. {netlist_rule} Never modify Liberty libraries, the tool, License configuration, or protected evaluation scripts.
For a gated scan partition, its scan_enable usually needs usage all so it controls both scan FFs and that partition's clock gates; usage scan alone does not connect gating control. Use a separate clock_gating signal only when the task specifies one. Clock off_state can be 0 or 1; when a latch passes a clock through its D pin, diagnose the source off level with DRC and associated_internal_clocks before proposing a netlist edit. Declare each clock port once, including associated_internal_clocks on that same set_scan_signal command; a second declaration fails instead of updating it. Use the actual parent module and instance from source excerpts, not an assumed hierarchy. To select a hierarchical subtree, filter full_name using the actual path and optional leading hierarchy prefix. Check sizeof_collection before applying a command that requires a nonempty instance list; a missing required object must remain unresolved. Use the derived shift-register endpoint/index hints where supplied, and use brace quoting/format for array pin paths so Tcl does not interpret numeric brackets as commands.
Configure indexed scan data port names with set_scan_cfg -si_port_format and -so_port_format, not set_scan_signal -port containing %d. DRC rules DFTR1-6 and DFTR8-16 accept only Error/Warning. If the task allows a residual warning, leave it as Warning and retain actual evidence; do not request Ignore. When an instance path/pattern is specified, use full_name rather than ref_name (which is a cell type). Hierarchical positional query patterns may not match; use get_cells -hier -filter with full_name, e.g. {{full_name =~ */core/* && full_name !~ *keep_reg* && is_sequential == true}}, substituting actual source paths. If separate uninstantiated wrapper modules must remain available, load all netlist roots without -top, then use present_design to select the real scan top. Apply shift-register templates to ALL supplied index tuples, using concise Tcl loops rather than configuring only index zero. Global wrapper disable is set_wrapper_cfg disable, never -style none without an actual -port list. When the task does not request wrappers, remove spurious wrapper settings inherited from a faulty original script.
Return exactly one compact JSON object with keys: dofile (complete Tcl script as a string), summary (one short sentence), requirement_mapping (array of objects with requirement and dft_config), and issue_resolutions (array; each item has issue_id, phenomenon, evidence_id or evidence_excerpt, located_object, diagnosis, root_cause, violated_requirement, fix, and optional verification). Use concise scripts with few comments and brief diagnosis fields; execution time is limited. Task 1 requires a nonempty mapping of key requirements; dft_config must contain literal Tcl statements copied from your returned Dofile, never descriptions or invented placeholders for collections. Prefer evidence_id such as E1 from the supplied actual evidence catalog; the runtime inserts its exact prior-run excerpt. Otherwise evidence_excerpt must be an exact short contiguous excerpt copied from the supplied PREVIOUS run's tool log or report. Never combine fragments, omit text inside a line, or cite the task specification as tool evidence. Describe a concrete object and root cause; use an empty array when no issue is directly evidenced. For verification you may provide an object with source (a report filename or relative report path) and expected_excerpt (a specific positive tool report value or completion message expected after the fix). This is a verification plan, not a claim that verification already occurred. Do not use disappearance of a diagnostic as positive evidence. Do not claim a requirement is met unless the script configures it. Declare reset ports named by the task or supported by actual FF set/clear connections, Liberty functions and uncontrolled-reset diagnostics. A generic task may leave these names implicit. Never classify functional data as reset based on its name alone; explicit task prohibitions take precedence. Wrapper shift and capture controls should use separate newly created ports, unless the task explicitly requires reusing existing ones.
The actual read-only input directory is {input_dir}. The current run directory and tool working directory are {run_dir}. Use the supplied absolute input file paths. Load multiple netlists together in one load_netlist file-list command with explicit -top when needed; separate load_netlist calls can change the scan engine's analyzed top. Use property names from the supplied actual cell property table, and get_property/get_attribute (not the nonexistent get_attr). For a user-defined dedicated wrapper, -interface is a list of semantic_role actual_module_port polarity triples; semantic roles are shift_clk, capture_en, shift_en, cti, cto, cfi, cfo. Read the provided module port declarations. Write reports under {run_dir / 'reports'} and deliverables under {run_dir / 'deliverables'}, or use paths relative to the current working directory. Add `exit` at the end. No markdown fences."""
    user = f"{mode}\n\n{context}\n\nReturn the JSON object now."
    system += ("\nPrioritize the recorded blocking tool and DRC findings. A functional clock violation "
               "needs a clock/control-path diagnosis based on literal source connections; changing SI/SO "
               "port names does not activate that clock. Configuration tables show effective values, "
               "including defaults; an omitted explicit declaration is not itself a defect when the "
               "effective value already satisfies the task. A gated-clock CE latch stores enable data: "
               "its Q is not a clock merely because the downstream clock is inactive. Associate a source "
               "clock only with a demonstrated derived clock output or clock pin, using actual hierarchy.")
    if segments:
        system += ("\nThe runtime compiles ALL supplied actual shift-register candidates into set_scan_segment "
                   "commands and preserves their actual scan-enable pin connections. You may omit your own segment "
                   "commands and focus on clock, scan, wrapper and output settings. Keep ordinary top-level "
                   "examine_scan_drc/examine_scan_chain before insertion, as the recipe is inserted before them. "
                   "Any segment commands you do provide must be separate statements or pure segment loops.")
    if floating:
        system += ("\nThe runtime declares the listed clock output pins of gates with disconnected inputs as pseudo primary inputs "
                   "and independent scan clocks before DRC. Omit your own pseudo-input discovery queries and clock "
                   "declarations for these pins; configure the normal top-level clocks and remaining DFT settings. "
                   "A clock-gating enable latch Q is an enable signal, not a clock waveform. For a buffer ANDing "
                   "the source clock with stored enable, its final clock output carries the clock, not that latch Q.")
    if base_dofile is not None:
        system += ("\nFor this repair, prefer dofile_edits: an array of at most 12 objects with old and new literal "
                   "Tcl spans copied exactly from the CURRENT Dofile. Each old span must occur once; provide enough "
                   "context to disambiguate repeated options. You may omit dofile when supplying edits. Keep valid "
                   "commands and output conventions. Edits must not overlap; combine changes in the same block. "
                   "Apply all edits to the same CURRENT base, never to another edit's replacement. Do not add "
                   "unrequested settings to already valid commands. Include concise issue_resolutions and summary. You may omit "
                   "requirement_mapping if unchanged; update it when edited configuration values change.")
    problems = []
    for attempt in range(2):
        if deadline is not None:
            remaining = deadline - time.monotonic()
            if remaining <= 1:
                raise TimeoutError("Dofile generation exhausted its remaining case budget")
            client = client.with_options(timeout=model_request_timeout(remaining), max_retries=0)
        log_name = "llm_response.json" if attempt == 0 else "llm_response_retry.json"
        raw = ask(client, system, user, request_log=run_dir / log_name)
        try:
            result = json_from_response(raw)
            if not isinstance(result.get("issue_resolutions", []), list):
                raise ValueError("issue_resolutions must be an array of evidence-backed issue objects")
            for issue in result.get("issue_resolutions", []):
                if isinstance(issue, dict) and issue.get("evidence_id"):
                    evidence = (catalog or {}).get(str(issue["evidence_id"]))
                    if not evidence:
                        raise ValueError("Unknown evidence_id; select an existing ID from the preceding actual tool evidence catalog")
                    issue["evidence_excerpt"] = evidence["excerpt"]
            # Normalize this spelling without changing the proposed Tcl or inventing a repair.
            dofile = result.get("dofile", result.get("dfile"))
            if "dofile_edits" in result and base_dofile is not None:
                dofile = apply_dofile_edits(base_dofile, result["dofile_edits"])
            if "requirement_mapping" not in result and previous_mapping:
                result["requirement_mapping"] = [dict(item) for item in previous_mapping]
            if not isinstance(dofile, str) or not dofile.strip():
                raise ValueError("LLM JSON is missing a non-empty dofile")
            adapted = normalize_wrapper_roots(normalize_scan_port_formats(
                normalize_load_file_lists(normalize_report_redirection(dofile))))
            adapted = normalize_reset_levels(adapted, control_hints or {})
            adapted = normalize_associated_pin_paths(adapted, instances or {})
            adapted, segment_references = configure_shift_segments(adapted, segments or [], spec)
            adapted, floating_references = configure_floating_inputs(adapted, floating or {})
            if adapted.strip() != dofile.strip():
                (run_dir / "llm_normalization.json").write_text(json.dumps({
                    "kind": "documented_api_and_input_derived_recipes", "original_dofile": dofile,
                    "executed_dofile": adapted}, ensure_ascii=False, indent=2))
                dofile = adapted
            if segment_references:
                mappings = result.get("requirement_mapping", [])
                if not isinstance(mappings, list):
                    raise ValueError("requirement_mapping must be an array")
                if task == "task1" and not mappings:
                    raise ValueError("Task 1 still needs model-provided mappings for its other key requirements")
                recipe_requirement = "All actual input-derived long shift registers remain indivisible scan segments"
                mappings = [item for item in mappings if not isinstance(item, dict) or item.get("requirement") != recipe_requirement]
                for item in mappings:
                    if isinstance(item, dict) and isinstance(item.get("dft_config"), str):
                        item["dft_config"] = normalize_unrequested_counts(item["dft_config"], spec)
                    if isinstance(item, dict) and "set_scan_segment" in str(item.get("dft_config", "")):
                        item["dft_config"] = "; ".join(segment_references)
                mappings.append({"requirement": recipe_requirement,
                                 "dft_config": "; ".join(segment_references)})
                result["requirement_mapping"] = mappings
                (run_dir / "llm_shift_register_recipe.json").write_text(json.dumps({"input_groups": segments,
                    "actual_commands": segment_references}, ensure_ascii=False, indent=2))
            if floating_references:
                mappings = result.get("requirement_mapping", [])
                if not isinstance(mappings, list) or (task == "task1" and not mappings):
                    raise ValueError("Model-provided key requirement mappings are still required")
                requirement = "Literal disconnected gating-clock inputs become independent pseudo primary clocks"
                mappings = [item for item in mappings if not isinstance(item, dict) or item.get("requirement") != requirement]
                for item in mappings:
                    if isinstance(item, dict) and "add_pseudo_pi" in str(item.get("dft_config", "")):
                        item["dft_config"] = "; ".join(floating_references)
                mappings.append({"requirement": requirement, "dft_config": "; ".join(floating_references)})
                result["requirement_mapping"] = mappings
                (run_dir / "llm_floating_clock_recipe.json").write_text(json.dumps({"input_pins": floating,
                    "actual_commands": floating_references}, ensure_ascii=False, indent=2))
            for item in result.get("requirement_mapping", []):
                if isinstance(item, dict) and isinstance(item.get("dft_config"), str):
                    clauses = re.split(r";\s*(?=[A-Za-z_]+\b)", item["dft_config"])
                    item["dft_config"] = "; ".join(normalize_wrapper_roots(
                        normalize_associated_pin_paths(normalize_reset_levels(normalize_scan_port_formats(normalize_load_file_lists(normalize_report_redirection(clause))), control_hints or {}, dofile), instances or {}, dofile), dofile).strip() for clause in clauses)
                    item["dft_config"] = normalize_mapping_annotation(dofile, item["dft_config"])
            problems = unsupported_options(dofile, spec, known_reset_ports=set(control_hints or {}),
                                           permit_reset_inference=bool((previous_unallowed_codes or set()) & {"DFTR2", "DFTR3"}))
            if previous_actual_dofile is not None:
                problems.extend(unchanged_control_retry_problems(
                    previous_actual_dofile, dofile, previous_unallowed_codes or set(),
                    netlist_edits=result.get("netlist_edits"), words_for=literal_tcl_words))
            if task == "task1":
                mappings = result.get("requirement_mapping")
                if not isinstance(mappings, list) or not mappings:
                    problems.append("Task 1 requires a nonempty requirement_mapping with literal Dofile configurations")
                else:
                    for index, item in enumerate(mappings):
                        if not isinstance(item, dict) or not str(item.get("requirement", "")).strip():
                            problems.append(f"requirement_mapping[{index}] needs a requirement and a literal dft_config")
                        elif not config_reference(dofile, str(item.get("dft_config", ""))):
                            problems.append(f"requirement_mapping[{index}] has no actual Tcl match: {str(item.get('dft_config', ''))[:500]}. Copy actual commands/options; omit prose suffixes and collection placeholders.")
            if not problems:
                return append_audit_reports(strip_fence(dofile), run_dir), result
        except ValueError as error:
            problems = [str(error)]
        (run_dir / "llm_validation.json").write_text(json.dumps({"problems": problems}, indent=2))
        user += "\n# Your previous proposed JSON\n" + raw + "\n# Preflight errors (no tool call made)\n" + "\n".join(problems)
        user += "\nReturn corrected JSON with key dofile and valid options from the supplied built-in help."
    raise ValueError("LLM Dofile failed command preflight: " + "; ".join(problems))


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
        if source.name.startswith("llm_") and source.suffix == ".json":
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


def tool_run(dofile: str, run_dir: Path, run_id: str, timeout: int, execute_path: Path | None = None,
             abort_on_error: bool = True, allowed_drc: set[str] | None = None) -> dict[str, Any]:
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
    with log_path.open("w", encoding="utf-8") as log:
        proc = subprocess.Popen(cmd, cwd=run_dir, stdout=log, stderr=subprocess.STDOUT,
                                start_new_session=True)
        error = None
        suffix = ""
        drc_count = 0
        observed_rules: set[str] = set()
        report_monitor_cache = {}
        with log_path.open(encoding="utf-8", errors="replace") as monitor:
            while proc.poll() is None:
                chunk = monitor.read(262144)
                window = suffix + chunk
                for line in window.splitlines():
                    if "CMD-0034" in line:
                        continue
                    if re.search(r"\[(?:WARNING|INFO)\].*\[\s*DFTDRC-", line):
                        observed_rules.update(re.sub(r"[-_ ]", "", rule).upper()
                                              for rule in re.findall(r"DFTR[-_ ]?(?:TIE[01]|\d+)", line))
                    summary = re.fullmatch(r"\s*Total violations:\s*(\d+)\s*", line)
                    if summary:
                        drc_count = int(summary.group(1))
                if abort_on_error and re.search(r"\[(?:ERROR|FATAL)\]", suffix + chunk):
                    error = "early_tool_error"
                elif abort_on_error and allowed_drc is not None and redirected_drc_codes(run_dir, report_monitor_cache) - allowed_drc:
                    error = "unallowed_drc"
                elif abort_on_error and allowed_drc is not None and drc_count > 0 and observed_rules - allowed_drc:
                    error = "unallowed_drc"
                elif time.monotonic() - started >= max(1, timeout):
                    error = "timeout"
                if error:
                    try:
                        os.killpg(proc.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    proc.wait()
                    log.write("\n[agent] tool timeout\n" if error == "timeout" else
                              "\n[agent] generated script stopped after actual unallowed DRC; remaining commands were not executed\n"
                              if error == "unallowed_drc" else
                              "\n[agent] generated script stopped after actual ERROR; remaining commands were not executed\n")
                    break
                suffix = (suffix + chunk)[-100:]
                time.sleep(0.1)
        code = proc.wait()
        status = "aborted" if error == "timeout" else "error" if error or code != 0 else "completed"
    elapsed = time.monotonic() - started
    # Collect only actual tool outputs. Preserve subdirectories and never fabricate reports.
    output_files = collect_tool_outputs(run_dir, run_id)
    return {"run_id": run_id, "status": status, "returncode": code, "error": error,
            "elapsed_seconds": round(elapsed, 3), "log_path": log_path,
            "artifacts": [p.relative_to(run_dir).as_posix() for p in output_files]}


def check_output(run_dir: Path, task_spec: str, task: str, dofile: str, status: str,
                 expected_segments: list[dict[str, Any]] | None = None,
                 expected_floating: dict[str, list[str]] | None = None) -> tuple[bool, list[str]]:
    problems: list[str] = []
    log_path = run_dir / f"{run_dir.name}.log"
    log = read_text(log_path, 100000)
    if status != "completed":
        problems.append("ScanInsertion tool did not exit successfully")
    diagnostic_files = [p for p in (run_dir / "reports").rglob("*") if p.is_file()]
    diagnostic_files += [p for p in run_dir.rglob("*") if p.is_file() and p.suffix.lower() in {".rpt", ".report"}]
    diagnostic_files = list(dict.fromkeys(diagnostic_files))
    diagnostics = "\n".join(read_text(p, 100000) for p in diagnostic_files)
    diagnostic_text = log + "\n" + diagnostics
    if re.search(r"\[(?:ERROR|FATAL)\]", diagnostic_text + diagnostic_excerpt(log_path), re.I):
        problems.append("Tool log or DRC report contains an ERROR/FATAL diagnostic")
    allowed_codes = permitted_residual_drc_codes(task, task_spec)
    drc_required = bool(re.search(r"\bDRC\b|违例", task_spec, re.I))
    summaries = [summary for path in [log_path, *diagnostic_files] if path.is_file()
                 for summary in drc_summaries(path)]
    if qa_residual_codes(task, task_spec):
        exclusions = excluded_scan_cells([path for path in [log_path, *diagnostic_files] if path.is_file()])
        if exclusions:
            problems.append("Scan FFs were excluded instead of retaining the permitted DFTR10: " + exclusions[0])
    if drc_required:
        if not summaries:
            problems.append("No actual DRC summary was produced")
        for summary in summaries:
            if not summary_permitted(summary, allowed_codes):
                blocking_codes = set(summary["counts"]) - allowed_codes
                problems.append("DRC report has nonzero violations" +
                                (f" (unallowed codes: {', '.join(sorted(blocking_codes))})" if blocking_codes else
                                 " whose complete rule counts could not be verified"))
    actual_files = [p for p in run_dir.rglob("*") if p.is_file() and p.suffix.lower() not in {".dofile", ".log"} and not _is_inside(p, run_dir / "input")]
    if not any(p.suffix.lower() in {".v", ".vg"} for p in actual_files):
        problems.append("No actual Verilog deliverable was produced")
    report_files = [p for p in actual_files if p.suffix.lower() in {".rpt", ".report", ".txt"}]
    problems.extend(coverage_problems(report_files, dofile))
    problems.extend(wrapper_problems(report_files, task_spec))
    report_text = "\n".join(read_text(p, 50000) for p in report_files)
    actual_chains = chain_rows(report_files)
    problems.extend(chain_problems(actual_chains, task_spec))
    problems.extend(segment_problems(report_files, expected_segments or []))
    top = re.findall(r"(?m)^\s*present_design\s+([\w$]+)\s*$", dofile)
    problems.extend(pseudo_clock_problems(report_files, (expected_floating or {}).get(top[-1], []) if top else []))
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
            if actual_chains:
                actual_count = sum(not row["Chain"].startswith("W") for row in actual_chains)
            if actual_count is not None and actual_count != desired_count:
                default_partition = bool(re.search(r"默认分区|default[_ ]partition", task_spec, re.I))
                default_rows = bool(re.search(r"Default[_ ]Partition", report_text, re.I))
                one_implicit_default_chain = actual_count == desired_count + 1 and default_partition and default_rows
                if not one_implicit_default_chain:
                    problems.append(f"Scan-chain count mismatch: requested {desired_count}, tool report shows {actual_count}")
            elif actual_count is None:
                problems.append(f"Could not verify requested scan-chain count {desired_count} from reports")
        chain_cap = re.search(r"(?:扫描)?链数(?:量)?\s*(?:不得超过|不超过|最多|上限为)\s*(\d+)", task_spec)
        if chain_cap:
            chain_files = [p for p in report_files if "chain" in p.name.lower() and "cell" not in p.name.lower()]
            chain_count = len(actual_chains) if actual_chains else sum(
                len(re.findall(r"(?m)^\s*(?:I\s+)?\d+\s+\d+\s+\S+\s+\S+", read_text(p, 100000))) for p in chain_files)
            if not chain_count:
                problems.append("Could not verify the scan-chain channel budget from chain report rows")
            elif chain_count > int(chain_cap.group(1)):
                problems.append(f"Scan-chain count {chain_count} exceeds channel budget {chain_cap.group(1)}")
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
            exempt = ctl_overlength_exceptions(actual_chains, report_files, task_spec, log_path, max_length_value) if actual_chains else set()
            lengths = ([int(row["Length"]) for row in actual_chains if row["Chain"] not in exempt] if actual_chains else
                       [int(value) for value in re.findall(r"(?im)^\s*(?:I\s*)?\d+\s+(\d+)\s+\S+\s+\S+", report_text)])
            if not actual_chains:
                lengths.extend(int(value) for value in re.findall(r"Scan chain\s+['\"]?\w+['\"]?[^\n]*?includes\s+(\d+)\s+cells", log, re.I))
            if not lengths:
                problems.append(f"Could not verify scan-chain maximum length {max_length_value} from reports")
            elif max_length_value is not None and max(lengths) > max_length_value:
                bad_rows = [row for row in actual_chains if row["Chain"] not in exempt and int(row["Length"]) > max_length_value]
                if bad_rows:
                    for row in bad_rows[:3]:
                        role = "Wrapper" if row["Chain"].startswith("W") else "Internal scan"
                        problems.append(f"{role} chain {row['Chain']} length {row['Length']} exceeds maximum {max_length_value}; "
                                        f"actual evidence {row['source']}:L{row['line']}. Check that chain's own configuration.")
                else:
                    problems.append(f"Scan-chain length {max(lengths)} exceeds the specified maximum {max_length_value}")

    if re.search(r"DRC.{0,40}(?:报告|report|零|无|清零|zero|no\s+violation)|(?:零|无|清零).{0,30}DRC", task_spec, re.I):
        drc_reports = [p for p in report_files if "drc" in p.name.lower() or "violation" in p.name.lower()]
        if not drc_reports and not re.search(r"Total violations:\s*\d+", log, re.I):
            problems.append("Task requires DRC evidence, but no DRC report or violation summary was produced")
    # Check explicitly named output artifacts when the task specification lists them.
    output_section = re.search(r"(?:##\s*(?:输出文件|输出要求)|输出文件|输出要求)(.*?)(?=\n##\s|\Z)", task_spec, re.S)
    if output_section:
        listed = set(re.findall(r"(?<![\w./])([\w*.-]+\.(?:vg|v|ctl|def|rpt))(?!\w)", output_section.group(1), re.I))
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
    return sorted(reports, key=lambda p: p.stat().st_size) + ([log] if log.is_file() else [])


def evidence_catalog(run_dir: Path, output_dir: Path, maximum: int = 24,
                     task_spec: str = "") -> dict[str, dict[str, str]]:
    """Give the model stable IDs for actual diagnostics, never generated answers."""
    catalog = {}
    files = run_evidence_files(run_dir)
    for port in wrapper_targets(task_spec):
        rows = port_wrapper_rows(files, port)
        if rows:
            row = rows[0]
            path = Path(row["source"])
            with path.open(encoding="utf-8", errors="replace") as stream:
                excerpt = next((line.strip() for number, line in enumerate(stream, 1) if number == row["line"]), "")
            catalog[f"E{len(catalog)+1}"] = {"source": path.relative_to(output_dir).as_posix(),
                                           "locator": f"L{row['line']}", "excerpt": excerpt}
            if len(catalog) >= maximum:
                return catalog
    seen = set()
    counts = {}
    files = run_evidence_files(run_dir)
    files.sort(key=lambda path: (path.suffix != ".log", path.stat().st_size))
    for path in files:
        if path.suffix == ".log" or path.stat().st_size > 5000:
            continue
        text = read_text(path, 5001).strip()
        if not re.search(r"Chain\s+Length\s+Input|Name\s+SegmentProperty\s+Length|WrapperConfigurationParameter|ScanConfigurationParameter", text):
            continue
        catalog[f"E{len(catalog)+1}"] = {"source": path.relative_to(output_dir).as_posix(),
                                       "locator": f"L1-L{len(text.splitlines())}", "excerpt": text}
        if len(catalog) >= maximum:
            return catalog
    for path in files:
        stat = path.stat()
        for window in evidence_windows(str(path), stat.st_mtime_ns, stat.st_size):
            for number, line in window:
                if "CMD-0034" in line or line.lstrip().startswith("#"):
                    continue
                category = re.search(r"DFTR[-_]?(?:\d+|TIE[01])|\[(?:ERROR|FATAL)\]|^\s*[IW]\s+\S+\s+\d+", line, re.I)
                if not category or line in seen or counts.get(category.group(), 0) >= 2:
                    continue
                key = category.group()
                if re.search(r"\[(?:ERROR|FATAL)\]", line):
                    code = re.search(r"\[\s*((?:CMD|COM|SCAN|DFTDRC)-[\w-]+)\s*\]", line)
                    if code:
                        key = code.group(1)
                if counts.get(key, 0) >= 2:
                    continue
                seen.add(line)
                counts[key] = counts.get(key, 0) + 1
                catalog[f"E{len(catalog)+1}"] = {
                    "source": path.relative_to(output_dir).as_posix(), "locator": f"L{number}",
                    "excerpt": line.strip()[:600]}
                if len(catalog) >= maximum:
                    return catalog
    return catalog


@functools.lru_cache(maxsize=64)
def evidence_windows(path_string: str, mtime_ns: int, size: int) -> list[list[tuple[int, str]]]:
    """Index bounded evidence windows once; preserve original source line numbers."""
    head: list[tuple[int, str]] = []
    tail: deque[tuple[int, str]] = deque()
    head_size = tail_size = 0
    nearby: dict[int, str] = {}
    nearby_size = 0
    before: deque[tuple[int, str]] = deque(maxlen=3)
    after = 0
    counts: dict[str, int] = {}
    with Path(path_string).open(encoding="utf-8", errors="replace") as stream:
        for number, line in enumerate(stream, 1):
            category = re.search(r"\bDFTR[-_]?(?:\d+|TIE[01])\b|\[(?:ERROR|FATAL)\]", line, re.I)
            if category and counts.get(category.group(0), 0) < 3 and nearby_size < 131072:
                for n, text in before:
                    if n not in nearby:
                        nearby[n] = text[:2000]
                        nearby_size += len(nearby[n])
                after = 4
                counts[category.group(0)] = counts.get(category.group(0), 0) + 1
            if after > 0 and nearby_size < 131072:
                if number not in nearby:
                    nearby[number] = line[:2000]
                    nearby_size += len(nearby[number])
                after -= 1
            before.append((number, line))
            if head_size + len(line) <= 262144 and len(head) < 3000:
                head.append((number, line))
                head_size += len(line)
            tail.append((number, line))
            tail_size += len(line)
            while tail and (tail_size > 262144 or len(tail) > 3000):
                tail_size -= len(tail.popleft()[1])
    return [head, sorted(nearby.items()), list(tail)]


def locate_evidence(files: list[Path], output_dir: Path, excerpt: str,
                    positive: bool = False) -> dict[str, str] | None:
    """Locate an exact excerpt, retaining real line numbers even in long logs."""
    if not excerpt:
        return None
    line_count = excerpt.count("\n") + 1
    if re.search(r"\[(?:ERROR|FATAL|WARNING|INFO)\]", excerpt, re.I):
        files = sorted(files, key=lambda p: (p.suffix != ".log", p.stat().st_size))
    for path in files:
        stat = path.stat()
        for block in evidence_windows(str(path), stat.st_mtime_ns, stat.st_size):
            window: deque[str] = deque(maxlen=line_count)
            previous_number = 0
            for last_line, line in block:
                if last_line != previous_number + 1:
                    window.clear()
                previous_number = last_line
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
                       previous_run: str, current_run: str, change_id: str,
                       additional_change_ids: list[str] | None = None,
                       accepted_residual: set[str] | None = None) -> None:
    """Bind a proposed fix to the previous run that actually exposed the issue."""
    if not previous_run or not change_id:
        return
    files = run_evidence_files(output_dir / "runs" / previous_run)

    def command_failure_evidence(excerpt: str, command: str, located: str) -> dict[str, str] | None:
        """Locate a generic failure only in the concrete command's actual log block."""
        expected = literal_tcl_words(located.strip())
        if not expected or expected[0] != command:
            return None

        def matches(words: list[str]) -> bool:
            if not words or words[0] != command:
                return False
            actual = [word.strip('"{}') for word in words[1:]]
            requested = [word.strip('"{}') for word in expected[1:]]
            index = 0
            while index < len(requested):
                word = requested[index]
                if word.startswith("-") and index + 1 < len(requested) and not requested[index + 1].startswith("-"):
                    if not any(actual[n:n + 2] == requested[index:index + 2] for n in range(len(actual) - 1)):
                        return False
                    index += 2
                else:
                    if word not in actual:
                        return False
                    index += 1
            return True

        candidates = []
        for path in files:
            if path.suffix != ".log":
                continue
            active_command: list[str] = []
            with path.open(encoding="utf-8", errors="replace") as stream:
                for number, line in enumerate(stream, 1):
                    echo = re.search(r"\bCMD-0034\]\s+@\d+:\s*(.*)", line)
                    if echo:
                        active_command = literal_tcl_words(echo.group(1))
                        continue
                    if excerpt in line and re.search(r"\[(?:ERROR|FATAL)\]", line) and matches(active_command):
                        candidates.append((path, number, tuple(active_command)))
        # A command-only diagnosis must not choose among distinct failed objects.
        if not candidates or (len(expected) == 1 and len({words for _, _, words in candidates}) != 1):
            return None
        path, number, _ = candidates[0]
        return {"source": path.relative_to(output_dir).as_posix(), "locator": f"L{number}", "excerpt": excerpt}

    for item in meta.get("issue_resolutions", []):
        if not isinstance(item, dict):
            continue
        cited = str(item.get("evidence_excerpt", item.get("excerpt", ""))).strip()
        cited_rules = rule_codes(cited)
        if (accepted_residual and cited_rules and cited_rules <= accepted_residual and
                re.search(r"DFTDRC-|DRC rule '.+' fails", cited)):
            # A reviewed residual condition is not an unresolved defect to invent a repair for.
            continue
        if re.fullmatch(r"Total violations:\s*0", cited, re.I):
            # A clean DRC summary cannot discover an unrelated configuration fault.
            continue
        located = str(item.get("located_object", ""))
        diagnostic = str(item.get("diagnosis", "")) + " " + str(item.get("root_cause", ""))
        fix_text = str(item.get("fix", ""))
        diagnosed_rules = rule_codes(located + " " + diagnostic + " " + fix_text + " " + str(item.get("phenomenon", "")))
        if "WrapperConfigurationParameter" in cited and re.search(r"\bport\s+`?([A-Za-z_][\w$]*)", located, re.I):
            target_port = re.search(r"\bport\s+`?([A-Za-z_][\w$]*)", located, re.I).group(1)
            if not re.search(r"(?<![\w$])" + re.escape(target_port) + r"(?![\w$])", cited):
                continue
        if cited_rules and "DFTDRC-" in cited and diagnosed_rules and not cited_rules & diagnosed_rules:
            continue
        if (re.search(r"Chain\s+Length\s+Input", cited) and
                "insert_terminal_lockup" in diagnostic and "LOCKUP" not in cited):
            # Chain summary rows do not reveal whether terminal lockup was configured.
            continue
        if not re.search(r"\[(?:ERROR|FATAL|WARNING)\]", cited) and re.search(r"\bharmless\b|clean.?script|无害|脚本整洁", diagnostic, re.I):
            continue
        signal = re.search(r"\b(?:scan[_ ]enable|port)\s+`?([A-Za-z_][\w$]*)\b", located, re.I)
        if (signal and re.search(r"(?m)^\s*I\s+\S+\s+\d+\s+", cited) and
                not re.search(r"(?<![\w$])" + re.escape(signal.group(1)) + r"(?![\w$])", cited)):
            # A row about another signal cannot discover a parameter defect on this port.
            continue
        if (signal and re.search(r"(?m)^\s*I\s+\S+\s+\d+\s+", cited) and
                re.search(r"off_state|usage|incomplete.{0,30}(?:declaration|command)|缺少.{0,20}参数", diagnostic, re.I) and
                not re.search(r"OffState|Usage", cited)):
            continue
        if "ScanConfigurationParameter" in cited:
            if re.search(r"\b(?:set_scan_element|get_obj_insts|get_cells)\b", located):
                # A configuration table does not discover a failed object query or exclusion.
                continue
            parameters = set(re.findall(r"(?m)^\s*([a-z_]+)\s+\S+\s*$", cited))
            relevant = located + " " + diagnostic
            if "set_scan_cfg" not in relevant and not any(re.search(r"\b" + re.escape(name) + r"\b", relevant) for name in parameters):
                continue
            current_values = dict(re.findall(r"(?m)^\s*([a-z_]+)\s+(\S+)\s*$", cited))
            requested_values = [(name, value.strip('"{}')) for name, value in
                                re.findall(r'-([a-z_]+)\s+(\{[^{}]+\}|"[^"\n]+"|[^\s,;]+)', fix_text)
                                if name in current_values and not re.search(r"[$\[\\]", value)]
            if requested_values and all(current_values[name].lower() == value.lower() for name, value in requested_values):
                # Already effective values do not prove an absent explicit declaration is a defect.
                continue
        if (not re.search(r"\[(?:ERROR|FATAL|WARNING)\]", cited) and
                re.search(r"already corrected|already correct|no further change|already.*fixed|无需进一步|已经修复", fix_text, re.I)):
            continue
        if re.search(r"ScanConfigurationParameter|WrapperConfigurationParameter", cited) and re.search(r"redundan|duplicate configuration|冗余", diagnostic, re.I):
            continue
        if (re.search(r"Chain\s+Length\s+Input", cited) and
                re.search(r"empty.{0,25}chain|no scan chains|chains were (?:not|never)|no.*stitched", diagnostic, re.I) and
                re.search(r"(?m)^\s*[IW]\s+\S+\s+\d+\s+", cited)):
            continue
        failed_command = re.search(r"Command '([a-z_]+)' execution failed|for command '([a-z_]+)'", cited)
        commands = set(re.findall(r"\b(?:dump_[a-z_]+|set_[a-z_]+|rpt_[a-z_]+|examine_[a-z_]+|insert_[a-z_]+|present_design)\b", located))
        if failed_command and commands:
            actual = failed_command.group(1) or failed_command.group(2)
            if actual not in commands and actual not in fix_text:
                continue
        artifact_names = re.findall(r"[\w.-]+\.(?:rpt|report|txt|ctl|def)\b", located + " " + diagnostic)
        if (artifact_names and not re.search(r"\[(?:ERROR|FATAL|WARNING)\]", cited) and
                re.search(r"\bempty\b|\bmissing\b|\bno\b.{0,60}(?:written|produced)|未生成|为空|缺失", diagnostic, re.I) and
                not any(name in cited for name in artifact_names)):
            # An unrelated report row does not discover a missing output file.
            continue
        generic_failure = re.search(r"Command '([a-z_]+)' execution failed", cited)
        evidence = (command_failure_evidence(cited, generic_failure.group(1), located) if generic_failure
                    else locate_evidence(files, output_dir, cited))
        if not evidence:
            continue
        diagnosis = {"summary": str(item.get("diagnosis", "")),
                     "located_object": str(item.get("located_object", "")),
                     "root_cause": str(item.get("root_cause", "")),
                     "violated_requirement": str(item.get("violated_requirement", ""))}
        existing = next((issue for issue in issues
                         if (diagnosis["located_object"] and diagnosis["root_cause"] and
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
            "fix": {"action": str(item.get("fix", "")), "artifact_ref": [change_id] + (additional_change_ids or [])},
            "verify": {"run_ref": current_run, "source": f"runs/{current_run}/{current_run}.log",
                       "resolved": False, "locator": "", "excerpt": ""}})
        plan = item.get("verification", {})
        verification_plans[existing["issue_id"]] = plan if isinstance(plan, dict) else {}


def configuration_evidence(issue: dict[str, Any], files: list[Path], output_dir: Path,
                           dofile: str) -> dict[str, str] | None:
    """Bind the executed literal configuration to typed rows from the real tool."""
    exclusion = exclusion_command_evidence(issue, files, output_dir, dofile, literal_tcl_words)
    if exclusion:
        return exclusion
    diagnosis = issue["diagnosis"]
    fix = issue.get("attempts", [{}])[-1].get("fix", {}).get("action", "")
    subject = diagnosis.get("located_object", "") + " " + fix
    # A concrete tool failure can identify its command even when the model names
    # only a port. The original echo supplies context, never positive evidence.
    found = issue.get("found", {})
    source = Path(str(found.get("source", "")))
    locator = re.fullmatch(r"L(\d+)(?:-L(\d+))?", str(found.get("locator", "")))
    run_ref = str(found.get("run_ref", ""))
    excerpt = str(found.get("excerpt", ""))
    origin = (output_dir / source).resolve()
    if (not source.is_absolute() and source.suffix == ".log" and locator and
            re.fullmatch(r"R\d+", run_ref) and _is_inside(origin, (output_dir / "runs" / run_ref).resolve()) and
            origin.is_file() and re.search(r"\[(?:ERROR|FATAL)\]", excerpt)):
        first, last = int(locator.group(1)), int(locator.group(2) or locator.group(1))
        active_command = ""
        failed_command = ""
        fragment = []
        with origin.open(encoding="utf-8", errors="replace") as stream:
            for number, line in enumerate(stream, 1):
                if number > last:
                    break
                echo = re.search(r"\bCMD-0034\]\s+@\d+:\s*(.*)", line)
                if echo:
                    active_command = echo.group(1)
                if number == first:
                    failed_command = active_command
                if first <= number <= last:
                    fragment.append(line)
        words = literal_tcl_words(failed_command)
        if (excerpt in "".join(fragment) and words and words[0] in {
                "set_scan_signal", "set_scan_cell_mapping", "set_scan_drc_rule_handling",
                "set_scan_cfg", "set_wrapper_cfg"}):
            origin_port = re.search(r"-port\s+([A-Za-z_][\w$]*)\b", failed_command)
            if (words[0] != "set_scan_signal" or origin_port and
                    re.search(r"(?<![\w$])" + re.escape(origin_port.group(1)) + r"(?![\w$])", subject)):
                subject += " " + failed_command
    logical_lines = dofile.replace("\\\n", " ").splitlines()
    for command in logical_lines:
        if not re.match(r"\s*set_wrapper_cfg\b", command):
            continue
        words = literal_tcl_words(command)
        if "-style" not in words or "-port" not in words:
            continue
        style = words[words.index("-style") + 1].strip('"{}')
        ports = words[words.index("-port") + 1].strip('"{}').split()
        for port in ports:
            if re.fullmatch(r"[A-Za-z_][\w$]*", port) and re.search(r"(?<![\w$])" + re.escape(port) + r"(?![\w$])", subject):
                evidence = wrapper_style_evidence(files, output_dir, port, style)
                if evidence:
                    return evidence
    named_partition = re.search(r"(?:\bpartition\s+|\badd_scan_partition\s+|分区\s*)([A-Za-z_][\w$]*)",
                                diagnosis.get("located_object", ""), re.I)
    bare_partition = diagnosis.get("located_object", "").strip()
    if (named_partition is None and re.fullmatch(r"[A-Za-z_][\w$]*", bare_partition) and
            not source.is_absolute() and re.fullmatch(r"R\d+", run_ref) and
            _is_inside(origin, (output_dir / "runs" / run_ref).resolve()) and
            source.suffix.lower() in {".rpt", ".report", ".txt"} and origin.is_file() and locator and
            re.search(r"(?m)^\s*add_scan_partition\s+" + re.escape(bare_partition) + r"\s", dofile)):
        first, last = int(locator.group(1)), int(locator.group(2) or locator.group(1))
        if any(row["Partition"] == bare_partition and first <= row["line"] <= last
               for row in typed_report_rows(origin, {"Chain", "Partition"})):
            named_partition = re.search(r"partition\s+([A-Za-z_][\w$]*)", "partition " + bare_partition)
    complete_chain_table = False
    if (re.fullmatch(r"scan\s+chains?|扫描链", diagnosis.get("located_object", "").strip(), re.I) and
            not source.is_absolute() and source.suffix.lower() in {".rpt", ".report", ".txt"} and
            locator and re.fullmatch(r"R\d+", run_ref) and
            _is_inside(origin, (output_dir / "runs" / run_ref).resolve()) and origin.is_file() and
            re.search(r"Chain\s+Length\s+Input", excerpt)):
        first, last = int(locator.group(1)), int(locator.group(2) or locator.group(1))
        old_rows = [row for row in typed_report_rows(origin, {"Chain", "Length", "Clocks", "Partition", "ScanEnable"})
                    if re.fullmatch(r"I\s+\S+|\d+", row["Chain"]) and row["Length"].isdigit()]
        original_lines = origin.read_text(encoding="utf-8", errors="replace").splitlines(keepends=True)
        complete_chain_table = (bool(old_rows) and all(first <= row["line"] <= last for row in old_rows) and
                                excerpt in "".join(original_lines[first - 1:last]) and
                                all(original_lines[row["line"] - 1].strip() in excerpt for row in old_rows))
    if named_partition or complete_chain_table:
        partitions: dict[str, dict[str, Any]] = {}
        current_partition = "Default_Partition"
        ambiguous_partitions = set()
        for command in logical_lines:
            words = literal_tcl_words(command.strip())
            if not words:
                continue
            if words[0] == "add_scan_partition" and len(words) >= 4:
                name = words[1].strip('"{}')
                options = dict(zip(words[2::2], words[3::2]))
                clock_list = options.get("-clocks", "").strip('"{}')
                clocks = set(clock_list.split())
                if not re.fullmatch(r"[A-Za-z_][\w$]*", name) or not clocks or any(re.search(r"[$\[\\]", clock) for clock in clocks):
                    continue
                if name in partitions:
                    ambiguous_partitions.add(name)
                partitions[name] = {"clocks": clocks, "count": None, "enable": None}
            elif words[0] == "set_current_scan_partition" and len(words) == 2:
                current_partition = words[1].strip('"{}')
            elif current_partition in partitions and words[0] in {"set_scan_cfg", "set_scan_signal"}:
                options = {key: value.strip('"{}') for key, value in zip(words[1::2], words[2::2])}
                if words[0] == "set_scan_cfg" and options.get("-chain_count", "").isdigit():
                    partitions[current_partition]["count"] = int(options["-chain_count"])
                elif words[0] == "set_scan_signal" and options.get("-type") == "scan_enable":
                    port = options.get("-port", "")
                    if re.fullmatch(r"[A-Za-z_][\w$]*", port):
                        partitions[current_partition]["enable"] = port
        names = {named_partition.group(1)} if named_partition else set(partitions)
        if names and names <= set(partitions) and not names & ambiguous_partitions:
            for path in files:
                if (path.suffix.lower() not in {".rpt", ".report", ".txt"} or
                        "chain" not in path.name.lower() or "cell" in path.name.lower()):
                    continue
                rows = [row for row in typed_report_rows(path, {"Chain", "Length", "Clocks", "Partition", "ScanEnable"})
                        if re.fullmatch(r"I\s+\S+|\d+", row["Chain"]) and row["Length"].isdigit()]
                selected = []
                proven = True
                for name in names:
                    actual = [row for row in rows if row["Partition"] == name]
                    requested = partitions[name]
                    if not actual or any(not row["Clocks"] or not set(re.split(r",\s*", row["Clocks"])) <= requested["clocks"]
                                         for row in actual):
                        proven = False
                        break
                    if complete_chain_table and (requested["count"] is None or requested["enable"] is None or
                                                 len(actual) != requested["count"] or
                                                 any(row["ScanEnable"] != requested["enable"] for row in actual)):
                        proven = False
                        break
                    selected.extend(actual)
                if proven:
                    first, last = min(row["line"] for row in selected), max(row["line"] for row in selected)
                    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
                    return {"source": path.relative_to(output_dir).as_posix(),
                            "locator": f"L{first}" if first == last else f"L{first}-L{last}",
                            "excerpt": "\n".join(lines[first - 1:last])}
    if "set_scan_cell_mapping" in subject:
        for command in logical_lines:
            mapping = re.match(r"\s*set_scan_cell_mapping\s+(\w+)\s+(\w+)\s*$", command)
            if not mapping or mapping.group(2) not in subject:
                continue
            for path in files:
                if not any(name in path.name.lower() for name in ("cell", "element")):
                    continue
                for row in typed_report_rows(path, {"RefName"}):
                    if row.get("RefName") == mapping.group(2):
                        number = row["line"]
                        with path.open(encoding="utf-8", errors="replace") as stream:
                            for index, line in enumerate(stream, 1):
                                if index == number:
                                    return {"source": path.relative_to(output_dir).as_posix(),
                                            "locator": f"L{number}", "excerpt": line.strip()}
    if "set_scan_drc_rule_handling" in subject:
        for command in logical_lines:
            match = re.match(r"\s*set_scan_drc_rule_handling\s+(\{[^}]+\}|DFTR[\w-]+)\s+(Error|Warning|Info|Ignore)\b", command)
            if not match or "-inst" in command:
                continue
            rules = set(re.findall(r"DFTR[-\w]+", match.group(1)))
            if not rules or not all(rule.removeprefix("DFTR-") in subject or rule in subject for rule in rules):
                continue
            for path in files:
                if "rule_handling" not in path.name.lower() or path.suffix.lower() not in {".rpt", ".report", ".txt"}:
                    continue
                lines = read_text(path, 50000).splitlines()
                matches = []
                for number, line in enumerate(lines, 1):
                    row = re.fullmatch(r"\s*(DFTR[-\w]+)\s+(?:Error|Warning|Info|Ignore)\s+(Error|Warning|Info|Ignore)\s+all\s*", line)
                    if row and row.group(1) in rules and row.group(2) == match.group(2):
                        matches.append((number, row.group(1)))
                if {rule for _, rule in matches} == rules:
                    first, last = min(n for n, _ in matches), max(n for n, _ in matches)
                    return {"source": path.relative_to(output_dir).as_posix(),
                            "locator": f"L{first}" if first == last else f"L{first}-L{last}",
                            "excerpt": "\n".join(lines[first-1:last])}
    if "set_scan_signal" in subject or "associated_internal_clocks" in subject:
        for command in logical_lines:
            if not re.match(r"\s*set_scan_signal\b", command):
                continue
            words = literal_tcl_words(command)
            options = {key.removeprefix("-"): value.strip('"{}') for key, value in zip(words[1::2], words[2::2])}
            port, kind = options.get("port", ""), options.get("type", "")
            association = options.get("associated_internal_clocks", "")
            targeted = bool(re.search(r"(?<![\w$])" + re.escape(port) + r"(?![\w$])", subject))
            if not targeted and "set_scan_signal" in subject and "-type " + kind in subject:
                candidates = set()
                for line in logical_lines:
                    if re.match(r"\s*set_scan_signal\b", line) and re.search(r"-type\s+" + re.escape(kind) + r"\b", line):
                        candidate = re.search(r"-port\s+([A-Za-z_][\w$]*)\b", line)
                        if candidate:
                            candidates.add(candidate.group(1))
                targeted = candidates == {port}
            if association and "associated_internal_clocks" in subject and association in subject:
                targeted = True
            if not port or not kind or not targeted:
                continue
            for path in files:
                if "signal" not in path.name.lower() or path.suffix.lower() not in {".rpt", ".report", ".txt"}:
                    continue
                columns = []
                with path.open(encoding="utf-8", errors="replace") as stream:
                    for number, line in enumerate(stream, 1):
                        if re.search(r"\bPort\s+PortProperty\s+SignalType\s+OffState\b", line):
                            columns = [(match.group(0), match.start()) for match in re.finditer(r"\S+", line)]
                        elif columns and line.strip() and not line.lstrip().startswith("-"):
                            row = {key: line[start:columns[index + 1][1] if index + 1 < len(columns) else None].strip()
                                   for index, (key, start) in enumerate(columns)}
                            if row.get("Port") != port or row.get("SignalType", "").split("(")[0] != kind:
                                continue
                            if any(key in options and row.get(column) != options[key]
                                   for key, column in (("off_state", "OffState"), ("usage", "Usage"),
                                                       ("associated_internal_clocks", "AssociatedInternal"))):
                                continue
                            return {"source": path.relative_to(output_dir).as_posix(),
                                    "locator": f"L{number}", "excerpt": line.strip()}
    if "wrapper" in subject.lower() and re.search(r"remove|disabl|删除|移除|禁用", fix, re.I):
        if not re.search(r"(?m)^\s*set_wrapper_cfg\s+enable\b", dofile):
            for path in files:
                if "wrapper_cfg" in path.name.lower():
                    with path.open(encoding="utf-8", errors="replace") as stream:
                        for number, line in enumerate(stream, 1):
                            if re.fullmatch(r"\s*enable\s+N\s*", line):
                                return {"source": path.relative_to(output_dir).as_posix(),
                                        "locator": f"L{number}", "excerpt": line.strip()}
    if "set_scan_cfg" in subject:
        mentioned = set(re.findall(r"-([a-z_]+)", diagnosis.get("located_object", "") + " " + fix))
        for command in logical_lines:
            if not re.match(r"\s*set_scan_cfg\b", command):
                continue
            words = literal_tcl_words(command)
            parameters = [(key.removeprefix("-"), value.strip('"{}')) for key, value in zip(words[1::2], words[2::2])
                          if re.fullmatch(r"-[a-z_]+", key) and "$" not in value and not value.startswith("[")]
            for parameter, value in parameters:
                if not any(parameter.startswith(option) for option in mentioned):
                    continue
                for path in files:
                    if "cfg" not in path.name.lower() or path.suffix.lower() not in {".rpt", ".report", ".txt"}:
                        continue
                    with path.open(encoding="utf-8", errors="replace") as stream:
                        for number, line in enumerate(stream, 1):
                            if re.fullmatch(r"\s*" + re.escape(parameter) + r"\s+" + re.escape(value) + r"\s*", line, re.I):
                                return {"source": path.relative_to(output_dir).as_posix(),
                                        "locator": f"L{number}", "excerpt": line.strip()}
    return None


def positive_issue_evidence(issue: dict[str, Any], plan: dict[str, Any],
                           files: list[Path], output_dir: Path,
                           permitted_drc: set[str] | None = None) -> dict[str, str] | None:
    """Accept conservative, issue-specific positive evidence from a real rerun."""
    found = issue["found"]["excerpt"]
    diagnosis = issue["diagnosis"]
    if "Failed to retrieve the design" in found or re.search(r"Nothing matched for ['\"]design['\"]", found):
        for path in files:
            if path.suffix != ".log":
                continue
            script = read_text(path.parent / "deliverables" / f"{path.parent.name}.dofile", 100000)
            top = re.search(r"(?m)^\s*present_design\s+([\w$]+)\s*$", script)
            if top:
                for report in files:
                    if report.suffix.lower() in {".rpt", ".report", ".txt"}:
                        with report.open(encoding="utf-8", errors="replace") as stream:
                            for number, line in enumerate(stream, 1):
                                if re.fullmatch(r"\s*Design:\s*" + re.escape(top.group(1)) + r"\s*", line):
                                    return {"source": report.relative_to(output_dir).as_posix(),
                                            "locator": f"L{number}", "excerpt": line.strip()}
                                if number >= 20:
                                    break
    if re.search(r"Cannot execute command 'examine_scan_drc' after executing 'insert_dft_logic'", found):
        for path in files:
            if path.suffix != ".log":
                continue
            in_examination = False
            summary = None
            report_header = False
            with path.open(encoding="utf-8", errors="replace") as stream:
                for number, line in enumerate(stream, 1):
                    if "CMD-0034" in line:
                        if re.search(r"@\d+:\s*insert_dft_logic(?:\s|$)", line) and summary:
                            return {"source": path.relative_to(output_dir).as_posix(),
                                    "locator": f"L{summary[0]}", "excerpt": summary[1]}
                        in_examination = bool(re.search(r"@\d+:\s*examine_scan_drc(?:\s|$)", line))
                        report_header = False
                    elif in_examination and re.search(r"\[(?:ERROR|FATAL)\]", line):
                        in_examination = False
                        summary = None
                    elif in_examination and line.strip() == "DRC Report":
                        report_header = True
                    elif in_examination and report_header and re.fullmatch(r"Total violations:\s*\d+\s*", line):
                        # The caller has already checked permitted residual rules.
                        # This evidence proves execution order, not zero violations.
                        summary = (number, line.strip())
    empty_chain_table = (bool(re.search(r"Chain\s+Length\s+Input", found)) and
                         not re.search(r"(?m)^\s*[IW]\s+\S+\s+\d+\s+", found))
    if re.search(r"Cannot execute command 'examine_scan_chain' after executing 'insert_dft_logic'", found) or empty_chain_table:
        # The tool's own final chain examination supplies positive counts, not just silence.
        for path in files:
            if path.suffix != ".log":
                continue
            for window in evidence_windows(str(path), path.stat().st_mtime_ns, path.stat().st_size):
                text = "".join(line for _, line in window)
                match = re.search(r"Total scan chains checked:\s*(\d+)\nSuccess:\s*(\d+)\nFail:\s*0\b", text)
                if match and int(match.group(1)) > 0 and match.group(1) == match.group(2):
                    return locate_evidence([path], output_dir, match.group(0), positive=True)
    design_match = re.search(r"\bpresent_design\s+([\w$]+)", diagnosis.get("located_object", ""))
    if design_match and re.search(r"Nothing (?:implicitly )?matched|design.*not found", found, re.I):
        # A real configuration/chain report identifies the design now present in the tool.
        reports = [p for p in files if p.suffix.lower() in {".rpt", ".report", ".txt"}]
        for path in reports:
            with path.open(encoding="utf-8", errors="replace") as stream:
                for line in stream:
                    if re.fullmatch(r"\s*Design:\s*" + re.escape(design_match.group(1)) + r"\s*", line):
                        return locate_evidence([path], output_dir, line.strip(), positive=True)
    if re.search(r"unknown (?:option|argument)", found, re.I) and "rpt_scan_drc_violation" in found:
        # The reporting command emits a typed DRC summary rather than a completion message.
        # Bind it to that command's actual output block, never to an earlier examine_scan_drc.
        for path in files:
            if path.suffix != ".log":
                continue
            in_report = False
            with path.open(encoding="utf-8", errors="replace") as stream:
                for number, line in enumerate(stream, 1):
                    if "CMD-0034" in line:
                        in_report = bool(re.search(r"@\d+:\s*rpt_scan_drc_violation(?:\s|$)", line))
                    elif in_report and re.search(r"\[(?:ERROR|FATAL)\]", line):
                        in_report = False
                    elif in_report and re.fullmatch(r"Total violations:\s*0\s*", line):
                        return {"source": path.relative_to(output_dir).as_posix(),
                                "locator": f"L{number}", "excerpt": line.strip()}
    # A zero DRC summary proves a DRC condition only; it says nothing about configuration.
    if re.search(r"\bDFTR[-_ ]?(?:\d+|TIE[01]|L[12])\b|Total violations:\s*[1-9]\d*", found, re.I):
        fix = issue.get("attempts", [{}])[-1].get("fix", {}).get("action", "")
        subject = diagnosis.get("located_object", "") + " " + fix
        rule_configuration = ("set_scan_drc_rule_handling" in subject or
                              "RuleType" in found and "SpecifiedLevel" in found or
                              re.search(r"(?m)^\s*DFTR[-\w]+\s+(?:Error|Warning|Info|Ignore)\s+"
                                        r"(?:Error|Warning|Info|Ignore)\s+all\s*$", found))
        if rule_configuration:
            # An allowed Ignore setting needs the actual rule-handling row, not a zero DRC total.
            return None
        return residual_positive_evidence(files, output_dir, permitted_drc or set(), rule_codes(found))
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
        wanted = re.search(r"(\d+)\s*(?:条|(?:scan\s+)?chains?)|(?:chain[_ -]?count|(?:number|total)\s+(?:of\s+)?(?:scan\s+)?chains?)\s*[:=：]?\s*(\d+)", required, re.I)
        actual = re.search(r"(?:number\s+of\s+chains|total\s+(?:of\s+)?(?:scan\s+)?chains(?:\s+checked)?|scan\s+chains?)\s*[:=：]?\s*(\d+)", expected, re.I)
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
                       output_dir: Path, current_run: str, tool_checks_passed: bool,
                       permitted_drc: set[str] | None = None) -> None:
    if not tool_checks_passed:
        return
    files = run_evidence_files(output_dir / "runs" / current_run)
    dofile = read_text(output_dir / "runs" / current_run / "deliverables" / f"{current_run}.dofile", 100000)
    for issue in issues:
        attempts = issue.get("attempts", [])
        if not attempts or issue["found"]["run_ref"] == current_run:
            continue
        verify = attempts[-1]["verify"]
        if verify["resolved"]:
            continue
        evidence = positive_issue_evidence(issue, verification_plans.get(issue["issue_id"], {}), files, output_dir,
                                          permitted_drc)
        if not evidence:
            evidence = configuration_evidence(issue, files, output_dir, dofile)
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
    repair_attempts: list[dict[str, Any]] = []
    requirement_mapping: list[dict[str, Any]] = []
    final_dofile = ""
    task = "task1"
    error_message = None
    start = time.monotonic()
    final_run_dir: Path | None = None
    integrity_problems: list[str] = []
    try:
        if not input_dir.is_dir():
            raise FileNotFoundError(f"Input directory does not exist: {input_dir}")
        if not os.environ.get("SCANINSERTION_LICENSE_SERVER"):
            raise RuntimeError("SCANINSERTION_LICENSE_SERVER is required")
        task, task_spec, netlists, libs, original_path = get_task_artifacts(input_dir)
        active_netlists = {path: path for path in netlists}
        active_netlist_root = input_dir / "netlist"
        limits = read_text(input_dir / "limitations.md", 8000)
        timeout_total = parse_limit_seconds(limits)
        # Small-case artifacts finalize in seconds; do not discard 20% of a
        # 150-second budget. Large netlists retain the longer copy/audit reserve.
        finalize_reserve = 30 if sum(path.stat().st_size for path in netlists) > 64 * 1024 * 1024 else 8
        max_calls = parse_tool_limit(limits)
        client: OpenAI | None = None
        original = read_text(original_path, 50000) if original_path else None
        previous = original or ""
        last_log = ""
        generation_error = ""
        validation_problems: list[str] = []
        static_context = context_for_run(input_dir, task_spec, limits, netlists, libs, "")
        control_hints = reset_polarity_hints(netlists, libs)
        instances = source_instance_map(netlists) if re.search(r"闩锁|latch|关联关系", task_spec, re.I) else {}
        floating = (floating_clock_outputs(netlists) if re.search(r"悬空|浮空|unconnected|floating", task_spec, re.I) and
                    re.search(r"伪|pseudo", task_spec, re.I) and re.search(r"时钟|clock", task_spec, re.I) else {})
        expected_segments = (shift_register_groups(netlists, libraries=libs) if
                             re.search(r"所有.{0,20}移位寄存器|all.{0,20}shift.{0,20}register", task_spec, re.I) else [])
        for index in itertools.count(1):
            if max_calls is not None and index > max_calls:
                break
            remaining = timeout_total - (time.monotonic() - start)
            if remaining <= finalize_reserve + 1:
                break
            rid = f"R{index}"
            run_dir = runs_root / rid
            run_dir.mkdir(parents=True, exist_ok=False)
            script_root = run_dir / "input"
            if task == "task2":
                script_root.mkdir()
                for dirname in ("netlist", "lib", "ctl"):
                    source = input_dir / dirname
                    if source.exists():
                        (script_root / dirname).symlink_to(source, target_is_directory=True)
            previous_reports = ""
            if run_records:
                previous_dir = runs_root / run_records[-1]["run_id"]
                excerpts = []
                for rp in previous_dir.rglob("*"):
                    if rp.is_file() and rp.suffix.lower() in {".rpt", ".report", ".txt"}:
                        report_context = (diagnostic_excerpt(rp, 10000) if re.search(r"drc|violation", rp.name, re.I)
                                          else read_text(rp, 12000))
                        excerpts.append(f"### {rp.relative_to(previous_dir)}\n{report_context}")
                previous_reports = "\n\n".join(excerpts)[:18000]
            generation_base = previous
            generation_mapping = requirement_mapping
            if run_records:
                generation_base, generation_mapping = rebase_round(
                    previous, requirement_mapping, runs_root / run_records[-1]["run_id"], run_dir)
            generation_actual_base = generation_base
            previous_unallowed_codes = (redirected_drc_codes(runs_root / run_records[-1]["run_id"], {}) -
                                        permitted_residual_drc_codes(task, task_spec) if run_records else set())
            if run_records:
                generation_base = model_owned_script(generation_base)
            context = (static_context + f"\n# Current Dofile (output paths already rebased to this round)\n{generation_base}\n\n"
                       f"# Most recent tool log / diagnostics\n{last_log[-18000:] if last_log else '(no run yet)'}\n\n"
                       f"# Most recent tool reports\n{previous_reports[-18000:] if previous_reports else '(no reports captured yet)'}\n")
            netlist_changes: list[dict[str, Any]] = []
            if run_records:
                context += "\n# Localized actual input source around prior diagnostics (Dofile repairs also need source traces)\n" + netlist_diagnostic_context(active_netlists, last_log + "\n" + previous_reports)
            if active_netlist_root != input_dir / "netlist":
                context += f"\n# EQY-proven current netlist directory\n{active_netlist_root}\n"
            if validation_problems:
                context += "\n# Independent output-validator findings from previous round\n" + "\n".join(validation_problems)
            pending = [issue for issue in issue_records if not issue.get("attempts", [{}])[-1].get("verify", {}).get("resolved")]
            if pending:
                context += ("\n# Existing audit records awaiting positive verification\n" +
                            json.dumps(pending, ensure_ascii=False)[:8000] +
                            "\nPreserve settings that already passed tool checks. Do not invent a new problem from a clean DRC summary. "
                            "Add only the actual reports needed for positive verification, or correct a diagnosis using its existing real discovery evidence.\n")
            if task == "task2" and index == 1 and original is not None:
                # R1 is a faithful diagnostic run of the supplied Dofile. Preserve the original as evidence.
                dofile, meta = original, {"summary": "Run the supplied original Dofile to gather diagnostic evidence.", "requirement_mapping": [], "issue_resolutions": []}
                (script_root / "original.dofile").write_text(original, encoding="utf-8")
                execution_path = script_root / "original.dofile"
            else:
                try:
                    if client is None:
                        client = get_client()
                    remaining = timeout_total - (time.monotonic() - start)
                    if remaining <= finalize_reserve + 1:
                        generation_error = f"Insufficient time for Dofile generation before {rid}; finalization reserve retained"
                        break
                    request_client = client.with_options(
                        timeout=model_request_timeout(remaining - finalize_reserve - 1), max_retries=0)
                    dofile, meta = call_for_dofile(request_client, task, context, original if task == "task2" else None,
                                                 input_dir, run_dir, start + timeout_total - finalize_reserve - 1,
                                                 base_dofile=generation_base if run_records else None,
                                                 previous_mapping=generation_mapping,
                                                 catalog=evidence_catalog(runs_root / run_records[-1]["run_id"], output_dir, task_spec=task_spec) if run_records else None,
                                                 segments=expected_segments, control_hints=control_hints, instances=instances, floating=floating,
                                                 previous_actual_dofile=generation_actual_base if run_records else None,
                                                 previous_unallowed_codes=previous_unallowed_codes)
                    if meta.get("netlist_edits"):
                        edits = meta["netlist_edits"]
                        if not isinstance(edits, list) or not all(isinstance(edit, dict) for edit in edits):
                            raise RepairRejected("netlist_edits must be an array of localized edit objects")
                        prior_files = run_evidence_files(runs_root / run_records[-1]["run_id"]) if run_records else []
                        if any(not locate_evidence(prior_files, output_dir, str(edit.get("evidence_excerpt", "")))
                               for edit in edits):
                            raise RepairRejected("Netlist edit is missing exact preceding tool diagnostic evidence")
                        active_netlists, netlist_changes = prepare_repair(
                            task, task_spec, original or "", input_dir, netlists, active_netlists, libs,
                            edits, output_dir, rid, start + timeout_total - finalize_reserve - 1)
                        active_netlist_root = output_dir / "netlist_versions" / rid
                        repair_attempts.append({"run_ref": rid, "admitted": True, "adopted": False,
                                                "lec_ref": f"lec/{rid}/aggregate.log"})
                    if active_netlist_root != input_dir / "netlist":
                        dofile = dofile.replace(str(input_dir / "netlist"), str(active_netlist_root))
                        if task == "task2":
                            (script_root / "netlist").unlink()
                            (script_root / "netlist").symlink_to(active_netlist_root, target_is_directory=True)
                except RepairRejected as e:
                    generation_error = f"Netlist repair rejected before {rid}: {e}"
                    repair_attempts.append({"run_ref": rid, "adopted": False, "reason": str(e),
                                            "lec_ref": f"lec/{rid}/aggregate.log" if (output_dir / "lec" / rid / "aggregate.log").exists() else ""})
                    (run_dir / "repair_rejection.json").write_text(json.dumps(repair_attempts[-1], ensure_ascii=False, indent=2))
                    if run_records:
                        break
                    raise
                except Exception as e:
                    generation_error = f"LLM Dofile generation failed before R{index}: {type(e).__name__}: {e}"
                    if run_records:
                        break
                    raise
                execution_path = None
                if task == "task2":
                    execution_path = script_root / f"{rid}.dofile"
                    execution_path.write_text(dofile, encoding="utf-8")
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
            netlist_change_ids = []
            for change in netlist_changes:
                change["change_id"] = f"F{len(changes)+1}"
                netlist_change_ids.append(change["change_id"])
                changes.append(change)
            final_dofile = dofile
            snapshot = {}
            if active_netlist_root != input_dir / "netlist":
                protected = list(active_netlists.values())
                protected.extend(path for path in (output_dir / "lec").rglob("*")
                                 if path.is_file() and path.name in {"check.eqy", "eqy.log", "aggregate.log", "PASS"})
                snapshot = fingerprint_paths(protected)
                (run_dir / "llm_protected_repair_fingerprints.json").write_text(json.dumps(snapshot, indent=2))
            remaining = timeout_total - (time.monotonic() - start)
            if remaining <= finalize_reserve + 1:
                generation_error = f"Insufficient time after fingerprinting before {rid}"
                break
            per_run_timeout = max(1, int(remaining - finalize_reserve))
            result = tool_run(dofile, run_dir, rid, per_run_timeout, execution_path,
                              abort_on_error=not (task == "task2" and index == 1),
                              allowed_drc=permitted_residual_drc_codes(task, task_spec) if re.search(r"\bDRC\b|违例", task_spec, re.I) else None)
            record = {k: v for k, v in result.items() if k != "log_path"}
            record["log_file"] = str((run_dir / f"{rid}.log").relative_to(output_dir)).replace("\\", "/")
            record["exit_status"] = result["status"]
            run_records.append(record)
            for attempt in repair_attempts:
                if attempt.get("run_ref") == rid and attempt.get("admitted"):
                    attempt["adopted"] = True
            last_log = diagnostic_excerpt(run_dir / f"{rid}.log")
            previous = dofile
            final_run_dir = run_dir
            ok, problems = check_output(run_dir, task_spec, task, dofile, result["status"], expected_segments, floating)
            modified = changed_paths(snapshot)
            if modified:
                integrity_problems = ["EQY-proven candidate or proof artifact changed during the tool run: " + name for name in modified]
                record["repair_integrity_passed"] = False
                (run_dir / "repair_integrity_failure.json").write_text(json.dumps({"modified_paths": modified}, indent=2))
                ok = False
                problems.extend(integrity_problems)
            elif snapshot:
                record["repair_integrity_passed"] = True
            validation_problems = problems
            if meta.get("requirement_mapping"):
                requirement_mapping = []
                for item in meta.get("requirement_mapping", []):
                    if isinstance(item, dict):
                        requirement_mapping.append({"requirement": str(item.get("requirement", "")),
                                                    "dft_config": str(item.get("dft_config", "")),
                                                    "config_ref": {"source": "final_results/deliverables/final.dofile", "locator": ""}})
            record_issue_fixes(meta, issue_records, verification_plans, output_dir, previous_run, rid, change_id,
                               netlist_change_ids, qa_residual_codes(task, task_spec))
            verify_issue_fixes(issue_records, verification_plans, output_dir, rid, ok,
                               permitted_residual_drc_codes(task, task_spec))
            validation_problems = problems + issue_audit_problems(task, issue_records, changes)
            if integrity_problems:
                break
            unresolved = any(issue.get("found", {}).get("verified") and
                             not (issue.get("attempts") and issue["attempts"][-1].get("verify", {}).get("resolved"))
                             for issue in issue_records)
            if ok and not unresolved and not issue_audit_problems(task, issue_records, changes):
                break
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
        tool_checks_passed, final_problems = check_output(final_run_dir, task_spec, task, final_dofile,
                                                         run_records[-1]["exit_status"], expected_segments, floating)
        if integrity_problems:
            tool_checks_passed = False
            final_problems.extend(integrity_problems)
        audit_problems = issue_audit_problems(task, issue_records, changes)
        audit_complete = not audit_problems
        passed = tool_checks_passed and audit_complete
        for mapping in requirement_mapping:
            config = mapping.get("dft_config", "")
            mapping.setdefault("config_ref", {})["locator"] = config_reference(final_dofile, config)
        decision = {
            "case_id": case_id_for(input_dir),
            "organizer_clarifications": {"source": QA_URL, "read_date": QA_READ_DATE,
                                        "tool_call_limit": max_calls,
                                        "permitted_residual_rules": sorted(qa_residual_codes(task, task_spec))},
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
                           "elapsed_seconds": r.get("elapsed_seconds"), "artifacts": r.get("artifacts", []),
                           **({"repair_integrity_passed": r["repair_integrity_passed"]} if "repair_integrity_passed" in r else {})}
                          for r in run_records],
            "file_changes": changes,
            "netlist_repair_attempts": repair_attempts,
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
