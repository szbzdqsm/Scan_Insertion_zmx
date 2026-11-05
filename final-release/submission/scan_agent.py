#!/usr/bin/env python3
"""Auditable ScanInsertion agent runtime for the contest container."""
from __future__ import annotations

import eco_object_contract
import eco_object_selection

import argparse
import copy
from collections import deque
import difflib
import functools
import hashlib
import itertools
import json
import os
import re
import shutil
import stat
import sys
import time
from pathlib import Path
from typing import Any

from openai import OpenAI
from platform_protocol import completed_main, wait_input
import model_config
from netlist_repair import RepairRejected, changed_paths, edits_allowed, fingerprint_paths, prepare_repair
from netlist_structure import shift_register_context, shift_register_groups
from report_validation import chain_problems, chain_rows, coverage_problems, ctl_overlength_exceptions, pseudo_clock_problems, segment_problems
from report_validation import report_rows as typed_report_rows, _full_insertion_designs
from report_validation import chain_role_requirements, wrapper_chain_configuration_problems
from dofile_recipe import configure_floating_inputs, configure_shift_segments, normalize_unrequested_counts, tcl_chunks
from dofile_recipe import normalize_empty_icg_exclusions
from icg_protection import source_facts as icg_protection_source, compile_protection
from floating_inputs import floating_clock_outputs
from clock_latch_context import clock_latch_context, clock_latch_hints
from clock_association_recipe import clock_association_problems, configure_clock_associations
from mode_control_context import mode_control_context, mode_control_hints, mode_control_problems, requested_constant_modes
from mode_control_context import mode_control_report_problems
from insertion_evidence import insertion_replacement_evidence
from shift_report_recipe import configure as configure_natural_shift_reports, natural_shift_report_problems
from model_script_view import edit_anchor_context, model_owned_script, repeated_edit_context
from plan_provenance import project as project_requirement_mapping
from drc_retry_preflight import gated_clock_retry_feedback, unchanged_control_retry_problems
from wrapper_validation import port_wrapper_rows, wrapper_problems, wrapper_style_evidence, wrapper_targets, wrapper_style_configuration_problems, global_wrapper_style
from wrapper_validation import wrapper_maximum_evidence, wrapper_type_evidence, contradicted_wrapper_policy
from contest_rules import QA_READ_DATE, QA_URL, qa_context, qa_residual_codes
from drc_validation import authorized_ignored_rule_codes, authorized_rule_codes, drc_summaries, excluded_scan_cells, residual_positive_evidence, rule_codes, summary_permitted
from drc_validation import preceding_drc_observation, required_rule_handling_problems, scoped_gate_reads
from drc_validation import diagnostic_residual_claim_problems, prior_exclusion_claim_problems
from drc_validation import signal_declaration_claim_problems, signal_fact_claim_problems
from scan_exclusion_evidence import exclusion_command_evidence
from artifact_operations import RunValidationCache, assert_output_directories, independent_copy, _run_signature
from canonical_delivery import CanonicalDeliveryError, publish_canonical_artifacts
from operation_audit import report_requests, fix_action_reference_problems, control_repair_reference_problems
from configuration_evidence import selected_evidence_check
from completion_policy import completion_outcome, _capture_delivery_proof
from help_selection import render_selected_help
from runtime_limits import effective_case_seconds
from audit_refresh import build_audit_refresh_request, current_evidence_catalog, validate_audit_refresh
from audit_refresh import (apply_claim_correction, correction_context, correction_messages,
                           effective_issue_views, issue_digest, official_issue_projection)
from case_deadline import CaseDeadline, CaseDeadlineExceeded
from original_dofile import copy_original_dofile, read_original_text
from repair_deliverables import publish_repair_deliverables
from dft_signal_requirements import explicit_signal_role_requirements, preflight_signal_role_problems, signal_role_report_problems, signal_declaration_conflicts
from exclusion_requirements import debug_domain_source_context, debug_exclusion_requested, exclusion_configuration_problems, exclusion_report_problems, subtree_exclusion_requirements
from source_hierarchy import source_hierarchy_context, source_hierarchy_hints
from tool_process import run_tool_process
from partial_insertion_validation import partial_flow_artifact_paths, partial_insertion_requirements, partial_insertion_validation
from partial_issue_evidence import partial_issue_positive_evidence
from command_error_evidence import bare_configuration_evidence, grouped_signal_evidence, load_input_evidence, mismatched_signal_target, netlist_export_evidence
from audit_no_progress import AuditProgress, audit_artifacts_unchanged, audit_gap_details, repeated_audit_request, save_stop_diagnostic
from command_error_evidence import mapping_command_evidence, failed_command as native_failed_command
from command_error_evidence import command_binding_problem, command_proof_kind, report_operation_binding_problem
from command_error_evidence import command_parameter_claim_problems, command_parameter_claim_assessment, command_parameter_scope, command_parameter_delivery_condition
from library_cell_catalog import LibraryCellCatalog, mapping_kind_problems
from debug_exclusion_preflight import debug_exclusion_source_facts, debug_exclusion_preflight_problems
import eco_evidence
from eco_feedback import Observer as EcoObserver, bounded_context as eco_feedback_context
from runtime_events import Journal, active as active_journal, emit as runtime_event, usage_fields
from eco_structure import original_tie_authority, preserve_original_tie_handling


TOOL = os.environ.get("DFTEXP_SCAN", "/opt/dftexp_scan/bin/dftexp_scan")
MANUAL = Path("/opt/dftexp_scan/doc/Scan_User_Manual.pdf")
_SUMMARY_MODULE = re.compile(r"\s*module\s+([\w$]+)")
_SUMMARY_DIRECTION = re.compile(r"\s*(?:input|output|inout)\b")
_SUMMARY_CONTROL = re.compile(r"clk|clock|rst|reset|test|scan|mode|mbist|jtag", re.I)
_SUMMARY_INSTANCE = re.compile(r"\s*([\w$]+)\s+(\\[^\s]+|[\w$]+)\s*\(")
_SUMMARY_END = re.compile(r"\s*endmodule\b")
_SUMMARY_WORDS = re.compile(r"[\w$]+")


def timed_call(stages: dict[str, float], name: str, function, *args, **kwargs):
    started = time.monotonic()
    tracked = name in {'scope_delivery_proof', 'canonical_delivery', 'final_validation',
                       'repair_delivery', 'final_copy', 'eco_final_publication'}
    if tracked: runtime_event('finalization_stage_start', stage=name)
    try:
        return function(*args, **kwargs)
    finally:
        elapsed = time.monotonic() - started
        stages[name] = stages.get(name, 0.0) + elapsed
        if tracked and not isinstance(sys.exc_info()[1], CaseDeadlineExceeded):
            runtime_event('finalization_stage_end', stage=name, elapsed_seconds=elapsed)


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


def role_input_files(input_dir: Path, netlists: list[Path], libs: list[Path], original: Path | None) -> list[Path]:
    """Freeze declared input roles, never read answers or credentials for hashing."""
    paths = [*netlists, *libs]
    paths.extend(p for p in (input_dir / 'task_spec.md', input_dir / 'limitations.md', original) if p and p.is_file())
    paths.extend(p for p in input_dir.rglob('*') if p.is_file() and p.suffix.lower() in {'.ctl', '.vh', '.svh', '.sdc'})
    return sorted({p for p in paths if p.name.lower() not in {'golden.dofile', 'preset_issues.json', '.env'}
                   and not p.name.lower().startswith('.env.')})


def actual_run_files(run_dir: Path) -> list[Path]:
    """Bind current tool products and scripts to their exact bytes and path set."""
    return sorted(p for p in run_dir.rglob('*') if p.is_file() and
                  p.relative_to(run_dir).parts[0] not in {'input', 'rejected_proposals'} and
                  not p.name.startswith('llm_'))


def input_tree_signature(input_dir: Path) -> tuple | None:
    """Track input contents/links, without unrelated ancestor directory timestamps."""
    snapshot = _run_signature(input_dir, exclude_input=False)
    if snapshot is None:
        return None
    root = Path(os.path.abspath(input_dir))
    return tuple(record[:4] + (None, None, None) + record[7:] if
                 stat.S_ISDIR(record[3]) and not Path(record[0]).is_relative_to(root) else record
                 for record in snapshot)


def netlist_summary(paths: list[Path], query: str = "", *, hierarchy_hints: dict | None = None) -> str:
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
                    m = _SUMMARY_MODULE.match(line)
                    if m:
                        current_module = m.group(1)
                        module_names.add(current_module)
                        if len(modules) < 80:
                            modules.append(current_module)
                    if special_remaining:
                        special_instances[-1]["literal"] += line
                        special_remaining = 0 if ";" in line else special_remaining - 1
                    if current_module and _SUMMARY_DIRECTION.match(line):
                        if _SUMMARY_CONTROL.search(line):
                            entries = control_ports.setdefault(current_module, [])
                            if len(entries) < 24:
                                entries.append(line.strip()[:240])
                        if len(ports) < 160:
                            ports.extend(_SUMMARY_WORDS.findall(line))
                    c = _SUMMARY_INSTANCE.match(line)
                    if c and c.group(1) != "module" and current_module and len(special_instances) < 12:
                        if c.group(2).removeprefix("\\") in mentioned:
                            special_instances.append({"module": current_module, "instance": c.group(2),
                                                      "source": f"{p}:L{i+1}", "literal": line})
                            special_remaining = 0 if ";" in line else 8
                    if c and any(term in c.group(1).lower() for term in ("df", "dl", "latch", "clk", "clock")):
                        kind = c.group(1)
                        if not kind.startswith("sky130_fd_sc_"):
                            kind = re.sub(r"\d+$", "*", kind)
                        cells[kind] = cells.get(kind, 0) + 1
                    if c and current_module and not c.group(1).startswith("sky130_fd_sc_"):
                        entries = hierarchy.setdefault(current_module, [])
                        if len(entries) < 64:
                            entries.append((c.group(2), c.group(1)))
                    if _SUMMARY_END.match(line):
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
        roots = (hierarchy_hints["roots"] if hierarchy_hints is not None else sorted(module_names - child_modules))
        preferred = sorted(module_names.intersection(re.findall(r"[A-Za-z_][\w$]*", query)))
        preferred_roots = [name for name in preferred if name in roots]
        order = list(dict.fromkeys(preferred_roots + preferred + roots + list(links)))
        shown_roots = list(dict.fromkeys(preferred_roots + roots))[:40]
        scope = "provided file family" if hierarchy_hints is not None else "this file (bounded legacy hint)"
        description = (f"Root modules (not instantiated by another module in {scope})" if
                       hierarchy_hints is None or hierarchy_hints.get('roots_complete') else
                       'Unverified root candidates (source hierarchy incomplete; use actual tool discovery)')
        out.append(description + ': ' + ', '.join(shown_roots))
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
        (r"移位寄存器|segment", ["rpt_shift_register", "set_scan_segment", "rpt_scan_segment"]),
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


def command_syntax(query: str, max_chars: int = 30000, *, current: str = "", original: str = "",
                   diagnostics: str = "") -> str:
    path = Path(__file__).with_name("tool_help.json")
    if not path.is_file():
        return "No build-time command syntax cache; consult the manual excerpts."
    syntax = json.loads(path.read_text())
    # max_chars is retained for call compatibility; selected required help is
    # always complete rather than silently losing entries at a character limit.
    return render_selected_help(syntax, query, current, original, diagnostics)[0]


def allowed_drc_codes(spec: str) -> set[str]:
    return authorized_rule_codes(spec)


def permitted_residual_drc_codes(task: str, spec: str) -> set[str]:
    return allowed_drc_codes(spec) | qa_residual_codes(task, spec)


def audit_visible_residual_codes(task: str, spec: str) -> set[str]:
    """Visible authorized residuals are observations, not defects to invent.

    A task's Ignore handling remains independently verifiable configuration.
    """
    return qa_residual_codes(task, spec) | (allowed_drc_codes(spec) - authorized_ignored_rule_codes(spec))


def collection_handle_list_problems(dofile: str) -> list[str]:
    """Reject the observed Tcl-list-of-tool-handles argument, without rewriting Tcl."""
    problems: list[str] = []
    lists: set[str] = set()
    collections: set[str] = set()

    def inspect(script: str, handles: set[str]) -> set[str]:
        handles = set(handles)
        for chunk in tcl_chunks(script):
            words = literal_tcl_words(chunk.strip())
            if not words or words[0].startswith('#'):
                continue
            if words[0] == 'set' and len(words) == 3:
                lists.discard(words[1])
                handles.discard(words[1])
                collections.discard(words[1])
                if re.match(r'^\[(?:get_cells|get_obj_insts)\s', words[2]):
                    collections.add(words[1])
            elif (words[0] == 'lappend' and len(words) == 3 and
                  words[2].startswith('$') and words[2][1:] in handles):
                lists.add(words[1])
            elif (words[0] == 'set_scan_element' and len(words) == 3 and
                  words[2].startswith('$') and words[2][1:] in lists):
                problems.append(
                    f"set_scan_element argument {words[2]} is a Tcl list of tool collection handles, "
                    "not an instance collection; this produces COM-2003 Nothing matched for _dbColl. "
                    "Use one get_cells/get_obj_insts -filter query with inclusion and exception "
                    "predicates and pass its returned collection directly. Update the corresponding "
                    "requirement_mapping to match the corrected actual Tcl.")
            elif (words[0] in {'cluster_foreach', 'foreach_in_collection'} and len(words) == 4 and
                  re.fullmatch(r'\w+', words[1]) and words[2].startswith('$') and
                  words[2][1:] in collections and words[3].startswith('{') and words[3].endswith('}')):
                inspect(words[3][1:-1], handles | {words[1]})
            elif words[0] == 'if':
                if len(words) >= 3 and words[1].strip('{}').strip() in {'0', 'false'}:
                    continue
                for body in words[2:]:
                    if body.startswith('{') and body.endswith('}'):
                        # A conditional rebind makes the later value unknown; do not assume a handle.
                        handles.intersection_update(inspect(body[1:-1], handles))
        return handles

    if not re.search(r'(?m)^\s*(?:proc|source|eval|interp|namespace)\b', dofile):
        try:
            inspect(dofile, set())
        except ValueError:
            # Existing Tcl syntax validation remains responsible for incomplete scripts.
            pass
    return list(dict.fromkeys(problems))


def required_scan_signal_option_problems(dofile: str, syntax: dict) -> list[str]:
    """Check only statically known option/value pairs against native help rows.

    Unknown argument expansion, wrappers and command rebinding stay with the
    real Tcl/tool interpreter. This neither evaluates Tcl nor chooses objects.
    """
    help_text = syntax.get("set_scan_signal", "")
    if not isinstance(help_text, str) or not re.match(r"set_scan_signal\b", help_text):
        return []
    required = set(re.findall(r"(?m)^[ \t]+(-[a-z_]+)[ \t]+\S", help_text))
    allowed = set(re.findall(r"(?<![\w-])(-[a-z_]+)\b", help_text))
    if not required or re.search(
            r"(?:^|[;\n\[{])\s*(?:::)?(?:proc|source|eval|interp|namespace|rename|trace|uplevel|upvar|apply)\b",
            dofile):
        return []
    try:
        chunks = tcl_chunks(dofile.replace("\r\n", "\n"))
    except ValueError:
        return []  # Existing syntax validation owns incomplete Tcl.
    problems = []
    next_line = 1
    for chunk in chunks:
        start_line = next_line + chunk[:len(chunk) - len(chunk.lstrip())].count("\n")
        next_line += chunk.count("\n")
        text = re.sub(r"\\\r?\n[ \t]*", " ", chunk.strip())
        words = literal_tcl_words(text)
        if (not words or words[0] not in {"set_scan_signal", "::set_scan_signal"}
                or ";" in text or any(word.startswith("{*}") for word in words)):
            continue
        seen = set()
        for index in range(1, len(words), 2):
            option = words[index]
            if ((option.startswith('{') and option.endswith('}')) or
                    (option.startswith('"') and option.endswith('"'))):
                option = option[1:-1]
            matches = [name for name in allowed if name.startswith(option)]
            if index + 1 >= len(words) or re.search(r"[$\[\\]", option):
                break
            if option in allowed:
                seen.add(option)
            elif len(matches) == 1:
                seen.add(matches[0])
            else:
                break  # Unknown/ambiguous options belong to existing checks/tool.
        else:
            for option in sorted(required - seen):
                problems.append(f"set_scan_signal at candidate L{start_line}: missing required "
                                f"{option} (unbracketed in installed command help)")
    return problems


def unsupported_options(dofile: str, task_spec: str | None = None, *,
                        known_reset_ports: set[str] | None = None,
                        permit_reset_inference: bool = False,
                        original_tie_codes: set[str] | None = None) -> list[str]:
    """Check literal options on simple commands against the installed tool's help."""
    path = Path(__file__).with_name("tool_help.json")
    if not path.is_file():
        return []
    syntax = json.loads(path.read_text())
    problems = collection_handle_list_problems(dofile)
    problems.extend(required_scan_signal_option_problems(dofile, syntax))
    dynamic_commands = re.search(r"(?m)^\s*(?:proc|source|eval|interp|namespace)\b", dofile)
    if not dynamic_commands and re.search(r"(?m)^\s*set_scan_cfg\s*$", dofile):
        problems.append("Bare set_scan_cfg has no arguments and is invalid; remove it or provide supported options")
    if not dynamic_commands and 'mkdir' not in syntax and re.search(r"(?m)^\s*mkdir(?:\s|$)", dofile):
        problems.append("mkdir is a shell command, not a Tcl command; use file mkdir. "
                        "The runtime already creates the reports and deliverables directories.")
    if (task_spec is not None and qa_residual_codes("task2", task_spec) and
            re.search(r"(?m)^\s*set_scan_element\s+(?:false|0|no|off)\b", dofile, re.I)):
        problems.append("Q19 permits visible DFTR10, not exclusion of scan FFs; remove set_scan_element false")
    if re.search(r"set_dft_clock_gating_cfg[^\n]*-exclude_elements\s+(?:\{\s*\}|\"\")", dofile):
        problems.append("Empty -exclude_elements is invalid; omit this option when no objects are excluded")
    design = ""
    inserted = set()
    problems.extend(signal_declaration_conflicts(dofile, literal_tcl_words))
    for logical_line, line in enumerate(dofile.replace("\\\n", " ").splitlines(), 1):
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
        rule_words = literal_tcl_words(line.strip()) if re.match(r"\s*set_scan_drc_rule_handling\b", line) else []
        if rule_words and len(rule_words) >= 2 and not re.search(r"[$\[\\]", rule_words[1]):
            literal_level = rule_words[2].strip('"{}') if len(rule_words) >= 3 else ""
            if not re.search(r"[$\[\\]", literal_level) and literal_level not in {"Error", "Warning", "Info", "Ignore"}:
                problems.append("set_scan_drc_rule_handling needs rule_names followed directly by Error/Warning/Info/Ignore; "
                                "do not insert a '-' placeholder before the level")
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
                disallowed = changed - authorized_ignored_rule_codes(task_spec) - (
                    ((original_tie_codes or set()) & {'DFTRTIE0', 'DFTRTIE1'}) if level.group(2) == 'Ignore' else set())
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
    return effective_case_seconds(text, os.environ.get("AGENT_CASE_TIMEOUT"))


def parse_tool_limit(text: str) -> int | None:
    """Q15/A16 cancels old case call limits; an explicit local budget remains optional."""
    configured = os.environ.get("AGENT_MAX_TOOL_CALLS", "").strip()
    return max(1, int(configured)) if configured else None


def model_request_timeout(remaining: float) -> float:
    default = 120 if remaining >= 180 else 90
    return max(1.0, min(float(os.environ.get("AGENT_LLM_TIMEOUT", str(default))), remaining))


def contest_model() -> str:
    return model_config.model()


def get_client() -> OpenAI:
    model_config.require_model_requests()
    _, key, base = model_config.settings()
    return OpenAI(api_key=key, base_url=base, timeout=45.0, max_retries=0)


def ask(client: OpenAI, system: str, user: str, max_tokens: int = 7000,
        request_log: Path | None = None) -> str:
    model_config.require_model_requests()
    started = time.monotonic()
    thinking = os.environ.get("LLM_ENABLE_THINKING", "false").lower() == "true"
    journal = active_journal()
    timeout = getattr(client, 'timeout', None)
    allocated = timeout if isinstance(timeout, (float, int)) else getattr(timeout, 'read', None)
    if os.environ.get('AGENT_MAX_MODEL_REQUESTS') and journal is None:
        raise RuntimeError('A capped normal run requires the production request journal')
    request_id = journal.request(request_log, contest_model(), allocated_seconds=allocated) if journal else None
    request = {"model": contest_model(),
               "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
               "max_tokens": max(16000, max_tokens) if thinking else max_tokens,
               "temperature": 0.1, "response_format": {"type": "json_object"},
               "extra_body": {"enable_thinking": thinking}}
    if request_log is not None:
        from runtime_events import model_record
        model_record(request_log.with_suffix(".request.json"),
                     {**request, "meaning": "actual SDK keyword body; credentials/headers excluded; text redacted only"})
    try:
        response = client.chat.completions.create(
            **request,
        )
    except BaseException as exc:
        runtime_event('model_request_end', request_id=request_id, status='failed_or_interrupted',
                      error_type=type(exc).__name__, elapsed_seconds=time.monotonic()-started)
        raise
    response_elapsed = time.monotonic()-started
    runtime_event('model_request_end', request_id=request_id, status='returned',
                  response_model=getattr(response,'model',None), response_id=getattr(response,'id',None),
                  usage=usage_fields(getattr(response,'usage',None)), elapsed_seconds=response_elapsed)
    if request_log is not None:
        usage = getattr(response, "usage", None)
        model_record(request_log, {
            "model": contest_model(), "response_model": getattr(response, "model", None),
            "response_id": getattr(response, "id", None),
            "elapsed_seconds": round(response_elapsed, 3),
            "finish_reason": getattr(response.choices[0], "finish_reason", None),
            "thinking_enabled": thinking,
            "reasoning_content": getattr(response.choices[0].message, "reasoning_content", None),
            "usage": usage.model_dump() if usage is not None else None,
            "content": response.choices[0].message.content,
        })
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


def get_task_artifacts(input_dir: Path, *, upload_root: Path | None = None) -> tuple[str, str, list[Path], list[Path], Path | None]:
    root = upload_root if upload_root is not None else input_dir
    input_dir.resolve().relative_to(root.resolve())
    wait_input(root)
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


def liberty_summary(path: Path, *, cell_names: set[str] | None = None) -> str:
    """Read pins and literal gate-control facts, without guessing control polarity."""
    names = []
    pin_map: dict[str, list[str]] = {}
    current = ""
    current_pin = ""
    gate_facts: list[dict[str, Any]] = []
    facts: list[dict[str, Any]] = []
    is_gate = False
    table_lines = 0
    cell_pattern = re.compile(r'\s*cell\s*\(\s*"?([^"\s)]+)')
    pin_pattern = re.compile(r'\s*pin\s*\(\s*"?([^"\s)]+)')

    def finish_cell() -> None:
        if is_gate and facts and len(gate_facts) < 8:
            candidate = {"cell": current, "source": str(path), "literal_facts": list(facts)}
            if len(json.dumps([*gate_facts, candidate])) <= 5000:
                gate_facts.append(candidate)

    with path.open(encoding="utf-8", errors="replace") as stream:
        for number, line in enumerate(stream, 1):
            cell = cell_pattern.match(line)
            if cell:
                finish_cell()
                current = cell.group(1)
                current_pin, facts, is_gate, table_lines = "", [], False, 0
                names.append(current)
                if cell_names is not None:
                    cell_names.add(current)
                if re.search(r"df|sdf|latch|clk|dl", current, re.I) and len(pin_map) < 128:
                    pin_map[current] = []
            if cell_names is not None and hasattr(cell_names, 'observe_line'):
                cell_names.observe_line(current, line)
            pin = pin_pattern.match(line)
            if pin:
                current_pin = pin.group(1)
            if pin and current in pin_map and len(pin_map[current]) < 24:
                pin_map[current].append(pin.group(1))
            marker = "clock_gate_" in line or "clock_gating_integrated_cell" in line
            if marker and not line.lstrip().startswith(("//", "/*", "*")):
                is_gate = True
            state_header = bool(re.match(r"\s*statetable\s*\(", line))
            if state_header:
                table_lines = 12
            elif table_lines and line.strip() == "}":
                table_lines = 0
            # Keep complete short source lines; no synthesized truth table or level.
            if (marker or state_header or table_lines and re.match(r'\s*(?:table\s*:|["\'LHXN01-])', line)):
                literal = line.rstrip("\r\n")
                if len(literal) <= 1200 and len(facts) < 16:
                    facts.append({"line": number, "pin": "" if state_header or table_lines else current_pin,
                                  "text": literal})
            if table_lines:
                table_lines -= 1
        finish_cell()
    pins = dict(sorted(pin_map.items(), key=lambda item: ("sdf" not in item[0], item[0]))[:80])
    pin_summary = (f"{path.name}: {len(names)} cells; sample={', '.join(names[:30])}\n"
                   "Actual sequential/clock cell pin names (scan cells first): " + json.dumps(pins))[:8000]
    evidence = ("\nActual Liberty clock-gate control evidence (source lines; infer polarity only when supported): "
                + json.dumps(gate_facts) if gate_facts else "")
    return pin_summary + evidence


def mapping_cell_problems(script: str, cell_names: set[str]) -> list[str]:
    """Reject only nonexistent literal mapping names; never execute dynamic Tcl."""
    if not cell_names:
        return []
    problems = []
    for chunk in tcl_chunks(script):
        if not re.match(r"\s*set_scan_cell_mapping\b", chunk):
            continue
        words = literal_tcl_words(chunk.strip())
        if len(words) != 3:
            continue
        problems.extend(mapping_kind_problems(words, cell_names))
        for word in words[1:]:
            literal = word[1:-1] if word[:1] in {'"', '{'} and word[-1:] in {'"', '}'} else word
            if re.search(r"[$\[\]\\;\s]", literal):
                continue
            if literal not in cell_names:
                problems.append(f"set_scan_cell_mapping references '{literal}', absent from the actual supplied Liberty cells")
    return list(dict.fromkeys(problems))


def netlist_diagnostic_context(active: dict[Path, Path], diagnostic: str, limit: int = 6000) -> str:
    """Provide literal localized source evidence around diagnosed instances for a repair proposal."""
    tokens = re.findall(r"'([^'\n]{3,120})'", diagnostic)
    needles = list(dict.fromkeys(token.split("/")[-1] for token in tokens
                                if token.split("/")[-1] and re.fullmatch(r"[\w$\[\]\\/.-]+", token)))[:24]
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


def append_audit_reports(dofile: str, run_dir: Path, task_spec: str = "", *, evidence_claims: list | None = None) -> str:
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
                    r"(?:rpt_(?:scan_(?:signal|cfg|drc_rule_handling|element|chain|chain_cell)|insertion_info|wrapper_(?:cfg|implementation)|pseudo_pi)(?: -type all)? > [^\n]+\.audit\.rpt\"?\n)+"
                    r"(?:# End agent audit reports\n)?", "", dofile)
    dofile = re.sub(r"(?m)^\n?# Agent task-listed DRC reports\n"
                    r'(?:rpt_scan_drc_violation > "[^"\n]+"\n)+'
                    r"# End agent task-listed DRC reports\n", "", dofile)
    reports = [(name, "") for name in commands]
    if "rpt_scan_element" in known and (re.search(r"\bset_scan_element\b", dofile) or
            subtree_exclusion_requirements(task_spec) or debug_exclusion_requested(task_spec)):
        reports.append(("rpt_scan_element", " -type all"))
    if "rpt_wrapper_implementation" in known and re.search(r"\bset_wrapper_cfg\b", dofile):
        reports.append(("rpt_wrapper_implementation", ""))
    extra = "\n# Agent audit reports from actual tool state\n" + "\n".join(
        f'{name}{options} > "{run_dir / "reports" / (name + ".audit.rpt")}"' for name, options in reports)
    for name in report_requests(dofile, evidence_claims or [], literal_tcl_words):
        if name not in known:
            continue  # Missing native syntax cannot create imaginary evidence.
        target = run_dir / 'reports' / (name + '.operation.audit.rpt')
        if str(target) in dofile:
            raise ValueError('Post-operation report path conflicts with model-owned script')
        options = ' -type all' if name == 'rpt_scan_element' else ''
        extra += f'\n{name}{options} > "{target}"'
    extra += "\n# End agent audit reports\n"
    required_drc = set()
    if "rpt_scan_drc_violation" in known:
        for line in task_spec.splitlines():
            if not re.search(r"\bDRC\b|DRC.{0,10}(?:报告|检查)|违例报告", line, re.I):
                continue
            if re.search(r"rule.handling|规则|等级|SpecifiedLevel", line, re.I):
                continue
            names = re.findall(r"(?<![\w./])([\w.-]+\.rpt)(?![\w./])", line, re.I)
            named_drc = [name for name in names if re.search(r"drc|violation|违例", name, re.I)
                         and not re.search(r"rule|handling|规则|等级", name, re.I)]
            # A mixed output list does not assign every report the DRC role.
            # A sole arbitrary filename can be bound by its DRC description.
            if named_drc:
                required_drc.update(named_drc)
            elif len(names) == 1 and not re.search(r"chain|signal|cfg|config|handling|wrapper|element", names[0], re.I):
                required_drc.update(names)
    if required_drc:
        extra += "\n# Agent task-listed DRC reports\n" + "\n".join(
            f'rpt_scan_drc_violation > "{run_dir / "reports" / name}"' for name in sorted(required_drc)) + "\n# End agent task-listed DRC reports\n"
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
    """Keep object identity: a same-named top leaf is not proof of an alias.

    The compatibility entry point remains. Hierarchical repairs must come from
    actual source/tool evidence, never by silently discarding path components.
    """
    return dofile


def apply_dofile_edits(base: str, edits: Any) -> str:
    """Validate unique, disjoint spans against the same original round, then apply."""
    if not isinstance(edits, list) or not 0 <= len(edits) <= 12:
        raise ValueError("dofile_edits must contain 0 to 12 localized replacements")
    replacements = []
    for edit_index, edit in enumerate(edits, 1):
        if not isinstance(edit, dict) or not isinstance(edit.get("old"), str) or not isinstance(edit.get("new"), str):
            raise ValueError("Each Dofile edit needs literal old/new Tcl strings")
        old, new = edit["old"], edit["new"]
        position = base.find(old)
        if not old or max(len(old), len(new)) > 20000 or position < 0 or base.find(old, position + 1) >= 0:
            reason = "not found in the current editable script" if position < 0 else "empty, repeated or too large"
            anchors = (edit_anchor_context(base, old) if old and len(old) <= 20000 and
                       position >= 0 and base.find(old, position + 1) >= 0 else {})
            raise ValueError(f"Dofile edit {edit_index} old span must be nonempty, unique and no larger than 20000 characters ({reason}). "
                             "Copy a unique span from the displayed CURRENT Dofile, or return the complete dofile without dofile_edits."
                             + (" Exact CURRENT locations and unique literal context: " + json.dumps(anchors, ensure_ascii=False) if anchors else ""))
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


def requirement_mapping_problems(task: str, mappings: Any, dofile: str) -> list[str]:
    """Any published mapping must cite literal configuration in its actual script."""
    if not isinstance(mappings, list):
        return ["requirement_mapping must be an array"]
    if task == "task1" and not mappings:
        return ["Task 1 requires a nonempty requirement_mapping with literal Dofile configurations"]
    problems = []
    for index, item in enumerate(mappings):
        if (not isinstance(item, dict) or not isinstance(item.get("requirement"), str) or
                not item["requirement"].strip() or not isinstance(item.get("dft_config"), str)):
            problems.append(f"requirement_mapping[{index}] needs a requirement and a literal dft_config")
        elif not config_reference(dofile, item["dft_config"]):
            problems.append(f"requirement_mapping[{index}] has no actual Tcl match: {item['dft_config'][:500]}. "
                            "Copy actual commands/options. An implicit tool default has no script locator; "
                            "update the actual supported configuration or remove this optional Task 2 mapping.")
    return problems


def retain_unchanged_task1_mappings(previous: list[dict], updates: list, dofile: str) -> list:
    """Merge repair updates with prior literal mappings still present in the actual candidate."""
    if not updates:
        return updates  # An empty Task 1 mapping remains subject to the existing mandatory check.
    updated_requirements = {item.get('requirement') for item in updates
                            if isinstance(item, dict) and isinstance(item.get('requirement'), str)}
    retained = [dict(item) for item in previous if isinstance(item, dict) and
                item.get('requirement') not in updated_requirements and
                not requirement_mapping_problems('task1', [item], dofile)]
    return retained + updates


def context_for_run(input_dir: Path, task_spec: str, limits: str, netlists: list[Path], libs: list[Path], dofile: str, log: str = "", reports: str = "",
                    clock_candidates: list[dict] | None = None, mode_hints: list[dict] | None = None,
                    structural_groups: list[dict] | None = None, include_command_help: bool = True,
                    library_cells: set[str] | None = None, hierarchy_hints_out: dict | None = None) -> str:
    lib_names = [str(p) for p in libs]
    if isinstance(library_cells, LibraryCellCatalog):
        library_cells.capture_clock_pins = debug_exclusion_requested(task_spec)
    lib_summary = [liberty_summary(p, cell_names=library_cells) for p in libs]
    hierarchy = source_hierarchy_hints(netlists, library_cells)
    if hierarchy_hints_out is not None:
        hierarchy_hints_out.update(hierarchy)
        hierarchy_hints_out['debug_exclusion_facts'] = debug_exclusion_source_facts(
            netlists, task_spec, hierarchy, library_cells)
    shift_summary = shift_register_context(netlists, libraries=libs, hints=structural_groups) if re.search(r"移位寄存器|scan\s+segment", task_spec, re.I) else "Not requested"
    context = f"""# Natural-language task specification
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
{netlist_summary(netlists, task_spec, hierarchy_hints=hierarchy)}

# Source module hierarchy, completeness and literal paths
{source_hierarchy_context(netlists, task_spec, hints=hierarchy)}

# Shift-register structures requested by the task
{shift_summary}

# Exact chain classes and named DFT control roles required by the task
{json.dumps({'chain_counts': chain_role_requirements(task_spec), 'global_wrapper_style': global_wrapper_style(task_spec), 'signals': [{'port': item.port, 'roles': sorted(item.roles), 'off_state': item.off_state} for item in explicit_signal_role_requirements(task_spec)], 'subtree_exclusions': subtree_exclusion_requirements(task_spec), 'debug_domain_exclusion': debug_exclusion_requested(task_spec)}, ensure_ascii=False)}

# Literal debug-module clock binding excerpts; role names are candidates, not domain proof
{debug_domain_source_context(netlists, task_spec, hierarchy)}

# Literal clock-buffer and enable-latch connections (structural candidates, not proof)
{clock_latch_context(netlists, libs, hints=clock_candidates) if re.search(r'ICG|门控|缓冲|latch|闩锁', task_spec, re.I) else 'Not requested'}

# Real top-level mode inputs and task-conditioned constant settings
{mode_control_context(netlists, task_spec, hints=mode_hints) if requested_constant_modes(task_spec) else 'Not requested'}

# ScanInsertion manual excerpts (authoritative syntax reference)
{manual_context(task_spec)}

"""
    if include_command_help:
        context += "\n# Command syntax from this installed tool's built-in verbose help\n" + command_syntax(task_spec, current=dofile, diagnostics=log)
    if dofile or log or reports:
        context += f"""\n# Current Dofile
{dofile}

# Most recent tool log / diagnostics
{log[-18000:] if log else '(no run yet)'}

# Most recent tool reports
{reports[-18000:] if reports else '(no reports captured yet)'}
"""
    return context


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
                    previous_unallowed_codes: set[str] | None = None,
                    known_reset_ports: set[str] | None = None,
                    reset_inference_evidenced: bool = False,
                    clock_candidates: list[dict] | None = None,
                    mode_hints: list[dict] | None = None,
                    diagnostics: str = "", library_cells: set[str] | None = None,
                    exclusion_source_facts: dict | None = None,
                    eco_inventory: dict | None = None,
                    drc_phase_observation: dict | None = None,
                    icg_protection_facts: dict | None = None,
                    eco_feedback_state: dict | None = None) -> tuple[str, dict[str, Any]]:
    mode = ("Repair the CURRENT Dofile from actual diagnostics and task requirements; preserve already valid settings."
            if base_dofile is not None else "Generate a Dofile from the task requirements.")
    if base_dofile is not None:
        anchors = repeated_edit_context(base_dofile)
        if anchors:
            context += "\n# Exact unique edit context for repeated CURRENT statements (not automatic edits)\n" + json.dumps(anchors, ensure_ascii=False)
            (run_dir / 'llm_edit_anchors.json').write_text(json.dumps({
                'current_dofile_sha256': hashlib.sha256(base_dofile.encode()).hexdigest(),
                'repeated_spans': anchors}, ensure_ascii=False, indent=2))
    if task == "task2" and original:
        if base_dofile is not None and original.strip() == base_dofile.strip():
            context += "\n# The displayed CURRENT Dofile is the supplied original diagnostic baseline.\n"
        else:
            context += "\n# Original Dofile (diagnostic baseline; patch the CURRENT Dofile)\n" + original
    syntax_path = Path(__file__).with_name("tool_help.json")
    syntax = {}
    help_text = ""
    actual_diagnostics = diagnostics
    if syntax_path.is_file():
        syntax = json.loads(syntax_path.read_text())
        actual_diagnostics = diagnostics + "\n" + "\n".join(
            str(value.get("excerpt", "")) for value in (catalog or {}).values() if isinstance(value, dict))
        help_text, help_metadata = render_selected_help(syntax, read_text(input_dir / "task_spec.md", 60000),
                                                       base_dofile or "", original or "", actual_diagnostics)
        context += "\n# Complete installed help for task roles and actual commands\n" + help_text
        (run_dir / "llm_help_selection.json").write_text(json.dumps(help_metadata, ensure_ascii=False, indent=2))
    if previous_mapping:
        context += "\n# Previous requirement mapping (may be inherited if unchanged)\n" + json.dumps(previous_mapping, ensure_ascii=False)
    if catalog:
        context += "\n# Exact evidence catalog from the preceding actual tool run\n" + json.dumps(catalog, ensure_ascii=False)
        (run_dir / "llm_evidence_catalog.json").write_text(json.dumps(catalog, ensure_ascii=False, indent=2))
    if control_hints:
        context += "\n# Reset inactive levels traced from actual Liberty clear/preset functions and input connections\n" + json.dumps(control_hints, ensure_ascii=False)
    if floating:
        context += "\n# Clock outputs of gates whose input clocks are literally disconnected in original source\n" + json.dumps(floating, ensure_ascii=False)
    disconnected_test_cones = [p for p in (eco_feedback_state or {}).get('ICG_test_pin_observations',[]) if p.get('declared_controls_proven_absent_from_test_cone') is True]
    gate_feedback = (gated_clock_retry_feedback(previous_actual_dofile or '', diagnostics, literal_tcl_words)
                     if drc_phase_observation is None or set(drc_phase_observation.get('blocking_codes', [])) & {'DFTR9', 'DFTR17'}
                     else None)
    if gate_feedback and not disconnected_test_cones:
        context += "\n# Actual inactive-clock failure: inspect gate test-control coverage\n" + json.dumps(gate_feedback, ensure_ascii=False)
        (run_dir / 'llm_clock_control_feedback.json').write_text(json.dumps(gate_feedback, ensure_ascii=False, indent=2))
    if previous_unallowed_codes:
        context += ("\n# Actual blocking DRC rules from the preceding tool result\n" +
                    ", ".join(sorted(previous_unallowed_codes)) +
                    "\nThe displayed current Dofile contains the editable model code. Runtime-owned recipes "
                    "and audit reports are restored automatically; removing their former text cannot repair these rules.")
    if disconnected_test_cones:
        context += '\n# Actual failing gate control path (bound export)\n' + json.dumps(disconnected_test_cones,ensure_ascii=False) + '\nThese failing gate test pins do not depend on any declared test-control port in the fully parsed cone. Choose a task-valid mode_mux operation from the current control_plan_options and fresh eco_ref operands; off_state-only edits cannot change that connection. Original functional logic and consumer nets must remain.\n'
    if not disconnected_test_cones and previous_actual_dofile and (previous_unallowed_codes or set()) & {'DFTR9', 'DFTR17'}:
        shift_declarations = []
        try:
            declarations = tcl_chunks(previous_actual_dofile.replace('\\\n', ' '))
        except ValueError:
            declarations = []
        for declaration in declarations:
            words = literal_tcl_words(declaration.strip())
            if not words or words[0] != 'set_scan_signal' or len(words) % 2 != 1:
                continue
            options = dict(zip(words[1::2], words[2::2]))
            port, off = options.get('-port', ''), options.get('-off_state')
            if (options.get('-type') == 'scan_enable' and options.get('-usage') == 'all' and
                    off in {'0', '1'} and re.fullmatch(r'[A-Za-z_]\w*', port)):
                shift_declarations.append({'port': port, 'capture_off_state': int(off),
                                           'shift_level': 1 - int(off)})
        if shift_declarations:
            context += ("\n# Literal declarations in the preceding executed Dofile: shift = 1 - off_state\n" +
                        json.dumps(shift_declarations[:24]) +
                        "\nThe actual preceding DRC still has gated-clock failures. Check these computed shift "
                        "levels against the supplied actual Liberty clock_gate_test_pin/statetable and source "
                        "hookup, then choose the inactive/capture level as the complement of the required shift "
                        "level. The old Dofile value is not proof of polarity. A clock -internal_clock setting "
                        "does not change the declared scan-enable shift level. Neither high nor low polarity "
                        "is assumed here; validate the actual effective signals and gate connections.")
    spec = read_text(input_dir / "task_spec.md", 60000)
    if task == 'task1' and partial_insertion_requirements(spec)['icg_excluded_scopes'] and icg_protection_facts is None:
        raise ValueError('Required task-derived ICG protection source binding was not supplied')
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
Follow the task specification exactly. Use only commands and options supported by the supplied manual excerpts, this tool's built-in help and evidence from existing Dofiles. Built-in help determines valid command options; do not use options from another EDA product. Correct every earlier ERROR before retrying. Use the actual Liberty pin names, never guess SE/SI/CLK. Choose the requested top module from root-module evidence, rather than an internal module whose name appears first. For reset signals, -off_state is the INACTIVE level: active-low reset means -off_state 1; active-high reset means -off_state 0. get_cells/get_pins return tool collections; use foreach_in_collection to iterate them. Declare wrapper control signals with set_scan_signal before referring to them in set_wrapper_cfg. For full scan-chain insertion, complete examine_scan_drc/examine_scan_chain before insert_dft_logic; partial connect/replace-only tasks follow their separate manual flow and do not require chain analysis. For a clock passed through a latch, use the documented associated_internal_clocks option and exclude that latch from scan elements as required. Group repeated diagnostics by concrete root cause, rather than one issue per cell. Keep each diagnosis and summary short. Never disable DRC to hide a violation. {netlist_rule} Never modify Liberty libraries, the tool, License configuration, or protected evaluation scripts.
For a gated scan partition, configure its scan_enable with usage all so it controls both scan FFs and that partition's clock gates; usage scan alone does not connect gating control. Use a separate clock_gating signal only when the task specifies one. Clock off_state can be 0 or 1; when a latch passes a clock through its D pin, diagnose the source off level with DRC and associated_internal_clocks before proposing a netlist edit. Declare each clock port once, including associated_internal_clocks on that same set_scan_signal command; a second declaration fails instead of updating it. Use the actual parent module and instance from source excerpts, not an assumed hierarchy. To select a hierarchical subtree, filter full_name using the actual path and optional leading hierarchy prefix. Include exception predicates in the same query, and pass its returned collection directly to set_scan_element. Do not build a Tcl list of collection handles with lappend or capture printed names from cluster_foreach. Check sizeof_collection before applying a command that requires a nonempty instance list; a missing required object must remain unresolved. Use the derived shift-register endpoint/index hints where supplied, and use brace quoting/format for array pin paths so Tcl does not interpret numeric brackets as commands.
For scan_enable, -off_state is the INACTIVE/capture level; scan shifting uses the complementary level. Determine it from actual scan-cell and clock-gate functions/state tables and hookup polarity. A faulty original Dofile is not proof of the correct value. When DFTR9/DFTR17 remain with usage all, check whether the shift level opens the actual clock gate before changing lockups, chain lengths or latch clock associations. Never assume every library has active-high scan enable.
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
    system += ("\nThe runtime already creates the reports and deliverables directories. "
               "Write Tcl rather than shell commands: if another directory is required, use file mkdir, "
               "never bare mkdir or mkdir -p. Do not invent a defect solely because those output directories "
               "are not created explicitly in the Dofile.")
    system += ("\nEvery supplied requirement_mapping, including optional Task 2 mappings, must match "
               "literal Tcl in the returned script. Do not map an implicit default to a command that was "
               "never written. Task 2 may explicitly return requirement_mapping: [] to clear optional "
               "mappings; omit the field only when an inherited mapping remains unchanged and valid.")
    system += ("\nWrapper chain counts and internal/unwrapper chain counts are separate report requirements. "
               "Set set_wrapper_cfg -chain_count to the requested Wrapper count. With Wrapper enabled, the installed "
               "tool's global set_scan_cfg -chain_count is the TOTAL of internal plus Wrapper chains, so use their sum. "
               "Then verify actual typed I and W report counts independently; a configuration table is insufficient. "
               "A literal mapping alone does not prove its natural-language requirement. Configure the exact "
               "task-named ICG control port with clock_gating/all usage; another port with usage all is not evidence "
               "for that named control. Preserve any explicitly named scan FF shift/capture control independently. "
               "If a subtree exclusion has exceptions, select sequential descendant leaves, never the parent "
               "Hinstance that recursively disables its exceptions. Restrict exceptions to the given subtree. "
               "For a debug/TAP-only exclusion, trace actual source clocks and keep functional-clock synchronizer FFs; "
               "do not exclude the entire mixed-clock interface parent. Resolve remaining debug-clock FFs using "
               "the actual source and DRC, rather than hiding clock-controlled functional FFs. "
               "Select the smallest actual TAP state-machine subtree; inspect its sibling synchronizer module's "
               "clock connection before using a parent wildcard. If a global Wrapper style is explicitly "
               "required, declare that style: enable alone defaults to shared. A successful DFF replacement "
               "count followed by missing scan pins while tracing Wrapper chains is not proof replacement "
               "was disabled; check ordinary cells reused by shared Wrappers and the requested dedicated style. "
               "For a task with only max_length and no chain_count requirement, let the tool choose counts; "
               "fixed global or Wrapper counts can override the length bound.")
    system += ("\nWrapper enable/disable is GLOBAL. Never combine enable or disable with -port: "
               "the installed tool warns SCAN-4306 and can leave Wrapper disabled. Use a separate "
               "set_wrapper_cfg enable with global custom-cell/threshold options, followed by "
               "set_wrapper_cfg -style dedicated/shared/none -port {actual_port_list}. "
               "Adding a dedicated cell type to a disabled per-port enable command cannot enable Wrappers.")
    system += ("\nThe earlier DRC/chain-analysis ordering applies to FULL chain insertion. For a task that only "
               "connects ICG or replaces FFs without scan chains, follow the manual's partial-flow API instead. "
               "insert_dft_logic -replace_unscan can revert both user-selected non-scan SFFs and SFFs that fail DRC. "
               "Running unrequested DRC with unconfigured clocks/resets before it can revert every SFF, including "
               "required scan FFs outside the target scope. Do not add that DRC pass to a partial task that does not "
               "require it; if DRC is explicitly required, configure the controls correctly and preserve the target "
               "scope. Keep actual post_replace_sff and final post_replace_unscan outputs so retained replacements "
               "outside the non-scan scope can be checked. Never replace all SFFs just to satisfy one domain's unscan. "
               "Honor explicit ICG exclusion scopes BEFORE connect_icg_only: use the installed "
               "set_dft_clock_gating_cfg -exclude_elements with actual is_icg leaf collections from those scopes. "
               "A scan_enable usage setting alone does not preserve an excluded ICG subtree's original test pins. "
               "Keep ICG exclusions separate from the FF back-replacement scope.")
    if mode_hints:
        system += ("\nUse the supplied real top-level mode-port declarations and task-conditioned constants. "
                   "Do not invent test_mode when only scan_mode exists. A scan_enable declaration is distinct "
                   "from locking an existing scan/test mode input. If replacing a nonexistent control port, "
                   "describe the actual replacement set_scan_signal command in the same issue's fix, so its "
                   "SignalType and ConstantValue can be verified in the real signal report. "
                   "Prefer Dofile mode and reset configuration before structural edits. A zero replacement "
                   "count requires actual subsequent insertion and chain evidence, not just a control declaration.")
    system += ("\nFor a report of naturally identified shift registers use the installed rpt_shift_register -file API "
               "after actual examine_scan_chain analysis. rpt_scan_segment reports explicitly configured segments; "
               "an empty segment table does not prove natural ShiftReg membership. The runtime can compile the "
               "task-listed natural report command, but the tool must actually produce and validate it.")
    if segments:
        system += ("\nThe runtime compiles ALL supplied actual shift-register candidates into set_scan_segment "
                   "commands and preserves their actual scan-enable pin connections. Omit your own segment "
                   "commands: do not expand the supplied index tuples into individual set_scan_segment statements. "
                   "Return a compact Dofile for clock, scan, wrapper and output settings. Keep ordinary top-level "
                   "examine_scan_drc/examine_scan_chain before insertion, as the recipe is inserted before them. "
                   "The runtime restores every supplied segment and its actual mapping after generation.")
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
        from eco_plan_context import request_context
        plan_context = request_context(eco_inventory)
        if plan_context:
            user = plan_context + "\n" + user if plan_context not in user else user
            system += "\nExisting functional-driver changes MUST use the supplied eco_ref/eco_link mode_mux protocol; no raw disconnect/reconnect bypass. Choose operands from native evidence, never guess.\n" if "no raw disconnect/reconnect bypass" not in system else ""
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
            if not isinstance(result.get("requirement_mapping", []), list):
                raise ValueError("requirement_mapping must be an array")
            if not isinstance(dofile, str) or not dofile.strip():
                raise ValueError("LLM JSON is missing a non-empty dofile")
            adapted = normalize_wrapper_roots(normalize_scan_port_formats(
                normalize_load_file_lists(normalize_report_redirection(dofile))))
            adapted = normalize_reset_levels(adapted, control_hints or {})
            adapted = normalize_associated_pin_paths(adapted, instances or {})
            adapted, segment_references = configure_shift_segments(adapted, segments or [], spec)
            adapted, floating_references = configure_floating_inputs(adapted, floating or {})
            adapted, natural_shift_references = configure_natural_shift_reports(adapted, spec, literal_tcl_words)
            if task == 'task2':
                adapted, tie_inheritance = preserve_original_tie_handling(
                    adapted, spec, original or '', literal_tcl_words)
                if tie_inheritance['authority']['codes']:
                    (run_dir / 'llm_original_tie_inheritance.json').write_text(json.dumps(
                        tie_inheritance, ensure_ascii=False, indent=2))
            adapted, empty_icg_commands = normalize_empty_icg_exclusions(
                adapted, base_dofile or original or "", annotations={
                    "requirement_mapping": result.get("requirement_mapping", []),
                    "issue_resolutions": result.get("issue_resolutions", [])})
            if empty_icg_commands:
                (run_dir / "llm_empty_exclusion_normalization.json").write_text(json.dumps({
                    "kind": "omit_invalid_standalone_literal_empty_icg_exclusion",
                    "removed_commands": empty_icg_commands,
                    "nonempty_exclusions_changed": False,
                    "acceptance_and_audit_checks_unchanged": True}, ensure_ascii=False, indent=2))
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
            if natural_shift_references:
                mappings = result.get("requirement_mapping", [])
                if not isinstance(mappings, list) or (task == "task1" and not mappings):
                    raise ValueError("Task 1 still needs model-provided key configuration mappings")
                requirement = "Native report of tool-identified natural shift registers"
                mappings = [item for item in mappings if not isinstance(item, dict) or item.get("requirement") != requirement]
                mappings.append({"requirement": requirement, "dft_config": "; ".join(natural_shift_references)})
                result["requirement_mapping"] = mappings
                (run_dir / "llm_natural_shift_report_recipe.json").write_text(json.dumps(
                    {"actual_commands": natural_shift_references}, ensure_ascii=False, indent=2))
            dofile, icg_record = compile_protection(dofile, icg_protection_facts, literal_tcl_words,
                result.get('requirement_mapping', []))
            if icg_record['applicable']:
                (run_dir / 'icg_protection.plan.json').write_text(json.dumps(icg_record, ensure_ascii=False, indent=2))
            for item in result.get("requirement_mapping", []):
                if isinstance(item, dict) and isinstance(item.get("dft_config"), str):
                    clauses = re.split(r";\s*(?=[A-Za-z_]+\b)", item["dft_config"])
                    item["dft_config"] = "; ".join(normalize_wrapper_roots(
                        normalize_associated_pin_paths(normalize_reset_levels(normalize_scan_port_formats(normalize_load_file_lists(normalize_report_redirection(clause))), control_hints or {}, dofile), instances or {}, dofile), dofile).strip() for clause in clauses)
                    item["dft_config"] = normalize_mapping_annotation(dofile, item["dft_config"])
            dofile, clock_references = configure_clock_associations(dofile, clock_candidates or [], spec, literal_tcl_words)
            if clock_references:
                mappings = result.get("requirement_mapping", [])
                if not isinstance(mappings, list) or (task == "task1" and not mappings):
                    raise ValueError("Model-provided key requirement mappings are still required before clock propagation compilation")
                requirement = "Source-derived CE-latch clock outputs propagate the declared primary clock"
                mappings = [item for item in mappings if not isinstance(item, dict) or item.get("requirement") != requirement]
                mappings.append({"requirement": requirement, "dft_config": "; ".join(clock_references)})
                result["requirement_mapping"] = mappings
                (run_dir / "llm_clock_association_recipe.json").write_text(json.dumps({"input_candidates": clock_candidates,
                    "actual_commands": clock_references}, ensure_ascii=False, indent=2))
            if task == 'task1' and previous_mapping:
                updates = result.get('requirement_mapping', [])
                merged = retain_unchanged_task1_mappings(previous_mapping, updates, dofile)
                if len(merged) > len(updates):
                    (run_dir / 'llm_mapping_inheritance.json').write_text(json.dumps({
                        'reason': 'Preserve prior Task 1 mappings with unchanged literal Tcl; updated labels override prior entries',
                        'retained': merged[:len(merged) - len(updates)],
                        'updated_requirements': [item.get('requirement') for item in updates if isinstance(item, dict)]
                    }, ensure_ascii=False, indent=2))
                result['requirement_mapping'] = merged
            problems = unsupported_options(dofile, spec, known_reset_ports=set(control_hints or {}) | (known_reset_ports or set()),
                                           permit_reset_inference=reset_inference_evidenced or
                                           bool((previous_unallowed_codes or set()) & {"DFTR2", "DFTR3"}),
                                           original_tie_codes=set(original_tie_authority(spec, original or '', literal_tcl_words)['codes']))
            problems.extend(mode_control_problems(dofile, spec, mode_hints or [], literal_tcl_words))
            problems.extend(mapping_cell_problems(dofile, library_cells or set()))
            problems.extend(wrapper_chain_configuration_problems(dofile, spec, literal_tcl_words))
            problems.extend(wrapper_style_configuration_problems(dofile, spec, literal_tcl_words))
            problems.extend(preflight_signal_role_problems(dofile, spec, literal_tcl_words, signal_help=syntax.get("set_scan_signal", "")))
            problems.extend(exclusion_configuration_problems(dofile, spec, literal_tcl_words))
            exclusion_source_errors = debug_exclusion_preflight_problems(
                dofile, spec, exclusion_source_facts or {}, literal_tcl_words)
            if exclusion_source_errors:
                feedback_path = run_dir / "llm_debug_exclusion_preflight.json"
                feedback = json.loads(feedback_path.read_text()) if feedback_path.is_file() else {"rejections": []}
                feedback["rejections"].append({
                    "response_file": log_name, "tool_called": False,
                    "kind": "literal_source_clock_boundary_conflict",
                    "problems": exclusion_source_errors})
                feedback_path.write_text(json.dumps(feedback, ensure_ascii=False, indent=2))
            problems.extend(exclusion_source_errors)
            if previous_actual_dofile is not None:
                problems.extend(unchanged_control_retry_problems(
                    previous_actual_dofile, dofile, previous_unallowed_codes or set(),
                    netlist_edits=result.get("netlist_edits"), words_for=literal_tcl_words))
            if task == "task2":
                admitted, rejected = [], []
                for item in result.get("requirement_mapping", []):
                    errors = requirement_mapping_problems(task, [item], dofile)
                    if errors:
                        rejected.append({"mapping": item, "problems": errors, "adopted": False})
                    else:
                        admitted.append(item)
                result["requirement_mapping"] = admitted
                if rejected:
                    (run_dir / "llm_mapping_rejections.json").write_text(json.dumps(
                        {"reason": "Invalid optional Task 2 annotations were not adopted; executable configuration remains unchanged",
                         "rejected": rejected}, ensure_ascii=False, indent=2))
            problems.extend(requirement_mapping_problems(task, result.get("requirement_mapping", []), dofile))
            if not problems:
                return append_audit_reports(strip_fence(dofile), run_dir, spec,
                                            evidence_claims=result.get('issue_resolutions', [])), result
        except ValueError as error:
            problems = [str(error)]
        (run_dir / "llm_validation.json").write_text(json.dumps({"problems": problems}, indent=2))
        runtime_event('candidate_rejected', status='no_tool_call', problem_count=len(problems),
                      proposal_index=attempt+1, source=(run_dir / 'llm_validation.json').name)
        user += "\n# Your previous proposed JSON\n" + raw + "\n# Preflight errors (no tool call made)\n" + "\n".join(problems)
        if base_dofile is not None:
            user += (
                "\nReturn one corrected JSON object using either a nonempty complete dofile string, or "
                "dofile_edits (an array of 0 to 12 objects with string old and new fields). "
                "All edits apply to the SAME displayed CURRENT Dofile, never the rejected proposal or "
                "another edit's replacement. Each old must be nonempty and occur exactly once in CURRENT; "
                "each old/new span must be at most 20000 characters, and old spans must not overlap. "
                "The resulting script must be nonempty. When dofile_edits is supplied, dofile may be omitted; "
                "if both are supplied, the parser uses dofile_edits against CURRENT. "
                f"CURRENT SHA256: {hashlib.sha256(base_dofile.encode()).hexdigest()}. "
                "Keep the existing response metadata schema and use valid options from the supplied built-in help.")
        else:
            user += ("\nReturn one corrected JSON object with a nonempty complete dofile string and the existing "
                     "response metadata schema. No CURRENT edit base is available, so dofile_edits cannot replace "
                     "the dofile string. Use valid options from the supplied built-in help.")
        if syntax:
            expanded, expanded_metadata = render_selected_help(syntax, spec, raw, original or "",
                actual_diagnostics + "\n" + "\n".join(problems))
            if expanded != help_text:
                user = user.replace("# Complete installed help for task roles and actual commands\n" + help_text,
                                    "# Complete installed help for task roles and actual commands\n" + expanded, 1)
                help_text = expanded
                (run_dir / "llm_help_selection.json").write_text(json.dumps(expanded_metadata, ensure_ascii=False, indent=2))
        if any("Dofile edit" in problem for problem in problems):
            user += ("\nYour localized replacement was not applied. Recopy unique, nonoverlapping old spans from "
                     "the same CURRENT Dofile, or return the complete editable script in dofile. "
                     "Preserve valid configuration; runtime-owned recipes and reports will be restored separately.")
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
            if source.suffix.lower() != ".dofile":
                copied.append(source)
            if _is_inside(source, reports) and source.suffix.lower() in {'.v','.vg','.ctl','.def','.scandef'}:
                target = delivery / source.relative_to(reports)
                target.parent.mkdir(parents=True, exist_ok=True)
                if target.exists():
                    if target.is_symlink():
                        raise RuntimeError('Conflicting real deliverable paths: ' + str(target))
                    with target.open('rb') as left, source.open('rb') as right:
                        while True:
                            a,b = left.read(1048576),right.read(1048576)
                            if a != b:
                                raise RuntimeError('Conflicting real deliverable paths: ' + str(target))
                            if not a:
                                break
                if not target.exists():
                    independent_copy(source, target)
                copied.append(target)
            continue
        rel = source.relative_to(run_dir)
        if rel.parts and rel.parts[0] in {"input", "rejected_proposals"}:
            continue
        if source.name.endswith(".dofile") or source.suffix.lower() == ".log":
            continue
        if source.name.startswith("llm_") and source.suffix == ".json":
            continue
        if source.name in {"repair_rejection.json", "repair_integrity_failure.json"}:
            continue

        parts = list(rel.parts)
        lower_parts = [part.lower() for part in parts]
        report_at = next((i for i in range(len(lower_parts) - 1, -1, -1) if lower_parts[i] in {"report", "reports"}), None)
        output_at = next((i for i in range(len(lower_parts) - 1, -1, -1) if lower_parts[i] in {"output", "deliverable", "deliverables"}), None)
        if source.suffix.lower() in {'.v','.vg','.ctl','.def','.scandef'}:
            boundary = max(position for position in (report_at, output_at) if position is not None) if any(
                position is not None for position in (report_at, output_at)) else -1
            destination_root, subparts = delivery, parts[boundary + 1:]
        elif report_at is not None:
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
                independent_copy(source, target)
            copied.append(target)
        except OSError:
            continue
    return copied


def prepare_eco_candidate(dofile, run_dir, libs, task_spec):
    """Shared production compiler entrance; no model or tool invocation here."""
    from partial_insertion_validation import _libraries
    library, problems = _libraries(libs)
    if problems:
        raise RepairRejected('ECO library contract unresolved: '+ '; '.join(problems[:3]))
    protected = set()
    design = None
    original_inputs = sorted((run_dir / 'input/netlist').rglob('*.v'))
    from eco_structure import requires_eco, source_design
    if requires_eco(task_spec):
        if not original_inputs:
            raise RepairRejected('Original object scope unavailable for ECO driver-plan validation')
        _, design = source_design(original_inputs, libs, task_spec, dofile)
        protected = {name+'/'+pin for name, cell in design['cells'].items()
                     for pin, prop in library[cell['type']]['pins'].items() if prop.get('direction') == 'output'}
    from eco_plan_semantics import gate_control_contract
    control_roles = gate_control_contract(task_spec,dofile,literal_tcl_words,design,library,libs) if design else None
    compiled, plan = eco_object_selection.instrument(dofile, literal_tcl_words,
        failure_snapshot=run_dir / 'deliverables/object_contract_failed.v',
        library=library, task_spec=task_spec, protected_drivers=protected, original_design=design, control_roles=control_roles)
    (run_dir/'eco_plan.source.dofile').write_text(dofile,encoding='utf-8')
    plan['source_input_fingerprints'] = fingerprint_paths([*original_inputs, *libs])
    plan['task_spec_sha256'] = hashlib.sha256(task_spec.encode()).hexdigest()
    return compiled, plan


def tool_run(dofile: str, run_dir: Path, run_id: str, timeout: int, execute_path: Path | None = None,
             abort_on_error: bool = True, allowed_drc: set[str] | None = None,
             original_source: Path | None = None, pre_scan_gate=None) -> dict[str, Any]:
    delivery = run_dir / "deliverables"
    reports = run_dir / "reports"
    delivery.mkdir(parents=True, exist_ok=True)
    reports.mkdir(parents=True, exist_ok=True)
    dofile_path = delivery / f"{run_id}.dofile"
    if original_source is not None:
        execute_path = execute_path or run_dir / f"{run_id}.dofile"
        copy_original_dofile(original_source, execute_path, dofile_path)
    else:
        dofile_path.write_text(dofile, encoding="utf-8")
    if execute_path is None:
        # Keep [info script] rooted at the run directory so common script_dir-relative
        # output conventions stay inside this round's isolated workspace.
        execute_path = run_dir / f"{run_id}.dofile"
        execute_path.write_text(dofile, encoding="utf-8")
    log_path = run_dir / f"{run_id}.log"
    cmd = [TOOL, "-f", str(execute_path)]
    runtime_event('tool_start', stage='native_tool', allocated_seconds=timeout)
    try:
        result = run_tool_process(cmd, run_dir, run_id, timeout, log_path,
                                  abort_on_error=abort_on_error, allowed_drc=allowed_drc, pre_scan_gate=pre_scan_gate)
    except BaseException as exc:
        actual = getattr(exc, 'tool_record', None)
        if actual and active_journal():
            active_journal().tool(actual)
        runtime_event('tool_interrupted', status='incomplete', error_type=type(exc).__name__)
        raise
    if active_journal():
        active_journal().tool(result)
    # Collect only actual tool outputs. Preserve subdirectories and never fabricate reports.
    collection_started = time.monotonic()
    try:
        output_files = collect_tool_outputs(run_dir, run_id)
    except CaseDeadlineExceeded as exc:
        exc.tool_record = result
        raise
    result.update(collection_seconds=round(time.monotonic() - collection_started, 3),
                  artifacts=[p.relative_to(run_dir).as_posix() for p in output_files])
    if active_journal():
        from runtime_events import atomic
        atomic(active_journal().root / (run_id + '.tool.json'),
               {'trace_id':active_journal().trace_id, 'run_ref':run_id, 'kind':'finished_native_tool_record',
                **{k:v for k,v in result.items() if k != 'log_path'}})
    runtime_event('collection_end', stage='native_collection', elapsed_seconds=result['collection_seconds'])
    return result


def check_output(run_dir: Path, task_spec: str, task: str, dofile: str, status: str,
                 expected_segments: list[dict[str, Any]] | None = None,
                 expected_floating: dict[str, list[str]] | None = None,
                 clock_candidates: list[dict] | None = None,
                 mode_hints: list[dict] | None = None, *,
                 eco_stage: eco_evidence.NativeTrace | None = None) -> tuple[bool, list[str]]:
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
    if eco_stage is not None:
        # Keep early diagnosis reports intact. Only a native, current-case
        # stage binding can choose DRC evidence for the adopted ECO state.
        try:
            summaries = eco_evidence.current_drc(eco_stage)
        except RepairRejected as exc:
            summaries = []
            problems.append('ECO DRC stage binding: ' + str(exc))
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
    problems.extend(required_rule_handling_problems(run_dir, report_files, dofile, task_spec, literal_tcl_words))
    problems.extend(coverage_problems(report_files, dofile))
    problems.extend(wrapper_problems(report_files, task_spec))
    problems.extend(signal_role_report_problems(report_files, task_spec))
    problems.extend(exclusion_report_problems(report_files, task_spec, dofile, literal_tcl_words))
    problems.extend(clock_association_problems(report_files, dofile, clock_candidates or [], task_spec, literal_tcl_words))
    problems.extend(mode_control_report_problems(report_files, dofile, task_spec, mode_hints or [], literal_tcl_words))
    problems.extend(natural_shift_report_problems([log_path, *report_files], task_spec))
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
            independent_copy(p, dest)


def write_diff(out: Path, old: str, new: str, old_name: str, new_name: str) -> str:
    diffs = out / "diffs"
    diffs.mkdir(parents=True, exist_ok=True)
    path = diffs / f"dofile_{old_name}_to_{new_name}.diff"
    lines = difflib.unified_diff(old.splitlines(True), new.splitlines(True), fromfile=old_name, tofile=new_name)
    path.write_text("".join(lines), encoding="utf-8")
    return str(path.relative_to(out))


def native_diagnostic_reports(run_dir: Path) -> list[Path]:
    """Discover only native-echo-bound diagnostic report paths in this run.

    Original scripts may write under their private input/output directory.
    These are diagnosis sources, not proof of repair or final delivery. Never
    recurse through the input netlist/library links or accept a guessed basename.
    """
    from pathlib import PurePosixPath
    from canonical_delivery import _target, _real_file, CanonicalDeliveryError
    run = run_dir.absolute(); root = run.parent.parent
    if not re.fullmatch(r'R[1-9]\d*', run.name) or run.parent.name != 'runs':
        return []
    log = run / (run.name + '.log'); script = run / 'deliverables' / (run.name + '.dofile')
    try:
        _real_file(log, root); _real_file(script, root)
        physical = script.read_text().splitlines()
        virtual = None; variables = {}; pending = None; top = ''; requested_top = ''
        reports = []; active = None
        for number, line in enumerate(log.read_text(errors='replace').splitlines(), 1):
            origin = re.search(r'\[SOURCE TCL FILE\]\s+(\S+)\s*:', line)
            if origin:
                source = PurePosixPath(origin[1]); hits = [i for i,p in enumerate(source.parts)
                    if p == 'runs' and source.parts[i+1:i+2] == (run.name,)]
                if virtual is not None or len(hits) != 1 or '..' in source.parts: return []
                cut = hits[0] + 2; virtual = PurePosixPath(*source.parts[:cut])
                executed = run.joinpath(*source.parts[cut:]); _real_file(executed, root)
                if executed.read_bytes() != script.read_bytes(): return []
            echo = re.search(r'CMD-0034\]\s+@(\d+):\s*(.*)', line)
            if echo:
                n, code = int(echo[1]), echo[2].strip()
                if n < 1 or n > len(physical): return []
                expanded = physical[n-1].strip(); i = n
                while expanded.endswith('\\') and i < len(physical):
                    expanded = expanded[:-1] + ' ' + physical[i].strip(); i += 1
                if code != expanded: return []
                w = literal_tcl_words(code); pending = None; active = w[0] if w else ''
                if len(w) == 3 and active == 'set':
                    pending = w[1]; variables.pop(pending, None)
                if active == 'present_design':
                    if len(w) != 2: return []
                    requested_top = w[1]
                # Only the exact two DRC writers; arbitrary files and report
                # lookalikes never become catalog entries through this helper.
                if active in {'examine_scan_drc','rpt_scan_drc_violation'} and len(w) == 3 and w[1] in {'-file','>'} and top and virtual is not None:
                    try:
                        target = _target(w[2], variables, virtual, run, literal_tcl_words, native_generated=True)
                        if target.suffix.lower() not in {'.rpt','.report','.txt'}: continue
                        _real_file(target, root)
                        # Must have the native DRC report header and both actual
                        # counts and diagnosis; file existence is insufficient.
                        text = read_text(target, 200000)
                        if re.search(r'(?mi)^Total violations:\s*\d+', text) and re.search(r'(?m)DFTR(?:[-_]?(?:\d+|TIE[01]))', text):
                            reports.append(target)
                    except (OSError, ValueError, CanonicalDeliveryError):
                        continue
                continue
            if pending:
                value = line.strip()
                if value and not value.startswith('[') and not re.search(r'[$\[\]\\;]', value):
                    variables[pending] = value
                pending = None
            design = re.search(r"CMD-1300\]\s+Present design is '([^']+)'", line)
            if design and active == 'present_design':
                if design[1] != requested_top or top and top != design[1]: return []
                top = design[1]
        return list(dict.fromkeys(reports))
    except (OSError, ValueError, CanonicalDeliveryError):
        return []


def run_evidence_files(run_dir: Path) -> list[Path]:
    """Enumerate real evidence without loading large logs into memory."""
    reports = sorted(p for p in (run_dir / "reports").rglob("*")
                     if p.is_file() and p.suffix.lower() in {".rpt", ".report", ".txt"})
    log = run_dir / f"{run_dir.name}.log"
    reports = list(dict.fromkeys(reports + native_diagnostic_reports(run_dir)))
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


def chain_count_claim(text: str, rows: list[dict[str, Any]]) -> tuple[str, int] | None:
    """Identify one explicit count and one real partition; ambiguous claims abstain."""
    counts = set(int(value) for value in re.findall(r"\bchain_count\b[\s`'\"=:]*(\d+)\b", text, re.I))
    partitions = {row["Partition"] for row in rows if row["Partition"] and
                  re.search(r"(?<![\w$])" + re.escape(row["Partition"]) + r"(?![\w$])", text)}
    if len(counts) == len(partitions) == 1 and next(iter(counts)) > 0:
        return next(iter(partitions)), next(iter(counts))
    return None


def internal_partition_count(rows: list[dict[str, Any]], partition: str) -> int:
    return sum(row["Partition"] == partition and bool(re.fullmatch(r"I\s+\S+|\d+", row["Chain"]))
               for row in rows)


def chain_count_positive_evidence(issue: dict[str, Any], files: list[Path], output_dir: Path) -> dict[str, str] | None:
    """Bind a real before/after count change to all actual rows of one partition."""
    found = issue.get("found", {})
    subject = str(issue.get("phenomenon", "")) + " " + str(issue.get("diagnosis", {}).get("located_object", ""))
    if not re.search(r"\bchain_count\b", subject, re.I):
        return None
    old_path = output_dir / found.get("source", "")
    if old_path.suffix.lower() not in {".rpt", ".report", ".txt"} or not old_path.is_file():
        return None
    old_rows = chain_rows([old_path])
    claim = chain_count_claim(subject, old_rows)
    if not claim or internal_partition_count(old_rows, claim[0]) == claim[1]:
        return None
    for path in files:
        if path.suffix.lower() not in {".rpt", ".report", ".txt"}:
            continue
        rows = chain_rows([path])
        if internal_partition_count(rows, claim[0]) != claim[1]:
            continue
        actual = [row for row in rows if row["Partition"] == claim[0] and
                  re.fullmatch(r"I\s+\S+|\d+", row["Chain"])]
        first, last = min(row["line"] for row in actual), max(row["line"] for row in actual)
        with path.open(encoding="utf-8", errors="replace") as stream:
            excerpt = "".join(line for number, line in enumerate(stream, 1) if first <= number <= last).rstrip("\r\n")
        return {"source": path.relative_to(output_dir).as_posix(),
                "locator": f"L{first}" if first == last else f"L{first}-L{last}", "excerpt": excerpt}
    return None


def nonrepair_action_problem(issue: dict[str, Any]) -> dict[str, Any] | None:
    """A statement that no repair was needed cannot describe a repair attempt.

    Keep the original proposal in the admission review. This does not waive a
    task condition or turn a real diagnostic into a successful repair.
    """
    attempts = issue.get("attempts") or []
    action = str(attempts[-1].get("fix", {}).get("action", "")).strip() if attempts else ""
    no_action = re.search(
        r"^no\s+(?:(?:additional|further)\s+)?(?:fix(?:es)?|repairs?|changes?|edits?|actions?)\s+"
        r"(?:(?:is|are)\s+)?(?:needed|required|necessary)\b|"
        r"already corrected|already correct|\bno fix needed\b|no further change|"
        r"already.*fixed|already resolved|无需进一步|已经修复",
        action, re.I)
    if not no_action:
        return None
    return {"reason": "no_repair_action_claimed", "original_action": action,
            "conclusion": "No repair is claimed by this action. Do not record it as a repaired issue; "
                          "actual changes and native task checks remain required. This is not a task waiver."}


def record_issue_fixes(meta: dict[str, Any], issues: list[dict[str, Any]],
                       verification_plans: dict[str, dict[str, Any]], output_dir: Path,
                       previous_run: str, current_run: str, change_id: str,
                       additional_change_ids: list[str] | None = None,
                       accepted_residual: set[str] | None = None,
                       task_spec: str | None = None,
                       admission_reviews: list[dict[str, Any]] | None = None) -> None:
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
        requirement = str(item.get("violated_requirement", "")).strip()
        denies_violation = re.search(
            r"^none\b|does not violate (?:any |a )?(?:task )?requirement|"
            r"不违反|未违反|没有违反|无(?:任务)?要求", requirement, re.I)
        cosmetic = re.search(r"redundan|duplicate|冗余|重复", diagnostic + " " + fix_text, re.I)
        no_effect = re.search(
            r"does not (?:change|affect)|no (?:functional |behavioral )?effect|"
            r"for clarity|unnecessary complexity|不影响|仅.{0,12}(?:可读|清晰|整洁)",
            diagnostic + " " + fix_text + " " + requirement, re.I)
        if (denies_violation and cosmetic and no_effect and
                not re.search(r"\[(?:ERROR|FATAL)\]", cited)):
            # A model's explicitly harmless cleanup is not a task fault. A
            # real warning quoted next to it does not prove the other claim.
            # Keep native failures and all actual task/output checks intact.
            continue
        if (task_spec is not None and re.search(r"off[-_ ]state", diagnostic, re.I) and
                re.search(r"\bscan_enable\(spec\)", cited, re.I) and
                not re.search(r"\[(?:ERROR|FATAL|WARNING)\]", cited)):
            # A reported value alone is not a polarity failure. A port suffix
            # does not supply a task-required capture/inactive level.
            declared = explicit_signal_role_requirements(task_spec)
            if not any(requirement.off_state is not None and re.search(
                    r"(?<![\w$])" + re.escape(requirement.port) + r"(?![\w$])", cited)
                       for requirement in declared):
                continue
        diagnosed_rules = rule_codes(located + " " + diagnostic + " " + fix_text + " " + str(item.get("phenomenon", "")))
        chain_evidence = bool(re.search(r"(?m)^\s*(?:[IW]\s+\S+|\d+)\s+\d+\s+", cited) or
                              re.search(r"Chain\s+Length\s+Input", cited))
        if (chain_evidence and re.search(r"(?m)^\s*(?:[IW]\s+\S+|\d+)\s+\d+\s+", cited) and
                not re.search(r"\[(?:ERROR|FATAL|WARNING)\]", cited) and
                re.search(r"\b(?:examine_scan_drc|examine_scan_chain|insert_dft_logic)\b", located + " " + diagnostic) and
                re.search(r"\b(?:duplicate|duplicated|repeated|unreachable|unexecuted)\b|"
                          r"execution.{0,20}(?:order|structure)|script.{0,20}(?:structure|ordering)|"
                          r"重复|不可达|未执行|执行顺序", diagnostic, re.I)):
            # Nonempty chain topology does not prove which Tcl commands ran,
            # how many times they ran, or whether a later block was reachable.
            continue
        claim_rules = rule_codes(located + " " + diagnostic + " " + str(item.get("phenomenon", "")))
        if (claim_rules and not cited_rules and re.fullmatch(
                r"\[INFO\]\s+\[\s*DFTDRC-7006\]\s+Cannot make cell '[^'\n]+' "
                r"scannable due to 'set_scan_element' command\.", cited)):
            # This confirms an exclusion command, not a violation of the
            # claimed DRC rule. Actual exclusion-scope faults remain admissible
            # and all native DRC/report checks still run.
            continue
        if (not cited_rules and re.fullmatch(r"\[ERROR\]\s+\[\s*COM-3301\] Failed to open file [^\n]+", cited) and
                (rule_codes(str(item.get("phenomenon", ""))) or
                 re.search(r"\b(?:no|zero|0)\s+(?:scan\s+)?chains?\b|\b(?:0|zero)\s*(?:DFFs?|FFs?)\b",
                           str(item.get("phenomenon", "")), re.I))):
            # A single file-open failure does not observe DRC or insertion counts.
            # Keep real file-open diagnoses and all native error checks unchanged.
            continue
        if chain_evidence and claim_rules and not cited_rules and not re.search(r"\[(?:ERROR|FATAL|WARNING)\]", cited):
            # A chain table supplies topology, not an observed DRC rule result.
            continue
        parameter_claim = bool(re.search(r"off[-_ ]state|\busage\b|\bclock_gating_init_cycles\b|incomplete.{0,30}(?:declaration|command)|"
                                         r"missing.{0,20}(?:parameters?|options?)|缺少.{0,20}参数", diagnostic, re.I))
        if (chain_evidence and parameter_claim and not re.search(r"\[(?:ERROR|FATAL)\]", cited) and
                not re.search(r"OffState|Usage", cited)):
            # Chain topology does not reveal signal parameters, regardless of
            # whether the diagnosis names one port, several ports, or a partition.
            continue
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
        if re.search(r"ScanConfigurationParameter|WrapperConfigurationParameter", cited):
            config_command = "set_wrapper_cfg" if "WrapperConfigurationParameter" in cited else "set_scan_cfg"
            if re.search(r"\b(?:set_scan_element|get_obj_insts|get_cells)\b", located):
                # A configuration table does not discover a failed object query or exclusion.
                continue
            parameters = set(re.findall(r"(?m)^\s*([a-z_]+)\s+\S+\s*$", cited))
            relevant = located + " " + diagnostic
            if config_command not in relevant and not any(re.search(r"\b" + re.escape(name) + r"\b", relevant) for name in parameters):
                continue
            current_values = dict(re.findall(r"(?m)^\s*([a-z_]+)\s+(\S+)\s*$", cited))
            requested_values = [(name, value.strip('"{}') if value.startswith(('"', '{'))
                                 else value.rstrip('.,;')) for name, value in
                                re.findall(r'-([a-z_]+)\s+(\{[^{}]+\}|"[^"\n]+"|[^\s,;]+)', fix_text)
                                if name in current_values and not re.search(r"[$\[\\]", value)]
            if requested_values and all(current_values[name].lower() == value.lower() for name, value in requested_values):
                # Already effective values do not prove an absent explicit declaration is a defect.
                continue
        if re.search(r"ScanConfigurationParameter|WrapperConfigurationParameter", cited) and re.search(r"redundan|duplicate configuration|冗余", diagnostic, re.I):
            continue
        if re.search(r"ScanConfigurationParameter|WrapperConfigurationParameter", cited):
            wrapper_limit = ('WrapperConfigurationParameter' in cited and
                             bool(re.search(r'(?m)^\s*max_length\s+\S+\s*$', cited)) and
                             bool(re.search(r'\bmax_length\b', located + ' ' + diagnostic)))
            if parameter_claim and not re.search(r"OffState|Usage", cited) and not wrapper_limit:
                continue
            if (re.search(r"chain.{0,30}length|链.{0,15}长度", diagnostic, re.I) and
                    not re.search(r"Chain\s+Length", cited) and not wrapper_limit):
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
        # A report may locate a parameter fault without itself being absent.
        # Bind the absence predicate to a file/report noun or the named artifact,
        # rather than to any unrelated "missing" in the diagnosis.
        artifact_absence = re.search(
            r"\b(?:missing|empty)\s+(?:(?:the|required|expected|final|output)\s+)*"
            r"(?:files?|reports?|outputs?|artifacts?)\b|"
            r"\b(?:no|not)\b.{0,30}\b(?:files?|reports?|outputs?)\b.{0,30}(?:written|produced|generated)|"
            r"(?:报告|文件|输出)\s*(?:未生成|为空|缺失)|(?:缺失|未生成)\s*(?:报告|文件|输出)", diagnostic, re.I)
        named_absence = any(re.search(
            r"(?:\b(?:missing|empty)\s+(?:the\s+)?[`\"']?" + re.escape(name) +
            r"|" + re.escape(name) + r"[`\"']?\s+(?:(?:is|was)\s+)?(?:missing|empty|not\s+(?:written|produced|generated)))",
            diagnostic, re.I) for name in artifact_names)
        if (artifact_names and not re.search(r"\[(?:ERROR|FATAL|WARNING)\]", cited) and
                (artifact_absence or named_absence) and
                not any(name in cited for name in artifact_names)):
            # An unrelated report row does not discover a missing output file.
            continue
        generic_failure = re.search(r"Command '([a-z_]+)' execution failed", cited)
        evidence = (command_failure_evidence(cited, generic_failure.group(1), located) if generic_failure
                    else locate_evidence(files, output_dir, cited))
        if not evidence:
            continue
        candidate_issue = {'phenomenon': str(item.get('phenomenon', '')),
                           'found': {'run_ref': previous_run, **evidence},
                           'diagnosis': {'located_object': located, 'summary': str(item.get('diagnosis', '')),
                                         'root_cause': str(item.get('root_cause', ''))},
                           'attempts': [{'fix': {'action': fix_text}}]}
        binding_problem = (nonrepair_action_problem(candidate_issue) or
                           command_binding_problem(candidate_issue, output_dir, literal_tcl_words) or
                           report_operation_binding_problem(candidate_issue))
        if binding_problem:
            if admission_reviews is not None:
                admission_reviews.append({'proposed_in': current_run, 'status': 'not_admitted',
                                          'original_claim': copy.deepcopy(item),
                                          'found': candidate_issue['found'], **binding_problem})
            continue
        if contradicted_wrapper_policy(item, {'run_ref': previous_run, **evidence}, output_dir, task_spec):
            continue
        source = output_dir / evidence['source']
        segment_locator = re.fullmatch(r'L(\d+)(?:-L(\d+))?', evidence['locator'])
        if (source.suffix.lower() in {'.rpt', '.report', '.txt'} and
                ('segment' in source.name.lower() or re.search(r'Name\s+SegmentProperty\s+Length', cited)) and
                not re.search(r'\[(?:ERROR|FATAL|WARNING)\]', cited) and segment_locator and
                re.search(r'\bset_wrapper_cfg\b|wrapper.{0,30}chain.{0,40}(?:length|长度)',
                          located + ' ' + diagnostic + ' ' + str(item.get('phenomenon', '')), re.I) and
                any(int(segment_locator[1]) <= row['line'] <= int(segment_locator[2] or segment_locator[1])
                    for row in typed_report_rows(source, {'Name', 'SegmentProperty', 'Length'}))):
            # A segment table describes atoms, not Wrapper configuration or
            # assembled-chain faults. Real configuration/chain checks still apply.
            continue
        if mismatched_signal_target(item, {"run_ref": previous_run, **evidence}, output_dir, literal_tcl_words):
            continue
        if chain_evidence and not re.search(r"\[(?:ERROR|FATAL|WARNING)\]", cited):
            source = output_dir / evidence["source"]
            if source.suffix.lower() in {".rpt", ".report", ".txt"}:
                actual_rows = chain_rows([source])
                if (any(int(row["Length"]) > 0 and not row.get("_chain_conflict") for row in actual_rows) and
                        re.search(r"\b(?:no|zero|0)\s+(?:scan\s+)?chains?(?:\s+(?:created|formed|generated))?(?=\s*(?:[;,.]|$))",
                                  str(item.get("phenomenon", "")), re.I)):
                    # A positive typed chain row cannot prove global zero chains.
                    continue
                claim = chain_count_claim(str(item.get("phenomenon", "")) + " " + located + " " + diagnostic, actual_rows)
                if claim and internal_partition_count(actual_rows, claim[0]) == claim[1]:
                    # A satisfied full typed count cannot discover a count failure.
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
                           dofile: str, *, file_changes: list[dict] | None = None) -> dict[str, str] | None:
    """Bind the executed literal configuration to typed rows from the real tool."""
    if nonrepair_action_problem(issue) or report_operation_binding_problem(issue):
        return None
    check = selected_evidence_check(issue, files, output_dir, dofile, "", literal_tcl_words,
                                    file_changes=file_changes)
    if check['applicable']:
        return check.get('evidence') if check['status'] == 'pass' else None
    failed_mapping = literal_tcl_words(native_failed_command(issue.get('found', {}), output_dir) or '')
    mapping_error_claim = (str(issue.get('found', {}).get('source', '')).endswith('.log') and
                           '[ERROR]' in str(issue.get('found', {}).get('excerpt', '')) and
                           re.search(r'\bset_scan_cell_mapping\b',
                                     str(issue.get('diagnosis', {}).get('located_object', ''))))
    if failed_mapping and failed_mapping[0] == 'set_scan_cell_mapping' or mapping_error_claim:
        # A malformed discovery reference must not fall through to a typed-name
        # match after the strict native-command proof has rejected it.
        return mapping_command_evidence(issue, files, output_dir, dofile, literal_tcl_words)
    if failed_mapping and failed_mapping[0] in {'load_lib', 'load_netlist'}:
        return load_input_evidence(issue, files, output_dir, dofile, literal_tcl_words)
    if (re.search(r'wrapper.*implementation', str(issue.get('found', {}).get('source', '')), re.I) and
            '-dedicated_cell_type' in str(issue.get('attempts', [{}])[-1].get('fix', {}).get('action', ''))):
        # A style-only row cannot substitute for the claimed dedicated cell type.
        return wrapper_type_evidence(issue, files, output_dir, dofile, literal_tcl_words)
    specific = (netlist_export_evidence(issue, files, output_dir, dofile, literal_tcl_words) or
                bare_configuration_evidence(issue, files, output_dir, dofile, literal_tcl_words) or
                grouped_signal_evidence(issue, files, output_dir, dofile, literal_tcl_words) or
                wrapper_maximum_evidence(issue, files, output_dir, dofile, literal_tcl_words))
    if specific:
        return specific
    if re.search(r"\[INFO\]\s+\[\s*SCAN-7600\]\s+There were 0 'D' flip-flops", issue.get("found", {}).get("excerpt", "")):
        # A declaration alone cannot prove that zero replacement was repaired.
        return None
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
    if (re.search(r"-(?:si|so)_port_format\b", fix) and locator and origin.is_file() and
            not source.is_absolute() and _is_inside(origin, (output_dir / "runs" / run_ref).resolve()) and
            source.suffix.lower() in {".rpt", ".report", ".txt"}):
        first, last = int(locator.group(1)), int(locator.group(2) or locator.group(1))
        old_rows = [row for row in typed_report_rows(origin, {"Chain", "Input", "Output", "Partition"})
                    if first <= row["line"] <= last]
        formats = set()
        for command in logical_lines:
            words = literal_tcl_words(command.strip())
            if words and words[0] == "set_scan_cfg" and len(words[1:]) % 2 == 0:
                options = {key: value.strip('"{}') for key, value in zip(words[1::2], words[2::2])}
                pair = (options.get("-si_port_format", ""), options.get("-so_port_format", ""))
                if all(value.count("%d") == 1 and re.fullmatch(r"[A-Za-z_][\w]*%d[\w]*", value) for value in pair):
                    formats.add(pair)
        designs = _full_insertion_designs(dofile)
        if len(formats) == len(designs) == 1 and old_rows:
            pair = next(iter(formats)); design = next(iter(designs))
            patterns = [re.escape(value).replace("%d", r"\d+") for value in pair]
            partitions = {row["Partition"] for row in old_rows}
            was_wrong = any(not re.fullmatch(pattern, row[column]) for row in old_rows
                            for column, pattern in zip(("Input", "Output"), patterns))
            if was_wrong:
                for path in files:
                    if "chain" not in path.name.lower() or "cell" in path.name.lower() or path.suffix.lower() not in {".rpt", ".report", ".txt"}:
                        continue
                    if not re.search(r"(?m)^\s*Design:\s*" + re.escape(design) + r"\s*$", read_text(path, 2000)):
                        continue
                    rows = [row for row in typed_report_rows(path, {"Chain", "Length", "Input", "Output", "Partition"})
                            if row["Partition"] in partitions and row["Length"].isdigit() and int(row["Length"]) > 0]
                    if {row["Partition"] for row in rows} != partitions or any(
                            not re.fullmatch(pattern, row[column]) for row in rows
                            for column, pattern in zip(("Input", "Output"), patterns)):
                        continue
                    first, last = min(row["line"] for row in rows), max(row["line"] for row in rows)
                    lines = path.read_text(errors="replace").splitlines()
                    return {"source": path.relative_to(output_dir).as_posix(), "locator": f"L{first}-L{last}",
                            "excerpt": "\n".join(lines[first - 1:last])}
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
        requested = rule_codes(" ".join(str(diagnosis.get(key, "")) for key in
                                       ("located_object", "summary", "root_cause")) +
                               " " + str(issue.get("phenomenon", ""))) or rule_codes(excerpt) or rule_codes(fix)
        effective = {}
        for command in logical_lines:
            match = re.match(r"\s*set_scan_drc_rule_handling\s+(\{[^}]+\}|DFTR[\w-]+)\s+(Error|Warning|Info|Ignore)\b", command)
            if not match or "-inst" in command:
                continue
            for rule in re.findall(r"DFTR[-\w]+", match.group(1)):
                if rule_codes(rule) & requested:
                    effective[rule] = match.group(2)
        if requested and requested <= rule_codes(" ".join(effective)):
            for path in files:
                if "rule_handling" not in path.name.lower() or path.suffix.lower() not in {".rpt", ".report", ".txt"}:
                    continue
                lines = read_text(path, 50000).splitlines()
                matches = []
                for number, line in enumerate(lines, 1):
                    row = re.fullmatch(r"\s*(DFTR[-\w]+)\s+(?:Error|Warning|Info|Ignore)\s+(Error|Warning|Info|Ignore)\s+all\s*", line)
                    if row and row.group(1) in effective and row.group(2) == effective[row.group(1)]:
                        matches.append((number, row.group(1)))
                if {rule for _, rule in matches} == set(effective):
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
                                                       ("constant_value", "ConstantValue"),
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
    if nonrepair_action_problem(issue) or report_operation_binding_problem(issue):
        return None
    found = issue["found"]["excerpt"]
    diagnosis = issue["diagnosis"]
    count_evidence = chain_count_positive_evidence(issue, files, output_dir)
    if count_evidence:
        return count_evidence
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


def _store_issue_verdict(verify: dict, current_run: str, evidence: dict | None,
                         checks: dict, families: list[str]) -> None:
    """One boolean writer; only applicable necessary checks participate."""
    statuses = [check.get('status') for check in checks.values()]
    # All callers, including structural supplementation and read-only revisions,
    # must supply the same complete four-part closure contract.
    required = {'diagnosis_and_action', 'operation_binding', 'selected_families', 'positive_evidence'}
    if verify.get('diagnostic_requirements', {}).get('gate', {}).get('required'):
        gate_status = verify.get('gate_diagnosis_check', {}).get('status')
        statuses.append(gate_status if gate_status in {'pass','fail','incomplete'} else 'incomplete')
    if (not required <= set(checks) or
            any(s not in {'pass','fail','incomplete','not_applicable'} for s in statuses) or
            any(checks[k].get('status') == 'not_applicable' for k in required - {'selected_families'})):
        statuses.append('incomplete')
    status = ('fail' if 'fail' in statuses else
              'incomplete' if 'incomplete' in statuses or not evidence else 'pass')
    verify.update(run_ref=current_run, source=f'runs/{current_run}/{current_run}.log',
                  resolved=status == 'pass', locator='', excerpt='')
    verify['closure_check'] = {'status': status, 'checks': checks, 'required_families': families}
    if evidence:
        if status == 'pass':
            verify.update(evidence)
        else:
            verify['closure_check']['condition_evidence'] = {'run_ref': current_run, **evidence}


def _adopt_partial_issue_evidence(issue: dict, current_run: str, evidence: dict) -> bool:
    """A structural positive fills only an otherwise unselected proof slot."""
    verify = issue['attempts'][-1]['verify']; closure = verify.get('closure_check')
    if not closure or closure.get('required_families'):
        return False
    checks = copy.deepcopy(closure['checks'])
    if any(c['status'] not in {'pass', 'not_applicable'} for n, c in checks.items() if n != 'positive_evidence'):
        return False
    checks['positive_evidence'] = {'status': 'pass', 'kind': 'partial_structure', 'evidence': evidence}
    _store_issue_verdict(verify, current_run, evidence, checks, [])
    return verify['resolved']


@scoped_gate_reads
def verify_issue_fixes(issues: list[dict[str, Any]], verification_plans: dict[str, dict[str, Any]],
                       output_dir: Path, current_run: str, tool_checks_passed: bool,
                       permitted_drc: set[str] | None = None, *, task_spec: str = "",
                       file_changes: list[dict] | None = None,
                       input_dir: Path | None = None, projection_journal: bool = False) -> None:
    if not tool_checks_passed:
        return
    files = run_evidence_files(output_dir / "runs" / current_run)
    dofile = read_text(output_dir / "runs" / current_run / "deliverables" / f"{current_run}.dofile", 100000)
    for issue in issues:
        attempts = issue.get("attempts", [])
        if not attempts or issue["found"]["run_ref"] == current_run:
            continue
        original_projection = copy.deepcopy(issue) if projection_journal else None
        verify = attempts[-1]["verify"]
        verify.clear()
        verify.update(run_ref=current_run, source=f'runs/{current_run}/{current_run}.log',
                      resolved=False, locator='', excerpt='')
        diagnosis_problems = diagnostic_residual_claim_problems(issue, permitted_drc or set())
        diagnosis_problems.extend(signal_declaration_claim_problems(issue, output_dir, literal_tcl_words))
        diagnosis_problems.extend(signal_fact_claim_problems(issue, output_dir, literal_tcl_words, input_dir))
        from drc_validation import (library_relation_claim_assessment, prior_exclusion_claim_assessment,
                                    aggregate_drc_scope_assessment, gate_diagnosis_requirement, gate_diagnosis_result)
        gate_requirement = gate_diagnosis_requirement(issue, output_dir, literal_tcl_words, input_dir)
        verify['diagnostic_requirements'] = {'gate': gate_requirement}
        try:
            library_assessment = library_relation_claim_assessment(issue, output_dir, literal_tcl_words, input_dir, requirement=gate_requirement)
        except (TimeoutError, OSError, ValueError, TypeError) as error:
            library_assessment = {'applicable': True, 'status': 'incomplete', 'claims': [], 'problems': [], 'failure': type(error).__name__}
        gate_result = gate_diagnosis_result(gate_requirement, library_assessment)
        verify['gate_diagnosis_check'] = gate_result
        if not isinstance(library_assessment, dict):
            library_assessment = {'applicable': True, 'status': 'incomplete', 'claims': [], 'problems': []}
        if gate_result['status'] in {'fail', 'incomplete'} and not library_assessment.get('problems'):
            library_assessment = dict(library_assessment, applicable=True, status='incomplete', problems=[{
                'status':'incomplete', 'reason':'material_premise_result_missing', 'family':'library_relation',
                'detail':'Native clock-gate diagnostic obligation lacks a bound complete verifier result.'}])
        premise_assessments = {
            'aggregate_drc_scope': aggregate_drc_scope_assessment(issue, output_dir, literal_tcl_words, input_dir),
            'prior_scan_exclusion': prior_exclusion_claim_assessment(issue, output_dir, literal_tcl_words),
            'connection_action': __import__('operation_audit').connection_action_assessment(issue,file_changes or [],output_dir,current_run,literal_tcl_words,input_dir),
            'prior_configuration': __import__('configuration_evidence').prior_configuration_claim_assessment(issue,file_changes or [],output_dir,current_run,literal_tcl_words,input_dir),
            'library_relation': library_assessment,
            'command_parameter': command_parameter_claim_assessment(issue, output_dir, literal_tcl_words),
        }
        for family, assessment in premise_assessments.items():
            # A known material premise needs an explicit result. An empty
            # failure list cannot silently turn an applicable unknown into pass.
            applicable = assessment.get('applicable')
            status = assessment.get('status')
            claims = assessment.get('claims', [])
            valid = (applicable is False and status == 'not_applicable' and not claims or
                     applicable is True and status in {'pass', 'fail', 'incomplete'} and
                     (status != 'pass' or bool(claims) or
                      isinstance(assessment.get('evidence'), dict) and bool(assessment['evidence'])))
            # A producer's partial pass must not hide an explicit unresolved or
            # refuted subclaim. Do not infer support from an empty failure list.
            substatuses = [c.get('status') for c in claims if isinstance(c, dict) and 'status' in c]
            if status == 'pass' and any(s != 'pass' for s in substatuses):valid = False
            found_problems = list(assessment.get('problems', []))
            if not valid or status in {'fail', 'incomplete'} and not found_problems:
                # Unknown is not a counterexample and cannot erase an
                # authenticated refutation of a different subclaim.
                found_problems.append({'status': 'incomplete', 'reason': 'material_premise_result_missing',
                                       'family': family, 'detail': 'Applicable material premise has no complete structured verdict.'})
                assessment['status'] = 'incomplete'
            assessment['problems'] = found_problems
            diagnosis_problems.extend(found_problems)
        verify['premise_assessments'] = premise_assessments
        if file_changes is not None:
            diagnosis_problems.extend(fix_action_reference_problems(issue, file_changes, output_dir, literal_tcl_words))
            diagnosis_problems.extend(control_repair_reference_problems(issue, file_changes, output_dir, current_run, literal_tcl_words))
        diagnosis_status = ('fail' if any(p.get('status') == 'fail' for p in diagnosis_problems)
                            else 'incomplete' if diagnosis_problems else 'pass')
        if not diagnosis_problems:
            verify.pop('diagnosis_check', None)
        # A stored true is not evidence that the current scope/operations were
        # fully checked. Recompute against this actual run, including bindings.
        if diagnosis_problems:
            verify['resolved'] = False
            verify['diagnosis_check'] = {'status': diagnosis_status, 'problems': diagnosis_problems,
                                        'scope': 'Explicit permissions, prior operation/type premises and referenced command edits; arbitrary diagnostic causality is not established by DRC elimination.'}
        binding_problem = (nonrepair_action_problem(issue) or
                           command_binding_problem(issue, output_dir, literal_tcl_words) or
                           report_operation_binding_problem(issue))
        zero_replacement = bool(re.search(r"\[INFO\]\s+\[\s*SCAN-7600\]\s+There were 0 'D' flip-flops", issue["found"]["excerpt"]))
        kind = command_proof_kind(issue, output_dir, literal_tcl_words)
        for key in ('evidence_selection', 'operation_check', 'configuration_check'):
            verify.pop(key, None)
        check = selected_evidence_check(issue, files, output_dir, dofile, task_spec, literal_tcl_words,
                                        file_changes=file_changes)
        if check['applicable']:
            verify['evidence_selection'] = check
            if 'coverage' in check['checks']:
                verify['operation_check'] = check['checks']['coverage']
            if 'configuration' in check['checks']:
                verify['configuration_check'] = check['checks']['configuration']
            evidence = check.get('evidence') if check['status'] == 'pass' else None
        elif kind == 'mapping':
            evidence = mapping_command_evidence(issue, files, output_dir, dofile, literal_tcl_words)
        elif kind == 'netlist_export':
            evidence = netlist_export_evidence(issue, files, output_dir, dofile, literal_tcl_words)
        else:
            evidence = (insertion_replacement_evidence(issue, files, output_dir, dofile, literal_tcl_words)
                        if zero_replacement else
                        positive_issue_evidence(issue, verification_plans.get(issue["issue_id"], {}), files, output_dir, permitted_drc))
        if not evidence and kind is None and not check['applicable']:
            evidence = configuration_evidence(issue, files, output_dir, dofile)
        checks = {
            'diagnosis_and_action': {'status': diagnosis_status,
                                     'problems': diagnosis_problems},
            'operation_binding': {'status': 'incomplete' if binding_problem else 'pass', 'problem': binding_problem},
            'selected_families': {'status': check['status'] if check['applicable'] else 'not_applicable'},
            'positive_evidence': {'status': 'pass' if evidence else 'incomplete'},
        }
        _store_issue_verdict(verify, current_run, evidence, checks, check['families'] if check['applicable'] else [])
        if evidence and diagnosis_problems:
            verify['diagnosis_check']['condition_evidence'] = {"run_ref": current_run, **evidence}
        if projection_journal:
            from audit_refresh import record_verification_projection
            record_verification_projection(output_dir, original_projection, issue, current_run)


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
            conflicts = attempts[-1]['verify'].get('diagnosis_check', {}).get('problems', []) if attempts else []
            if conflicts:
                problems.append(f"{issue['issue_id']} diagnosis/action has an unsupported claim: " +
                                "; ".join(str(item.get('original_clause', item.get('detail', item['reason'])))
                                          for item in conflicts))
            else:
                problems.append(f"{issue['issue_id']} lacks positive verification evidence from a later tool run")
        for attempt in attempts:
            if nonrepair_action_problem({'attempts': [attempt]}):
                problems.append(f"{issue['issue_id']} claims no repair action; native success cannot validate that fix")
            if not attempt["fix"].get("action") or not attempt["fix"].get("artifact_ref") or any(
                    ref not in change_ids for ref in attempt["fix"].get("artifact_ref", [])):
                problems.append(f"{issue['issue_id']} has an incomplete fix or a non-closing change reference")
    return problems


def refresh_existing_audit(client: OpenAI, output_dir: Path, issues: list[dict], plans: dict,
                           run_records: list[dict], current_run: str, frozen_inputs: dict,
                           input_signature: tuple | None, input_dir: Path, frozen_artifacts: tuple | None,
                           deadline: float, reviews: list[dict], permitted_drc: set[str], *,
                           file_changes: list[dict] | None = None,
                           correction_state: dict | None = None, final_views: dict | None = None,
                           tool_checks_passed: bool = False) -> bool:
    """Update plans using an unchanged finished run, without inventing R/F events."""
    run_dir = output_dir / 'runs' / current_run
    if (not frozen_inputs or input_signature is None or frozen_artifacts is None or
            changed_paths(frozen_inputs) or input_tree_signature(input_dir) != input_signature or
            _run_signature(run_dir) != frozen_artifacts):
        return False
    if correction_state is not None and final_views is not None:
        if tool_checks_passed is not True:
            return False
        if correction_state.get('requested') and final_views:
            return False  # No repeated semantic attempts to close a textual claim.
        context = (correction_context(issues, run_records, current_run, file_changes or [], output_dir,
                                      literal_tcl_words) if not correction_state.get('requested') and
                   deadline - time.monotonic() > 1 else None)
        if context is not None:
            return refresh_record_correction(client, output_dir, issues, plans, run_records, current_run,
                frozen_inputs, input_signature, input_dir, frozen_artifacts, deadline, reviews, permitted_drc,
                file_changes or [], correction_state, final_views, context)
    catalog = current_evidence_catalog(output_dir, current_run)
    messages = build_audit_refresh_request(issues, run_records, current_run, catalog)
    if not json.loads(messages[1]['content'])['issues'] or not catalog:
        return False
    folder = output_dir / 'audit_reviews' / f'A{len(reviews) + 1}'
    folder.mkdir(parents=True, exist_ok=False)
    record = {'audit_review_id': folder.name, 'actual_run_ref': current_run, 'tool_called': False,
              'status': 'not_applied', 'updated_issue_ids': []}
    reviews.append(record)
    (folder / 'evidence_catalog.json').write_text(json.dumps(catalog, ensure_ascii=False, indent=2))
    try:
        remaining = deadline - time.monotonic()
        if remaining <= 1:
            return False
        response = ask(client.with_options(timeout=model_request_timeout(remaining), max_retries=0),
                       messages[0]['content'], messages[1]['content'], max_tokens=1500,
                       request_log=folder / 'llm_response.json')
        updates = validate_audit_refresh(json_from_response(response), issues, run_records, current_run, catalog)
        for update in updates.values():
            actual = locate_evidence(run_evidence_files(run_dir), output_dir, update['expected_excerpt'], positive=True)
            if not actual or actual['source'] != update['source'] or actual['locator'] != update['locator']:
                raise ValueError('Selected audit evidence differs from the actual source/line locator')
        if (changed_paths(frozen_inputs) or input_tree_signature(input_dir) != input_signature or
                _run_signature(run_dir) != frozen_artifacts):
            raise ValueError('Inputs/proofs/artifacts changed during read-only audit refresh')
        work_issues, work_plans = copy.deepcopy(issues), copy.deepcopy(plans)
        work_plans.update(updates)
        verify_issue_fixes(work_issues, work_plans, output_dir, current_run, True, permitted_drc,
                           task_spec=read_text(input_dir / 'task_spec.md'), file_changes=file_changes, input_dir=input_dir)
        if (changed_paths(frozen_inputs) or input_tree_signature(input_dir) != input_signature or
                _run_signature(run_dir) != frozen_artifacts):
            raise ValueError('Inputs/proofs/artifacts changed while verifying read-only audit plans')
        issues[:] = work_issues
        plans.clear()
        plans.update(work_plans)
        record.update(status='plans_applied', updated_issue_ids=sorted(updates))
        return bool(updates)
    except Exception as exc:
        record.update(status='rejected', reason=f'{type(exc).__name__}: {exc}')
        return False
    finally:
        (folder / 'review.json').write_text(json.dumps(record, ensure_ascii=False, indent=2))


def refresh_record_correction(client, output_dir, issues, plans, runs, current, frozen_inputs,
                              input_signature, input_dir, frozen_artifacts, deadline, reviews, permitted,
                              changes, state, views, context):
    """One existing audit opportunity, separate immutable history/final view.

    Same-attempt final description projection is an engineering interpretation
    of Guide 5.5.2/8.1, not an official revision schema or repair operation.
    """
    def intact():
        return (not changed_paths(frozen_inputs) and input_tree_signature(input_dir) == input_signature and
                _run_signature(output_dir/'runs'/current) == frozen_artifacts)

    if state.get('requested') or deadline - time.monotonic() <= 1 or not intact():
        return False
    folder = output_dir/'audit_reviews'/f'A{len(reviews)+1}'
    folder.mkdir(parents=True, exist_ok=False)
    original = next(i for i in issues if i['issue_id'] == context['issue_id'])
    messages = correction_messages(context, original)
    record = {'audit_review_id': folder.name, 'actual_run_ref': current, 'tool_called': False,
              'status': 'not_applied', 'updated_issue_ids': []}
    reviews.append(record)
    state['requested'] = True  # Case-owned state survives all later actual rounds.
    history = {'kind': 'record_description_correction_not_new_execution',
               'engineering_assumption': 'Existing final diagnosis/fix fields with immutable original history; official acceptance unverified',
               'original_issue': copy.deepcopy(original), 'original_issue_hash': issue_digest(original),
               'original_runs': copy.deepcopy(runs), 'original_changes': copy.deepcopy(changes),
               'context': context, 'response': None, 'status': 'not_applied'}
    try:
        # x-mode makes every version/request immutable; never rewrite old logs.
        for name, value in [('original.json', history), ('request.json', messages),
                            ('correction_context.json', context)]:
            with (folder/name).open('x', encoding='utf-8') as stream:
                stream.write(json.dumps(value, ensure_ascii=False, indent=2))
                stream.flush()
                os.fsync(stream.fileno())
        remaining = deadline - time.monotonic()
        if remaining <= 1:
            raise ValueError('No audit time remains; original record retained')
        response = ask(client.with_options(timeout=model_request_timeout(remaining), max_retries=0),
            messages[0]['content'], messages[1]['content'], max_tokens=1500, request_log=folder/'llm_response.json')
        history['response'] = response
        if deadline - time.monotonic() <= 0 or not intact():
            raise ValueError('Audit deadline/input/artifact changed; no correction adopted')
        corrected = apply_claim_correction(json_from_response(response), context, issues, runs, current,
                                          changes, output_dir, literal_tcl_words)
        if corrected is None:
            history['status'] = 'declined'
            return False
        work = [corrected]
        verify_issue_fixes(work, copy.deepcopy(plans), output_dir, current, True, permitted,
                          task_spec=read_text(input_dir/'task_spec.md'), file_changes=changes, input_dir=input_dir)
        if not context['scope_complete']:
            # A true command correction cannot prove an aggregate DRC cause.
            # Retain all original observations, and conservatively keep false.
            verify = work[0]['attempts'][-1]['verify']
            problem = {'status': 'incomplete', 'reason': 'correction_original_scope_unproven',
                       'detail': 'Command correction does not establish every material claim in the original discovery',
                       'original_clause': original['phenomenon']}
            problems = verify.setdefault('diagnosis_check', {'status': 'incomplete', 'problems': []})['problems']
            problems.append(problem)
            checks = copy.deepcopy(verify['closure_check']['checks'])
            checks['diagnosis_and_action'] = {
                'status': 'fail' if any(p.get('status') == 'fail' for p in problems) else 'incomplete',
                'problems': problems}
            evidence = ({k: verify[k] for k in ['source', 'locator', 'excerpt']} if verify.get('resolved') else None)
            _store_issue_verdict(verify, current, evidence, checks, verify['closure_check']['required_families'])
        if deadline - time.monotonic() <= 0 or not intact():
            raise ValueError('No time or changed artifacts during revalidation; original retained')
        history.update(status='revalidated_final_view', corrected_issue=work[0],
                       final_official_issue=official_issue_projection(work[0]),
                       semantic_repair_closed=work[0]['attempts'][-1]['verify']['resolved'])
        # Persist the relation and full original verification BEFORE effective adoption.
        with (folder/'revision.json').open('x', encoding='utf-8') as stream:
            stream.write(json.dumps(history, ensure_ascii=False, indent=2))
            stream.flush()
            os.fsync(stream.fileno())
        entry = {'run_ref': current, 'base_issue_hash': context['base_issue_hash'], 'issue': work[0],
                 'facts': context['facts'], 'history_source': str((folder/'revision.json').relative_to(output_dir))}
        # A report or old baseline may have changed while the journal was written.
        if (not intact() or apply_claim_correction(json_from_response(response), context, issues, runs,
                current, changes, output_dir, literal_tcl_words) is None or deadline - time.monotonic() <= 0):
            raise ValueError('Final correction adoption guard failed')
        record.update(status='record_view_saved', updated_issue_ids=[context['issue_id']])
        with (folder/'review.json').open('x', encoding='utf-8') as stream:
            stream.write(json.dumps(record, ensure_ascii=False, indent=2))
            stream.flush()
            os.fsync(stream.fileno())
        with (folder/'outcome.json').open('x', encoding='utf-8') as stream:
            stream.write(json.dumps({'status': history['status'], 'record': record, 'error': None},
                                    ensure_ascii=False, indent=2))
            stream.flush()
            os.fsync(stream.fileno())
        entry['journal'] = {str(p.relative_to(output_dir)): hashlib.sha256(p.read_bytes()).hexdigest()
                            for p in folder.iterdir() if p.is_file()}
        views[context['issue_id']] = entry
        return True
    except Exception as exc:
        history.update(status='rejected', error=f'{type(exc).__name__}: {exc}')
        record.update(status='rejected', reason=history['error'])
        return False
    finally:
        # Separate outcome even for rejection/empty/timeout; no history overwrite.
        if not (folder/'outcome.json').exists():
            with (folder/'outcome.json').open('x', encoding='utf-8') as stream:
                stream.write(json.dumps({'status': history['status'], 'record': record,
                                         'error': history.get('error')}, ensure_ascii=False, indent=2))


def serialize_tool_runs(records: list[dict]) -> list[dict]:
    return [{'tool_call_id': r['run_id'], 'log_file': r['log_file'], 'exit_status': r['exit_status'],
             'returncode': r.get('returncode'), 'elapsed_seconds': r.get('elapsed_seconds'),
             'collection_seconds': r.get('collection_seconds', 0), 'artifacts': r.get('artifacts', []),
             **({'termination_reason': r['termination_reason']} if r.get('termination_reason') else {}),
             **({'command_timing': r['command_timing']} if r.get('command_timing') else {}),
             **({'structural_check_ref': r['structural_check_ref']} if r.get('structural_check_ref') else {}),
             **({'repair_integrity_passed': r['repair_integrity_passed']} if 'repair_integrity_passed' in r else {})}
            for r in records]


@scoped_gate_reads
def prepare_scope_delivery_proof(output_dir, input_dir, task, runs, issues, changes, *,
        original_issues, final_views, tool_checks_passed, canonical_delivery,
        execution_fingerprints, artifact_fingerprints, protected_fingerprints,
        source_signature, active_netlists, repair_attempts, repair_delivery,
        expected_checks, structural_check=None, deadline=None,
        eco_stage=None, eco_validation=None, eco_delivery=None):
    """Bind current delivery separately from a corrected diagnostic's scope.

    This finite path reuses the native task verifier and existing operation,
    canonical and EQY proof machinery. It never changes diagnostic checks or
    runs a tool. An unknown/missing binding produces NO delivery proof.
    """
    from canonical_delivery import _native_sources, _sha
    from configuration_evidence import _settings
    from operation_audit import operation_trace
    from repair_deliverables import _proof_files
    # Optional diagnostic lives outside captured run/final delivery materials.
    # It cannot satisfy or weaken any proof condition, and is written before
    # the final decision and completion marker.
    proof = None
    diagnostic = {'status':'not_issued','stage':'entry','task':task,
        'case_output':str(output_dir),'case_input':str(input_dir),
        'run_ref':runs[-1].get('run_id') if runs else None,
        'fingerprint_counts':{'execution':len(execution_fingerprints),'artifacts':len(artifact_fingerprints),
            'protected':len(protected_fingerprints)},'formal_evidence':False}
    if eco_stage is not None:
        diagnostic['native_binding']={'design':eco_stage.data.get('design'),
            'run_ref':eco_stage.context.rid,'fixed_export':eco_stage.data.get('fixed_export',{}).get('path'),
            'proof_ref':'eco/'+eco_stage.context.rid+'/lec/eqy.log'}
    stage_started = time.monotonic()
    def stage(name):
        nonlocal stage_started
        runtime_event('delivery_proof_stage_end', stage=diagnostic['stage'],
                      elapsed_seconds=time.monotonic()-stage_started)
        timings=diagnostic.setdefault('stage_seconds',{})
        timings[diagnostic['stage']]=timings.get(diagnostic['stage'],0)+time.monotonic()-stage_started
        diagnostic['stage'] = name
        stage_started = time.monotonic()
        runtime_event('delivery_proof_stage_start', stage=name,
                      remaining_seconds=None if deadline is None else max(0,deadline-time.monotonic()))
        if deadline is not None and time.monotonic() >= deadline:
            raise CaseDeadlineExceeded('Delivery proof work deadline reached; success not established')
    def decline(reason):
        import sys
        diagnostic.update(reason=reason,rejection_line=sys._getframe(1).f_lineno)
        return None
    try:
        from drc_validation import (prior_signal_scope, signal_scope_delivery_condition,
                                    library_relation_scope, library_relation_delivery_condition, eco_gate_diagnostic_scope, eco_gate_delivery_condition,
                                    prior_exclusion_scope, prior_exclusion_delivery_condition,
                                    aggregate_drc_scope, aggregate_drc_delivery_condition)
        from configuration_evidence import prior_configuration_scope, prior_configuration_delivery_condition
        from drc_validation import task_scope_diagnostic_basis, task_native_delivery_scope
        native_scope_bases = {}
        for i in issues:
            if i['attempts'][-1]['verify']['resolved'] or eco_stage is not None:continue
            stage('diagnostic_scope_binding')  # Same absolute work deadline; never spend failure reserve.
            native_scope_bases[i['issue_id']] = task_scope_diagnostic_basis(i,
                i['attempts'][-1]['verify'].get('diagnosis_check', {}).get('problems', []),
                output_dir, runs[-1]['run_id'], changes, literal_tcl_words, input_dir)
        from partial_issue_evidence import partial_diagnostic_delivery_basis
        partial_bases={}
        _,partial_spec,partial_nets,partial_libs,_=get_task_artifacts(input_dir)
        if structural_check and partial_insertion_requirements(partial_spec)['applicable']:
            for i in issues:
                if not i['attempts'][-1]['verify']['resolved']:
                    b=partial_diagnostic_delivery_basis(i,output_dir,runs[-1]['run_id'],partial_spec,
                        changes,literal_tcl_words,input_dir,structural_check)
                    if b:partial_bases[i['issue_id']]=b
        selected = [i for i in issues if (partial_bases.get(i['issue_id']) or native_scope_bases.get(i['issue_id']) or any(p.get('reason') in {
            'correction_original_scope_unproven', 'fix_action_reference_not_bound'}
            for p in i['attempts'][-1]['verify'].get('diagnosis_check', {}).get('problems', [])) or
            prior_configuration_scope(i['attempts'][-1]['verify'].get('diagnosis_check', {}).get('problems', [])) or
            aggregate_drc_scope(i['attempts'][-1]['verify'].get('diagnosis_check', {}).get('problems', [])) or
            prior_exclusion_scope(i['attempts'][-1]['verify'].get('diagnosis_check', {}).get('problems', [])) or
            prior_signal_scope(i['attempts'][-1]['verify'].get('diagnosis_check', {}).get('problems', [])) or
            command_parameter_scope(i['attempts'][-1]['verify'].get('diagnosis_check', {}).get('problems', [])) or
            library_relation_scope(i['attempts'][-1]['verify'].get('diagnosis_check', {}).get('problems', [])) or
            eco_gate_diagnostic_scope(i['attempts'][-1]['verify'].get('diagnosis_check', {}).get('problems', [])))]
        diagnostic['selected_issues']=[i['issue_id'] for i in selected]
        if not selected:
            diagnostic['status']='not_applicable'
            return decline('not_required')  # Normal path performs no extra scan or validation.
        stage('initial_guard')
        rid = runs[-1]['run_id']; run = output_dir/'runs'/rid
        if (tool_checks_passed is not True or deadline is None or time.monotonic() >= deadline or
                not execution_fingerprints or not artifact_fingerprints or source_signature is None or
                input_tree_signature(input_dir) != source_signature or
                changed_paths(execution_fingerprints) or changed_paths(artifact_fingerprints) or
                changed_paths(protected_fingerprints) or
                set(artifact_fingerprints) != {str(p) for p in actual_run_files(run)} or
                effective_issue_views(original_issues, final_views, rid, output_dir) != issues):
            return decline('required_binding_not_established')
        stage('task_roles')
        actual_task, spec, netlists, libraries, original = get_task_artifacts(input_dir)
        roles = role_input_files(input_dir, netlists, libraries, original)
        if actual_task != task or not {str(p) for p in roles} <= set(execution_fingerprints):
            return decline('required_binding_not_established')
        if (set(active_netlists) != set(netlists) or not active_netlists or
                expected_checks.get('task') != task):
            return decline('required_binding_not_established')
        if original and (output_dir/'runs'/runs[0]['run_id']/'deliverables'/
                         (runs[0]['run_id']+'.dofile')).read_bytes() != original.read_bytes():
            return decline('required_binding_not_established')
        # Bind the actual case mount, not only an identical task description.
        # Saved-container replays must explicitly rebind their isolated links
        # to the byte-verified local official input, never change the originals.
        stage('mount_binding')
        for dirname, target in [('lib', input_dir/'lib'),
                ('netlist', next(iter(active_netlists.values())).parent)]:
            # Task1's normal executor loads the read-only case mount directly;
            # Task2 creates per-round links. Absence is not a synthetic link.
            mount = (input_dir/dirname if task == 'task1' and not (run/'input').exists()
                     else run/'input'/dirname)
            if not mount.is_dir() or mount.resolve() != target.resolve():
                return decline('required_binding_not_established')
        dofile = (run/'deliverables'/(rid+'.dofile')).read_text()
        stage('native_task')
        passed, problems = check_output(run, spec, task, dofile, runs[-1]['exit_status'],
            expected_checks.get('segments', []), expected_checks.get('floating', {}),
            expected_checks.get('clock_candidates', []), expected_checks.get('mode_hints', []),
            **({'eco_stage': eco_stage} if eco_stage is not None else {}))
        if not passed or problems or runs[-1].get('returncode') != 0:
            return decline('required_binding_not_established')
        if partial_insertion_requirements(spec)['applicable']:
            path = output_dir/'structural_checks'/(rid+'.json')
            if (not structural_check or structural_check.get('status') != 'pass' or
                    json.loads(path.read_text()) != json.loads(json.dumps(structural_check)) or
                    runs[-1].get('structural_check_ref') != path.relative_to(output_dir).as_posix()):
                return decline('required_binding_not_established')

        stage('canonical_publication')
        export, config, design = _native_sources(output_dir, rid, literal_tcl_words, eco_trace=eco_stage)
        if (not canonical_delivery or canonical_delivery.get('status') != 'published' or
                canonical_delivery.get('run_ref') != rid or canonical_delivery.get('design') != design):
            return decline('required_binding_not_established')
        bindings = canonical_delivery.get('bindings', [])
        if len(bindings) != 2:
            return decline('required_binding_not_established')
        for native, target in [(export, 'final_results/deliverables/post_scan.v'),
                               (config, 'final_results/reports/scan_configuration.rpt')]:
            rows = [b for b in bindings if b['target'] == target]
            if len(rows) != 1:
                return decline('required_binding_not_established')
            b = rows[0]
            if (b['source'] != native['source'].relative_to(output_dir).as_posix() or
                    b['script'] != f'runs/{rid}/deliverables/{rid}.dofile' or
                    b['command'] != native['command'] or b['script_line'] != native['script_line'] or
                    b['command_log_line'] != native['command_log_line'] or
                    b['sha256'] != _sha(native['source']) or b['sha256'] != _sha(output_dir/target)):
                return decline('required_binding_not_established')
        if (_sha(output_dir/'final_results/deliverables/final.dofile') !=
                _sha(run/'deliverables'/(rid+'.dofile')) or
                _sha(output_dir/'final_results/final.log') != _sha(run/(rid+'.log'))):
            return decline('required_binding_not_established')
        # Check effective configuration, without pretending the original DRC
        # discovery was a configuration-fault discovery. Same native writer.
        stage('native_configuration')
        files = run_evidence_files(run)
        partial_task=partial_insertion_requirements(spec)['applicable']
        trace = operation_trace(files, output_dir, dofile, literal_tcl_words,
            allow_verbose=True, require_insertion=not partial_task, eco_trace=eco_stage)
        settings = _settings(dofile, literal_tcl_words, partial=partial_task)
        if not settings or settings[0] != design or not trace or trace.get('design') != design:
            return decline('required_binding_not_established')
        # rpt_scan_cfg has partition blocks rather than a Design header. Reuse
        # its existing configuration-check writer/phase rule, not the helper
        # for signal/chain reports that require a Design header.
        writers = [w for w in trace['reports'] if w['kind'] == 'rpt_scan_cfg' and
            w['design'] == design and w['log_line'] > (trace['operation']['log_line'] if partial_task else trace['operation']['replacement']['log_line'])]
        if (not writers or max(writers, key=lambda w: w['log_line'])['path'] != config['source'] or
                max(writers, key=lambda w: w['log_line'])['log_line'] != config['command_log_line']):
            return decline('required_binding_not_established')
        blocks = {}; partition = None; active = False
        for line in config['source'].read_text().splitlines():
            header = re.fullmatch(r'Scan partition:\s*(\S+)\s*', line)
            if header:
                partition = header[1]; active = False
                if partition in blocks:
                    return decline('required_binding_not_established')
                blocks[partition] = {}
            elif 'ScanConfigurationParameter' in line and 'Value' in line:
                active = True
            elif active and partition and (pair := re.fullmatch(r'\s*([a-z_]+)\s+(\S+)\s*', line)):
                if pair[1] in blocks[partition]:
                    return decline('required_binding_not_established')
                blocks[partition][pair[1]] = pair[2].lower()
        if set(blocks) != set(settings[1]):
            return decline('required_binding_not_established')
        for partition, local in settings[1].items():
            expected = {**settings[1].get('Default_Partition', {}), **local}
            if any(blocks[partition].get(k) != str(v).lower() for k, v in expected.items()):
                return decline('required_binding_not_established')

        stage('condition_binding')
        proof_paths = list(execution_fingerprints) + list(protected_fingerprints)
        conditions = []
        native_task_scope = None
        native_task_scope_paths = []
        native_task_objects = set()
        scope_failure = None
        if any(native_scope_bases.values()):
            stage('independent_native_task_scope')
            try:
                native_task_scope, native_task_scope_paths, native_task_objects = task_native_delivery_scope(
                    output_dir, input_dir, rid, spec, netlists, libraries, files, dofile,
                    literal_tcl_words, deadline=deadline)
            except (OSError, ValueError, KeyError, TypeError) as error:
                scope_failure = str(error)
                diagnostic['task_scope_failure'] = {'kind':type(error).__name__,'detail':scope_failure}
        diagnostic['issue_conditions'] = []
        for issue in selected:
            iid = issue['issue_id']; entry = final_views.get(iid)
            stage('condition_binding_'+iid)
            conflicts = issue['attempts'][-1]['verify'].get('diagnosis_check', {}).get('problems', [])
            basis = native_scope_bases.get(iid)
            if iid in partial_bases:
                final_paths,replacement_paths=partial_flow_artifact_paths(run,spec)
                actual=partial_insertion_validation(netlists,final_paths,libraries,spec,
                    report_paths=list((run/'reports').rglob('*.rpt')),replacement_paths=replacement_paths)
                if (actual.get('status')!='pass' or
                        json.loads(json.dumps(actual))!=json.loads(json.dumps(structural_check))):
                    return decline('partial_task_proof_not_reproduced')
                conditions.append({'issue_id':iid,'kind':'independent_partial_task_delivery',
                    'run_ref':rid,'located_object':issue['diagnosis']['located_object'],
                    'diagnostic_check_sha256':hashlib.sha256(json.dumps(conflicts,sort_keys=True,
                        ensure_ascii=False,separators=(',',':')).encode()).hexdigest(),
                    'diagnostic_basis':partial_bases[iid],'actual_task':actual})
                proof_paths += [str(output_dir/'structural_checks'/(rid+'.json'))]
                proof_paths += [str(output_dir/'structural_checks'/(partial_bases[iid]['prior_run']+'.json'))]
                diagnostic['issue_conditions'].append({'issue_id':iid,'status':'issued',
                    'kind':'independent_partial_task_delivery','diagnosis_unchanged':True})
                continue
            if basis:
                objects=set(basis['objects'])
                ports={row['port'] for row in (native_task_scope or {}).get('roles',[])}
                if not native_task_scope or not objects <= (native_task_objects | ports):
                    diagnostic['issue_conditions'].append({'issue_id':iid,'status':'not_issued',
                        'detail':scope_failure or 'Diagnostic primary objects absent from complete native task scope'})
                    scope_failure=scope_failure or 'Diagnostic object does not belong to task scope'
                    continue
                conditions.append({'issue_id':iid,'kind':'independent_native_task_delivery',
                    'run_ref':rid,'located_object':issue['diagnosis']['located_object'],
                    'diagnostic_check_sha256':hashlib.sha256(json.dumps(conflicts,sort_keys=True,
                        ensure_ascii=False,separators=(',',':')).encode()).hexdigest(),
                    'diagnostic_basis':basis,'actual_task':native_task_scope})
                proof_paths += [str(p) for p in native_task_scope_paths]
                proof_paths += [str(output_dir/ref['source']) for ref in basis['native_evidence']]
                diagnostic['issue_conditions'].append({'issue_id':iid,'status':'issued',
                    'kind':basis['kind'],'diagnosis_unchanged':True})
                continue
            if prior_configuration_scope(conflicts):
                bound = prior_configuration_delivery_condition(issue, conflicts, output_dir,
                    rid, spec, files, dofile, literal_tcl_words, changes=changes, input_dir=input_dir)
                if bound is None:return decline('required_binding_not_established')
                condition, paths = bound
                conditions.append({'issue_id': iid, **condition,
                    'diagnostic_check_sha256': hashlib.sha256(json.dumps(conflicts,
                        sort_keys=True, ensure_ascii=False, separators=(',', ':')).encode()).hexdigest()})
                proof_paths += [str(p) for p in paths]
                continue
            if aggregate_drc_scope(conflicts):
                bound = aggregate_drc_delivery_condition(issue, conflicts, output_dir, rid, spec,
                    files, dofile, literal_tcl_words, input_dir,
                    permitted_rules=permitted_residual_drc_codes(task, spec))
                if bound is None:return decline('required_binding_not_established')
                condition, paths = bound
                conditions.append({'issue_id': iid, **condition,
                    'diagnostic_check_sha256': hashlib.sha256(json.dumps(conflicts,
                        sort_keys=True, ensure_ascii=False, separators=(',', ':')).encode()).hexdigest()})
                proof_paths += [str(p) for p in paths]
                continue
            if prior_exclusion_scope(conflicts):
                bound = prior_exclusion_delivery_condition(issue,conflicts,output_dir,rid,spec,files,dofile,literal_tcl_words)
                if bound is None:return decline('required_binding_not_established')
                condition,paths=bound
                conditions.append({'issue_id':iid,**condition,'diagnostic_check_sha256':hashlib.sha256(json.dumps(conflicts,sort_keys=True,ensure_ascii=False,separators=(',',':')).encode()).hexdigest()})
                proof_paths += [str(p) for p in paths]
                continue
            if command_parameter_scope(conflicts):
                bound = command_parameter_delivery_condition(issue, conflicts, output_dir, rid,
                    spec, files, dofile, literal_tcl_words)
                if bound is None:return decline('required_binding_not_established')
                condition, paths = bound
                conditions.append({'issue_id': iid, **condition,
                    'diagnostic_check_sha256': hashlib.sha256(json.dumps(conflicts,
                        sort_keys=True, ensure_ascii=False, separators=(',', ':')).encode()).hexdigest()})
                proof_paths += [str(p) for p in paths]
                continue
            if eco_stage is not None and eco_gate_diagnostic_scope(conflicts):
                bound=eco_gate_delivery_condition(issue,conflicts,changes,output_dir,rid,literal_tcl_words,input_dir,eco_stage,eco_validation)
                if bound is None:return decline('required_binding_not_established')
                condition,paths=bound
                conditions.append({'issue_id':iid,**condition,'diagnostic_check_sha256':hashlib.sha256(json.dumps(conflicts,sort_keys=True,ensure_ascii=False,separators=(',',':')).encode()).hexdigest()})
                proof_paths += [str(p) for p in paths]
                continue
            if library_relation_scope(conflicts):
                bound = library_relation_delivery_condition(issue, conflicts, output_dir, rid, spec,
                    files, dofile, literal_tcl_words, input_dir)
                if bound is None:return decline('required_binding_not_established')
                condition, paths = bound
                conditions.append({'issue_id': iid, **condition,
                    'diagnostic_check_sha256': hashlib.sha256(json.dumps(conflicts,
                        sort_keys=True, ensure_ascii=False, separators=(',', ':')).encode()).hexdigest()})
                proof_paths += [str(p) for p in paths]
                continue
            if prior_signal_scope(conflicts):
                bound = signal_scope_delivery_condition(issue, conflicts, output_dir, rid, spec,
                    files, dofile, literal_tcl_words, eco_stage, eco_validation,
                    source_netlists=netlists, source_libraries=libraries)
                if bound is None:return decline('required_binding_not_established')
                condition, paths = bound
                conditions.append({'issue_id': iid, **condition,
                    'diagnostic_check_sha256': hashlib.sha256(json.dumps(conflicts,
                        sort_keys=True, ensure_ascii=False, separators=(',', ':')).encode()).hexdigest()})
                proof_paths += [str(p) for p in paths]
                continue
            action_gap = bool(conflicts) and all(p.get('reason') == 'fix_action_reference_not_bound' for p in conflicts)
            action_revision = (len(conflicts) == 1 and conflicts[0].get('reason') == 'correction_original_scope_unproven'
                and entry and json.loads((output_dir/entry['history_source']).read_text())['context'].get('kind') == 'native_literal_action_reference')
            if action_gap or action_revision:
                if eco_stage is None or not eco_validation or eco_validation.get('status') != 'pass':
                    return decline('required_binding_not_established')  # This bounded addition supports proven native ECO delivery only.
                if (action_gap and not (len(conflicts)==1 and conflicts[0].get('assessment_scope',{}).get('kind')=='native_connection_action') and
                        fix_action_reference_problems(issue, changes, output_dir, literal_tcl_words) != conflicts):
                    return decline('required_binding_not_established')  # Reproduce the real delta failure; never trust a model-supplied reason.
                from operation_audit import connection_action_delivery_condition
                if len(conflicts)==1 and conflicts[0].get('assessment_scope',{}).get('kind')=='native_connection_action':
                    bound=connection_action_delivery_condition(issue,conflicts,changes,output_dir,rid,literal_tcl_words,input_dir,eco_stage,eco_validation)
                    if bound is None:return decline('required_binding_not_established')
                    condition,paths=bound
                    conditions.append({'issue_id':iid,**condition,'diagnostic_check_sha256':hashlib.sha256(json.dumps(conflicts,sort_keys=True,ensure_ascii=False,separators=(',',':')).encode()).hexdigest()})
                    proof_paths += [str(p) for p in paths]
                    continue
                location = issue['diagnosis']['located_object']
                library, before = eco_evidence.source_design(netlists, libraries, spec, original.read_text() if original else '')
                fixed = eco_evidence.read_design([Path(eco_stage.data['fixed_export']['path'])], library, design)
                routes = eco_validation['structure']['changed_routes']
                objects = {r['consumer']: {'kind': 'preserved_consumer', 'route': r} for r in routes}
                # Only exact paths actually covered by the adopted structural
                # proof, its mode controls, and the native scan-enable report.
                ports = fixed['modules'][design]['ports']
                signals = Path(eco_stage.data['reports']['rpt_scan_signal']['path'])
                for line in signals.read_text().splitlines():
                    words = line.split()
                    if (len(words) >= 3 and words[0] in ports and
                            words[2].split('(')[0] in {'scan_enable', 'constant'}):
                        objects[words[0]] = {'kind': 'native_task_control_port', 'report_row': line,
                                            'source': str(signals), 'port': ports[words[0]]}
                objects[design] = {'kind': 'complete_task_design', 'design': design}
                if location not in objects:
                    from command_delivery import retained_command_condition
                    command_fact = retained_command_condition(issue, conflicts, output_dir,
                        runs, eco_stage, eco_validation, literal_tcl_words, changes=changes)
                    if command_fact is None:
                        return decline('required_binding_not_established')  # No unknown object, command or cross-round fallback.
                    condition, bound_paths = command_fact
                    conditions.append({'issue_id': iid, **condition,
                        'diagnostic_check_sha256': hashlib.sha256(json.dumps(conflicts,
                            sort_keys=True, ensure_ascii=False, separators=(',', ':')).encode()).hexdigest()})
                    proof_paths += [str(p) for p in bound_paths]
                    continue
                conditions.append({'issue_id': iid, 'kind': 'native_ECO_delivery_object',
                    'design': design, 'run_ref': rid, 'located_object': location,
                    'object': objects[location], 'diagnostic_check_sha256':
                        hashlib.sha256(json.dumps(conflicts, sort_keys=True, ensure_ascii=False,
                            separators=(',', ':')).encode()).hexdigest()})
                if entry:
                    proof_paths += [str(output_dir/p) for p in entry['journal']]
                    proof_paths += [str(output_dir/f['source']) for f in entry['facts'].values()]
                continue
            if not entry or entry['issue'] != issue:
                return decline('required_binding_not_established')
            history = json.loads((output_dir/entry['history_source']).read_text())
            if history['original_runs'] != runs or history['original_changes'] != changes:
                return decline('required_binding_not_established')
            check = selected_evidence_check(issue, files, output_dir, dofile, spec,
                                            literal_tcl_words, file_changes=changes)
            if (not set(check['families']) <= {'signal', 'configuration'} or
                    check.get('unbound_signal_operations') or check['checks'].get('signal', {}).get('status') != 'pass'):
                return decline('required_binding_not_established')
            cfg = check['checks'].get('configuration')
            if cfg and cfg.get('status') != 'pass' and cfg.get('missing') != ['discovery does not describe the claimed configuration']:
                return decline('required_binding_not_established')
            signal = check['checks']['signal']['evidence']
            # Authenticity plus the existing dedicated signal semantic check.
            from completion_policy import _reference
            _reference(output_dir, {'run_ref': rid, **signal}, {r['run_id']: r for r in runs})
            proof_paths += [str(output_dir/p) for p in entry['journal']]
            proof_paths += [str(output_dir/f['source']) for f in entry['facts'].values()]
            conditions.append({'issue_id': iid, 'design': design, 'run_ref': rid,
                               'signal_condition': signal, 'configuration_source': config['source'].relative_to(output_dir).as_posix()})

        # Reuse actual final repair publication/proof files, never execute EQY.
        stage('adopted_proof_materials')
        modified = any(Path(a).resolve() != Path(b).resolve() for a, b in active_netlists.items())
        if eco_stage is not None or eco_validation is not None or eco_delivery is not None:
            # A native in-memory ECO leaves the read-only input paths unchanged.
            # It has its own current-stage export and original-to-fixed proof;
            # do not impersonate a private on-disk repair or waive that proof.
            if modified or repair_delivery is not None:
                return decline('required_binding_not_established')  # Mixed repair mechanisms remain outside this finite binding.
            adopted = [c for c in changes if c.get('type') == 'dofile' or
                c.get('path') == Path(eco_stage.data['fixed_export']['path']).relative_to(output_dir).as_posix()]
            for change in changes:
                proof_paths += [str(output_dir/change['path']), str(output_dir/change['diff_path'])]
                if change.get('origin') == 'native_in_memory_ECO':
                    ref = Path(change['lec_ref'])
                    if (ref.parts[:1] != ('eco',) or len(ref.parts) != 4 or ref.parts[2:] != ('lec', 'eqy.log')):
                        return decline('required_binding_not_established')
                    historic = json.loads((output_dir/'eco'/ref.parts[1]/'validation.json').read_text())
                    if change['path'] != Path(historic['native']['fixed_export']['path']).relative_to(output_dir).as_posix():
                        return decline('required_binding_not_established')
                    proof = eco_evidence.eco_equivalence.verify(historic['equivalence']['plan'],
                        output_dir/ref.parent, historic['equivalence_binding'])
                    proof_paths += proof['proof_files']
            stage('ECO_delivery_proof')
            proof_paths += [str(p) for p in eco_evidence.delivery_proof_paths(
                eco_stage, eco_validation, eco_delivery, output_dir, input_dir, rid,
                netlists, libraries, adopted)]
        elif modified or any(c.get('type') != 'dofile' for c in changes):
            if (not modified or not repair_delivery or repair_delivery.get('final_run') != rid or
                    repair_delivery.get('exported_single_file_proved') is not True):
                return decline('required_binding_not_established')
            manifest_file = output_dir/'final_results/deliverables/pre_scan_final.manifest.json'
            if json.loads(manifest_file.read_text()) != repair_delivery:
                return decline('required_binding_not_established')
            sources = repair_delivery['sources']
            if ({r['original_path']: r['candidate_path'] for r in sources} !=
                    {str(k): str(v) for k, v in active_netlists.items()}):
                return decline('required_binding_not_established')
            if (_sha(output_dir/'final_results/deliverables/pre_scan_final.v') != repair_delivery['pre_scan_final_sha256'] or
                    _sha(output_dir/'final_results/reports/lec_report.rpt') != repair_delivery['lec_report_sha256']):
                return decline('required_binding_not_established')
            adopted = [a for a in repair_attempts if a.get('admitted') is True and a.get('adopted') is True]
            if not adopted:
                return decline('required_binding_not_established')
            matched = 0
            for attempt in adopted:
                root = (output_dir/attempt['lec_ref']).parent
                for summary_path in root.rglob('summary.json'):
                    summary = json.loads(summary_path.read_text())
                    if set(summary.get('candidate_netlists', [])) != {str(p) for p in active_netlists.values()}:
                        continue
                    if set(summary.get('original_netlists', [])) != {str(p) for p in active_netlists}:
                        return decline('required_binding_not_established')
                    proof_paths += [str(p) for p in _proof_files(summary_path.parent)]
                    matched += 1
            if not matched:
                return decline('required_binding_not_established')
            for source in sources:
                if (_sha(Path(source['original_path'])) != source['original_sha256'] or
                        _sha(Path(source['candidate_path'])) != source['sha256']):
                    return decline('required_binding_not_established')
            proof_refs = repair_delivery['proof_refs'] + repair_delivery.get('export_proof_refs', [])
            if not proof_refs:
                return decline('required_binding_not_established')
            for ref in proof_refs:
                path = output_dir/ref['path']
                if _sha(path) != ref['sha256']:
                    return decline('required_binding_not_established')
                proof_paths.append(str(path))
                if path.name == 'summary.json':
                    proof_paths += [str(p) for p in _proof_files(path.parent)]
        elif repair_delivery is not None:
            return decline('required_binding_not_established')
        stage('final_fingerprints')
        if (time.monotonic() >= deadline or changed_paths(execution_fingerprints) or
                changed_paths(artifact_fingerprints) or changed_paths(protected_fingerprints)):
            return decline('required_binding_not_established')
        stage('capture')
        if scope_failure:
            return decline('independent_native_task_scope_not_established')
        proof = _capture_delivery_proof(output_dir, input_dir, task, runs, changes,
            canonical_delivery, issues, [Path(p) for p in proof_paths], conditions)
        diagnostic.update(status='issued',condition_count=len(conditions))
        return proof
    except (OSError, ValueError, TypeError, KeyError, IndexError, CanonicalDeliveryError, RepairRejected) as exc:
        import traceback
        diagnostic['error']={'type':type(exc).__name__,'message':str(exc)[:600],
            'locations':[{'file':Path(f.filename).name,'line':f.lineno} for f in traceback.extract_tb(exc.__traceback__)]}
        return decline('bound_evidence_rejected')
    finally:
        # Optional proof diagnostics must not consume the failure reserve while
        # the mandatory-work exception is propagating. The last durable stage
        # start remains available; the real failed decision is written by main.
        if not isinstance(sys.exc_info()[1], CaseDeadlineExceeded):
            runtime_event('delivery_proof_stage_end', stage=diagnostic['stage'], elapsed_seconds=time.monotonic()-stage_started)
            timings=diagnostic.setdefault('stage_seconds',{})
            timings[diagnostic['stage']]=timings.get(diagnostic['stage'],0)+time.monotonic()-stage_started
            from runtime_events import atomic
            try:
                (output_dir/'delivery_verification').mkdir(parents=True,exist_ok=True)
                atomic(output_dir/'delivery_verification'/'scope.json',diagnostic)
            except OSError:
                runtime_event('delivery_proof_diagnostic_unavailable',stage=diagnostic['stage'])


def write_final_decision(output_dir, decision, *, final_problems, audit_problems):
    """Shared production state sink; caller supplies a validated final decision.

    Does not set completion to success or replace any task/semantic check.
    Saved-scene replays must use the same validators and completion_outcome.
    """
    outcome = decision['completion']
    (output_dir/'decision_log.json').write_text(
        json.dumps(decision,ensure_ascii=False,indent=2),encoding='utf-8')
    print(json.dumps({'status':outcome['status'],'task':decision['task'],
        'tool_calls':len(decision['tool_runs']),'tool_checks_passed':decision['tool_checks_passed'],
        'issue_audit_complete':decision['issue_audit_complete'],
        'problems':final_problems+audit_problems+outcome['blocking_reasons']},ensure_ascii=False))
    return outcome['exit_code']


@completed_main
def main(started_at: float | None = None, entry_clock: dict | None = None) -> int:
    start = time.monotonic() if started_at is None else started_at
    parser = argparse.ArgumentParser()
    parser.add_argument("-input", "--input", required=True)
    parser.add_argument("-output", "--output", required=True)
    args = parser.parse_args()
    input_dir, output_dir = Path(args.input).resolve(), Path(args.output).resolve()
    upload_root = input_dir
    # Accept both the platform's case directory (`case/input/task_spec.md`) and a
    # direct mount of the case input directory (`/input/task_spec.md`).
    if not (input_dir / "task_spec.md").is_file() and (input_dir / "input" / "task_spec.md").is_file():
        input_dir = input_dir / "input"
    output_dir.mkdir(parents=True, exist_ok=True)
    runs_root = output_dir / "runs"
    runs_root.mkdir(exist_ok=True)
    # Stable parent directories let metadata validation distinguish unchanged
    # evidence from modifications while final products remain independent copies.
    for directory in ("final_results", "final_results/reports", "final_results/deliverables", "audit_reviews"):
        (output_dir / directory).mkdir(exist_ok=True)
    journal = Journal(output_dir, start, entry_clock)
    final_exit_code = None
    eco_observer, eco_feedback_last = EcoObserver(), None
    validation_cache = RunValidationCache()
    performance_stages: dict[str, float] = {}
    run_records: list[dict[str, Any]] = []
    changes: list[dict[str, Any]] = []
    issue_records: list[dict[str, Any]] = []
    verification_plans: dict[str, dict[str, Any]] = {}
    repair_attempts: list[dict[str, Any]] = []
    generation_rejections: list[dict[str, Any]] = []
    audit_reviews: list[dict[str, Any]] = []
    correction_state: dict[str, Any] = {}
    final_issue_views: dict[str, Any] = {}
    issue_admission_reviews: list[dict[str, Any]] = []
    audit_stop_events: list[dict[str, Any]] = []
    audit_progress = AuditProgress()
    audit_only_last_run = False
    audit_previous_artifacts = None
    audit_gap_feedback = None
    case_deadline: CaseDeadline | None = None
    final_protected_snapshot: dict = {}
    final_execution_snapshot: dict = {}
    final_active_netlists: dict[Path, Path] = {}
    final_source_signature: tuple | None = None
    final_artifact_fingerprints: dict = {}
    final_structural_check: dict | None = None
    requirement_mapping: list[dict[str, Any]] = []
    final_dofile = ""
    final_eco_stage = None
    final_eco_validation = None
    eco_delivery = None
    task = "task1"
    error_message = None
    final_run_dir: Path | None = None
    integrity_problems: list[str] = []
    try:
        if not input_dir.is_dir():
            raise FileNotFoundError(f"Input directory does not exist: {input_dir}")
        if not os.environ.get("SCANINSERTION_LICENSE_SERVER"):
            raise RuntimeError("SCANINSERTION_LICENSE_SERVER is required")
        limits_path = input_dir / 'limitations.md'
        limits = read_original_text(limits_path) if limits_path.is_file() else ''
        timeout_total = parse_limit_seconds(limits)
        supplied_remaining = os.environ.get('AGENT_CONTROLLER_REMAINING_SECONDS', '').strip()
        controller_remaining = float(supplied_remaining) if supplied_remaining else None
        if controller_remaining is not None:
            import math
            if not math.isfinite(controller_remaining) or controller_remaining <= 0:
                raise ValueError('Invalid controller remaining duration')
            timeout_total = min(timeout_total, controller_remaining)
        journal.deadline = start + timeout_total
        runtime_event('case_budget', limit_seconds=timeout_total, deadline_monotonic=journal.deadline,
                      controller_remaining_seconds=controller_remaining,
                      controller_clock_domain='controller monotonic duration cap; transport delay not inferred from UTC')
        # The official absolute deadline is unchanged. Mandatory work must end
        # before it, leaving the existing reserve for an honest failure record,
        # Journal closure and the final completion marker (not optional proof).
        completion_reserve = min(8.0, timeout_total / 4)
        work_deadline = start + timeout_total - completion_reserve
        runtime_event('completion_budget', deadline_monotonic=work_deadline, allocated_seconds=completion_reserve,
                      scope='Mandatory work stops before unchanged official deadline to write failure state/marker')
        case_deadline = CaseDeadline(work_deadline, clock=time.monotonic)
        case_deadline.arm()
        task, task_spec, netlists, libs, original_path = timed_call(performance_stages, "input_discovery", get_task_artifacts, input_dir, upload_root=upload_root)
        partial_requirements = partial_insertion_requirements(task_spec)
        icg_protection_facts = timed_call(performance_stages, 'source_icg_protection',
            icg_protection_source, task, task_spec, netlists, libs)
        if icg_protection_facts['applicable']:
            (output_dir / 'source_analysis').mkdir(exist_ok=True)
            (output_dir / 'source_analysis/icg_protection.json').write_text(json.dumps(icg_protection_facts, ensure_ascii=False, indent=2))
        active_netlists = {path: path for path in netlists}
        active_netlist_root = input_dir / "netlist"
        # Small-case artifacts finalize in seconds; do not discard 20% of a
        # 150-second budget. Large netlists retain the longer copy/audit reserve.
        finalize_reserve = 30 if sum(path.stat().st_size for path in netlists) > 64 * 1024 * 1024 else 8
        max_calls = parse_tool_limit(limits)
        client: OpenAI | None = None
        original = read_original_text(original_path) if original_path else None
        previous = original or ""
        last_log = ""
        generation_error = ""
        validation_problems: list[str] = []
        clock_candidates = (timed_call(performance_stages, "source_clock", clock_latch_hints, netlists, libs) if re.search(r"ICG|门控|缓冲|latch|闩锁", task_spec, re.I) else [])
        mode_hints = timed_call(performance_stages, "source_modes", mode_control_hints, netlists) if requested_constant_modes(task_spec) else []
        reset_hints: dict[str, Any] = {}
        instances: dict[str, Any] = {}
        structural_groups = timed_call(performance_stages, "source_structure", shift_register_groups, netlists, libraries=libs, reset_hints=reset_hints,
            instance_map=instances if re.search(r"闩锁|latch|关联关系", task_spec, re.I) else None)
        control_hints = {root: values for root, values in reset_hints.items() if values}
        library_cells: set[str] = LibraryCellCatalog()
        hierarchy_hints: dict = {}
        static_context = timed_call(performance_stages, "static_context", context_for_run, input_dir, task_spec, limits, netlists, libs, "",
                                         clock_candidates=clock_candidates, mode_hints=mode_hints,
                                         structural_groups=structural_groups, include_command_help=False,
                                         library_cells=library_cells, hierarchy_hints_out=hierarchy_hints)
        if hierarchy_hints.get('debug_exclusion_facts', {}).get('applicable'):
            (output_dir / 'source_analysis').mkdir(exist_ok=True)
            (output_dir / 'source_analysis/debug_exclusion_source.json').write_text(json.dumps(
                hierarchy_hints['debug_exclusion_facts'], ensure_ascii=False, indent=2))
        if partial_requirements["applicable"]:
            static_context += "\n# Explicit replacement-only task requirements\n" + json.dumps(partial_requirements, ensure_ascii=False)
        from eco_plan_context import collect as collect_eco_inventory
        eco_inventory = timed_call(performance_stages, "native_object_inventory", collect_eco_inventory,
            netlists, libs, task_spec, original or "", output_dir, literal_tcl_words, tool_run,
            start + timeout_total - finalize_reserve - 1)
        known_reset_ports = set(control_hints)
        reset_inference_evidenced = False
        floating = (timed_call(performance_stages, "source_floating", floating_clock_outputs, netlists) if re.search(r"悬空|浮空|unconnected|floating", task_spec, re.I) and
                    re.search(r"伪|pseudo", task_spec, re.I) and re.search(r"时钟|clock", task_spec, re.I) else {})
        expected_segments = (structural_groups if
                             re.search(r"所有.{0,20}移位寄存器|all.{0,20}shift.{0,20}register", task_spec, re.I) else [])
        runtime_event('preparation_end', stage='input_and_context', elapsed_seconds=time.monotonic()-start)
        for index in itertools.count(1):
            if max_calls is not None and index > max_calls:
                break
            remaining = timeout_total - (time.monotonic() - start)
            if remaining <= finalize_reserve + 1:
                break
            rid = f"R{index}"
            run_dir = runs_root / rid
            run_dir.mkdir(parents=True, exist_ok=False)
            journal.round(rid)
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
                        phase_note = (' [diagnostic history; current ECO DRC is determined only by the bound native snapshot]'
                                      if eco_evidence.requires_eco(task_spec) and re.search(r'drc|violation', rp.name, re.I) else '')
                        excerpts.append(f"### {rp.relative_to(previous_dir)}{phase_note}\n{report_context}")
                previous_reports = "\n\n".join(excerpts)[:18000]
            generation_base = previous
            generation_mapping = requirement_mapping
            if run_records:
                generation_base, generation_mapping = rebase_round(
                    previous, requirement_mapping, runs_root / run_records[-1]["run_id"], run_dir)
            generation_actual_base = generation_base
            previous_unallowed_codes = set()
            prior_drc = None
            if run_records:
                prior_drc = preceding_drc_observation(runs_root / run_records[-1]['run_id'],
                    permitted_residual_drc_codes(task, task_spec),
                    eco_stage=final_eco_stage, eco_required=eco_evidence.requires_eco(task_spec))
                (run_dir / 'llm_prior_drc_observation.json').write_text(json.dumps(prior_drc, ensure_ascii=False, indent=2))
                previous_unallowed_codes = set(prior_drc['blocking_codes'])
            reset_inference_evidenced = reset_inference_evidenced or bool(previous_unallowed_codes & {"DFTR2", "DFTR3"})
            if run_records:
                generation_base = model_owned_script(generation_base)
            context = (static_context + f"\n# Current Dofile (output paths already rebased to this round)\n{generation_base}\n\n"
                       f"# Most recent tool log / diagnostics\n{last_log[-18000:] if last_log else '(no run yet)'}\n\n"
                       f"# Most recent tool reports\n{previous_reports[-18000:] if previous_reports else '(no reports captured yet)'}\n")
            if prior_drc is not None and eco_evidence.requires_eco(task_spec):
                context += '\n# Bound current ECO DRC vs historical discovery (neither replaces EQY/task validation)\n' + json.dumps(prior_drc, ensure_ascii=False)
            netlist_changes: list[dict[str, Any]] = []
            prepared_eco_script = None
            if run_records:
                context += "\n# Localized actual input source around prior diagnostics (Dofile repairs also need source traces)\n" + netlist_diagnostic_context(active_netlists, last_log + "\n" + previous_reports)
            if active_netlist_root != input_dir / "netlist":
                context += (f"\n# EQY-proven current netlist directory; preceding static hints refer to the original input\n{active_netlist_root}\n"
                            + source_hierarchy_context(list(active_netlists.values()), task_spec, hints=hierarchy_hints))
            if validation_problems:
                context += "\n# Independent output-validator findings from previous round\n" + "\n".join(validation_problems)
            if eco_feedback_last:
                context += "\n# Bound failed-ECO state (diagnostic only, not adopted or functionally proved)\n" + eco_feedback_context(eco_feedback_last)
            if audit_gap_feedback:
                context += "\n# Read-only audit evidence gaps; previous native outputs already passed\n" + json.dumps(audit_gap_feedback, ensure_ascii=False)
            context_issues = (effective_issue_views(issue_records, final_issue_views, run_records[-1]['run_id'], output_dir)
                              if run_records else issue_records)
            pending = [issue for issue in context_issues if not issue.get("attempts", [{}])[-1].get("verify", {}).get("resolved")]
            if pending:
                context += ("\n# Existing audit records awaiting positive verification\n" +
                            json.dumps(pending, ensure_ascii=False)[:8000] +
                            "\nPreserve settings that already passed tool checks. Do not invent a new problem from a clean DRC summary. "
                            "Add only the actual reports needed for positive verification, or correct a diagnosis using its existing real discovery evidence.\n")
            if task == "task2" and index == 1 and original is not None:
                # R1 is a faithful diagnostic run of the supplied Dofile. Preserve the original as evidence.
                dofile, meta = original, {"summary": "Run the supplied original Dofile to gather diagnostic evidence.", "requirement_mapping": [], "issue_resolutions": []}
                execution_path = script_root / "original.dofile"
                (run_dir / 'deliverables').mkdir(exist_ok=True)
                copy_original_dofile(original_path, execution_path, run_dir / 'deliverables/R1.dofile')
            else:
                admitted = False
                for proposal_index in range(3):
                    prepared_eco_script = None
                    repair_tag = rid if proposal_index == 0 else f"{rid}_proposal{proposal_index + 1}"
                    try:
                        if client is None:
                            client = get_client()
                        remaining = timeout_total - (time.monotonic() - start)
                        if remaining <= finalize_reserve + 1:
                            generation_error = f"Insufficient time for Dofile generation before {rid}; finalization reserve retained"
                            break
                        request_client = client.with_options(
                            timeout=model_request_timeout(remaining - finalize_reserve - 1), max_retries=0)
                        dofile, meta = timed_call(performance_stages, "model_and_candidate", call_for_dofile, request_client, task, context, original if task == "task2" else None,
                                                     input_dir, run_dir, start + timeout_total - finalize_reserve - 1,
                                                     base_dofile=generation_base if run_records else None,
                                                     previous_mapping=generation_mapping,
                                                     catalog=evidence_catalog(runs_root / run_records[-1]["run_id"], output_dir, task_spec=task_spec) if run_records else None,
                                                     segments=expected_segments, control_hints=control_hints, instances=instances, floating=floating,
                                                     previous_actual_dofile=generation_actual_base if run_records else None,
                                                     previous_unallowed_codes=previous_unallowed_codes,
                                                     known_reset_ports=known_reset_ports,
                                                     reset_inference_evidenced=reset_inference_evidenced,
                                                     clock_candidates=clock_candidates, mode_hints=mode_hints,
                                                     diagnostics=last_log + "\n" + previous_reports,
                                                     library_cells=library_cells,
                                                     exclusion_source_facts=hierarchy_hints.get('debug_exclusion_facts'), eco_inventory=eco_inventory,
                                                     drc_phase_observation=prior_drc if eco_evidence.requires_eco(task_spec) else None,
                                                     icg_protection_facts=icg_protection_facts,
                                                     eco_feedback_state=eco_feedback_last)
                        previous_netlist_root = active_netlist_root
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
                                edits, output_dir, repair_tag, start + timeout_total - finalize_reserve - 1)
                            active_netlist_root = output_dir / "netlist_versions" / repair_tag
                            current_paths = list(active_netlists.values())
                            hierarchy_hints = source_hierarchy_hints(current_paths, library_cells)
                            clock_candidates = (clock_latch_hints(current_paths, libs) if
                                                re.search(r'ICG|门控|缓冲|latch|闩锁', task_spec, re.I) else [])
                            mode_hints = mode_control_hints(current_paths) if requested_constant_modes(task_spec) else []
                            reset_hints, instances = {}, {}
                            structural_groups = shift_register_groups(current_paths, libraries=libs, reset_hints=reset_hints,
                                instance_map=instances if re.search(r'闩锁|latch|关联关系', task_spec, re.I) else None)
                            control_hints = {root: values for root, values in reset_hints.items() if values}
                            floating = (floating_clock_outputs(current_paths) if
                                        re.search(r'悬空|浮空|unconnected|floating', task_spec, re.I) and
                                        re.search(r'伪|pseudo', task_spec, re.I) and re.search(r'时钟|clock', task_spec, re.I) else {})
                            expected_segments = (structural_groups if
                                re.search(r'所有.{0,20}移位寄存器|all.{0,20}shift.{0,20}register', task_spec, re.I) else [])
                            dofile = normalize_reset_levels(model_owned_script(dofile), control_hints)
                            dofile, _ = configure_shift_segments(dofile, expected_segments, task_spec)
                            dofile, _ = configure_floating_inputs(dofile, floating)
                            dofile, _ = configure_natural_shift_reports(dofile, task_spec, literal_tcl_words)
                            dofile, _ = configure_clock_associations(dofile, clock_candidates, task_spec, literal_tcl_words)
                            dofile = append_audit_reports(dofile, run_dir, task_spec,
                                                         evidence_claims=meta.get('issue_resolutions', []))
                            repair_attempts.append({"run_ref": rid, "admitted": True, "adopted": False,
                                                    "lec_ref": f"lec/{repair_tag}/aggregate.log"})
                        if active_netlist_root != input_dir / "netlist":
                            dofile = dofile.replace(str(previous_netlist_root), str(active_netlist_root))
                            dofile = dofile.replace(str(input_dir / "netlist"), str(active_netlist_root))
                            if task == "task2":
                                (script_root / "netlist").unlink()
                                (script_root / "netlist").symlink_to(active_netlist_root, target_is_directory=True)
                        # Compile before admission so unsupported candidates use
                        # the existing finite correction budget, not the outer
                        # case-error exit. Keep CURRENT/raw audit comparison intact.
                        if task == 'task2' and (eco_evidence.requires_eco(task_spec) or
                                re.search(r'\beco_(?:ref|link)\b', dofile) or
                                eco_evidence.proposal(dofile, literal_tcl_words)['proposed_commands']):
                            prepared_eco_script, object_contract_plan = prepare_eco_candidate(dofile, run_dir, libs, task_spec)
                            if object_contract_plan.get('scope_unresolved'):
                                prepared_eco_script = None
                                raise RepairRejected('ECO object scope unresolved: nested or computed connection '
                                    'operations/command redefinition cannot be safely resolved. No tool call or '
                                    'candidate adoption occurred. Use explicit top-level eco_ref/eco_link or '
                                    'supported native selectors for each intended endpoint; do not hide '
                                    'connections in loops or evaluated bodies. CURRENT remains unchanged. '
                                    'REJECTED fragments below are NOT the editable CURRENT or executed state: ' +
                                    json.dumps(object_contract_plan.get('rejected_scope_fragments', []), ensure_ascii=False))
                            prepared_eco_script = eco_evidence.instrument(
                                prepared_eco_script, run_dir, literal_tcl_words)
                        admitted = True
                        generation_error = ""
                        break
                    except (RepairRejected, ValueError) as e:
                        generation_error = f"Candidate rejected before {rid}: {type(e).__name__}: {e}"
                        rejection = {"run_ref": rid, "proposal_index": proposal_index + 1,
                                     "tool_called": False, "reason": str(e), "error_type": type(e).__name__}
                        generation_rejections.append(rejection)
                        rejected_dir = run_dir / "rejected_proposals" / f"P{proposal_index + 1}"
                        rejected_dir.mkdir(parents=True, exist_ok=False)
                        for artifact in run_dir.glob("llm_*"):
                            if artifact.is_file():
                                shutil.move(str(artifact), rejected_dir / artifact.name)
                        (rejected_dir / "rejection.json").write_text(json.dumps(rejection, ensure_ascii=False, indent=2))
                        if isinstance(e, RepairRejected):
                            proof_log = f"lec/{repair_tag}/aggregate.log"
                            repair_attempts.append({"run_ref": rid, "proposal_index": proposal_index + 1,
                                                    "admitted": False, "adopted": False, "reason": str(e),
                                                    "lec_ref": proof_log if (output_dir / proof_log).exists() else ""})
                        context += ("\n# Rejected proposal; NO tool call and NO candidate adoption\n" + generation_error +
                                    "\nThe displayed CURRENT Dofile and current netlists remain the authoritative base. "
                                    "Correct the configuration using actual input ports and source paths. "
                                    "Return either a complete dofile or legal dofile_edits against the SAME displayed "
                                    "CURRENT, following the existing parser protocol; never patch a rejected candidate. "
                                    f"CURRENT SHA256: {hashlib.sha256(generation_base.encode()).hexdigest()}. "
                                    "A netlist edit still needs exact diagnostics, a unique source span and a successful EQY proof.\n")
                    except Exception as e:
                        generation_error = f"LLM Dofile generation failed before {rid}: {type(e).__name__}: {e}"
                        if not run_records:
                            raise
                        break
                if not admitted:
                    break
                if audit_only_last_run and repeated_audit_request(generation_actual_base, dofile,
                        outputs_passed=True, audit_unclosed=True,
                        inputs_unchanged=(input_tree_signature(input_dir) == final_source_signature and
                            not changed_paths(final_protected_snapshot) and not changed_paths(final_execution_snapshot)),
                        artifacts_unchanged=audit_artifacts_unchanged(final_run_dir,
                            audit_previous_artifacts, _run_signature(final_run_dir)),
                        netlist_changes=bool(netlist_changes)):
                    # Recheck existing real evidence, never mint a new R/F event
                    # merely to update an audit reference or declaration.
                    actual_run = run_records[-1]['run_id']
                    verify_issue_fixes(issue_records, verification_plans, output_dir, actual_run, True,
                                       permitted_residual_drc_codes(task, task_spec), task_spec=task_spec, file_changes=changes, input_dir=input_dir,
                                       projection_journal=True)
                    read_only_issues = effective_issue_views(issue_records, final_issue_views, actual_run, output_dir)
                    remaining_audit = issue_audit_problems(task, read_only_issues, changes)
                    if remaining_audit:
                        generation_error = 'Audit no progress: repeated execution request after successful native checks; candidate not adopted'
                        audit_stop_events.append({'reason': 'repeated_execution_request', 'actual_run': actual_run,
                            'proposed_run': rid, 'tool_called': False, 'candidate_adopted': False,
                            'diagnostic': audit_gap_details(read_only_issues, verification_plans, output_dir,
                                                            actual_run, remaining_audit)})
                        save_stop_diagnostic(output_dir, event=audit_stop_events[-1], issues=issue_records,
                            plans=verification_plans, tool_runs=serialize_tool_runs(run_records), changes=changes)
                    break
                execution_path = None
                if task == "task2":
                    execution_path = script_root / f"{rid}.dofile"
                    execution_path.write_text(dofile, encoding="utf-8")
            # The faithful original R1 is diagnostic; every subsequent ECO attempt
            # must pass structure + exact-version functional EQY before insertion.
            if prepared_eco_script is not None:
                dofile = prepared_eco_script
                eco_object_contract.bind_plan(object_contract_plan, dofile, run_dir, literal_tcl_words)
                if execution_path is not None:
                    execution_path.write_text(dofile, encoding='utf-8')
            # Generation and report-context reads consumed time; never reuse the pre-LLM budget.
            remaining = timeout_total - (time.monotonic() - start)
            if remaining <= finalize_reserve + 1:
                generation_error = f"Insufficient time for tool call {rid}; finalization reserve retained"
                break
            previous_run = run_records[-1]["run_id"] if run_records else ""
            change_id = ""
            pending_changes = []
            if index > 1:
                prior = run_records[-1]
                diff_path = write_diff(output_dir, previous, dofile, prior["run_id"], rid)
                change_id = f"F{len(changes)+1}"
                pending_changes.append({"change_id": change_id, "type": "dofile",
                                "path": f"runs/{rid}/deliverables/{rid}.dofile", "diff_path": diff_path, "lec_ref": ""})
            netlist_change_ids = []
            for change in netlist_changes:
                change["change_id"] = f"F{len(changes)+len(pending_changes)+1}"
                netlist_change_ids.append(change["change_id"])
                pending_changes.append(change)
            snapshot = {}
            if active_netlist_root != input_dir / "netlist":
                protected = list(active_netlists) + list(active_netlists.values())
                protected.extend(path for path in (output_dir / "lec").rglob("*")
                                 if path.is_file() and path.name in {"summary.json", "check.eqy", "eqy.log", "aggregate.log", "PASS"})
                snapshot = fingerprint_paths(protected)
                (run_dir / "llm_protected_repair_fingerprints.json").write_text(json.dumps(snapshot, indent=2))
            remaining = timeout_total - (time.monotonic() - start)
            if remaining <= finalize_reserve + 1:
                generation_error = f"Insufficient time after fingerprinting before {rid}"
                break
            guarded_sources = role_input_files(input_dir, netlists, libs, original_path) + list(active_netlists.values())
            if execution_path is not None:
                guarded_sources.append(execution_path)
            execution_snapshot = fingerprint_paths(guarded_sources)
            source_signature = input_tree_signature(input_dir)
            eco_context = eco_evidence.begin(output_dir, input_dir, run_dir, rid, task,
                task_spec, original or '', netlists, libs, dofile,
                execution_path or run_dir / (rid + '.dofile'), literal_tcl_words)
            pre_scan_gate = (eco_evidence.PreScanGate(eco_context, literal_tcl_words,
                start + timeout_total - finalize_reserve - 1)
                if eco_context is not None and index > 1 else None)
            # Fresh allocation AFTER fingerprinting/context work, same deadline.
            remaining = start + timeout_total - time.monotonic()
            if remaining <= finalize_reserve + 1:
                generation_error = f"Insufficient time immediately before {rid}"
                break
            per_run_timeout = int(remaining - finalize_reserve)
            result = timed_call(performance_stages, "eda_and_collection", tool_run, dofile, run_dir, rid, per_run_timeout, execution_path,
                              abort_on_error=not (task == "task2" and index == 1),
                               allowed_drc=permitted_residual_drc_codes(task, task_spec) if re.search(r"\bDRC\b|违例", task_spec, re.I) else None,
                               original_source=original_path if task == 'task2' and index == 1 else None, pre_scan_gate=pre_scan_gate)
            eco_stage, eco_validation = None, None
            if eco_context is not None:
                try:
                    eco_stage = eco_evidence.trace(eco_context, result, literal_tcl_words)
                    eco_evidence.collect_bound_outputs(eco_stage)
                except (RepairRejected, CanonicalDeliveryError, OSError, ValueError, KeyError) as exc:
                    gate_problems = pre_scan_gate.record.get('problems', []) if pre_scan_gate else []
                    eco_validation = eco_evidence.failure(eco_context, '; '.join([str(exc), *gate_problems]))
            completed_artifact_fingerprints = fingerprint_paths(actual_run_files(run_dir))
            changes.extend(pending_changes)
            final_dofile = dofile
            if not (task == "task2" and index == 1):
                for statement in dofile.replace("\\\n", " ").splitlines():
                    if re.match(r"\s*set_scan_signal\b", statement) and re.search(r"-type\s+reset\b", statement):
                        words = literal_tcl_words(statement)
                        if "-port" in words and words.index("-port") + 1 < len(words):
                            port = words[words.index("-port") + 1].strip('"{}')
                            if re.fullmatch(r"[A-Za-z_][\w$]*", port):
                                known_reset_ports.add(port)
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
            expected_checks = {"task": task, "segments": expected_segments, "floating": floating,
                               "clock_candidates": clock_candidates, "mode_hints": mode_hints}
            if eco_context is not None:
                expected_checks['eco_native_binding'] = eco_stage.fingerprints if eco_stage is not None else 'unverified'
            runtime_event('validation_start', stage='native_task_ECO')
            ok, problems = timed_call(performance_stages, "round_validation", validation_cache.validate, run_dir,
                lambda: check_output(run_dir, task_spec, task, dofile, result["status"], expected_segments, floating, clock_candidates, mode_hints,
                                     eco_stage=eco_stage),
                dofile=dofile, task_spec=task_spec, status=result["status"], expected=expected_checks, tool_finished=True)
            mapping_review = project_requirement_mapping(task, meta.get("requirement_mapping", requirement_mapping),
                dofile, run_dir, literal_tcl_words, config_reference, native=True)
            mapping_dir = output_dir/'mapping_reviews'
            mapping_dir.mkdir(exist_ok=True)
            (mapping_dir/(rid+'.json')).write_text(json.dumps(mapping_review,ensure_ascii=False,indent=2))
            mapping_errors = mapping_review['required_problems']
            problems.extend(mapping_errors)
            ok = ok and not mapping_errors
            if partial_requirements["applicable"]:
                final_paths, replacement_paths = partial_flow_artifact_paths(run_dir, task_spec)
                final_structural_check = timed_call(
                    performance_stages, "partial_structure_validation", partial_insertion_validation,
                    netlists, final_paths, libs, task_spec,
                    report_paths=list((run_dir / "reports").rglob("*.rpt")),
                    replacement_paths=replacement_paths)
                structural_dir = output_dir / "structural_checks"
                structural_dir.mkdir(exist_ok=True)
                (structural_dir / f"{rid}.json").write_text(
                    json.dumps(final_structural_check, ensure_ascii=False, indent=2), encoding="utf-8")
                record["structural_check_ref"] = f"structural_checks/{rid}.json"
                structural_problems = list(final_structural_check["problems"])
                structural_problems.extend("Partial-flow structural proof incomplete: " + item
                                           for item in final_structural_check["unknown"])
                if final_structural_check["status"] != "pass" and not structural_problems:
                    structural_problems.append("Partial-flow structural proof did not pass")
                problems.extend(structural_problems)
                ok = ok and not structural_problems
            if eco_context is not None:
                if eco_stage is not None:
                    eco_validation = timed_call(performance_stages, 'eco_functional_validation', eco_evidence.evaluate,
                        eco_stage, literal_tcl_words, start + timeout_total - finalize_reserve - 1,
                        native_checks_passed=ok, pre_scan_gate=pre_scan_gate)
                record['eco_validation_ref'] = 'eco/' + rid + '/validation.json'
                if eco_validation.get('status') != 'pass':
                    ok = False
                    problems.extend('ECO required validation: ' + p for p in eco_validation.get('problems', ['incomplete']))
                else:
                    eco_change = eco_evidence.change(eco_stage, eco_validation)
                    eco_change['change_id'] = f'F{len(changes)+1}'
                    changes.append(eco_change)
                    netlist_change_ids.append(eco_change['change_id'])
                    snapshot.update(fingerprint_paths([Path(p) for p in
                        list(eco_validation['equivalence']['plan']['input_fingerprints']) +
                        eco_validation['equivalence']['proof_files']]))
            final_eco_stage, final_eco_validation = eco_stage, eco_validation
            eco_feedback_last = (eco_observer.observe(eco_context, result, literal_tcl_words,
                current_check=eco_evidence._current, native_trace=eco_stage, required_problems=(
                    pre_scan_gate.record.get('problems', []) if pre_scan_gate is not None and pre_scan_gate.called
                    and pre_scan_gate.record['status'] != 'pass' else [])) if eco_context is not None and
                eco_validation is not None and eco_validation.get('status') != 'pass' else None)
            if eco_feedback_last:
                runtime_event('eco_observation', status=eco_feedback_last['status'],
                              feedback_ref=eco_feedback_last['record_ref'],
                              reason=eco_feedback_last.get('progress', {}).get('action', 'unknown'))
            modified = changed_paths(snapshot) + changed_paths(execution_snapshot)
            if modified:
                integrity_problems = ["EQY-proven candidate or proof artifact changed during the tool run: " + name for name in modified]
                record["repair_integrity_passed"] = False
                (run_dir / "repair_integrity_failure.json").write_text(json.dumps({"modified_paths": modified}, indent=2))
                ok = False
                problems.extend(integrity_problems)
            elif snapshot:
                record["repair_integrity_passed"] = True
            final_protected_snapshot, final_execution_snapshot = snapshot, execution_snapshot
            final_active_netlists = dict(active_netlists)
            final_source_signature = source_signature
            final_artifact_fingerprints = completed_artifact_fingerprints
            validation_problems = problems
            if "requirement_mapping" in meta:
                requirement_mapping = []
                for item in meta.get("requirement_mapping", []):
                    if isinstance(item, dict):
                        requirement_mapping.append({"requirement": str(item.get("requirement", "")),
                                                    "dft_config": str(item.get("dft_config", "")),
                                                    "config_ref": {"source": "final_results/deliverables/final.dofile", "locator": ""}})
            record_issue_fixes(meta, issue_records, verification_plans, output_dir, previous_run, rid, change_id,
                               netlist_change_ids, audit_visible_residual_codes(task, task_spec), task_spec=task_spec,
                               admission_reviews=issue_admission_reviews)
            verify_issue_fixes(issue_records, verification_plans, output_dir, rid, ok,
                               permitted_residual_drc_codes(task, task_spec), task_spec=task_spec, file_changes=changes, input_dir=input_dir,
                               projection_journal=True)
            if ok and partial_requirements["applicable"]:
                for issue in issue_records:
                    evidence = partial_issue_positive_evidence(
                        issue, output_dir, rid, task_spec, final_structural_check, changes)
                    if evidence:
                        _adopt_partial_issue_evidence(issue, rid, evidence)
            validation_problems = problems + issue_audit_problems(task, issue_records, changes)
            runtime_event('validation_end', stage='native_task_ECO', checks_passed=ok,
                          problem_count=len(problems))
            if eco_feedback_last and eco_feedback_last.get('stop'):
                generation_error = ('ECO evidence unavailable: repeated bound native failures without new verified information; incomplete'
                    if eco_feedback_last.get('progress',{}).get('action') == 'stop_failed_evidence_unavailable' else
                    'ECO no progress: repeated bound failed state without new native information; incomplete')
                runtime_event('no_progress_stop', status='failed_incomplete', reason=generation_error,
                              feedback_ref=eco_feedback_last['record_ref'])
                runtime_event('round_end', status='failed_incomplete', checks_passed=False)
                break
            if integrity_problems:
                break
            if ok and client is not None and issue_audit_problems(task, issue_records, changes):
                frozen_artifacts = _run_signature(run_dir)
                audit_guard = {**execution_snapshot, **snapshot,
                               **fingerprint_paths([run_dir / 'deliverables' / f'{rid}.dofile'])}
                for _ in range(2):
                    updated = timed_call(performance_stages, 'audit_refresh', refresh_existing_audit,
                        client, output_dir, issue_records, verification_plans, run_records, rid,
                        audit_guard, source_signature, input_dir, frozen_artifacts,
                        start + timeout_total - finalize_reserve - 1, audit_reviews,
                        permitted_residual_drc_codes(task, task_spec), file_changes=changes,
                        correction_state=correction_state, final_views=final_issue_views, tool_checks_passed=ok)
                    audit_records = effective_issue_views(issue_records, final_issue_views, rid, output_dir)
                    if not updated or not issue_audit_problems(task, audit_records, changes):
                        break
                validation_problems = problems + issue_audit_problems(task, audit_records, changes)
            audit_records = effective_issue_views(issue_records, final_issue_views, rid, output_dir)
            remaining_audit = issue_audit_problems(task, audit_records, changes)
            runtime_event('round_end', status='task_checks_passed' if ok else 'task_checks_failed',
                          checks_passed=ok, problem_count=len(remaining_audit), scope='audit gaps counted separately')
            audit_only_last_run = bool(ok and remaining_audit)
            audit_previous_artifacts = _run_signature(run_dir) if audit_only_last_run else None
            audit_gap_feedback = (audit_gap_details(audit_records, verification_plans, output_dir, rid, remaining_audit)
                                  if audit_only_last_run else None)
            if ok:
                # Existing read-only audit opportunity has ended. Missing text
                # is not a request to execute another Dofile. Publish and let
                # the unchanged strict delivery gates/classification decide.
                runtime_event('audit_only_finalize', checks_passed=True,
                              problem_count=len(remaining_audit),
                              reason='Read-only audit opportunity ended; no additional Dofile execution requested')
                break
            if audit_progress.observe(audit_records, outputs_passed=ok, audit_problems=remaining_audit,
                    input_signature=source_signature, netlist_changes=bool(netlist_change_ids)):
                generation_error = 'Audit no progress: two output-valid rounds without new verified audit closure'
                audit_stop_events.append({'reason': 'consecutive_audit_stall', 'actual_run': rid,
                    'stalled_rounds': audit_progress.stalled_rounds,
                    'last_run_executed': True, 'extra_tool_called': False, 'diagnostic': audit_gap_feedback})
                save_stop_diagnostic(output_dir, event=audit_stop_events[-1], issues=issue_records,
                    plans=verification_plans, tool_runs=serialize_tool_runs(run_records), changes=changes)
                break
            unresolved = any(issue.get("found", {}).get("verified") and
                             not (issue.get("attempts") and issue["attempts"][-1].get("verify", {}).get("resolved"))
                             for issue in audit_records)
            if ok and not unresolved and not issue_audit_problems(task, audit_records, changes):
                break
        if not run_records:
            raise RuntimeError("No ScanInsertion tool call was made within the time budget")
        final_run_dir = runs_root / run_records[-1]["run_id"]
        assert_output_directories(output_dir, ['final_results/reports', 'final_results/deliverables'])
        final_results = output_dir / "final_results"
        final_results.mkdir(exist_ok=True)
        timed_call(performance_stages, "final_copy", independent_copy, final_run_dir / f"{run_records[-1]['run_id']}.log", final_results / "final.log")
        deliverables = final_results / "deliverables"
        reports = final_results / "reports"
        deliverables.mkdir(exist_ok=True)
        reports.mkdir(exist_ok=True)
        timed_call(performance_stages, 'final_copy', independent_copy,
                   final_run_dir / 'deliverables' / f"{run_records[-1]['run_id']}.dofile", deliverables / 'final.dofile')
        # Copy actual tool-created products only.
        timed_call(performance_stages, "final_copy", copy_tree_contents, final_run_dir / "reports", reports)
        timed_call(performance_stages, "final_copy", copy_tree_contents, final_run_dir / "deliverables", deliverables)
        tool_checks_passed, final_problems = timed_call(performance_stages, "final_validation", validation_cache.validate, final_run_dir,
            lambda: check_output(final_run_dir, task_spec, task, final_dofile,
                                run_records[-1]["exit_status"], expected_segments, floating, clock_candidates, mode_hints,
                                eco_stage=final_eco_stage),
            dofile=final_dofile, task_spec=task_spec, status=run_records[-1]["exit_status"],
            expected=expected_checks, tool_finished=True)
        if partial_requirements["applicable"] and (
                final_structural_check is None or final_structural_check["status"] != "pass"):
            tool_checks_passed = False
            final_problems.extend(validation_problems)
            final_problems.append("Final partial-flow structural proof did not pass")
        if final_eco_validation is not None and final_eco_validation.get('status') != 'pass':
            tool_checks_passed = False
            final_problems.extend('Final ECO validation incomplete: ' + p for p in final_eco_validation.get('problems', []))
        if integrity_problems:
            tool_checks_passed = False
            final_problems.extend(integrity_problems)
        final_changed = (changed_paths(final_protected_snapshot) + changed_paths(final_execution_snapshot) +
                         changed_paths(final_artifact_fingerprints))
        if set(final_artifact_fingerprints) != {str(p) for p in actual_run_files(final_run_dir)}:
            final_changed.append('Actual tool artifact path set changed after process completion')
        if final_source_signature is not None and input_tree_signature(input_dir) != final_source_signature:
            final_changed.append('Input directory metadata/path set changed after execution')
        if final_changed:
            tool_checks_passed = False
            final_problems.append('Inputs/executed candidates/proofs changed before final adoption: ' + ', '.join(final_changed))
        repair_delivery = None
        if not final_changed and not integrity_problems:
            try:
                repair_delivery = timed_call(performance_stages, 'repair_delivery', publish_repair_deliverables,
                    output_dir, task=task, final_run=run_records[-1]['run_id'],
                    active_netlists=final_active_netlists, repair_attempts=repair_attempts,
                    protected_fingerprints=final_protected_snapshot, libraries=libs,
                    deadline=work_deadline)
            except RepairRejected as exc:
                tool_checks_passed = False
                final_problems.append('Final repair delivery rejected: ' + str(exc))
        delivery_issues = effective_issue_views(issue_records, final_issue_views, run_records[-1]['run_id'], output_dir)
        audit_problems = issue_audit_problems(task, delivery_issues, changes)
        audit_complete = not audit_problems
        final_mapping_review = project_requirement_mapping(task, requirement_mapping, final_dofile,
            final_run_dir, literal_tcl_words, config_reference, native=True)
        mapping_dir = output_dir/'mapping_reviews';mapping_dir.mkdir(exist_ok=True)
        (mapping_dir/'final.json').write_text(json.dumps(final_mapping_review,ensure_ascii=False,indent=2))
        requirement_mapping = final_mapping_review['adopted']
        mapping_errors = final_mapping_review['required_problems']
        if mapping_errors:
            tool_checks_passed = False
            final_problems.extend(mapping_errors)
        canonical_delivery = None
        if tool_checks_passed:
            try:
                canonical_delivery = timed_call(performance_stages, 'canonical_delivery', publish_canonical_artifacts,
                    output_dir, run_records[-1]['run_id'], run_records[-1], words_for=literal_tcl_words, eco_trace=final_eco_stage)
            except (CanonicalDeliveryError, OSError) as exc:
                tool_checks_passed = False
                final_problems.append('Final canonical artifact publication rejected: ' + str(exc))
        if final_eco_validation is not None and tool_checks_passed:
            try:
                eco_delivery = timed_call(performance_stages, 'eco_final_publication', eco_evidence.publish,
                    final_eco_stage, final_eco_validation)
            except (RepairRejected, CanonicalDeliveryError, OSError, ValueError) as exc:
                tool_checks_passed = False
                final_problems.append('Final ECO proof/publication rejected: ' + str(exc))
        scope_delivery_proof = timed_call(performance_stages, 'scope_delivery_proof', prepare_scope_delivery_proof,
            output_dir, input_dir, task, run_records, delivery_issues, changes,
            original_issues=issue_records, final_views=final_issue_views, tool_checks_passed=tool_checks_passed,
            canonical_delivery=canonical_delivery, execution_fingerprints=final_execution_snapshot,
            artifact_fingerprints=final_artifact_fingerprints, protected_fingerprints=final_protected_snapshot,
            source_signature=final_source_signature, active_netlists=final_active_netlists,
            repair_attempts=repair_attempts, repair_delivery=repair_delivery, expected_checks=expected_checks,
            structural_check=final_structural_check, deadline=work_deadline,
            eco_stage=final_eco_stage, eco_validation=final_eco_validation, eco_delivery=eco_delivery)
        outcome = completion_outcome(output_dir, task, run_records, delivery_issues, changes,
            tool_checks_passed=tool_checks_passed, audit_problems=audit_problems,
            audit_stop_events=audit_stop_events, canonical_delivery=canonical_delivery,
            within_limit=time.monotonic() - start < timeout_total, delivery_proof=scope_delivery_proof)
        decision = {
            "case_id": case_id_for(input_dir),
            "organizer_clarifications": {"source": QA_URL, "read_date": QA_READ_DATE,
                                        "tool_call_limit": max_calls,
                                        "permitted_residual_rules": sorted(qa_residual_codes(task, task_spec))},
            "task": task,
            "final_run": run_records[-1]["run_id"],
            "summary": f"Tool calls: {len(run_records)}; wall time: {time.monotonic() - start:.1f}s. Verified artifact checks: {'passed' if tool_checks_passed else 'incomplete'}; issue audit: {'complete' if audit_complete else 'incomplete'}; delivery: {outcome['status']}. " + ("; ".join(final_problems + audit_problems) if final_problems or audit_problems else "") + (f"; {generation_error}" if generation_error else ""),
            "tool_checks_passed": tool_checks_passed,
            "issue_audit_complete": audit_complete,
            "completion": outcome,
            "audit_problems": audit_problems,
            "requirement_mapping": requirement_mapping,
            "requirement_mapping_review": 'mapping_reviews/final.json',
            "issue_resolutions": [official_issue_projection(issue) if issue != issue_records[index] else issue
                                  for index, issue in enumerate(delivery_issues)],
            "tool_runs": serialize_tool_runs(run_records),
            "file_changes": changes,
            "netlist_repair_attempts": repair_attempts,
            "generation_rejections": generation_rejections,
            "optional_mapping_rejection_files": [str(path.relative_to(output_dir)) for path in
                                                  sorted(runs_root.glob("R*/llm_mapping_rejections.json"))],
            "audit_reviews": audit_reviews,
            "issue_admission_reviews": issue_admission_reviews,
            "audit_no_progress": audit_stop_events,
            "repair_delivery": repair_delivery,
            "canonical_delivery": canonical_delivery,
            "partial_structure_validation": final_structural_check,
            "source_analysis": {"hierarchy_complete": hierarchy_hints.get('complete', False),
                                "hierarchy_issues": hierarchy_hints.get('issue_counts', {}),
                                "mode_levels": "task_grounded_or_unknown",
                                "physical_scan_eligibility": "not_independently_verified"},
            "performance": {"validation_cache": dict(validation_cache.stats),
                            "stages_seconds": {name: round(value, 6) for name, value in performance_stages.items()},
                            "elapsed_before_serialization": round(time.monotonic() - start, 6)},
        }
        if final_eco_validation is not None:
            decision['eco_validation'] = final_eco_validation
            decision['eco_delivery'] = eco_delivery
        if delivery_issues != issue_records:
            sources = [entry['history_source'] for key, entry in final_issue_views.items()
                       if any(i['issue_id'] == key and i != issue_records[n] for n, i in enumerate(delivery_issues))]
            decision['summary'] += ' Record description correction history: ' + ', '.join(sources) + '; tool attempts were not added.'
        final_exit_code = write_final_decision(output_dir, decision,
            final_problems=final_problems, audit_problems=audit_problems)
        return final_exit_code
    except (Exception, CaseDeadlineExceeded) as e:
        if isinstance(e, CaseDeadlineExceeded):
            actual_record = getattr(e, 'tool_record', None)
            if actual_record and not any(r['run_id'] == actual_record['run_id'] for r in run_records):
                raw = {key: value for key, value in actual_record.items() if key != 'log_path'}
                raw['log_file'] = actual_record['log_path'].relative_to(output_dir).as_posix()
                raw['exit_status'] = actual_record['status']
                run_records.append(raw)
        error_message = f"{type(e).__name__}: {e}"
        if isinstance(e, CaseDeadlineExceeded):
            error_message = ('CaseDeadlineExceeded: mandatory-work deadline reached; '
                             'required checks not completed; cleanup reserve retained')
        print(error_message, file=sys.stderr)
        if not (output_dir / "decision_log.json").exists():
            (output_dir / "decision_log.json").write_text(json.dumps({"case_id": case_id_for(input_dir), "task": task,
                "final_run": run_records[-1]["run_id"] if run_records else "", "summary": "Agent failed: " + error_message,
                "requirement_mapping": requirement_mapping, "issue_resolutions": issue_records,
                "tool_runs": serialize_tool_runs(run_records), "file_changes": changes,
                "status": 'aborted' if isinstance(e, CaseDeadlineExceeded) else 'error',
                "tool_checks_passed": False, "issue_audit_complete": False,
                "audit_reviews": audit_reviews,
                "issue_admission_reviews": issue_admission_reviews,
                "audit_no_progress": audit_stop_events,
                "generation_rejections": generation_rejections}, ensure_ascii=False, indent=2), encoding="utf-8")
        final_exit_code = 1
        runtime_event('case_error', status='incomplete', error_type=type(e).__name__)
        return final_exit_code
    finally:
        if case_deadline is not None:
            case_deadline.close()
        journal.close(final_exit_code)


if __name__ == "__main__":
    raise SystemExit(main())
