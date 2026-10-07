"""Select complete installed-tool help using task roles and actual commands.

This changes only reference documentation in a model prompt. It does not parse
or rewrite executable Tcl, task requirements, tool diagnostics, or evidence.
Unknown task descriptions retain every available help entry.
"""
from __future__ import annotations

import re
from typing import Any


CORE_COMMANDS = (
    "load_lib", "load_netlist", "present_design", "set_scan_signal", "set_scan_cfg",
    "set_scan_cell_mapping", "insert_dft_logic", "dump_netlist", "examine_scan_drc",
    "examine_scan_chain", "set_scan_drc_cfg", "get_cells", "get_obj_insts",
    "get_property", "get_attribute", "sizeof_collection", "foreach_in_collection",
    "__cell_properties",
)

# A role can enable several relevant commands; it never requires the model to
# execute them. In particular, reporting natural ShiftRegs and configured scan
# segments uses different native APIs, so both help entries remain available.
ROLE_COMMANDS = (
    (r"\bICG\b|门控|clock[ _-]*gat", ("set_dft_clock_gating_cfg",)),
    (r"分区|\bpartition\w*\b", (
        "add_scan_partition", "set_current_scan_partition", "rpt_scan_partition")),
    (r"wrapper|\bCTL\b|black[ _-]*box|黑盒|包裹", (
        "load_ctl", "set_wrapper_cfg", "add_dedicated_wrapper_cell_type",
        "rpt_dedicated_wrapper_cell_type", "rpt_wrapper_cfg", "rpt_wrapper_implementation")),
    (r"pseudo|伪.{0,8}(?:输入|端口|时钟)|悬空|浮空|floating|unconnected", (
        "add_pseudo_pi", "rpt_pseudo_pi")),
    (r"移位寄存器|shift[ _-]*register|scan[ _-]*segment|扫描段", (
        "rpt_shift_register", "set_scan_segment", "rpt_scan_segment")),
    (r"排除|不.{0,12}(?:参与|纳入|扫描)|非扫描|不可扫描|回替|替换|"
     r"exclude|unscan|non[ _-]*scan|replace|\blatch\b|闩锁|锁存", ("set_scan_element",)),
    (r"\bDRC\b|违例|\bDFTR[-_ ]?(?:TIE[01]|\d+)\b", ("rpt_scan_drc_violation",)),
    (r"忽略|允许.{0,15}(?:违例|遗留)|无需处理|无需.{0,8}违例|"
     r"\bignore\b|\bpermit\w*\b|\ballow\w*\b.{0,30}(?:violation|residual|DFTR)", (
        "set_scan_drc_rule_handling", "rpt_scan_drc_rule_handling")),
    (r"(?:插链|扫描|DFT).{0,8}信息.{0,8}报告|insertion[ _-]*(?:info|report)|"
     r"insertion.{0,20}report", ("rpt_insertion_info",)),
    (r"扫描链.{0,12}(?:报告|明细)|scan[ _-]*chain.{0,20}(?:report|\.rpt)|"
     r"chain[ _-]*report|链数|链长|chain[ _-]*(?:count|length)|\bmax_length\b", (
        "rpt_scan_chain",)),
    (r"扫描链上单元|上链扫描单元|扫描链.{0,8}(?:单元|成员|明细)|"
     r"scan[ _-]*chain[ _-]*(?:cell|member)|chain.{0,15}(?:cell|member).{0,15}report", (
        "rpt_scan_chain_cell",)),
    (r"(?:寄存器|扫描单元).{0,12}(?:报告|明细)|上链扫描单元|"
     r"scan[ _-]*element|register.{0,15}report|扫描覆盖|可扫描.{0,20}(?:覆盖|100%)", (
        "rpt_scan_element",)),
    (r"(?:插链|扫描|DFT).{0,8}配置.{0,8}报告|scan[ _-]*(?:cfg|configuration)|"
     r"scan.{0,15}configuration.{0,15}report", ("rpt_scan_cfg",)),
    (r"(?:插链|扫描|DFT).{0,8}信号.{0,8}报告|scan[ _-]*signal|"
     r"scan.{0,15}signal.{0,15}report", ("rpt_scan_signal",)),
    (r"\bCTL\b|core[ _-]*test[ _-]*language", ("dump_ctl",)),
    (r"\bSCANDEF\b|scan[ _-]*def|(?<![\w])(?:[\w.-]+\.)?def(?![\w])", ("dump_def",)),
    (r"(?:引脚|pin).{0,15}(?:查询|query)|(?:查询|query).{0,15}(?:引脚|pin)", ("get_pins",)),
    (r"(?:端口|port).{0,15}(?:查询|query)|(?:查询|query).{0,15}(?:端口|port)", ("get_ports",)),
    (r"(?:网线|net).{0,15}(?:查询|query)|(?:查询|query).{0,15}(?:网线|net)", ("get_nets",)),
)

_TASK_DOMAIN = re.compile(r"scan|扫描|插链|DFT|DFF|SFF|ICG|触发器", re.I)
_SPECIFIC_REQUIREMENT = re.compile(
    r"任务要求|验收标准|输出要求|输出文件|扫描链|链数|链长|时钟|复位|替换|回替|"
    r"分区|门控|移位寄存器|黑盒|包裹|报告|网表|\b(?:clock|reset|partition|wrapper|"
    r"netlist|report|CTL|SCANDEF)\b|chain[ _-]*(?:count|length)|\bmax_length\b|"
    r"scan[ _-]*signal|scan[ _-]*cfg|replace|scan[ _-]*segment", re.I)
_ACTION_OR_OUTPUT = re.compile(
    r"任务要求|验收标准|输出|读取|配置|插入|构建|替换|回替|生成|导出|报告|约束|要求|"
    r"排除|锁定|\b(?:require\w*|configur\w*|replace\w*|insert\w*|connect\w*|load|build|"
    r"read|export|dump|report|budget|maximum|minimum|enable|disable|exclude)\b", re.I)
_COMMAND_TOKEN = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]*\b")


def _available(syntax: dict) -> set[str]:
    return {name for name, text in syntax.items()
            if isinstance(name, str) and isinstance(text, str) and text.strip()}


def _fallback_reason(spec: str) -> str | None:
    if not spec.strip():
        return "empty_task_spec"
    if not _TASK_DOMAIN.search(spec):
        return "unrecognized_task_domain"
    if not _SPECIFIC_REQUIREMENT.search(spec) or not _ACTION_OR_OUTPUT.search(spec):
        return "ambiguous_task_spec"
    return None


def select_help_commands(syntax: dict, spec: str, current: str = "",
                         original: str = "", diagnostics: str = "") -> list[str]:
    """Return a stable command list without omitting actual referenced APIs.

    References are conservative text matches, not an attempt to execute or
    interpret Tcl. Commands mentioned in comments or errors remain documented.
    The complete property table is always retained when available.
    """
    available = _available(syntax)
    desired = set(CORE_COMMANDS)
    if _fallback_reason(spec):
        desired.update(available)
    else:
        for pattern, commands in ROLE_COMMANDS:
            if re.search(pattern, spec, re.I):
                desired.update(commands)
    for text in (spec, current, original, diagnostics):
        desired.update(available.intersection(_COMMAND_TOKEN.findall(text)))
    preferred = list(CORE_COMMANDS)
    for _, commands in ROLE_COMMANDS:
        preferred.extend(commands)
    preferred.extend(sorted(available))
    return [name for name in dict.fromkeys(preferred) if name in desired and name in available]


def render_selected_help(syntax: dict, spec: str, current: str = "",
                         original: str = "", diagnostics: str = "") -> tuple[str, dict[str, Any]]:
    """Render full selected entries; metadata contains no task or source text."""
    selected = select_help_commands(syntax, spec, current, original, diagnostics)
    text = "\n\n".join(syntax[name] for name in selected)
    metadata = {
        "selected_commands": selected,
        "selected_entry_chars": sum(len(syntax[name]) for name in selected),
        "rendered_chars": len(text),
        "available_commands": len(_available(syntax)),
        "fallback_reason": _fallback_reason(spec),
    }
    return text, metadata
