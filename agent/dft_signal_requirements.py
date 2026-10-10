"""Check explicitly named scan and clock-gating controls against actual tool roles.

Only clear task statements become requirements. Neither identifier spelling nor
unrelated controls establish a role or its inactive level. Tcl is never evaluated.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re
from typing import Callable

from dofile_recipe import tcl_chunks
from report_validation import report_rows


_IDENTIFIER = r"[A-Za-z_][\w$]*(?:\[\d+\])?"
_QUOTED_NAME = re.compile(r"`(" + _IDENTIFIER + r")`")
_NAMED_PORT = re.compile(
    r"(?:端口(?:名(?:称)?)?|\b(?:port|signal)\s+)[\s:：]*`?(" + _IDENTIFIER + r")`?", re.I)
_ROLE_NAMES = {"scan_enable", "clock_gating", "scan", "all", "ICG", "SFF", "FF", "shift", "capture"}
_SCAN = re.compile(r"scan[_ -]enable|扫描使能", re.I)
_SCAN_CELLS = re.compile(r"\bSFF\b|扫描\s*(?:FF|触发器|单元)|scan\s*(?:FF|flip.flop|cell)", re.I)
_SHIFT_CAPTURE = re.compile(r"shift\s*(?:/|→|to|and)\s*capture|移位.{0,12}捕获", re.I)
_GATES = re.compile(r"\bICG\b|时钟门控|clock[_ -]gat(?:ing|es?)", re.I)
_GATE_ACTION = re.compile(r"驱动|重连|控制|使能|保持|导通|打开|旁路|确保|覆盖|用于|connect|driv|control|enable|keep|hold|bypass|cover", re.I)
_UNCERTAIN = re.compile(
    r"不允许|不得|禁止|不能|不可|不要|不用于|不是|不作为|无需|不需要|未要求|"
    r"如果|仅在|只有|可选|可能|建议|例如|示例|反例|假设|"
    r"\b(?:not|never|cannot|if|when|unless|optional|may|might|example|assume)\b", re.I)
_OFF_STATE = re.compile(r"off[_ -]state\s*(?:=|:|：|为)?\s*([01])\b", re.I)
_OTHER_ROLE = re.compile(r"(?:配置为|作为|设为|\bas\s+|\btype\s+)\s*`?(?:reset\b|constant\b|clock\b|复位|常量|时钟信号)", re.I)


@dataclass(frozen=True)
class SignalRoleRequirement:
    port: str
    roles: frozenset[str]
    off_state: str | None = None


def _roles(text: str) -> set[str]:
    gate = bool(_GATES.search(text) and _GATE_ACTION.search(text) or re.search(r"\bclock_gating\b", text))
    scan_cells = bool(_SCAN_CELLS.search(text) and
                      (_SHIFT_CAPTURE.search(text) or gate and re.search(r"覆盖|两类|\bboth\b|\bcover", text, re.I)))
    scan = scan_cells or bool(_SCAN.search(text) and not gate)
    return ({"scan"} if scan else set()) | ({"clock_gating"} if gate else set())


def _names(text: str) -> list[str]:
    named = _NAMED_PORT.findall(text)
    quoted = list(_QUOTED_NAME.finditer(text))
    # A labelled port binds the action even when the sentence also quotes an
    # instance or an ICG cell type. Unlabelled statements need a single name.
    subject = (len(quoted) == 1 and re.fullmatch(
        r"\s*(?:[-*+]|\d+[.)、])?\s*(?:(?:使用|将|配置|定义|信号|Use|Declare|Configure)\s*)?", text[:quoted[0].start()], re.I))
    if named:
        return list(dict.fromkeys(named))
    candidates = [quoted[0][1]] if subject else []
    return [name for name in dict.fromkeys(candidates) if name.lower() not in {s.lower() for s in _ROLE_NAMES}]


def _cells(line: str) -> list[str]:
    return [cell.strip() for cell in line.strip().strip("|").split("|")]


def explicit_signal_role_requirements(spec: str) -> list[SignalRoleRequirement]:
    """Extract conservative port-bound requirements from prose and Markdown tables.

    Conditions, prohibitions, examples, conflicting levels and contradictory
    signal types suppress inference for their named port. A qualified subset of
    gates may still have an unconditional, explicitly named control port.
    """
    wanted: dict[str, set[str]] = {}
    levels: dict[str, set[str]] = {}
    denied: set[str] = set()
    global_levels: set[str] = set()

    def observe(text: str, names: list[str] | None = None, inherited_roles: set[str] | None = None) -> None:
        ports = _names(text) if names is None else names
        roles = _roles(text) | (inherited_roles or set())
        if _UNCERTAIN.search(text) or _OTHER_ROLE.search(text):
            denied.update(ports)
            return
        states = set(_OFF_STATE.findall(text))
        if not ports and _SCAN.search(text) and states:
            global_levels.update(states)
        for port in ports:
            levels.setdefault(port, set()).update(states if len(ports) == 1 else set())
        if not roles:
            return
        for port in ports:
            wanted.setdefault(port, set()).update(roles)

    lines = spec.splitlines()
    index = 0
    context = ""
    fenced = False
    example_depth: int | None = None
    while index < len(lines):
        line = lines[index].strip()
        index += 1
        if line.startswith(("```", "~~~")):
            fenced = not fenced
            continue
        if fenced or line.startswith(">"):
            continue
        heading = re.match(r"^(#{1,6})\s+(.+)", line)
        if heading:
            depth = len(heading[1])
            if example_depth is not None and depth <= example_depth:
                example_depth = None
            if re.search(r"示例|反例|例如|\bexamples?\b", heading[2], re.I):
                example_depth = depth
            context = ""
            continue
        if example_depth is not None or not line:
            continue
        if line.startswith("|") and index < len(lines) and all(
                re.fullmatch(r":?-{2,}:?", cell.replace(" ", "")) for cell in _cells(lines[index])):
            headers = _cells(line)
            index += 1
            inherited = _roles(context) if not _UNCERTAIN.search(context) else set()
            while index < len(lines) and lines[index].strip().startswith("|"):
                row = _cells(lines[index])
                index += 1
                if len(row) != len(headers):
                    continue
                for column, header in enumerate(headers):
                    header = header.strip("` ")
                    scan_column = bool(re.fullmatch(r"scan[_ -]enable", header, re.I))
                    port_column = bool(re.fullmatch(r"端口|端口名|Port|Signal|使能信号|enable signal", header, re.I))
                    if not (scan_column or port_column):
                        continue
                    port = row[column].strip("` ")
                    if not re.fullmatch(_IDENTIFIER, port):
                        continue
                    roles = {"scan"} if scan_column else set()
                    if re.fullmatch(r"使能信号|enable signal", header, re.I):
                        roles |= inherited
                    text = " ".join(row)
                    if _UNCERTAIN.search(context):
                        text = context + " " + text
                    observe(text, [port], roles)
            context = ""
            continue
        if line.startswith("|"):
            continue
        # Wraps in a list paragraph retain the explicit name on its first line.
        while index < len(lines) and lines[index].strip() and lines[index].startswith((" ", "\t")):
            line += " " + lines[index].strip()
            index += 1
        context = line
        if _UNCERTAIN.search(line):
            observe(line)
            continue
        for clause in re.split(r"[;；。]|[，,](?=\s*(?:`" + _IDENTIFIER + r"`|端口|\b(?:port|signal)\b))", line):
            observe(clause)

    scan_ports = [port for port, roles in wanted.items() if "scan" in roles and port not in denied]
    if len(scan_ports) == 1 and global_levels:
        levels.setdefault(scan_ports[0], set()).update(global_levels)
    return [SignalRoleRequirement(port, frozenset(roles), next(iter(levels[port])) if levels[port] else None)
            for port, roles in sorted(wanted.items()) if port not in denied and len(levels[port]) <= 1]


def _statements(script: str) -> list[str]:
    statements = []
    for chunk in tcl_chunks(script):
        if chunk.lstrip().startswith("#"):
            continue
        braces = brackets = 0
        quoted = escaped = False
        start = 0
        for index, char in enumerate(chunk):
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"' and not braces:
                quoted = not quoted
            elif not quoted:
                braces += (char == "{") - (char == "}")
                brackets += (char == "[") - (char == "]")
                if char == ";" and not (braces or brackets):
                    statements.append(chunk[start:index])
                    start = index + 1
        statements.append(chunk[start:])
    return [re.sub(r"\\\r?\n[ \t]*", " ", statement).strip() for statement in statements if statement.strip()]


def _literal(word: str) -> str | None:
    braced = word.startswith("{") and word.endswith("}")
    if braced or word.startswith('"') and word.endswith('"'):
        word = word[1:-1]
    if not braced and re.search(r"[$\[\]\\;\n]", word):
        return None
    return word if re.fullmatch(_IDENTIFIER + r"|[01]", word) else None


def _covers(usage: str, roles: frozenset[str]) -> bool:
    return usage == "all" or roles == {usage}


def preflight_signal_role_problems(dofile: str, spec: str,
                                   words_for: Callable[[str], list[str]]) -> list[str]:
    """Reject missing literal port/usage declarations; abstain on dynamic setup.

    Dynamic Tcl cannot establish or disprove a declaration statically. Its
    actual tool report remains subject to signal_role_report_problems.
    """
    requirements = explicit_signal_role_requirements(spec)
    if not requirements:
        return []
    declarations: dict[str, list[dict[str, str | None]]] = {}
    try:
        statements = _statements(dofile)
    except ValueError:
        return []
    for statement in statements:
        words = words_for(statement)
        if not words:
            return []
        if words[0] in {"source", "eval", "interp", "namespace", "uplevel", "apply"}:
            return []
        if words[0] != "set_scan_signal":
            if re.search(r"\bset_scan_signal\b", statement):
                return []
            continue
        options = {}
        for option in ("-port", "-type", "-usage", "-off_state"):
            if words.count(option) > 1:
                return []
            if option in words and words.index(option) + 1 < len(words):
                value = _literal(words[words.index(option) + 1])
                if value is None:
                    return []
                options[option] = value
        if options.get("-port"):
            declarations.setdefault(options["-port"], []).append(options)
    problems = []
    for requirement in requirements:
        matches = [options for options in declarations.get(requirement.port, [])
                   if options.get("-type") == "scan_enable" and _covers(options.get("-usage", ""), requirement.roles)
                   and (requirement.off_state is None or options.get("-off_state") == requirement.off_state)]
        if not matches:
            role = "/".join(sorted(requirement.roles))
            level = f" and explicit off_state {requirement.off_state}" if requirement.off_state is not None else ""
            problems.append(f"Task explicitly requires port {requirement.port} as scan_enable with usage covering {role}{level}; "
                            "no matching literal set_scan_signal declaration was found. A different port cannot satisfy this role.")
    return problems


def signal_role_report_problems(paths: list[Path], spec: str) -> list[str]:
    """Require port-specific SignalType/Usage rows from actual signal reports."""
    requirements = explicit_signal_role_requirements(spec)
    if not requirements:
        return []
    rows = []
    for path in paths:
        if path.suffix.lower() in {".rpt", ".report", ".txt", ".log"} and path.is_file():
            rows.extend(report_rows(path, {"Port", "SignalType", "Usage"}))
    problems = []
    for requirement in requirements:
        named = [row for row in rows if row.get("Port") == requirement.port]
        valid = [row for row in named if row.get("SignalType", "").split("(")[0] == "scan_enable"
                 and _covers(row.get("Usage", ""), requirement.roles)
                 and (requirement.off_state is None or row.get("OffState") == requirement.off_state)]
        if not valid or len(valid) != len(named):
            role = "/".join(sorted(requirement.roles))
            level = f" and off_state {requirement.off_state}" if requirement.off_state is not None else ""
            problems.append(f"Actual typed signal report does not consistently prove port {requirement.port} "
                            f"as scan_enable with usage covering {role}{level}. Other ports and Dofile text are not signal-role evidence.")
    return problems
