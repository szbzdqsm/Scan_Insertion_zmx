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


def _statement_rows(script: str) -> list[tuple[int, str]]:
    statements = []
    base_line = 1
    for chunk in tcl_chunks(script):
        if chunk.lstrip().startswith("#"):
            base_line += chunk.count("\n")
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
                    raw = chunk[start:index]
                    statements.append((base_line + chunk[:start].count("\n") +
                                       raw[:len(raw) - len(raw.lstrip())].count("\n"), raw))
                    start = index + 1
        raw = chunk[start:]
        statements.append((base_line + chunk[:start].count("\n") +
                           raw[:len(raw) - len(raw.lstrip())].count("\n"), raw))
        base_line += chunk.count("\n")
    return [(line, re.sub(r"\\\r?\n[ \t]*", " ", text).strip())
            for line, text in statements if text.strip()]


def _statements(script: str) -> list[str]:
    return [text for _, text in _statement_rows(script)]


def _literal(word: str) -> str | None:
    braced = word.startswith("{") and word.endswith("}")
    if braced or word.startswith('"') and word.endswith('"'):
        word = word[1:-1]
    if not braced and re.search(r"[$\[\]\\;\n]", word):
        return None
    return word if re.fullmatch(_IDENTIFIER + r"|[01]", word) else None


def _covers(usage: str, roles: frozenset[str]) -> bool:
    return usage == "all" or roles == {usage}


def signal_declaration_conflicts(script: str, words_for: Callable[[str], list[str]]) -> list[str]:
    """Compare literal declarations, not regex prefixes of ports or Tcl bodies.

    Wrapper controls are design/IP-group specifications, not partition-local
    aliases. Scan-enable existing/spec views are separate (manual pp. 13–14).
    Native probe confirms shared in/out shift controls, but rejects shared
    in/out capture controls and repeated Wrapper declarations. All final roles
    and task requirements still require actual native reports.
    """
    try:
        rows = _statement_rows(script)
    except ValueError:
        return []  # Existing Tcl syntax checks/tool own unresolved scripts.
    if any(re.search(r"\b(?:source|eval|interp|namespace|uplevel|apply|proc)\b", text)
           or (words_for(text) and words_for(text)[0] in {"if", "foreach", "for", "while"}
               and re.search(r"\b(?:set_scan_signal|remove_scan_signal|present_design|load_netlist|set_current_dft_ip_group)\b", text))
           for _, text in rows):
        return []  # A computed state is not a proven duplicate.

    def scalar(word: str) -> str | None:
        braced = word.startswith("{") and word.endswith("}")
        if braced or word.startswith('"') and word.endswith('"'):
            word = word[1:-1]
        if not braced and re.search(r"[$\[\]\\]", word):
            return None
        return word if re.fullmatch(r"[A-Za-z_][\w$/.:_-]*(?:\[\d+\])*|[01]", word) else None

    def ports(word: str) -> list[str] | None:
        # A braced list may contain distinct bus bits. Unbraced brackets are
        # command substitution, never a literal bit name.
        if word.startswith("{") and word.endswith("}"):
            items = words_for(word[1:-1])
            values = [scalar("{" + item + "}") for item in items]
        else:
            values = [scalar(word)]
        return values if values and all(v is not None for v in values) else None

    design: str | None = "(current)"
    groups: dict[str, str | None] = {}
    partition: str | None = "Default_Partition"
    declarations: dict[tuple, list[dict]] = {}
    problems = []
    for line, text in rows:
        words = words_for(text)
        if not words:
            continue
        command = words[0]
        if command == "load_netlist":
            declarations.clear()  # Old objects/specifications cannot prove a new load.
            design, partition = None, "Default_Partition"
            groups.clear()
        elif command == "present_design" and len(words) > 1:
            design = scalar(words[1])
        elif command == "set_current_scan_partition" and len(words) > 1:
            partition = scalar(words[1])
        elif command == "set_current_dft_ip_group" and len(words) > 1 and design is not None:
            groups[design] = scalar(words[1])
        elif command == "remove_scan_signal":
            # Removal semantics depend on view/group: abstain until native
            # re-observation rather than retaining a known-stale conflict.
            declarations.clear()
        if command != "set_scan_signal" or design is None:
            continue
        if len(words) % 2 != 1 or any(not words[i].startswith("-") for i in range(1, len(words), 2)):
            continue
        options = dict(zip(words[1::2], words[2::2]))
        if len(options) * 2 != len(words) - 1:
            continue
        kind = scalar(options.get("-type", ""))
        named = ports(options.get("-port", ""))
        group = groups.get(design, "(default)")
        view = scalar(options.get("-view", "spec"))
        if not kind or not named or group is None or view is None:
            continue
        if kind != "scan_enable" and "-view" in options:
            continue  # Wrapper view overrides are not a documented valid operation.
        scope = view if kind == "scan_enable" else "spec"
        for port in named:
            key = (design, group, scope, port)
            previous = declarations.setdefault(key, [])
            current = {"kind": kind, "line": line, "text": text, "partition": partition,
                       "options": options}
            for prior in previous:
                before = prior["kind"]
                pair = {before, kind}
                if pair == {"wrp_in_shift_en", "wrp_out_shift_en"}:
                    # The simple pair is measured valid; additional hookup or
                    # polarity semantics are unknown here and remain native
                    # checks, not a statically established conflict or proof.
                    continue
                if before == kind and kind not in {"clock", "reset", "wrapper_clock",
                        "wrp_in_shift_en", "wrp_out_shift_en", "wrp_in_capture_en", "wrp_out_capture_en"}:
                    continue  # Existing documented scan-enable update behavior.
                if kind.startswith("wrp_") or before.startswith("wrp_"):
                    problems.append(
                        f"Port {port} in design {design}, IP group {group}, view {scope} has conflicting "
                        f"or duplicate declarations ({before}, {kind}): candidate L{prior['line']}: "
                        f"{prior['text']!r}; candidate L{line}: {text!r}. "
                        f"Partition contexts: {prior['partition']} -> {partition}; Wrapper signal roles are "
                        "not partition-local aliases. Native capture-role conflicts and repeated Wrapper "
                        "declarations require reconciliation; the simple in/out shift pair is supported. "
                        "Use task requirements and actual native evidence to select valid declarations; "
                        "a later Wrapper declaration is not a replacement. Do not change unrelated valid settings.")
                elif pair == {"constant", "scan_enable"}:
                    problems.append(
                        f"Port {port} in design {design} has conflicting declarations ({before}, {kind}): "
                        f"candidate L{prior['line']}: {prior['text']!r}; candidate L{line}: {text!r}. "
                        "The same design/port cannot simultaneously have constant and scan_enable roles. "
                        "Reconcile the declarations using the task requirements and actual source/tool evidence; "
                        "preserve required mode constants and valid settings. Do not treat a second declaration "
                        "as an update to the first.")
                else:
                    problems.append(f"Port {port} has conflicting or duplicate declarations ({before}, {kind}); "
                                    "combine clock options and use separate wrapper control ports")
                break
            previous.append(current)
    return problems


def preflight_signal_role_problems(dofile: str, spec: str,
                                   words_for: Callable[[str], list[str]], *,
                                   signal_help: str = "") -> list[str]:
    """Reject missing literal port/usage declarations; abstain on dynamic setup.

    Dynamic Tcl cannot establish or disprove a declaration statically. Its
    actual tool report remains subject to signal_role_report_problems.
    """
    requirements = explicit_signal_role_requirements(spec)
    if not requirements:
        return []
    usage_default = re.search(r"\[-usage[^\n]*default value:\s*(all|scan|clock_gating)\b", signal_help)
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
        for option in ("-port", "-type", "-usage", "-off_state", "-view"):
            if words.count(option) > 1:
                return []
            if option in words and words.index(option) + 1 < len(words):
                value = _literal(words[words.index(option) + 1])
                if value is None:
                    return []
                options[option] = value
        if "-usage" not in options and usage_default:
            options["-usage"] = usage_default[1]
        if options.get("-port"):
            declarations.setdefault(options["-port"], []).append(options)
    problems = []
    for requirement in requirements:
        specified = [options for options in declarations.get(requirement.port, [])
                     if options.get("-type") == "scan_enable" and options.get("-view", "spec") == "spec"]
        # Native specification updates use the last value for this port; an
        # existing-chain view does not configure newly inserted scan cells.
        matches = [options for options in specified[-1:]
                   if _covers(options.get("-usage", ""), requirement.roles)
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
