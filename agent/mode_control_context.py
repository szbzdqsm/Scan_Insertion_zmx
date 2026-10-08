"""Conservative source-only mode-port hints and checks for literal Dofile settings.

These checks neither edit a netlist nor prove scan semantics. Names are weak
investigation hints. A literal setting is required only when the task supplies
its value and the corresponding scalar input is established from source.
"""
from __future__ import annotations

import json
from pathlib import Path
import re
from typing import Callable, Any

from clock_association_recipe import _chunks, _literal, _readonly_word, _safe_non_scope, _text, _TOOL_CONFIGURATION


_IDENTIFIER = r"[A-Za-z_$][\w$]*"
_MODULE = re.compile(rf"^\s*module\s+({_IDENTIFIER})\b")
_INSTANCE = re.compile(rf"^\s*({_IDENTIFIER})\s+(?:\\\S+|{_IDENTIFIER})\s*\(")
_PARAMETERIZED_INSTANCE = re.compile(rf"^\s*{_IDENTIFIER}\s*#\s*\(")
_DECLARATION_START = re.compile(r"^\s*(?:input|output|inout)\b")
_HEADER_DIRECTION = re.compile(r"\b(?:input|output|inout)\b")
_ENDMODULE = re.compile(r"\bendmodule\b")
_WIDTH = re.compile(r"\[(\d+)\s*:\s*(\d+)\]\s*")
_PORT_IDENTIFIER = re.compile(_IDENTIFIER)
_DIRECTION = re.compile(r"^(input|output|inout)\s+", re.I)
_TYPES = re.compile(r"^(?:(?:wire|reg|logic|tri|signed|unsigned)\s+)+")
_MODE_NAME = re.compile(r"^(scan_mode|test_mode|mbist_mode|mbist_en|mbist_enable)(?:_(n|b|l))?(?:_(i|in))?$", re.I)
_CONSTANT_LANGUAGE = re.compile(
    r"常量|锁定|锁死|固定|\bconstants?\b|\btie(?:d)?\b|\bheld\b|\block(?:ed)?\b", re.I)
_AMBIGUOUS_VALUE_CONTEXT = re.compile(
    r"禁止|不允许|不得|不能|不要|功能模式|正常模式|"
    r"\b(?:if|when|unless|never)\b|\b(?:must|shall|do)\s+not\b|\bnot\s+allowed\b|"
    r"\bfunctional\s+mode\b", re.I)
_VALUE = r"(?:1'[bB][01]|[01]|high|low|高电平|低电平)"
_AFTER_PORT_VALUE = re.compile(
    r"\s*[`'\"]?\s*(?:(?:must|shall|should)\s+be\s+)?(?:(?:is|(?:held|tied|locked|set)\s+(?:to|at)|to|"
    r"(?:应|必须|需|需要)?(?:设置|设定|配置|锁定|固定|保持|置)?(?:成|为|到|于)|[=:：])\s*)?"
    r"(?:(?:constant(?:\s+value)?|常量(?:值)?|logic)\s*(?:of|[=:：]|为)?\s*)?"
    r"(?P<value>" + _VALUE + r")(?![\w'])", re.I)


def _uncomment(raw: str, blocked: bool) -> tuple[str, bool]:
    # Most flattened-netlist lines contain neither kind of comment. Keep the
    # full state machine for slash-bearing lines and open block comments.
    if not blocked and "/" not in raw:
        return raw, False
    parts = []
    while raw:
        if blocked:
            end = raw.find("*/")
            if end < 0:
                break
            raw, blocked = raw[end + 2:], False
        comment, start = raw.find("//"), raw.find("/*")
        if comment >= 0 and (start < 0 or comment < start):
            parts.append(raw[:comment])
            break
        if start < 0:
            parts.append(raw)
            break
        parts.append(raw[:start])
        raw, blocked = raw[start + 2:], True
    return "".join(parts), blocked


def _declarations(text: str, source: str, line: int) -> tuple[dict[str, dict], bool]:
    """Read simple ANSI entries or a single non-ANSI declaration, fail closed."""
    ports: dict[str, dict] = {}
    direction, scalar = "", True
    for entry in text.strip().rstrip(";").split(","):
        entry = entry.strip()
        found = _DIRECTION.match(entry)
        if found:
            direction, scalar = found.group(1).lower(), True
            entry = entry[found.end():].strip()
            entry = _TYPES.sub("", entry).strip()
            if entry.startswith("["):
                width = _WIDTH.match(entry)
                if not width:
                    return {}, False
                scalar = width.group(1) == width.group(2)
                entry = entry[width.end():].strip()
        if not direction or not _PORT_IDENTIFIER.fullmatch(entry):
            return {}, False
        if entry in ports:
            return {}, False
        ports[entry] = {"direction": direction, "scalar": scalar, "source": source, "line": line}
    return ports, bool(ports)


def mode_control_hints(paths: list[Path]) -> list[dict[str, Any]]:
    """Stream input Verilog; retain only headers, declarations and module types.

    Escaped/parameterized headers, duplicate modules, unparsed declarations,
    oversized port lists, or uncertain hierarchy disable strict checks.
    """
    modules: dict[str, dict] = {}
    child_types: set[str] = set()
    hierarchy_ambiguous = False
    for path in paths:
        blocked = False
        current: dict | None = None
        header = ""
        header_pending = False
        declaration = ""
        declaration_line = 0
        with path.open(encoding="utf-8", errors="replace") as stream:
            for number, raw in enumerate(stream, 1):
                line, blocked = _uncomment(raw, blocked)
                line = line.strip()
                if not line:
                    continue
                found = _MODULE.match(line) if line.startswith("module") else None
                if found:
                    name = found.group(1)
                    if name in modules or len(modules) >= 100000:
                        return []
                    current = {"root": name, "ports": {}, "header_ports": set(), "source_ports_complete": True,
                               "source": str(path), "line": number}
                    modules[name] = current
                    header = line[found.end():].strip()
                    declaration = ""
                    header_pending = True
                elif current is not None and header_pending:
                    header += " " + line
                if current is None:
                    continue
                if header_pending:
                    if len(header) > 65536:
                        current["source_ports_complete"] = False
                        header_pending = False
                    elif ";" not in header:
                        continue
                    else:
                        header_pending = False
                        body = header.split(";", 1)[0].strip()
                        if not body or body == "()":
                            continue
                        if not (body.startswith("(") and body.endswith(")")):
                            current["source_ports_complete"] = False
                            continue
                        body = body[1:-1].strip()
                        if _HEADER_DIRECTION.search(body):
                            ports, complete = _declarations(body, str(path), current["line"])
                            current["ports"].update(ports)
                            current["header_ports"].update(ports)
                            current["source_ports_complete"] &= complete
                        else:
                            names = [word.strip() for word in body.split(",")]
                            if all(_PORT_IDENTIFIER.fullmatch(word) for word in names) and len(set(names)) == len(names):
                                current["header_ports"].update(names)
                            else:
                                current["source_ports_complete"] = False
                        # The declaration is already parsed; same-line endmodule
                        # is harmless because the next module resets the scope.
                        continue
                if declaration:
                    declaration += " " + line
                elif line.startswith(("input", "output", "inout")) and _DECLARATION_START.match(line):
                    declaration, declaration_line = line, number
                if declaration:
                    if len(declaration) > 65536:
                        current["source_ports_complete"] = False
                        declaration = ""
                    elif ";" in declaration:
                        ports, complete = _declarations(declaration.split(";", 1)[0], str(path), declaration_line)
                        if current["ports"].keys() & ports.keys():
                            current["source_ports_complete"] = False
                        current["ports"].update(ports)
                        current["source_ports_complete"] &= complete
                        declaration = ""
                else:
                    # Pin continuations cannot match either instance pattern;
                    # no parentheses means neither pattern could match.
                    instance = _INSTANCE.match(line) if "(" in line and not line.startswith(".") else None
                    if instance and instance.group(1) not in {"module", "assign", "input", "output", "inout"}:
                        child_types.add(instance.group(1))
                    if "#" in line and _PARAMETERIZED_INSTANCE.match(line):
                        hierarchy_ambiguous = True
                if len(current["ports"]) > 4096:
                    current["source_ports_complete"] = False
                    current["ports"].clear()
                if "endmodule" in line and _ENDMODULE.search(line):
                    if declaration:
                        current["source_ports_complete"] = False
                    current = None
    result = []
    for name in sorted(modules.keys() - child_types):
        module = modules[name]
        ports = module["ports"]
        complete = module["source_ports_complete"] and not hierarchy_ambiguous and module["header_ports"] == ports.keys()
        inputs = {port: detail for port, detail in ports.items() if detail["direction"] == "input"}
        candidates = []
        for port, detail in sorted(inputs.items()):
            found = _MODE_NAME.fullmatch(port)
            if found:
                candidates.append({"port": port, "role": "mbist" if found.group(1).lower().startswith("mbist") else "scan_test",
                                   "active_level": None, "name_polarity_hint": 0 if found.group(2) else 1,
                                   "confidence": "name_hint_only" if detail["scalar"] else "vector_not_inferred",
                                   **detail})
        result.append({"root": name, "input_ports": sorted(inputs),
                       "scalar_input_ports": sorted(port for port, detail in inputs.items() if detail["scalar"]),
                       "mode_candidates": candidates,
                       "source_ports_complete": bool(complete), "source": module["source"], "line": module["line"]})
    return result


def requested_constant_modes(spec: str) -> set[str]:
    """Recognize explicit constant requirements, never generic Scan Insertion."""
    requested = set()
    for sentence in re.split(r"[\n;；。]", spec):
        constant = re.search(r"常量|\bconstants?\b|锁定|锁死|tie(?:d)?\s+(?:high|low|to)|held\s+(?:at|high|low)", sentence, re.I)
        if not constant:
            continue
        negative_scan = re.search(r"不进入.{0,8}(?:扫描|scan)|不.{0,8}扫描测试|disable.{0,12}scan|not.{0,12}scan", sentence, re.I)
        if not negative_scan and re.search(r"(?:进入|处于|使能).{0,12}扫描(?:测试)?模式|(?:enter|enable|in).{0,15}scan(?:[- ]test)?\s+mode", sentence, re.I):
            requested.add("scan_test")
        if re.search(r"不进入\s*MBIST|(?:禁用|禁止|关闭).{0,12}MBIST|(?:disable|no|not(?:\s+enter)?|without).{0,12}MBIST", sentence, re.I):
            requested.add("mbist")
    literal_binding = any(
        _CONSTANT_LANGUAGE.search(line) and not _AMBIGUOUS_VALUE_CONTEXT.search(line) and
        any(_AFTER_PORT_VALUE.match(line[token.end():]) for token in _PORT_IDENTIFIER.finditer(line))
        for line in spec.splitlines())
    constant_table = any("|" in line and any(
        re.fullmatch(r"常量(?:值)?|锁定值|constant(?:[ _-]*value)?|ConstantValue", cell.strip().strip("`* "), re.I)
        for cell in line.strip().strip("|").split("|")) for line in spec.splitlines())
    if not requested and (literal_binding or constant_table):
        # A literal requirement can name an unfamiliar control rather than a
        # conventional scan/test/MBIST port. This enables source investigation;
        # _requirements still has to bind a value to an actual scalar input.
        requested.add("explicit_literal")
    return requested


def _value(text: str) -> int | None:
    return {"0": 0, "1": 1, "1'b0": 0, "1'b1": 1,
            "low": 0, "high": 1, "低电平": 0, "高电平": 1}.get(text.strip().lower())


def _requirements(hint: dict, spec: str) -> tuple[dict[str, dict], dict[str, str]]:
    """Bind exact task values to scalar source inputs, abstaining on ambiguity.

    Conventional names/suffixes and successful script declarations are never
    proof of functional mode polarity. This parser accepts direct bindings and
    explicit constant-value tables; it does not infer pairs stated respectively
    or interpret general descriptions of entering a test mode.
    """
    if not hint.get("source_ports_complete"):
        return {}, {}
    scalar = set(hint.get("scalar_input_ports", [])) & set(hint.get("input_ports", []))
    values: dict[str, list[dict]] = {}
    constant_column = None
    for number, line in enumerate(spec.splitlines(), 1):
        if _AMBIGUOUS_VALUE_CONTEXT.search(line):
            # A condition before a comma still scopes the later assignment.
            # Do not turn a functional-mode or prohibited setting into an
            # unconditional scan-test constant.
            constant_column = None
            continue
        if "|" in line:
            cells = [cell.strip().strip("`* ") for cell in line.strip().strip("|").split("|")]
            column = next((index for index, cell in enumerate(cells)
                           if re.fullmatch(r"常量(?:值)?|锁定值|constant(?:[ _-]*value)?|ConstantValue", cell, re.I)), None)
            if column is not None:
                constant_column = column
                continue
            if constant_column is not None and constant_column < len(cells):
                ports = [cell for index, cell in enumerate(cells) if index != constant_column and cell in scalar]
                value = _value(cells[constant_column])
                if len(ports) == 1 and value is not None and not _AMBIGUOUS_VALUE_CONTEXT.search(line):
                    values.setdefault(ports[0], []).append({"value": value, "source": "task_spec.md",
                                                           "line": number, "excerpt": line,
                                                           "confidence": "explicit_task_value"})
                elif not all(re.fullmatch(r"[:\-\s]+", cell) for cell in cells):
                    constant_column = None
        else:
            constant_column = None
        for clause in re.split(r"[;；。，,]", line):
            if not _CONSTANT_LANGUAGE.search(clause) or _AMBIGUOUS_VALUE_CONTEXT.search(clause):
                continue
            for token in _PORT_IDENTIFIER.finditer(clause):
                port = token.group()
                if port not in scalar:
                    continue
                match = _AFTER_PORT_VALUE.match(clause[token.end():])
                if match and (value := _value(match.group("value"))) is not None:
                    values.setdefault(port, []).append({"value": value, "source": "task_spec.md",
                                                       "line": number, "excerpt": line,
                                                       "confidence": "explicit_task_value"})
    expected, ambiguous = {}, {}
    for port, evidence in sorted(values.items()):
        if len({item["value"] for item in evidence}) == 1:
            expected[port] = evidence[0]
        else:
            ambiguous[port] = "conflicting_explicit_task_values"
    return expected, ambiguous


def _expected(hint: dict, spec: str) -> dict[str, int]:
    return {port: evidence["value"] for port, evidence in _requirements(hint, spec)[0].items()}


def mode_control_context(paths: list[Path], spec: str, *, hints: list[dict] | None = None, limit: int = 12000) -> str:
    candidates = mode_control_hints(paths) if hints is None else hints
    rows = []
    for hint in candidates:
        requirements, unverified = _requirements(hint, spec)
        rows.append({**hint, "required_literal_constants": {port: evidence["value"] for port, evidence in requirements.items()},
                     "constant_requirement_evidence": requirements, "unverified_constant_requirements": unverified})
    return ("Mode-port candidates from read-only input module declarations. Conventional names and suffixes are "
            "weak hints, not proof of functional polarity. active_level is unknown unless actual functional evidence "
            "establishes it. Do not infer a required constant from a name_polarity_hint. Only explicit task values "
            "bound to actual scalar inputs appear in required_literal_constants, with task source lines. Generic "
            "scan-test/MBIST descriptions require further source and tool investigation; unknown values remain unverified. "
            "Do not invent test_mode when the input top instead has scan_mode; do not treat generic scan-enable, clocks, "
            "resets or functional inputs as these mode constants. Missing/ambiguous names or unsupported HDL require actual "
            "source/tool investigation. Configure required constants with set_scan_signal -type constant -port PORT "
            "-constant_value 0/1. Any input listed in required_literal_constants MUST remain type constant; "
            "configuring it as scan_enable does not satisfy the constant-mode requirement. Use a separate scan-enable "
            "control (for example a new scan_enable port when allowed), preserving an existing dedicated enable when "
            "available. Verify both mode constants in actual scan_signal reports. This is structural guidance, not a "
            "DRC or post-scan proof.\n" +
            json.dumps(rows, ensure_ascii=False, indent=2))[:limit]


def mode_control_problems(script: str, spec: str, hints: list[dict],
                          words_for: Callable[[str], list[str]]) -> list[str]:
    """Reject nonexistent or missing/wrong constant modes in simple literal Tcl.

    Only reviewed output/directory guards and read-only queries are transparent.
    Evaluated Tcl, unknown bodies, or dynamic relevant declarations disable this
    narrow check. Literal continuations and command separators are supported.
    """
    expected_by_root = {hint.get("root"): _expected(hint, spec) for hint in hints if hint.get("source_ports_complete")}
    roots = {hint.get("root"): hint for hint in hints
             if hint.get("source_ports_complete") and (requested_constant_modes(spec) or expected_by_root[hint.get("root")])}
    if not roots:
        return []
    design = ""
    seen_roots: set[str] = set()
    declared: dict[tuple[str, str], list[tuple[str, str]]] = {}
    nonexistent = []
    try:
        chunks = _chunks(script)
    except ValueError:
        return []
    for chunk in chunks:
        line = _text(chunk)
        if not line or line.startswith("#"):
            continue
        words = words_for(line)
        if not words:
            return []
        if _safe_non_scope(words, words_for):
            continue
        if words[0] not in _TOOL_CONFIGURATION or not all(_readonly_word(word, words_for) for word in words[1:]):
            return []
        if words[0] == "load_netlist":
            design = ""
            if "-top" in words:
                if words.count("-top") != 1 or words.index("-top") + 1 >= len(words):
                    return []
                design = _literal(words[words.index("-top") + 1])
                if not design:
                    return []
                if design in roots:
                    seen_roots.add(design)
        if words[0] == "present_design":
            if len(words) != 2 or not (design := _literal(words[1])):
                return []
            if design in roots:
                seen_roots.add(design)
        if words[0] != "set_scan_signal" or design not in roots:
            continue
        if len(words[1:]) % 2:
            return []
        options = {key: _literal(value) for key, value in zip(words[1::2], words[2::2])}
        if len(options) != len(words[1::2]):
            return []
        if any(value is None for value in options.values()):
            return []
        ports = options.get("-port", "").split()
        if any(re.search(r"[$\[\]\\]", port) for port in ports):
            return []
        expected = expected_by_root[design]
        for port in ports:
            if _MODE_NAME.fullmatch(port) and port not in roots[design].get("input_ports", []):
                nonexistent.append(f"Mode control {port} is not a real input of {design}; use the input-source port declarations")
            if port in expected:
                if re.search(r"[$\[\]\\]", options.get("-type", "") + options.get("-constant_value", "")):
                    return []
                declared.setdefault((design, port), []).append((options.get("-type", ""), options.get("-constant_value", "")))
    problems = nonexistent
    for design in sorted(seen_roots):
        for port, value in expected_by_root[design].items():
            settings = declared.get((design, port), [])
            if settings != [("constant", str(value))]:
                problems.append(f"Task requires the real input {design}/{port} locked as -type constant -constant_value {value}; "
                                "the literal setting is missing, conflicting, or has the wrong type/value")
    return list(dict.fromkeys(problems))


def _mode_control_scope(script: str, spec: str, hints: list[dict],
                        words_for: Callable[[str], list[str]]) -> tuple[str, dict[str, int]] | None:
    """Identify one literal selected source root; unknown Tcl leaves it unverified."""
    roots = {hint.get("root"): expected for hint in hints if (expected := _expected(hint, spec))}
    if not roots:
        return None
    try:
        chunks = _chunks(script)
    except ValueError:
        return None
    design = ""
    selected = set()
    for chunk in chunks:
        text = _text(chunk)
        if not text or text.startswith("#"):
            continue
        words = words_for(text)
        if not words:
            return None
        if _safe_non_scope(words, words_for):
            continue
        if words[0] not in _TOOL_CONFIGURATION or not all(_readonly_word(word, words_for) for word in words[1:]):
            return None
        if words[0] == "load_netlist":
            design = ""
            if "-top" in words:
                if words.count("-top") != 1 or words.index("-top") + 1 >= len(words):
                    return None
                design = _literal(words[words.index("-top") + 1])
                if not design:
                    return None
                selected.add(design)
        if words[0] == "present_design":
            if len(words) != 2 or not (design := _literal(words[1])):
                return None
            selected.add(design)
        if words[0] == "set_scan_signal":
            if len(words[1:]) % 2 or len(set(words[1::2])) != len(words[1::2]):
                return None
            if any(_literal(word) is None for word in words[2::2]):
                return None
        if words[0] == "exit":
            break
    return (design, roots[design]) if len(selected) == 1 and design in roots else None


def mode_control_report_problems(paths: list[Path], script: str, spec: str, hints: list[dict],
                                 words_for: Callable[[str], list[str]]) -> list[str]:
    """Check actual typed mode rows for a proven script root or unique source top.

    Unknown Tcl cannot waive an unambiguous requirement on the only input top.
    If neither a script root nor one complete source top with unique scalar
    controls is available, this check stays unverified. A known target requires
    a real Design block and typed constant rows. Script text is never proof.
    """
    scope = _mode_control_scope(script, spec, hints, words_for)
    if scope is None and len(hints) == 1:
        hint = hints[0]
        expected = _expected(hint, spec)
        # A unique source top and explicit task-value bindings establish scope.
        # A conventional mode name alone cannot grant this fallback.
        if (hint.get("source_ports_complete") and expected
                and re.fullmatch(_IDENTIFIER, hint.get("root", ""))):
            scope = hint["root"], expected
    if scope is None:
        return []
    root, expected = scope
    required = {"Port", "SignalType", "ConstantValue"}
    seen = set()
    problems = []
    for path in paths:
        if path.suffix.lower() != ".rpt" or not path.is_file():
            continue
        design = ""
        columns: list[tuple[str, int]] = []
        with path.open(encoding="utf-8", errors="replace") as stream:
            for number, line in enumerate(stream, 1):
                design_line = re.fullmatch(r"\s*Design:\s*(\S+)\s*", line)
                if design_line:
                    design = design_line.group(1)
                    columns = []
                    continue
                names = [(match.group(), match.start()) for match in re.finditer(r"\S+", line)]
                labels = {name for name, _ in names}
                if "Port" in labels and ("SignalType" in labels or "ConstantValue" in labels or "signal" in path.name.lower()):
                    columns = names
                    if design == root and not required <= labels:
                        problems.append(f"Actual signal report {path}:{number} (Design {root}) lacks typed mode columns: " +
                                        ", ".join(sorted(required - labels)))
                    continue
                if design != root or not columns or not required <= {name for name, _ in columns}:
                    continue
                if not line.strip() or line.lstrip().startswith("-"):
                    continue
                row = {name: line[start:columns[index + 1][1] if index + 1 < len(columns) else None].strip()
                       for index, (name, start) in enumerate(columns)}
                port = row["Port"]
                if port not in expected:
                    continue
                if row["SignalType"] != "constant" or row["ConstantValue"] != str(expected[port]):
                    problems.append(f"Actual signal report {path}:{number} (Design {root}) reports {port} as "
                                    f"SignalType={row['SignalType']!r}, ConstantValue={row['ConstantValue']!r}; "
                                    f"task requires constant {expected[port]}")
                else:
                    seen.add(port)
    for port in sorted(expected.keys() - seen):
        problems.append(f"Actual signal reports do not prove Design {root} input {port} as constant {expected[port]} "
                        "with Port/SignalType/ConstantValue columns")
    return list(dict.fromkeys(problems))
