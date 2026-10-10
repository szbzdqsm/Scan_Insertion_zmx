"""Compile input-derived scan-segment recipes into an auditable complete Dofile."""
from __future__ import annotations

import re
from typing import Any


def tcl_chunks(script: str) -> list[str]:
    chunks = []
    current = ""
    braces = brackets = 0
    quoted = escaped = comment = False
    line_start = True
    for character in script:
        continuation = escaped and character == "\n"
        current += character
        if comment:
            if character == "\n":
                comment = False
                line_start = True
        elif escaped:
            escaped = False
        elif character == "\\":
            escaped = True
        elif character == "#" and line_start:
            comment = True
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
        if character == "\n" and not continuation and not (braces or brackets or quoted or escaped):
            chunks.append(current)
            current = ""
            line_start = True
        elif not character.isspace():
            line_start = False
        if braces < 0 or brackets < 0:
            raise ValueError("Unbalanced Tcl groups in the proposed Dofile")
    if braces or brackets or quoted or escaped:
        raise ValueError("Incomplete Tcl groups in the proposed Dofile")
    if current:
        chunks.append(current)
    return chunks


def normalize_unrequested_counts(script: str, spec: str) -> str:
    # Imported lazily: report_validation also consumes this module's Tcl lexer.
    from report_validation import chain_role_requirements
    if 'I' in chain_role_requirements(spec):
        return script
    if not spec or re.search(r"chain_count|链(?:数|数量)|\d+\s*条(?:扫描)?链|number.{0,20}chains", spec, re.I):
        return script
    return re.sub(r"(?m)^(\s*set_scan_cfg\b[^\n]*)", lambda match:
                  re.sub(r"\s+-chain_count\s+\S+", "", match.group()), script)


def shift_segment_recipe(groups: list[dict[str, Any]], spec: str = "") -> tuple[str, list[str]]:
    blocks = ["# Agent recipe from actual input shift-register connections\n",
              "set_scan_cfg -respect_sff_se_connection true\n"]
    references = [blocks[-1].strip()]
    for line in spec.splitlines():
        maximum = re.search(r"(?:长度|length)[^\d]{0,60}(\d+)", line, re.I)
        if "wrapper" in line.lower() and maximum:
            statement = "set_wrapper_cfg -max_length " + maximum.group(1)
            blocks.append(statement + "\n")
            references.append(statement)
            break
    for number, group in enumerate(groups):
        coordinates = " ".join("{" + " ".join(str(index) for index in indices) + "}" for indices in group["index_tuples"])
        variable_count = len(group["index_tuples"][0])
        blocks.append(f"set agent_segment_index_{number} 0\nforeach agent_coordinates_{number} {{{coordinates}}} {{\n")
        for index in range(variable_count):
            blocks.append(f"    set agent_i{index}_{number} [lindex $agent_coordinates_{number} {index}]\n")
        def endpoint(template: str, pin: str) -> str:
            arguments = []
            def replace(match: re.Match[str]) -> str:
                arguments.append(f"$agent_i{match.group(1)}_{number}")
                return "%d"
            pattern = re.sub(r"\{i(\d+)\}", replace, template) + "/" + pin
            if arguments:
                return "[format {" + pattern + "} " + " ".join(arguments) + "]"
            return "{" + pattern + "}"
        enable = endpoint(group["start_template"], group["scan_enable_pin"])
        si = endpoint(group["start_template"], group["scan_data_in_pin"])
        so = endpoint(group["end_template"], group["scan_data_out_pin"])
        statement = (f"set_scan_segment agent_shift_{number}_${{agent_segment_index_{number}}} "
                     f"-access [list scan_enable {enable} scan_data_in {si} scan_data_out {so}] -lockup_exists false")
        blocks.extend(["    " + statement + "\n", f"    incr agent_segment_index_{number}\n", "}\n"])
        references.append(statement)
    blocks.append("# End agent shift-register recipe\n")
    return "".join(blocks), references


def configure_shift_segments(script: str, groups: list[dict[str, Any]], spec: str = "") -> tuple[str, list[str]]:
    if not groups:
        return script, []
    script = normalize_unrequested_counts(script, spec)
    script = re.sub(r"(?ms)^# Agent recipe from actual input shift-register connections\n.*?^# End agent shift-register recipe\n", "", script)
    recipe, references = shift_segment_recipe(groups, spec)
    existing_limits = re.findall(r"(?m)^\s*set_wrapper_cfg\b(?![^\n]*\s-port\s)[^\n]*?-max_length\s+(\d+)\b", script)
    if existing_limits:
        repeated = "set_wrapper_cfg -max_length " + existing_limits[-1]
        if repeated in references:
            recipe = recipe.replace(repeated + "\n", "")
            references.remove(repeated)
    result = []
    inserted = False
    for chunk in tcl_chunks(script):
        stripped = chunk.lstrip()
        if not stripped.startswith("#") and re.search(r"\bset_scan_segment\b", chunk):
            command = re.match(r"([A-Za-z_]+)\b", stripped)
            names = set(re.findall(r"(?m)^\s*([a-z_]+)\b", chunk))
            if not command or command.group(1) not in {"set_scan_segment", "foreach", "for"}:
                raise ValueError("Use separate scan-segment statements or a pure loop; the runtime compiles all actual input-derived candidates")
            if names - {"set_scan_segment", "foreach", "for", "set", "incr", "if", "continue", "break"} or ";" in chunk:
                raise ValueError("Scan-segment loop contains other operations; separate those settings from segment configuration")
            continue
        if not inserted and re.match(r"(?:examine_scan_drc|examine_scan_chain|insert_dft_logic)\b", stripped):
            result.append(recipe)
            inserted = True
        if not re.match(r"(?:# (?:End )?[Aa]gent (?:shift-register recipe|recipe from actual input shift-register connections)|set agent_segment_index_\d+\s+0)\b", stripped):
            result.append(chunk)
    if not inserted:
        raise ValueError("No safe insertion point for scan segments before scan examination/insertion")
    return "".join(result), references


def configure_floating_inputs(script: str, inputs: dict[str, list[str]]) -> tuple[str, list[str]]:
    tops = re.findall(r"(?m)^\s*present_design\s+([\w$]+)\s*$", script)
    if len(set(tops)) != 1 or not inputs.get(tops[0]):
        return script, []
    pins = inputs[tops[0]]
    if any(re.search(r"[{}\\]", pin) for pin in pins):
        raise ValueError("Literal floating-pin recipe cannot safely quote these uncommon identifiers")
    statement = "add_pseudo_pi [list " + " ".join("{" + pin + "}" for pin in pins) + "]"
    clocks = ["set_scan_signal -type clock -port {" + pin + "} -off_state 0" for pin in pins]
    script = re.sub(r"(?ms)^# Agent literal floating-clock inputs\n.*?^# End agent floating-clock inputs\n", "", script)
    result = []
    inserted = False
    for chunk in tcl_chunks(script):
        stripped = chunk.lstrip()
        normalized = re.sub(r"\\\r?\n[ \t]*", " ", stripped).strip()
        if re.match(r"set_scan_signal\b", normalized) and re.search(r"(?:^|\s)-type\s+clock(?:\s|$)", normalized):
            # The recipe owns these literal clocks. Earlier model declarations
            # would address a pin before add_pseudo_pi, or redeclare it.
            managed_port = any(re.search(r"(?:^|\s)-port\s+(?:\{" + re.escape(pin) + r"\}|\"" +
                                         re.escape(pin) + r"\"|" + re.escape(pin) + r")(?=\s|;|$)", normalized)
                               for pin in pins)
            if managed_port:
                if ";" in normalized or "\n" in normalized:
                    raise ValueError("Keep runtime-owned floating clock declarations in separate statements")
                continue
        if not stripped.startswith("#") and re.search(r"\badd_pseudo_pi\b", chunk):
            command = re.match(r"([A-Za-z_]+)\b", stripped)
            names = set(re.findall(r"(?m)^\s*([a-z_]+)\b", chunk))
            if (not command or command.group(1) not in {"add_pseudo_pi", "foreach", "foreach_in_collection", "cluster_foreach", "if"} or
                    names - {"add_pseudo_pi", "foreach", "foreach_in_collection", "cluster_foreach", "if", "set", "lappend", "incr", "continue", "break"}):
                raise ValueError("Keep pseudo-input configuration separate from other operations; the runtime supplies actual disconnected clock pins")
            continue
        if not inserted and re.match(r"(?:examine_scan_drc|examine_scan_chain|insert_dft_logic)\b", stripped):
            result.extend(["# Agent literal floating-clock inputs\n", statement + "\n",
                           "\n".join(clocks) + "\n", "# End agent floating-clock inputs\n"])
            inserted = True
        result.append(chunk)
    if not inserted:
        raise ValueError("No safe point to declare floating clock inputs before DFT analysis")
    return "".join(result), [statement] + clocks
