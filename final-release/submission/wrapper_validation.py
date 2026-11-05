"""Verify explicit port wrapper requirements using actual implementation rows."""
from __future__ import annotations

from pathlib import Path
import re

from report_validation import report_rows, _full_insertion_designs
from dofile_recipe import tcl_chunks


def global_wrapper_style(spec: str) -> str | None:
    styles = set()
    for line in spec.splitlines():
        if re.search(r"端口|\bport\b|不启用|不得|例如|example|\bif\b", line, re.I):
            continue
        match = re.search(r"(?:启用|enable|configure).{0,20}\bwrapper\b.{0,16}(dedicated|shared)(?![A-Za-z_])", line, re.I)
        if match:
            styles.add(match[1].lower())
    return next(iter(styles)) if len(styles) == 1 else None


def global_wrapper_maximum(spec: str) -> int | None:
    values = set()
    for line in spec.splitlines():
        if re.search(r"端口|\bport\b|不启用|不得|例如|example|\bif\b", line, re.I):
            continue
        if not re.search(r"(?:启用|enable|configure).{0,20}\bwrapper\b", line, re.I):
            continue
        match = re.search(r"(?:最大链长度|最大链长|最大长度|maximum\s+(?:chain\s+)?length|max_length)"
                          r"\s*(?:is|of|:|=|为|：)?\s*[`*]*(\d+)", line, re.I)
        if match:
            values.add(int(match[1]))
    return next(iter(values)) if len(values) == 1 else None


def wrapper_style_configuration_problems(script: str, spec: str, words_for) -> list[str]:
    wanted = global_wrapper_style(spec)
    required = bool(wanted or any(style != 'none' for style, _ in wrapper_targets(spec).values()))
    problems = []
    commands = [words_for(chunk.strip()) for chunk in tcl_chunks(script)
                if chunk.strip() and not chunk.lstrip().startswith('#')]
    designs = {words[1].strip('"{}') for words in commands
               if len(words) == 2 and words[0] == 'present_design'}
    wrappers = {words[words.index('-design_name') + 1].strip('"{}') for words in commands
                if words and words[0] == 'add_dedicated_wrapper_cell_type' and
                '-design_name' in words and words.index('-design_name') + 1 < len(words)}
    if (len(designs) == 1 and wrappers - designs and
            all(re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', value) for value in designs | wrappers)):
        def simple_load(words):
            return bool(len(words) == 2 and words[0] == 'load_netlist' and
                        re.fullmatch(r'[^\s{}$\[\]\\;]+\.(?:v|sv)', words[1].strip('"{}')))
        if any(simple_load(first) and simple_load(second)
               for first, second in zip(commands, commands[1:])):
            problems.append('Adjacent separate load_netlist calls lose auxiliary/selected designs in this tool; '
                            'load all required netlists in ONE load_netlist [list file1 file2 ...], '
                            'then present_design the selected top and register the auxiliary wrapper')
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
    maximum = global_wrapper_maximum(spec)
    if maximum is not None:
        values = [row['Value'] for path in cfgs
                  for row in report_rows(path, {'WrapperConfigurationParameter', 'Value'})
                  if row['WrapperConfigurationParameter'] == 'max_length']
        if not values or any(value != str(maximum) for value in values):
            problems.append(f'Actual Wrapper configuration must report max_length {maximum}; '
                            'configure set_wrapper_cfg -max_length even when indivisible CTL atoms may exceed it')
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


def wrapper_maximum_evidence(issue: dict, paths: list[Path], output_dir: Path,
                             script: str, words_for) -> dict | None:
    """Prove only a changed, explicitly configured default Wrapper maximum."""
    found = issue.get('found', {})
    relative = Path(str(found.get('source', '')))
    run = str(found.get('run_ref', ''))
    locator = re.fullmatch(r'L(\d+)(?:-L(\d+))?', str(found.get('locator', '')))
    old = output_dir / relative
    if (relative.is_absolute() or '..' in relative.parts or not locator or
            not re.fullmatch(r'R\d+', run) or not old.is_file() or old.is_symlink() or
            not old.resolve().is_relative_to((output_dir / 'runs' / run).resolve())):
        return None
    diagnosis = issue.get('diagnosis', {})
    subject = str(diagnosis.get('located_object', ''))
    claim = ' '.join(str(diagnosis.get(key, '')) for key in ('summary', 'root_cause'))
    if not re.search(r'\bmax_length\b', subject + ' ' + claim) or re.search(r'\bstyle\b|\bchain_count\b', claim):
        return None
    context_fields = {}
    if re.search(r'\bstyle\b|\bchain_count\b', subject):
        # A quoted old command may locate the maximum defect without claiming
        # its other options are defective. Bind those options to unchanged rows.
        words = words_for(subject)
        if not words or words[0] != 'set_wrapper_cfg' or len(words) % 2 != 1:
            return None
        for option, value in zip(words[1::2], words[2::2]):
            value = value.strip('"{}')
            if (option not in {'-style', '-chain_count', '-max_length'} or
                    not re.fullmatch(r'[A-Za-z_0-9]+|--', value) or option[1:] in context_fields):
                return None
            context_fields[option[1:]] = value
    action = str(issue.get('attempts', [{}])[-1].get('fix', {}).get('action', ''))
    requested = set(re.findall(r'-max_length\s+["{]?(\d+)\b', action))
    if len(requested) != 1:
        return None
    first, last = int(locator[1]), int(locator[2] or locator[1])
    old_lines = old.read_text(errors='replace').splitlines()
    if not found.get('excerpt') or found['excerpt'] not in '\n'.join(old_lines[first - 1:last]):
        return None
    old_table = list(report_rows(old, {'WrapperConfigurationParameter', 'Value'}))
    old_rows = [row for row in old_table
                if row['WrapperConfigurationParameter'] == 'max_length']
    if len(old_rows) != 1 or not first <= old_rows[0]['line'] <= last:
        return None
    for field, value in context_fields.items():
        rows = [row for row in old_table if row['WrapperConfigurationParameter'] == field]
        if len(rows) != 1 or rows[0]['Value'] != value:
            return None
    context_fields.pop('max_length', None)  # Only this diagnosed field is allowed to change.
    old_designs = re.findall(r'(?m)^Design:\s*(\S+)\s*$', '\n'.join(old_lines))
    old_partitions = re.findall(r'(?m)^Scan partition:\s*(\S+)\s*$', '\n'.join(old_lines))
    if len(old_designs) != 1 or old_partitions != ['Default_Partition']:
        return None
    design, maximum = '', None
    selected_by_load = False
    for chunk in tcl_chunks(script):
        line = chunk.strip().replace('\\\n', ' ')
        if not line or line.startswith('#'):
            continue
        words = words_for(line)
        if not words:
            return None
        if words[0] == 'exit':
            break
        if words[0] in {'source', 'eval', 'uplevel', 'interp', 'namespace', 'set_current_scan_partition'}:
            return None
        if words[0] == 'load_netlist' and '-top' in words:
            index = words.index('-top')
            if design or words.count('-top') != 1 or index + 1 >= len(words):
                return None
            design = words[index + 1].strip('"{}')
            if not re.fullmatch(r'[A-Za-z_]\w*', design):
                return None
            selected_by_load = True
        elif words[0] == 'load_netlist' and design:
            return None  # Reloading can change the current design.
        elif words[0] == 'present_design':
            if len(words) != 2:
                return None
            selected = words[1].strip('"{}')
            if design and (not selected_by_load or selected != design):
                return None
            design, selected_by_load = selected, False
        elif words[0] == 'set_wrapper_cfg':
            if ';' in line or any(re.search(r'[$\[\\]', word) for word in words):
                return None
            if '-max_length' in words:
                index = words.index('-max_length')
                if not design or words.count('-max_length') != 1 or index + 1 >= len(words):
                    return None
                maximum = words[index + 1].strip('"{}')
                if not maximum.isdigit() or int(maximum) <= 0:
                    return None
        elif re.search(r'\b(?:set_wrapper_cfg|present_design|set_current_scan_partition)\b', line):
            return None
    if design != old_designs[0] or maximum not in requested or old_rows[0]['Value'] == maximum:
        return None
    proof = None
    for path in paths:
        if (path.is_symlink() or not path.is_file() or path.suffix != '.rpt' or
                not path.resolve().is_relative_to(output_dir.resolve()) or 'wrapper_cfg' not in path.name):
            continue
        lines = path.read_text(errors='replace').splitlines()
        text = '\n'.join(lines)
        if (re.findall(r'(?m)^Design:\s*(\S+)\s*$', text) != [design] or
                re.findall(r'(?m)^Scan partition:\s*(\S+)\s*$', text) != old_partitions):
            continue
        table = list(report_rows(path, {'WrapperConfigurationParameter', 'Value'}))
        rows = [row for row in table
                if row['WrapperConfigurationParameter'] == 'max_length']
        if len(rows) != 1 or rows[0]['Value'] != maximum:
            return None
        number = rows[0]['line']
        for field, value in context_fields.items():
            matching = [row for row in table if row['WrapperConfigurationParameter'] == field]
            if len(matching) != 1 or matching[0]['Value'] != value:
                return None
            number = max(number, matching[0]['line'])
        first = next(i for i, line in enumerate(lines, 1) if re.fullmatch(r'Design:\s*\S+\s*', line))
        proof = proof or {'source': path.relative_to(output_dir).as_posix(), 'locator': f'L{first}-L{number}',
                          'excerpt': '\n'.join(lines[first - 1:number])}
    return proof


def _names_wrapper_port(located: str, reported: str) -> bool:
    """Bind an exact reported bit or an explicitly named whole bus.

    A bare bus name identifies the object only; callers still check every
    reported bit, type, design, partition and actual executed configuration.
    """
    subject = re.sub(r'^(?:(?:ports?|bus)\s+|端口\s*)', '', located.strip(), flags=re.I)
    # Native rows supply the object. Accept a bounded role description around
    # one literal name, never a substring inside another/multiple/dynamic target.
    subject = re.sub(r'\s+(?:wrapper(?:\s+(?:configuration|implementation|policy|cell(?:\s+type)?))?'
                     r'|configuration|implementation|配置|实现)\s*$', '', subject, flags=re.I)
    if len(subject) >= 2 and (subject[0], subject[-1]) in {
            ('`', '`'), ('"', '"'), ("'", "'"), ('{', '}')}:
        subject = subject[1:-1]
    if not re.fullmatch(r'[A-Za-z_]\w*(?:\[\d+\])?', subject):
        return False
    name = reported.split()[0]
    bit = re.fullmatch(r'([A-Za-z_]\w*)\[\d+\]', name)
    return subject == name or bool(bit and subject == bit[1])


def _names_wrapper_row(located: str, row: dict) -> bool:
    """Bind a port and an optional explicit instance to the same native row.

    The instance is a literal, complete report value, never a leaf-name or
    substring search. This identifies the discovery object only; the caller
    still verifies the full bus and the later executed run's type and scope.
    """
    if _names_wrapper_port(located, row['PortName(I/O)']):
        return True
    pair = re.fullmatch(r'(\S+)\s+wrapper\s+instance\s+(\S+)', located.strip(), re.I)
    instance = row.get('WrapperInstances', '')
    return bool(pair and instance not in {'', '--'} and
                _names_wrapper_port(pair[1], row['PortName(I/O)']) and pair[2] == instance)


def wrapper_type_evidence(issue: dict, paths: list[Path], output_dir: Path,
                          script: str, words_for) -> dict | None:
    """Prove a changed dedicated type using the same ports' native implementation.

    A dedicated style alone cannot prove a user-defined cell. Unknown scope,
    dynamic configuration, changed port coverage or conflicting reports fail
    closed; this does not prove connection correctness or other requirements.
    """
    found = issue.get('found', {})
    relative = Path(str(found.get('source', '')))
    run = str(found.get('run_ref', ''))
    locator = re.fullmatch(r'L(\d+)(?:-L(\d+))?', str(found.get('locator', '')))
    old = output_dir / relative
    if (relative.is_absolute() or '..' in relative.parts or not locator or
            not re.fullmatch(r'R[1-9]\d*', run) or not old.is_file() or old.is_symlink() or
            not re.search(r'wrapper.*implementation', old.name, re.I) or
            not old.resolve().is_relative_to((output_dir / 'runs' / run).resolve())):
        return None
    action = str(issue.get('attempts', [{}])[-1].get('fix', {}).get('action', ''))
    requested = set(re.findall(r'-dedicated_cell_type\s+["{]?([A-Za-z_]\w*)', action))
    if len(requested) != 1:
        return None
    expected = next(iter(requested))
    lines = old.read_text(errors='replace').splitlines()
    first, last = int(locator[1]), int(locator[2] or locator[1])
    excerpt = str(found.get('excerpt', ''))
    if not excerpt or excerpt not in '\n'.join(lines[first-1:last]):
        return None
    table = list(report_rows(old, {'PortName(I/O)', 'WrapperStyle', 'DWCType', 'Partition'}))
    selected = [r for r in table if first <= r['line'] <= last and
                lines[r['line']-1].strip() in excerpt]
    if not selected or any(r['WrapperStyle'] != 'dedicated' or r['DWCType'] == expected for r in selected):
        return None
    base_names = {re.sub(r'\[\d+\]$', '', r['PortName(I/O)'].split()[0]) for r in selected}
    if len(base_names) != 1 or not re.fullmatch(r'[A-Za-z_]\w*', next(iter(base_names))):
        return None
    base = next(iter(base_names))
    located = str(issue.get('diagnosis', {}).get('located_object', ''))
    if not any(_names_wrapper_row(located, r) for r in selected):
        return None
    port_pattern = re.compile(re.escape(base) + r'(?:\[\d+\])?\s+\([IO]\)')
    old_rows = [r for r in table if port_pattern.fullmatch(r['PortName(I/O)'])]
    names = {r['PortName(I/O)'] for r in old_rows}
    old_designs = re.findall(r'(?m)^\s*Design\s*:\s*(\S+)\s*$', '\n'.join(lines))
    if (len(old_designs) != 1 or _full_insertion_designs(script) != set(old_designs) or
            any(r['Partition'] != 'Default_Partition' for r in old_rows)):
        return None
    configured = False
    for chunk in tcl_chunks(script):
        text = chunk.strip().replace('\\\n', ' ')
        if not text or text.startswith('#'):
            continue
        words = words_for(text)
        if words and words[0] == 'exit':
            break
        if words and words[0] in {'source', 'eval', 'uplevel', 'interp', 'namespace', 'set_current_scan_partition'}:
            return None
        if words and words[0] == 'insert_dft_logic':
            break
        if not words or words[0] != 'set_wrapper_cfg':
            if words and words[0] != 'present_design' and re.search(r'\b(?:set_wrapper_cfg|present_design)\b', text):
                return None
            continue
        if '-dedicated_cell_type' not in words:
            continue
        index = words.index('-dedicated_cell_type')
        if words.count('-dedicated_cell_type') != 1 or index + 1 >= len(words):
            return None
        if words[index+1].strip('"{}') != expected:
            continue
        ports = {base}
        if '-port' in words:
            index = words.index('-port')
            if words.count('-port') != 1 or index+1 >= len(words):
                return None
            value = words[index+1]
            if '[' in value and not (value.startswith('{') and value.endswith('}')):
                return None
            ports = set(value.strip('"{}').split())
        if base in ports or {name.split()[0] for name in names} <= ports:
            configured = True
    if not configured:
        return None
    proof = None
    for path in paths:
        if not re.search(r'wrapper.*implementation', path.name, re.I):
            continue
        relative = path.relative_to(output_dir)
        parts = relative.parts
        if (len(parts) != 4 or parts[0] != 'runs' or parts[2] != 'reports' or
                not re.fullmatch(r'R[1-9]\d*', parts[1]) or int(parts[1][1:]) <= int(run[1:]) or
                path.is_symlink() or not path.resolve().is_relative_to((output_dir/'runs'/parts[1]).resolve())):
            return None
        current = output_dir/'runs'/parts[1]
        executed = current/'deliverables'/(parts[1]+'.dofile')
        if not executed.is_file() or executed.is_symlink() or executed.read_text() != script:
            return None
        actual = path.read_text(errors='replace').splitlines()
        if re.findall(r'(?m)^\s*Design\s*:\s*(\S+)\s*$', '\n'.join(actual)) != old_designs:
            return None
        rows = [r for r in report_rows(path, {'PortName(I/O)', 'WrapperStyle', 'DWCType', 'Partition'})
                if port_pattern.fullmatch(r['PortName(I/O)'])]
        if (len(rows) != len(names) or {r['PortName(I/O)'] for r in rows} != names or
                any(r['WrapperStyle'] != 'dedicated' or r['DWCType'] != expected or
                    r['Partition'] != 'Default_Partition' for r in rows)):
            return None
        first, last = min(r['line'] for r in rows), max(r['line'] for r in rows)
        proof = proof or {'source': relative.as_posix(), 'locator': f'L{first}-L{last}',
                          'excerpt': '\n'.join(actual[first-1:last])}
    return proof


def contradicted_wrapper_policy(item: dict, found: dict, output_dir: Path,
                                task_spec: str | None) -> bool:
    """A task-compliant port row cannot discover its contrary style/type fault.

    This does not prove whole-bus coverage or reject connection/control faults.
    Global native checks remain responsible for every requested port and bit.
    """
    if task_spec is None:
        return False
    claim = ' '.join(str(item.get(k, '')) for k in ('phenomenon', 'diagnosis', 'root_cause'))
    if (not re.search(r'\b(?:style|DWCType|dedicated_cell_type|user_defined|WC_D\w*)\b|'
                      r'bus.{0,80}expand|总线.{0,30}展开', claim, re.I) or
            re.search(r'\b(?:reuse_threshold|depth_threshold|max_length|chain_count|'
                      r'connect\w*|polarity|hookup|clock\w*|reset\w*|capture\w*|shift\w*|control\w*|'
                      r'scan_enable|disabled|enablement)\b|连接|断裂|阈值|时钟|复位|使能|控制|捕获|移位|'
                      r'not\s+enabled|missing\s+enable', claim, re.I)):
        return False
    relative = Path(str(found.get('source', '')))
    run = str(found.get('run_ref', ''))
    locator = re.fullmatch(r'L(\d+)(?:-L(\d+))?', str(found.get('locator', '')))
    path = output_dir/relative
    if (relative.is_absolute() or '..' in relative.parts or not locator or
            not re.fullmatch(r'R[1-9]\d*', run) or not path.is_file() or path.is_symlink() or
            not re.search(r'wrapper.*implementation', path.name, re.I) or
            not path.resolve().is_relative_to((output_dir/'runs'/run).resolve())):
        return False
    lines = path.read_text(errors='replace').splitlines()
    first, last = int(locator[1]), int(locator[2] or locator[1])
    excerpt = str(found.get('excerpt', ''))
    script = output_dir/'runs'/run/'deliverables'/(run+'.dofile')
    designs = re.findall(r'(?m)^\s*Design\s*:\s*(\S+)\s*$', '\n'.join(lines))
    if (not excerpt or re.search(r'\[(?:ERROR|FATAL|WARNING)\]', excerpt) or
            excerpt not in '\n'.join(lines[first-1:last]) or len(designs) != 1 or
            not script.is_file() or script.is_symlink() or _full_insertion_designs(script.read_text()) != set(designs)):
        return False
    selected = [r for r in report_rows(path, {'PortName(I/O)', 'WrapperStyle', 'DWCType', 'Partition'})
                if first <= r['line'] <= last and lines[r['line']-1].strip() in excerpt]
    if not selected:
        return False
    targets = wrapper_targets(task_spec)
    located = str(item.get('located_object', ''))
    for row in selected:
        port = re.fullmatch(r'([A-Za-z_]\w*)(?:\[\d+\])?\s+\([IO]\)', row['PortName(I/O)'])
        if (not port or port[1] not in targets or row['Partition'] != 'Default_Partition' or
                row.get('IPGroup', '') not in {'', '--'} or
                not _names_wrapper_port(located, row['PortName(I/O)'])):
            return False
        style, cell_type = targets[port[1]]
        if row['WrapperStyle'].lower() != style or cell_type and row['DWCType'].lower() != cell_type:
            return False
    return True
