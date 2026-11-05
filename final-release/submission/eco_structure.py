"""Task-grounded ECO structure checks. Unsupported structures stay unknown.

This is not a functional equivalence proof. It retains original objects and
checks the functional input of actual library MUXes before mandatory EQY.
"""
from __future__ import annotations

from pathlib import Path
import re

from netlist_repair import RepairRejected, proof_top
from partial_insertion_validation import _libraries, _modules, _flatten, _boolean, _bits, _compatible
from report_validation import report_rows
from drc_validation import authorized_ignored_rule_codes


MUTATIONS = frozenset('add_inst add_net add_port delete_inst delete_net delete_port disconnect_net '
                      'connect_net connect_pin connect_pg_net rewire load_db'.split())
DYNAMIC = frozenset('source eval uplevel interp namespace rename apply exec'.split())


def requires_eco(spec: str) -> bool:
    return bool(re.search(r'(?:必须|须|must|require\w*)[^\n。]{0,100}(?:ECO|网表编辑)', spec.replace('**', ''), re.I))


def requirements(spec: str) -> dict:
    clean = spec.replace('**', '')
    required = requires_eco(spec)
    fixed = set(re.findall(r'(?:ECO\s*后[、，, ]*插链前|插链前)[^\n`]{0,35}`([^`]+\.v)`', clean, re.I))
    modes = {}
    for line in clean.splitlines():
        pairs = re.findall(r'`?([A-Za-z_]\w*)\s*=\s*([01])`?[^\n]{0,3}[）)]', line) if re.search(r'功能模式|功能态|functional mode', line, re.I) else []
        # A mode table labels the meaning of values rather than an assignment.
        if re.search(r'[01]\s*=\s*(?:功能模式|功能态|functional)', line, re.I):
            names = re.findall(r'`([A-Za-z_]\w*)`', line)
            values = re.findall(r'([01])\s*=\s*(?:功能模式|功能态|functional)', line, re.I)
            if len(names) == len(values) == 1:
                pairs.append((names[0], values[0]))
        for name, value in pairs:
            if name in modes and modes[name] != int(value):
                raise RepairRejected('Conflicting task functional-mode constraints')
            modes[name] = int(value)
    counts = {int(v) for v in re.findall(r'(?:全部|all)\s*(\d+)\s*(?:个)?\s*(?:可扫描\s*)?(?:FF|触发器)', clean, re.I)}
    chains = {int(v) for v in re.findall(r'(?:构建|build)[^\n。]{0,20}?(\d+)\s*条?\s*(?:扫描链|scan chains?)', clean, re.I)}
    scan_modes = {}
    for command in re.findall(r'`(set_scan_signal[^`\n]+)`', clean):
        port = re.search(r'-port\s+([A-Za-z_]\w*)\b', command)
        value = re.search(r'-constant_value\s+([01])\b', command)
        if re.search(r'-type\s+constant\b', command) and port and value:
            if port[1] in scan_modes and scan_modes[port[1]] != int(value[1]):
                raise RepairRejected('Conflicting task scan-analysis mode values')
            scan_modes[port[1]] = int(value[1])
    all_ff = bool(re.search(r'(?:全部|all)[^\n。]{0,25}(?:FF|触发器)', clean, re.I))
    return {'required': required, 'fixed_names': sorted(fixed), 'functional_modes': modes,
            'scan_modes': scan_modes,
            'all_original_FFs_required': all_ff,
            'ff_count': next(iter(counts)) if len(counts) == 1 else None,
            'chain_count': next(iter(chains)) if len(chains) == 1 else None,
            'keep_mux_A0': bool(re.search(r'原连接[^\n。]{0,40}A0', clean)),
            'raw_constraints_complete': bool(all_ff and len(counts) <= 1 and len(fixed) == 1 and modes and set(modes) <= set(scan_modes) and len(chains) == 1)}


def original_tie_authority(spec: str, original: str, words_for) -> dict:
    """Narrow organizer-original source, explicitly authorized by this integration.

    A faulty baseline never authorizes suppressing functional rules. Only the
    structural TIE rules already literally Ignore in the supplied original can
    be inherited, only for an ECO task, and never over explicit task denial.
    """
    if not requires_eco(spec):
        return {'codes': [], 'source': 'not_applicable'}
    if re.search(r'(?:禁止|不得|不允许)[^\n。]{0,30}(?:所有|任何|全部)[^\n。]{0,20}(?:忽略|豁免)|'
                 r'(?:禁止|不得|不允许)[^\n。]{0,20}(?:忽略|豁免)[^\n。]{0,20}(?:所有|任何|全部)', spec):
        return {'codes': [], 'source': 'task_denies_all_suppression'}
    for clause in re.split(r'[\n。;；]', spec):
        if (re.search(r'(?:不得|禁止|不允许|must\s+not|do\s+not|never)[^\n。]{0,60}(?:忽略|豁免|ignore|waiv|suppress)', clause, re.I)
                and re.search(r'DRC|违例|violations?|rules?', clause, re.I)
                and not re.search(r'DFTR[-_ ]?(?:TIE[01]|\d+)', clause, re.I)):
            return {'codes': [], 'source': 'task_general_suppression_prohibition'}
    rows = []
    for number, line in enumerate(original.splitlines(), 1):
        words = words_for(line.strip())
        if len(words) == 3 and words[0] == 'set_scan_drc_rule_handling' and words[2] == 'Ignore':
            rules = words[1].strip('{}"').split()
            if rules and set(rules) <= {'DFTR-TIE0', 'DFTR-TIE1'}:
                rows.append({'line': number, 'command': line.strip(), 'codes': rules})
    inherited = {x.replace('-', '') for r in rows for x in r['codes']}
    permission = spec + '\n允许忽略 ' + '、'.join(sorted(inherited)) + '。'
    allowed = inherited & authorized_ignored_rule_codes(permission)
    return {'codes': sorted(allowed), 'source': 'supplied_original_structural_TIE_only', 'rows': rows,
            'meaning': 'inherit exact structural handling, not residual permission for DFTR1/DFTR9'}


def preserve_original_tie_handling(script: str, spec: str, original: str, words_for) -> tuple[str, dict]:
    """Retain only omitted, literal original structural permission in its design.

    This compiles input configuration, not a model repair or a DRC waiver.
    Existing candidate settings (including narrower/overridden settings) remain
    visible to the unchanged native checks. Ambiguous scope is never guessed.
    """
    from dofile_recipe import tcl_chunks
    authority = original_tie_authority(spec, original, words_for)
    record = {'authority': authority, 'actual_commands': [], 'status': 'not_applicable'}
    if not authority['codes']:
        return script, record
    try:
        source = [words_for(c.strip()) for c in tcl_chunks(original)]
        chunks = tcl_chunks(script)
        candidate = [words_for(c.strip()) for c in chunks]
    except ValueError:
        record['status'] = 'scope_unknown'
        return script, record
    def design(rows):
        names = [w[1].strip('{}"') for w in rows if w and w[0] == 'present_design' and len(w) == 2]
        return names[0] if len(names) == 1 and re.fullmatch(r'[A-Za-z_][A-Za-z0-9_$]*', names[0]) else None
    top = design(source)
    anchors = [i for i, w in enumerate(candidate) if w and w[0] == 'present_design']
    loads = [i for i, w in enumerate(candidate) if w and w[0] == 'load_netlist']
    if (top is None or design(candidate) != top or len(anchors) != 1 or len(loads) != 1 or
            loads[0] >= anchors[0] or any(w and w[0] in MUTATIONS | {'examine_scan_drc',
            'examine_scan_chain', 'insert_dft_logic'} for w in candidate[:anchors[0]])):
        record['status'] = 'scope_unknown'
        return script, record
    # A nested/dynamic/abbreviated handling operation can affect the effective
    # state. Do not guess its targets or override it with inferred settings.
    explicit, source_final = set(), {}
    for text, rows, is_source in ((original, source, True), (script, candidate, False)):
        mentions = text.count('set_scan_drc_rule_handling')
        commands = [w for w in rows if w and w[0] == 'set_scan_drc_rule_handling']
        if mentions != len(commands) or any(w and w[0].startswith('set_scan_drc_rule') and
                w[0] != 'set_scan_drc_rule_handling' for w in rows):
            record['status'] = 'handling_unknown'
            return script, record
        for w in commands:
            codes = w[1].strip('{}"').split() if len(w) >= 3 else []
            if (len(w) != 3 or not codes or any(not re.fullmatch(r'DFTR(?:-[A-Z][A-Z0-9]*|[0-9]+)', c) for c in codes)):
                record['status'] = 'handling_unknown'
                return script, record
            if is_source:
                source_final.update({c.replace('-', ''): w[2] for c in codes})
            else:
                explicit.update(c.replace('-', '') for c in codes)
    missing = sorted(c for c in authority['codes'] if c not in explicit and source_final.get(c) == 'Ignore')
    if not missing:
        record['status'] = 'candidate_setting_preserved'
        return script, record
    command = 'set_scan_drc_rule_handling {' + ' '.join('DFTR-' + c[4:] for c in missing) + '} Ignore'
    chunks[anchors[0]] += ('\n# Agent inherited structural TIE authorization from this supplied original\n' +
                           command + '\n# End inherited structural TIE authorization\n')
    record.update(status='restored_omission', design=top, actual_commands=[command],
                  meaning='current task original permission only; native execution, scope and final DRC still required')
    return ''.join(chunks), record


def read_design(paths: list[Path], library: dict, top: str) -> dict:
    if sum(p.stat().st_size for p in paths) > 64 * 1024 * 1024:
        raise RepairRejected('ECO structural reader limit exceeded; object scope unknown')
    modules, unknown = _modules(paths, library)
    leaves, graph, issues, scopes = _flatten(modules, library, top)
    if unknown or issues or top not in modules:
        raise RepairRejected('ECO object structure unknown: ' + '; '.join((unknown + issues)[:5]))
    if any(len(library[c['type']]['ffs']) > 1 for c in leaves.values()):
        raise RepairRejected('Multi-state FF objects require an explicit bit mapping')
    return {'top': top, 'modules': modules, 'cells': leaves, 'graph': graph, 'scopes': scopes}


def source_design(originals: list[Path], libs: list[Path], spec: str, original: str) -> tuple:
    library, issues = _libraries(libs)
    if issues:
        raise RepairRejected('Ambiguous Liberty: ' + '; '.join(issues[:5]))
    top = proof_top(spec, original, originals)
    return library, read_design(originals, library, top)


def ff_objects(design: dict, library: dict) -> dict:
    return {name: cell for name, cell in design['cells'].items() if library[cell['type']]['ffs']}


def _driver(design, pin):
    return design['graph'].resolve(pin)


def structural_fix(before: dict, fixed: dict, library: dict, req: dict) -> dict:
    a, b = before['cells'], fixed['cells']
    if not set(a) <= set(b) or any(a[n]['type'] != b[n]['type'] for n in a):
        raise RepairRejected('Original functional cell removed, renamed without mapping, or replaced before scan')
    if set(ff_objects(before, library)) != set(ff_objects(fixed, library)):
        raise RepairRejected('ECO changed the original FF object set')
    original_ports = before['modules'][before['top']]['ports']
    target_ports = fixed['modules'][fixed['top']]['ports']
    for port, direction in original_ports.items():
        if target_ports.get(port) != direction or before['modules'][before['top']]['widths'].get(port) != fixed['modules'][fixed['top']]['widths'].get(port):
            raise RepairRejected('ECO changed a functional port or its width')
    changed = []

    def check_route(old_pin, new_pin, consumer):
        prior, now = _driver(before, old_pin), _driver(fixed, new_pin)
        if prior is None or now is None:
            raise RepairRejected('Unknown or ambiguous functional driver at ' + consumer)
        if prior == now:
            return
        if not req['functional_modes']:
            raise RepairRejected('Changed functional route without task mode constraint')
        mux = None
        for name, cell in b.items():
            if name in a:
                continue
            shape = library[cell['type']]
            if shape['ffs'] or shape['icg']:
                continue
            for out, props in shape['pins'].items():
                if props.get('direction') != 'output' or now != (fixed['top'] + '::' + name + '.' + out, 0):
                    continue
                for select, prop in shape['pins'].items():
                    if prop.get('direction') != 'input':
                        continue
                    driver = _driver(fixed, cell['pins'].get(select))
                    for mode, value in req['functional_modes'].items():
                        if driver != (fixed['top'] + '::' + mode, 0):
                            continue
                        function = _boolean(props.get('function', ''), {select: value})
                        other = _boolean(props.get('function', ''), {select: 1 - value})
                        if function and other and len(function[0]) == len(other[0]) == 1 and function[1] == other[1] == (0, 1):
                            data = function[0][0]
                            if data == other[0][0] or req['keep_mux_A0'] and (data != 'A0' or other[0][0] != 'A1'):
                                continue
                            if _driver(fixed, cell['pins'].get(data)) == prior:
                                mux = {'instance': name, 'type': cell['type'], 'functional_pin': data,
                                       'test_pin': other[0][0], 'select_pin': select, 'mode_port': mode,
                                       'functional_value': value, 'consumer': consumer,
                                       'original_driver': prior, 'fixed_driver': now}
        if mux is None:
            raise RepairRejected('Changed route is not an evidenced original-functional MUX path at ' + consumer)
        if old_pin != new_pin:
            raise RepairRejected('Task requires preserving the repaired consumer connection: ' + consumer)
        changed.append(mux)

    for name, cell in a.items():
        for pin, prop in library[cell['type']]['pins'].items():
            if prop.get('direction') == 'input':
                check_route(cell['pins'].get(pin), b[name]['pins'].get(pin), name + '/' + pin)
    for port, direction in original_ports.items():
        if direction == 'output':
            for bit in _bits(port, before['modules'][before['top']]['widths']) or []:
                check_route(before['top'] + '::' + bit, fixed['top'] + '::' + bit, 'output:' + bit)
    if not changed:
        raise RepairRejected('No verified ECO connectivity change; execution effect remains unconfirmed')
    return {'status': 'pass', 'changed_routes': changed, 'original_cell_count': len(a),
            'retained_original_cells': sorted(a), 'proof_kind': 'structural constraints only, EQY still required'}


def coverage(before: dict, fixed: dict, after: dict, library: dict, req: dict,
             mappings: dict, cell_report: Path, chain_report: Path, replacement: int,
             *, signal_report: Path | None = None) -> dict:
    originals, final = ff_objects(before, library), ff_objects(after, library)
    for name, cell in before['cells'].items():
        if not library[cell['type']]['ffs'] and (
                name not in after['cells'] or after['cells'][name]['type'] != cell['type']):
            raise RepairRejected('Post-scan removed or changed an original functional non-FF object: ' + name)
    if not originals or set(originals) != set(final) or set(originals) != set(ff_objects(fixed, library)):
        raise RepairRejected('Original FF to fixed/final FF object coverage is incomplete or has extras')
    if req['ff_count'] is not None and len(originals) != req['ff_count']:
        raise RepairRejected('Task FF count disagrees with the actual original object set')
    if replacement != len(originals):
        raise RepairRejected('Native replacement count does not cover all original FFs')
    for path in (cell_report, chain_report, *([signal_report] if signal_report is not None else [])):
        if re.findall(r'(?m)^\s*Design:\s*(\S+)\s*$', path.read_text()) != [before['top']]:
            raise RepairRejected('Coverage report belongs to another or ambiguous design')
    members, chains, chain = {}, {}, ''
    for row in report_rows(cell_report, {'ChainName', 'CellNo', 'InstanceName', 'RefName', 'ScanOut'}):
        if not row['InstanceName']:
            continue
        if row['ChainName']:
            chain = re.sub(r'\s+', '', row['ChainName'])
        if not chain or not row['CellNo'].isdigit():
            raise RepairRejected('Malformed native chain member row')
        name = row['InstanceName'].removeprefix('\\')
        if name.startswith(before['top'] + '/'):
            name = name[len(before['top']) + 1:]
        if name in members or name not in originals:
            raise RepairRejected('Duplicate, wrong hierarchy, or unknown native chain member: ' + name)
        old, new = originals[name]['type'], final[name]['type']
        if mappings.get(old) != new or row['RefName'] != new or _compatible(library[old], library[new]) is not True:
            raise RepairRejected('Native mapping/final type or functional FF mapping mismatch: ' + name)
        members[name] = {'chain': chain, 'index': int(row['CellNo']), 'source': str(cell_report),
                         'line': row['line'], 'original_type': old, 'final_type': new,
                         'scan_out_pin': row['ScanOut'],
                         'original_source': originals[name]['source'], 'original_line': originals[name]['line']}
        chains.setdefault(chain, []).append(int(row['CellNo']))
    if set(members) != set(originals):
        raise RepairRejected('Native chain members omit original FF objects')
    lengths, native_chains = {}, {}
    enable_settings = {}
    if signal_report is not None:
        for setting in report_rows(signal_report, {'Port', 'SignalType', 'OffState'}):
            if setting['SignalType'].split('(')[0] != 'scan_enable':
                continue
            if setting['Port'] in enable_settings or setting['OffState'] not in {'0', '1'}:
                raise RepairRejected('Ambiguous native scan-enable capture level')
            enable_settings[setting['Port']] = setting
    for row in report_rows(chain_report, {'Chain', 'Length', 'Input', 'Output', 'Partition', 'ScanEnable'}):
        name = re.sub(r'\s+', '', row['Chain'])
        if name in lengths or not row['Length'].isdigit() or not row['Input'] or not row['Output']:
            raise RepairRejected('Invalid or duplicate native chain summary row')
        lengths[name] = int(row['Length'])
        native_chains[name] = row
    if len(chains) != req['chain_count'] or set(lengths) != set(chains):
        raise RepairRejected('Task chain count/native member and chain report mismatch')
    for chain, indices in chains.items():
        if sorted(indices) != list(range(lengths[chain])):
            raise RepairRejected('Native chain indices incomplete or duplicated')
        row = native_chains[chain]
        previous = after['top'] + '::' + row['Input']
        enable = after['top'] + '::' + row['ScanEnable']
        for name, item in sorted(((n, m) for n, m in members.items() if m['chain'] == chain), key=lambda p: p[1]['index']):
            cell = final[name]; shape = library[cell['type']]
            ins = [p for p, v in shape['pins'].items() if v.get('signal_type') == 'test_scan_in']
            ens = [p for p, v in shape['pins'].items() if v.get('signal_type') == 'test_scan_enable']
            out = item['scan_out_pin']
            if len(ins) != len(ens) or len(ins) != 1 or shape['pins'].get(out, {}).get('direction') != 'output':
                raise RepairRejected('Unknown scan pin roles for native member ' + name)
            actual_enable, port_enable = _driver(after, cell['pins'].get(ens[0])), _driver(after, enable)
            if (_driver(after, previous) is None or port_enable is None or actual_enable is None or
                    _driver(after, cell['pins'].get(ins[0])) != _driver(after, previous)):
                raise RepairRejected('Native chain member is not physically connected to preceding SI/SE: ' + name)
            if signal_report is None:
                if actual_enable != port_enable:
                    raise RepairRejected('Scan-enable inversion requires bound native polarity evidence: ' + name)
            else:
                setting = enable_settings.get(row['ScanEnable'])
                if setting is None or actual_enable[0] != port_enable[0]:
                    raise RepairRejected('Native member scan-enable object/role is not bound: ' + name)
                off = int(setting['OffState']) ^ actual_enable[1] ^ port_enable[1]
                ordinary = library[originals[name]['type']]['ffs'][0]['properties']
                scan = shape['ffs'][0]['properties']
                for field in ('clocked_on', 'next_state', 'clear', 'preset'):
                    if (field in ordinary) != (field in scan):
                        raise RepairRejected('Unknown scan capture semantics: ' + name)
                    if field in ordinary:
                        first, last = _boolean(ordinary[field]), _boolean(scan[field], {ens[0]: off})
                        if first is None or last is None or first != last:
                            raise RepairRejected('Actual SE polarity does not preserve library functional capture: ' + name)
                item['scan_enable_binding'] = {'port':row['ScanEnable'], 'native_off_state':int(setting['OffState']),
                    'pin':ens[0], 'actual_driver':list(actual_enable), 'port_driver':list(port_enable),
                    'cell_capture_level':off, 'source':str(signal_report), 'line':setting['line']}
            previous = cell['pins'].get(out)
        if _driver(after, previous) is None or _driver(after, after['top'] + '::' + row['Output']) != _driver(after, previous):
            raise RepairRejected('Native chain final SO does not match actual netlist connectivity')
    return {'status': 'pass', 'object_mapping': members, 'chain_lengths': lengths,
            'replaced_count': replacement, 'functional_equivalence': 'separate mandatory EQY proof'}
