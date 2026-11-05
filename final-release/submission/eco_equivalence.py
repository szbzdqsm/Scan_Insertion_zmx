"""Functional original-to-ECO EQY preparation and exact-file proof binding.

No reference scripts, simplified ICGs, scan-mode assumptions or model-written
proofs are accepted. All transformations are private, task/library-derived.
Actual solver capability is established only by a real, bound EQY PASS.
"""
from __future__ import annotations

import hashlib
from itertools import product
import json
from pathlib import Path
import re
import time

from netlist_repair import RepairRejected, fingerprint_paths, changed_paths, run_proof
from partial_insertion_validation import _LIB_EVENT, _boolean
from repair_deliverables import _proof_files


def _sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _nodes(text):
    """Parse relevant actual Liberty groups; retain their original attributes."""
    root = {'name': '', 'args': '', 'props': {}, 'children': []}
    stack = [root]
    text = re.sub(r'/\*.*?\*/|//[^\n]*', '', text, flags=re.S)
    for e in _LIB_EVENT.finditer(text):
        if e['group']:
            node = {'name': e['group'], 'args': e['args'], 'props': {}, 'children': []}
            stack[-1]['children'].append(node); stack.append(node)
        elif e['open']:
            stack.append({'name': '__unknown', 'args': '', 'props': {}, 'children': []})
        elif e['close']:
            if len(stack) == 1:
                raise RepairRejected('Unbalanced Liberty model source')
            stack.pop()
        elif e['prop']:
            if e['prop'] in stack[-1]['props']:
                raise RepairRejected('Duplicate Liberty model property')
            stack[-1]['props'][e['prop']] = e['value'].strip().strip('"')
    if len(stack) != 1:
        raise RepairRejected('Unclosed Liberty model source')
    return root


def _arguments(text):
    return [a or b for a, b in re.findall(r'"([^"\n]+)"|([A-Za-z_$][\w$]*)', text)]


def _cells(root):
    for n in root['children']:
        if n['name'] == 'cell':
            yield n
        else:
            yield from _cells(n)


def _expression(expression, allowed):
    truth = _boolean(expression)
    if truth is None or not set(truth[0]) <= set(allowed):
        raise RepairRejected('Unsupported or unbound Liberty Boolean expression: ' + expression)
    names, values = truth
    terms = []
    for bits, value in zip(product((0, 1), repeat=len(names)), values):
        if value:
            terms.append('(' + ' & '.join(name if bit else '~' + name for name, bit in zip(names, bits)) + ')' if names else "1'b1")
    return ' | '.join(terms) or "1'b0"


def _transparent_latch(signals, values):
    """Factor a single-pin transparent enable only when the full table proves it.

    Both states and all binary inputs are retained. This is not a latch-to-FF
    substitution: it exposes the exact latch to Yosys's native formal clock
    pattern handling instead of encoding its enable as a data-dependent decoder.
    Other state-table shapes keep the existing exhaustive case implementation.
    """
    candidates = []
    for index, signal in enumerate(signals):
        for enabled in (0, 1):
            if all((value != 'N') == (int(bits[index]) == enabled)
                   for bits, value in values.items()):
                data = {bits[:index] + bits[index+1:]: value for bits, value in values.items()
                        if int(bits[index]) == enabled}
                candidates.append({'enable_pin': signal, 'enable_value': enabled,
                                   'data_inputs': signals[:index] + signals[index+1:],
                                   'data_truth': data})
    return candidates[0] if len(candidates) == 1 else None


def _state_table(node, inputs):
    args = _arguments(node['args'])
    if len(args) != 2:
        raise RepairRejected('Only complete single-state Liberty statetables are supported')
    signals, states = args[0].split(), args[1].split()
    if len(states) != 1 or not 1 <= len(signals) <= 6 or not set(signals) <= set(inputs):
        raise RepairRejected('Unsupported Liberty statetable state/input scope')
    rows = node['props'].get('table', '').replace('\\\n', '').split(',')
    values = {}
    for bits in product((0, 1), repeat=len(signals)):
        matches = set()
        for row in rows:
            fields = [f.strip().split() for f in row.split(':')]
            if len(fields) != 3 or len(fields[0]) != len(signals) or fields[1] != ['-'] or fields[2] not in [['L'], ['H'], ['N']]:
                raise RepairRejected('Unsupported edge/ambiguous state semantics in Liberty statetable')
            if any(x not in {'L', 'H', '-'} for x in fields[0]):
                raise RepairRejected('Unsupported statetable input transition symbol')
            if all(x == '-' or bit == int(x == 'H') for x, bit in zip(fields[0], bits)):
                matches.add(fields[2][0])
        if len(matches) != 1:
            raise RepairRejected('Incomplete/conflicting Liberty statetable')
        values[''.join(map(str, bits))] = next(iter(matches))
    state = states[0]
    if not re.fullmatch(r'[A-Za-z_]\w*', state):
        raise RepairRejected('Unsupported Liberty state identifier')
    latch = _transparent_latch(signals, values)
    if latch is not None:
        terms = []
        for bits, value in latch['data_truth'].items():
            if value == 'H':
                terms.append('(' + ' & '.join(pin if bit == '1' else '~' + pin
                    for pin, bit in zip(latch['data_inputs'], bits)) + ')' if bits else "1'b1")
        data = ' | '.join(terms) or "1'b0"
        enable = latch['enable_pin'] if latch['enable_value'] else '~' + latch['enable_pin']
        body = [f'reg {state};', 'always @* begin',
                f'  if ({enable}) {state} <= {data};',
                '  // Otherwise hold actual state; no initial-state assumption.', 'end']
        return body, [state], {'kind': 'Liberty statetable with explicit hold state',
            'inputs': signals, 'state': state, 'truth': values, 'initial_state': 'unconstrained',
            'transparent_enable_factorization': latch}
    body = [f'reg {state};', 'always @* begin', '  case ({' + ', '.join(signals) + '})']
    for bits, value in values.items():
        assignment = '; // hold actual state' if value == 'N' else state + " <= 1'b" + str(int(value == 'H')) + ';'
        body.append(f"    {len(signals)}'b{bits}: {assignment}")
    body += ['  endcase', 'end']
    return body, [state], {'kind': 'Liberty statetable with explicit hold state', 'inputs': signals,
                            'state': state, 'truth': values, 'initial_state': 'unconstrained'}


def cell_models(libs: list[Path], used: set[str]) -> tuple[str, list[dict]]:
    nodes = {}
    for path in libs:
        for cell in _cells(_nodes(path.read_text())):
            names = _arguments(cell['args'])
            if len(names) != 1:
                raise RepairRejected('Ambiguous Liberty cell name')
            if names[0] in used:
                if names[0] in nodes:
                    raise RepairRejected('Duplicate used Liberty cell')
                nodes[names[0]] = cell
    if set(nodes) != used:
        raise RepairRejected('Unknown used cell: ' + ', '.join(sorted(used - nodes.keys())))
    source, metadata = [], []
    for name in sorted(used):
        cell = nodes[name]
        if not re.fullmatch(r'[A-Za-z_]\w*', name):
            raise RepairRejected('Unsupported cell identifier')
        pins = {}
        for p in cell['children']:
            if p['name'] == 'pin':
                args = _arguments(p['args'])
                if len(args) != 1 or not re.fullmatch(r'[A-Za-z_]\w*', args[0]):
                    raise RepairRejected('Unsupported non-scalar Liberty pin')
                pins[args[0]] = p['props']
        inputs = {p for p, v in pins.items() if v.get('direction') == 'input'}
        outputs = {p for p, v in pins.items() if v.get('direction') == 'output'}
        if not outputs or any('three_state' in v for v in pins.values()):
            raise RepairRejected('Missing output or unsupported three-state semantics')
        sequential = [n for n in cell['children'] if n['name'] in {'ff', 'latch', 'statetable', 'ff_bank', 'latch_bank'}]
        if len(sequential) > 1:
            raise RepairRejected('Unsupported multiple sequential groups')
        if 'clock_gating_integrated_cell' in cell['props'] and (
                len(sequential) != 1 or sequential[0]['name'] != 'statetable'):
            raise RepairRejected('ICG needs its actual supported state table, never a buffer fallback')
        body, states, detail = [], [], {'kind': 'actual Liberty combinational functions'}
        if sequential:
            n = sequential[0]
            if n['name'] == 'statetable':
                body, states, detail = _state_table(n, inputs)
            elif n['name'] == 'ff':
                states = _arguments(n['args'])
                if len(states) != 2 or not all(re.fullmatch(r'[A-Za-z_]\w*', s) for s in states):
                    raise RepairRejected('Unsupported Liberty FF state')
                props = n['props']
                clock = _boolean(props.get('clocked_on', ''))
                if not clock or len(clock[0]) != 1 or clock[0][0] not in inputs or clock[1] not in {(0, 1), (1, 0)}:
                    raise RepairRejected('Unsupported FF clock semantics')
                if 'clear' in props or 'preset' in props:
                    raise RepairRejected('Async reset FF model not supported by this ECO adapter; proof blocked')
                nxt = _expression(props.get('next_state', ''), inputs | set(states))
                edge = 'posedge' if clock[1] == (0, 1) else 'negedge'
                body = [f'reg {states[0]};', f'wire {states[1]} = ~{states[0]};',
                        f'always @({edge} {clock[0][0]}) {states[0]} <= {nxt};']
                detail = {'kind': 'actual Liberty scalar edge FF', 'clock': clock[0][0],
                          'edge': edge, 'initial_state': 'unconstrained'}
            else:
                raise RepairRejected('Unsupported latch/bank model; no buffer or blackbox substitution')
        for p in sorted(outputs):
            expression = pins[p].get('function', pins[p].get('state_function', ''))
            if 'clock_gating_integrated_cell' in cell['props'] and not set(states) & set(re.findall(r'[A-Za-z_]\w*', expression)):
                raise RepairRejected('ICG output must retain the real gating state')
            body.append(f'assign {p} = ' + _expression(expression, inputs | set(states)) + ';')
        source += ['module ' + name + ' (' + ', '.join(sorted(inputs | outputs)) + ');',
                   'input ' + ', '.join(sorted(inputs)) + ';' if inputs else '',
                   'output ' + ', '.join(sorted(outputs)) + ';', *body, 'endmodule']
        metadata.append({'cell': name, **detail, 'pins': {p: pins[p] for p in sorted(inputs | outputs)}})
    return '\n'.join(source) + '\n', metadata


def _split_alias_groups(before: dict, repaired: dict) -> list[dict]:
    """Keep split original connectivity in one proof cone, not an assumption.

    Native EQY may cut original aliases independently when an ECO inserts logic
    between them. Group the still-present names using the parsed connectivity
    of both actual netlists. All comparison targets remain proof obligations.
    Unknown identifiers/connectivity keep the default (possibly failing) proof.
    """
    old_graph, new_graph = before['graph'], repaired['graph']
    members = {}
    def add(name, old_node, new_node):
        # These are exact flattened names, not glob patterns or leaf matches.
        if (not re.fullmatch(r'[A-Za-z_$][\w$]*(?:\[\d+\])?(?:[./][A-Za-z_$][\w$]*(?:\[\d+\])?)*', name)
                or old_node not in old_graph.parent or new_node not in new_graph.parent):
            return
        old_root = old_graph.find(old_node)
        new_root = new_graph.find(new_node)
        if old_root[0] in old_graph.bad or new_root[0] in new_graph.bad:
            return
        members.setdefault(old_root, {})['dut.' + name.replace('/', '.')] = {
            'original_node': old_node, 'fixed_node': new_node, 'fixed_group': new_root}
    old_prefix, new_prefix = before['top'] + '::', repaired['top'] + '::'
    for node in sorted(old_graph.parent):
        if node.startswith(old_prefix):
            relative = node[len(old_prefix):]
            add(relative, node, new_prefix + relative)
    for name, cell in before['cells'].items():
        other = repaired['cells'].get(name)
        if not other or other['type'] != cell['type']:
            continue
        for pin, node in cell['pins'].items():
            add(name + '/' + pin, node, other['pins'].get(pin))
    groups = []
    for (root, parity), entries in sorted(members.items()):
        if len(entries) < 2 or len({tuple(e['fixed_group']) for e in entries.values()}) < 2:
            continue
        names = sorted(entries)
        # Exact regex protects brackets and dots in actual hierarchy names.
        pattern = '/(?:' + '|'.join(re.escape(n) for n in names) + ')/'
        groups.append({'original_group': [root, parity], 'members': entries,
                       'eqy_collect': 'group ' + pattern,
                       'semantics': 'merge cones, retain all comparisons; no equality assumption'})
    return groups


def prepare(originals: list[Path], fixed: Path, libs: list[Path], before: dict, repaired: dict,
            modes: dict, original_dofile: str, words_for, directory: Path, binding: dict) -> dict:
    """Make private wrappers; every original functional output stays compared."""
    directory.mkdir(parents=True, exist_ok=False)
    a, b = before['modules'][before['top']], repaired['modules'][repaired['top']]
    old, new = a['ports'], b['ports']
    if not modes or any(p not in old or p not in new or old[p] != 'input' or new[p] != 'input' or
                        a['widths'].get(p) is not None or b['widths'].get(p) is not None for p in modes):
        raise RepairRejected('Functional-mode constraints not bound to actual scalar inputs of both stages')
    extra = set(new) - set(old)
    declared_test = set()
    for line in original_dofile.splitlines():
        w = words_for(line.strip())
        if w[:1] == ['set_scan_signal'] and '-type' in w and '-port' in w:
            kind, port = w[w.index('-type') + 1], w[w.index('-port') + 1]
            if kind in {'scan_enable', 'clock_gating'} and re.fullmatch(r'[A-Za-z_]\w*', port):
                declared_test.add(port)
    if not extra <= declared_test or any(new[p] != 'input' or b['widths'].get(p) is not None for p in extra):
        raise RepairRejected('Unexplained pre-scan interface change; no functional output may be dropped')
    if any(new.get(p) != direction or a['widths'].get(p) != b['widths'].get(p) for p, direction in old.items()):
        raise RepairRejected('Functional interface changed')
    if any(not re.fullmatch(r'[A-Za-z_]\w*', p) for p in set(old) | set(new)):
        raise RepairRejected('Unsupported wrapper port identifier')
    used = {c['type'] for d in (before, repaired) for c in d['cells'].values()}
    models, descriptions = cell_models(libs, used)
    model_file = directory / 'cells.v'; model_file.write_text(models)
    impl = '__eco_original_implementation'
    proof_top = '__eco_functional_boundary'
    if any(n in before['modules'] or n in repaired['modules'] for n in (impl, proof_top)):
        raise RepairRejected('Private proof name collision')
    gold_paths, gate_paths = [], []
    for role, paths, design in [('gold', originals, before), ('gate', [fixed], repaired)]:
        for index, path in enumerate(paths):
            raw = path.read_text()
            raw, count = re.subn(r'(?m)^(\s*module\s+)' + re.escape(design['top']) + r'(?=\s|\()',
                                 lambda m: m[1] + impl, raw)
            # Other files may contain only child modules.
            if count > 1:
                raise RepairRejected('Ambiguous proof top rename')
            copy = directory / f'{role}_{index}.v'; copy.write_text(raw)
            (gold_paths if role == 'gold' else gate_paths).append(copy)
        ports = {**old, **{p: 'input' for p in extra}}
        common = sorted(set(ports) - set(modes))
        lines = ['module ' + proof_top + ' (' + ', '.join(common) + ');']
        for p in common:
            width = a['widths'].get(p, b['widths'].get(p))
            lines.append(ports[p] + (' [%d:%d]' % width if width else '') + ' ' + p + ';')
        connections = []
        for p in design['modules'][design['top']]['ports']:
            value = "1'b" + str(modes[p]) if p in modes else p
            connections.append('.' + p + '(' + value + ')')
        lines += [impl + ' dut (' + ', '.join(connections) + ');', 'endmodule']
        wrapper = directory / (role + '_wrapper.v'); wrapper.write_text('\n'.join(lines) + '\n')
        (gold_paths if role == 'gold' else gate_paths).append(wrapper)
    def section(paths):
        return '\n'.join(['read_verilog -formal ' + ' '.join(json.dumps(str(p)) for p in [model_file, *paths]),
            'hierarchy -check -top ' + proof_top, 'select -assert-none A:blackbox',
            'prep -top ' + proof_top + ' -flatten', 'memory_map', 'clk2fflogic', 'check -assert'])
    alias_groups = _split_alias_groups(before, repaired)
    collect = ('\n\n[collect ' + proof_top + ']\n' +
               '\n'.join(g['eqy_collect'] for g in alias_groups)) if alias_groups else ''
    configuration = '[gold]\n' + section(gold_paths) + '\n\n[gate]\n' + section(gate_paths) + collect + '\n\n[strategy sat]\nuse sat\ndepth 10\n'
    config_file = directory / 'expected.eqy'; config_file.write_text(configuration)
    inputs = fingerprint_paths([*originals, fixed, *libs, model_file, *gold_paths, *gate_paths, config_file])
    plan = {'functional_original_top': before['top'], 'proof_top': proof_top, 'modes': modes,
            'all_functional_outputs': sorted(p for p, d in old.items() if d == 'output'),
            'extra_test_inputs': sorted(extra), 'extra_test_inputs_unconstrained': True,
            'models': descriptions, 'split_alias_groups': alias_groups,
            'input_fingerprints': inputs, 'config': str(config_file),
            'originals': [str(p) for p in originals], 'fixed': str(fixed), 'libraries': [str(p) for p in libs],
            'binding': binding, 'proof_semantics': 'only actual full EQY PASS; sat strategy induction, not bounded-no-sat'}
    (directory / 'plan.json').write_text(json.dumps(plan, ensure_ascii=False, indent=2) + '\n')
    return plan


def verify(plan: dict, proof_root: Path, binding: dict) -> dict:
    if plan['binding'] != binding or changed_paths(plan['input_fingerprints']):
        raise RepairRejected('ECO EQY proof inputs/configuration/binding changed')
    files = _proof_files(proof_root)
    summary = json.loads((proof_root / 'summary.json').read_text())
    if (summary.get('top') != plan['proof_top'] or summary.get('original_netlists') != plan['originals'] or
            summary.get('candidate_netlists') != [plan['fixed']] or
            (proof_root / 'check.eqy').read_bytes() != Path(plan['config']).read_bytes()):
        raise RepairRejected('EQY PASS is for another comparison, wrapper, or configuration')
    return {'status': 'pass', 'proof_files': [str(p) for p in files],
            'proof_file_fingerprints': fingerprint_paths(files), 'plan': plan,
            'meaning': 'bound actual EQY artifacts; not a diagnosis or causal proof'}


def execute(plan: dict, proof_root: Path, deadline: float) -> dict:
    """Runtime-only EQY call. Offline checks must stub the process, not run it."""
    if changed_paths(plan['input_fingerprints']):
        raise RepairRejected('ECO proof input changed before invocation')
    if deadline - time.monotonic() <= 1:
        raise RepairRejected('Insufficient remaining case budget for required ECO EQY')
    from runtime_events import emit
    started = time.monotonic()
    emit('eqy_start', stage='functional_equivalence', allocated_seconds=max(0,deadline-started))
    try:
        run_proof([Path(p) for p in plan['originals']], [Path(plan['fixed'])],
                  [Path(p) for p in plan['libraries']], plan['proof_top'], proof_root, deadline,
                  configuration=Path(plan['config']).read_text())
        result = verify(plan, proof_root, plan['binding'])
    except BaseException as exc:
        emit('eqy_end', stage='functional_equivalence', status='failed_or_unknown',
             error_type=type(exc).__name__, elapsed_seconds=time.monotonic()-started)
        raise
    emit('eqy_end', stage='functional_equivalence', status=result['status'], elapsed_seconds=time.monotonic()-started)
    return result
