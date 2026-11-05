"""Native ECO execution, stage exports, proof and coverage admission.

Proposal, observed native execution, exported structural effect and EQY result
are separate states. Unknown mutation paths keep proof required. No model can
provide a passing ledger or select a previous run as its current proof.
"""
from __future__ import annotations

from dataclasses import dataclass
import difflib
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import uuid

from artifact_operations import independent_copy, assert_output_directories
from canonical_delivery import _real_file, _target, CanonicalDeliveryError
from drc_validation import drc_summaries, rule_codes, authorized_ignored_rule_codes, required_ignored_rule_codes
from netlist_repair import RepairRejected, fingerprint_paths, changed_paths
from eco_structure import (MUTATIONS, DYNAMIC, requires_eco, requirements, source_design, read_design,
                           structural_fix, coverage, original_tie_authority)
from report_validation import report_rows
from clock_association_recipe import _chunks, _safe_condition
import eco_equivalence


_ISSUER = object()
_ECHO = re.compile(r'CMD-0034\]\s+@(\d+):\s*(.*)')


def _digest(value):
    return hashlib.sha256(json.dumps(value, ensure_ascii=False, sort_keys=True).encode()).hexdigest()


def _write(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + '\n')


def proposal(script: str, words_for) -> dict:
    commands, dynamic = set(), False
    def substitutions(word, depth):
        nonlocal dynamic
        if word.startswith('{') and word.endswith('}'):
            return  # Literal data is not a command body.
        index = 0
        while index < len(word):
            if word[index] == '\\':
                index += 2; continue
            if word[index] != '[':
                index += 1; continue
            end, count = index + 1, 1
            while end < len(word) and count:
                count += (word[end] == '[') - (word[end] == ']'); end += 1
            if count:
                dynamic = True; return
            inspect(word[index + 1:end - 1], depth + 1)
            index = end
    def body(word, depth):
        nonlocal dynamic
        if word.startswith('{') and word.endswith('}'):
            inspect(word[1:-1], depth + 1)
        else:
            dynamic = True  # An evaluated body cannot be inferred from data.
    def inspect(text, depth=0):
        nonlocal dynamic
        if depth > 12:
            dynamic = True; return
        try:
            chunks = _chunks(text)
            for chunk in chunks:
                code = chunk.strip().rstrip(';').strip()
                if not code or code.startswith('#'):
                    continue
                w = words_for(code)
                if not w:
                    continue
                head = w[0][1:-1] if w[0][:1] in {'"', '{'} and w[0][-1:] in {'"', '}'} else w[0]
                name = head.removeprefix('::')
                commands.update(full for full in MUTATIONS if full.startswith(name))
                dynamic |= name in DYNAMIC or bool(re.search(r'[$\[]', name))
                for word in w[1:]:
                    substitutions(word, depth)
                if name in {'foreach', 'foreach_in_collection', 'while', 'proc'}:
                    body(w[-1], depth)
                    if name == 'while': substitutions(w[1][1:-1], depth)
                elif name == 'catch' and len(w) >= 2:
                    body(w[1], depth)
                elif name == 'for' and len(w) == 5:
                    for index in (1, 3, 4): body(w[index], depth)
                    substitutions(w[2][1:-1], depth)
                elif name == 'if':
                    index = 1
                    while index < len(w):
                        if w[index] == 'else': body(w[index + 1], depth); break
                        if w[index] == 'elseif': index += 1
                        substitutions(w[index][1:-1] if w[index].startswith('{') else w[index], depth)
                        index += 1
                        if w[index] == 'then': index += 1
                        body(w[index], depth); index += 1
                elif name == 'expr':
                    for word in w[1:]:
                        if word.startswith('{') and word.endswith('}'): substitutions(word[1:-1], depth)
                        elif '$' in word: dynamic = True
        except (ValueError, IndexError):
            dynamic = True
    inspect(script)
    return {'proposed_commands': sorted(commands), 'dynamic_mutation_unknown': dynamic,
            'meaning': 'script intent/risk only, not evidence that any edit executed'}


@dataclass
class RunContext:
    issuer: object
    output: Path
    input_dir: Path
    run: Path
    rid: str
    spec: str
    original: str
    originals: list
    libs: list
    script: str
    execution: Path
    inputs: dict
    before_files: set
    intent: dict
    req: dict
    scope_digest: str = ''
    execution_id: str = ''


@dataclass
class NativeTrace:
    issuer: object
    context: RunContext
    data: dict
    fingerprints: dict
    data_digest: str


def _scope(context):
    return _digest({'output': str(context.output), 'input_dir': str(context.input_dir),
        'run': str(context.run), 'rid': context.rid, 'execution_id': context.execution_id,
        'spec': context.spec, 'original': context.original,
        'originals': list(map(str, context.originals)), 'libs': list(map(str, context.libs)),
        'script': context.script, 'execution': str(context.execution), 'inputs': context.inputs,
        'before_files': sorted(context.before_files), 'intent': context.intent, 'req': context.req})


def begin(output: Path, input_dir: Path, run: Path, rid: str, task: str, spec: str,
          original: str, originals: list[Path], libs: list[Path], script: str,
          execution: Path, words_for) -> RunContext | None:
    intent = proposal(script, words_for)
    if not requires_eco(spec) and not intent['proposed_commands'] and not intent['dynamic_mutation_unknown']:
        return None  # Old non-ECO execution path is unchanged.
    req = requirements(spec)
    if task != 'task2':
        raise RepairRejected('Task1 cannot adopt an in-memory Pre-scan ECO')
    inputs = fingerprint_paths([*originals, *libs, input_dir / 'task_spec.md',
                               *([input_dir / 'original.dofile'] if (input_dir / 'original.dofile').is_file() else [])])
    context = RunContext(_ISSUER, output.absolute(), input_dir.absolute(), run.absolute(), rid,
        spec, original, originals, libs, script, execution.absolute(), inputs,
        {str(p.absolute()) for p in run.rglob('*') if p.is_file()}, intent, req)
    context.execution_id = uuid.uuid4().hex  # Execution binding, not a guessed official case identifier.
    context.scope_digest = _scope(context)
    return context


def _current(context):
    if (not isinstance(context, RunContext) or context.issuer is not _ISSUER or
            not re.fullmatch(r'R[1-9]\d*', context.rid) or
            context.run != context.output / 'runs' / context.rid or changed_paths(context.inputs)):
        raise RepairRejected('ECO context is stale, from another case/round, or not runtime-issued')
    if _scope(context) != context.scope_digest or context.spec != (context.input_dir / 'task_spec.md').read_text() or (
            (context.input_dir / 'original.dofile').is_file() and context.original != (context.input_dir / 'original.dofile').read_text()):
        raise RepairRejected('ECO task, source authority, or context state changed')
    script = context.run / 'deliverables' / (context.rid + '.dofile')
    if (script.read_text() != context.script or context.execution.read_text() != context.script or
            not context.execution.is_relative_to(context.run)):
        raise RepairRejected('ECO executed/retained script differs from the current candidate')


def _value(raw, variables):
    literal = raw.startswith('{') and raw.endswith('}')
    value = raw[1:-1] if raw[:1] in {'"', '{'} else raw
    if not literal:
        value = re.sub(r'\$(?:\{([A-Za-z_]\w*)\}|([A-Za-z_]\w*))',
                       lambda m: variables.get(m[1] or m[2], '$UNKNOWN'), value)
    if re.search(r'[$\[\]\\;\r\n]', value):
        raise RepairRejected('Unresolved native input/operation argument')
    return value



def bound_loaded_inputs(context, name, arguments, variables, virtual, words_for):
    """Shared read-only native load binding; never execute Tcl or infer a basename."""
    arguments = list(arguments)
    declared_top = None
    if '-top' in arguments:
        if name != 'load_netlist' or arguments.count('-top') != 1:
            raise RepairRejected('Ambiguous or inapplicable native load top option')
        pos = arguments.index('-top')
        if pos + 1 >= len(arguments):
            raise RepairRejected('Native load top option has no design')
        declared_top = _value(arguments[pos + 1], variables)
        from netlist_repair import proof_top
        if declared_top != proof_top(context.spec, context.original, context.originals):
            raise RepairRejected('Native load top differs from bound task/input design')
        del arguments[pos:pos + 2]
    if len(arguments) == 1 and arguments[0].startswith('{') and arguments[0].endswith('}'):
        arguments = words_for(arguments[0][1:-1])
    if not arguments or any(arg.startswith('-') for arg in arguments):
        raise RepairRejected('Unknown/empty native load arguments')
    paths = set()
    for arg in arguments:
        path = PurePosixPath(_value(arg, variables))
        if not path.is_absolute():
            path = virtual / path
        if path.is_relative_to(virtual):
            target = context.run.joinpath(*path.relative_to(virtual).parts)
        elif path.is_relative_to(context.input_dir):
            target = context.input_dir.joinpath(*path.relative_to(context.input_dir).parts)
        elif path.is_relative_to('/input'):
            target = context.input_dir.joinpath(*path.relative_to('/input').parts)
        else:
            target = Path(str(path))
        resolved = target.resolve(strict=True)
        allowed = context.libs if name == 'load_lib' else context.originals
        if resolved not in {p.resolve() for p in allowed}:
            raise RepairRejected('Native ECO loaded another input/lib/database')
        paths.add(resolved)
    return paths


def _conditional_source_lines(script, words_for):
    """Recognize one bounded native multiline disconnect scope, not execute Tcl.

    The tool echoes physical lines while accumulating the braced body. Header
    and closing brace are syntax, never proof of an executed mutation. Require
    a native successful disconnect after the closing echo before admitting it.
    Other unsupported compound operations keep the prior rejection behavior.
    """
    syntax, bodies = {}, {}
    offset = 0
    for chunk in _chunks(script):
        code = chunk.strip().rstrip(';').strip()
        first = script[:offset + len(chunk) - len(chunk.lstrip())].count('\n') + 1
        offset += len(chunk)
        if not code or code.startswith('#') or '\n' not in code:
            continue
        w = words_for(code)
        if (len(w) != 3 or w[0] != 'if' or not _safe_condition(w[1], words_for) or
                not (w[2].startswith('{') and w[2].endswith('}'))):
            continue
        physical = code.splitlines()
        nonempty = [(first+i, line.strip()) for i,line in enumerate(physical) if line.strip()]
        if len(nonempty) != 3 or nonempty[-1][1] != '}':
            continue
        body_line, body = nonempty[1]
        bw = words_for(body)
        if len(bw) != 3 or bw[0] != 'disconnect_net':
            continue
        frame = {'header_line': first, 'body_line': body_line,
                 'closing_line': nonempty[-1][0], 'source_command': code,
                 'operation': body, 'native_execution_required': True}
        syntax[first] = ('header', frame)
        syntax[nonempty[-1][0]] = ('closing', frame)
        bodies[body_line] = frame
    return syntax, bodies


def trace(context: RunContext, result: dict, words_for, *, checkpoint=None) -> NativeTrace:
    _current(context)
    root, run, rid = context.output, context.run, context.rid
    log = checkpoint if checkpoint is not None else run / (rid + '.log')
    _real_file(log, root)
    if checkpoint is None and (result.get('returncode') != 0 or result.get('status', result.get('exit_status')) != 'completed'):
        raise RepairRejected('Native ECO round did not complete')
    text = log.read_text()
    if re.search(r'\[(?:ERROR|FATAL)\]', text):
        raise RepairRejected('Native ECO run contains tool error; no effect is accepted')
    if context.intent['dynamic_mutation_unknown']:
        raise RepairRejected('Dynamic mutation scope unknown; fixed export and mandatory proof still required')
    physical = context.script.splitlines()
    conditional_syntax, conditional_bodies = _conditional_source_lines(context.script, words_for)
    conditional_opened = set()
    virtual, variables, pending, top, events, active = None, {}, None, '', [], None
    loaded_netlists, loaded_libs, completed = set(), set(), False
    for number, line in enumerate(text.splitlines(), 1):
        origin = re.search(r'\[SOURCE TCL FILE\]\s+(\S+)\s*:', line)
        if origin:
            source = PurePosixPath(origin[1])
            hits = [i for i, p in enumerate(source.parts) if p == 'runs' and source.parts[i + 1:i + 2] == (rid,)]
            if virtual is not None or len(hits) != 1 or '..' in source.parts:
                raise RepairRejected('Unknown/multiple native ECO script origin')
            virtual = PurePosixPath(*source.parts[:hits[0] + 2])
            actual = run.joinpath(*source.parts[hits[0] + 2:])
            _real_file(actual, root)
            if actual != context.execution or actual.read_text() != context.script:
                raise RepairRejected('Native origin is not this actual candidate')
        echo = _ECHO.search(line)
        if echo:
            if active is not None:
                active['end_log_line'] = number - 1
            pending = None
            code, n = echo[2].strip(), int(echo[1])
            if not code or code.startswith('#'):
                active = None
                continue
            if n < 1 or n > len(physical):
                raise RepairRejected('Invalid native source line')
            actual = physical[n - 1].strip()
            index = n
            while actual.endswith('\\') and index < len(physical):
                actual = actual[:-1] + ' ' + physical[index].strip(); index += 1
            if code != actual:
                raise RepairRejected('Native command does not match actual script line')
            syntax = conditional_syntax.get(n)
            if syntax:
                kind, frame = syntax
                if virtual is None:
                    raise RepairRejected('Conditional ECO syntax lacks bound script origin')
                if kind == 'header':
                    if frame['header_line'] in conditional_opened:
                        raise RepairRejected('Duplicate conditional ECO header echo')
                    conditional_opened.add(frame['header_line'])
                    active = None
                else:
                    if (frame['header_line'] not in conditional_opened or active is None or
                            active.get('conditional_source') != frame or active.get('conditional_closed_log_line')):
                        raise RepairRejected('Conditional ECO closing echo lacks its exact body')
                    active['conditional_closed_log_line'] = number
                continue
            w = words_for(code)
            if not w or virtual is None:
                raise RepairRejected('Unknown native command origin')
            if re.search(r'(?:^|[\[;{])\s*(?:::)?open\b|'
                         r'(?:^|[\[;{])\s*(?:::)?file\s+(?:copy|delete|rename|link|attributes)\b', code):
                raise RepairRejected('Extra Tcl file mutation/I-O makes native export provenance unknown')
            if w[0] == 'puts':
                args = w[2:] if w[1:2] == ['-nonewline'] else w[1:]
                if len(args) != 1 and not (len(args) == 2 and args[0] in {'stdout', 'stderr'}):
                    raise RepairRejected('Non-console Tcl writes cannot establish immutable native exports')
            name = _value(w[0], variables).removeprefix('::')
            # Unique literal abbreviations use the same native semantics; a
            # dynamic or ambiguous command cannot establish mutation ordering.
            relevant = MUTATIONS | {'set', 'load_lib', 'load_netlist', 'present_design', 'set_scan_cell_mapping',
                'set_scan_drc_rule_handling',
                'insert_dft_logic', 'dump_netlist', 'examine_scan_drc', 'examine_scan_chain', 'rpt_scan_drc_violation',
                'rpt_scan_chain', 'rpt_scan_chain_cell', 'rpt_scan_drc_rule_handling'}
            matches = [x for x in relevant if x.startswith(name)]
            if name not in relevant and len(matches) == 1:
                name = matches[0]
            active = {'command': code, 'name': name, 'script_line': n, 'log_line': number,
                      'design': top, 'evidence': {'source': log.relative_to(root).as_posix(),
                      'locator': 'L' + str(number), 'excerpt': line.strip(), 'run_ref': rid}}
            if n in conditional_bodies:
                frame = conditional_bodies[n]
                if frame['header_line'] not in conditional_opened or name != 'disconnect_net':
                    raise RepairRejected('Unbound conditional ECO body')
                active['conditional_source'] = frame
            events.append(active)
            if name in DYNAMIC or name.startswith('$'):
                raise RepairRejected('Unknown executed ECO design mutation scope')
            if name == 'load_db':
                raise RepairRejected('Database replacement needs additional input/content binding; mutation remains unknown')
            if name == 'set' and len(w) == 3:
                variables.pop(w[1], None); pending = w[1]
            if name == 'present_design':
                if len(w) != 2 or not re.fullmatch(r'[A-Za-z_]\w*', w[1]) or top and top != w[1]:
                    raise RepairRejected('Multiple/ambiguous ECO design scope')
                active['requested_design'] = w[1]
            if name in {'load_lib', 'load_netlist'}:
                targets = bound_loaded_inputs(context, name, w[1:], variables, virtual, words_for)
                (loaded_libs if name == 'load_lib' else loaded_netlists).update(str(p) for p in targets)
            if name == 'set_scan_cell_mapping':
                if len(w) != 3:
                    raise RepairRejected('Dynamic/ambiguous ECO scan-cell mapping')
                active['mapping'] = [_value(x, variables) for x in w[1:]]
            if name == 'set_scan_drc_rule_handling':
                if len(w) != 3:
                    raise RepairRejected('Ambiguous native DRC handling operation')
                codes = rule_codes(_value(w[1], variables))
                level = _value(w[2], variables)
                if not codes or level not in {'Error', 'Warning', 'Info', 'Ignore'}:
                    raise RepairRejected('Unknown native DRC handling rule or level')
                active['drc_policy'] = {'codes': sorted(codes), 'level': level}
            if name == 'dump_netlist' or name.startswith('rpt_') or name == 'examine_scan_drc':
                if '-file' in w or '>' in w:
                    flag = '-file' if '-file' in w else '>'
                    if w.count(flag) != 1 or w.index(flag) + 2 != len(w):
                        raise RepairRejected('Ambiguous native ECO artifact target')
                    target = _target(w[-1], variables, virtual, run, words_for, native_generated=True)
                    _real_file(target, root)
                    if str(target) in context.before_files:
                        raise RepairRejected('Old preexisting ECO export/report cannot stand in for this execution')
                    active['path'] = str(target)
        elif pending:
            value = line.strip()
            if value and not value.startswith('[') and not re.search(r'[$\[\]\\;]', value):
                variables[pending] = value
            pending = None
        if active and active.get('conditional_source'):
            effect = re.search(r"CMD-1101\]\s+Successfully disconnected pin '([^']+)' from net '([^']+)'\.", line)
            if effect and active.get('conditional_closed_log_line', number + 1) < number:
                active['native_conditional_execution'] = {
                    'pin': effect[1], 'net': effect[2],
                    'source': log.relative_to(root).as_posix(), 'locator': 'L'+str(number),
                    'excerpt': line.strip(), 'run_ref': rid}
        if active and active['name'] == 'present_design':
            selected = re.search(r"CMD-1300\]\s+Present design is '([^']+)'", line)
            if selected:
                if selected[1] != active['requested_design']:
                    raise RepairRejected('Native ECO design differs from request')
                top = selected[1]; active['design'] = top
        if active and active['name'] == 'dump_netlist':
            if 'VRLG-O-0008]' in line and 'Begin to write Netlist.' in line:
                active['begun'] = number
            if 'VRLG-O-0009]' in line and 'Write Netlist successfully.' in line and active.get('begun'):
                active['success'] = {'source': log.relative_to(root).as_posix(), 'locator': 'L' + str(number),
                                     'excerpt': line.strip(), 'run_ref': rid}
        replaced = re.search(r"SCAN-7600\]\s+There were (\d+) 'D' flip-flops that have been replaced\.", line)
        if replaced:
            if active is None or active['name'] != 'insert_dft_logic' or 'replacement_count' in active:
                raise RepairRejected('Unbound or duplicate native scan rewrite')
            active['replacement_count'] = int(replaced[1])
        if 'CMD-0042]' in line and 'Thank you' in line:
            completed = True
    if active is not None:
        active['end_log_line'] = len(text.splitlines())
    if (checkpoint is None and not completed) or not top or loaded_libs != {str(p.resolve()) for p in context.libs} or loaded_netlists != {str(p.resolve()) for p in context.originals}:
        raise RepairRejected('Native library/netlist/design/run completion binding incomplete')
    if any(e.get('conditional_source') and not e.get('native_conditional_execution') for e in events):
        raise RepairRejected('Conditional ECO execution is unproved; source echo is not an executed mutation')
    edits = [e for e in events if e['name'] in MUTATIONS]
    rewrites = [e for e in events if e['name'] == 'insert_dft_logic']
    exports = [e for e in events if e['name'] == 'dump_netlist']
    if not edits or any(e['design'] != top for e in edits) or len(rewrites) != (0 if checkpoint else 1):
        raise RepairRejected('No fully observed same-design ECO followed by one scan rewrite')
    if any(e['log_line'] > edits[0]['log_line'] and e['name'] in
           {'load_lib', 'load_netlist', 'load_ctl', 'present_design'} for e in events):
        raise RepairRejected('Design reload/switch after ECO invalidates adopted-state continuity')
    if re.search(r'(?:不得|禁止|must\s+not)[^\n。]{0,100}add_pseudo_pi', context.spec, re.I) and any(
            e['name'] == 'add_pseudo_pi' for e in events):
        raise RepairRejected('Cannot establish that executed pseudo-PI respects task no-bypass constraint')
    scan = rewrites[0] if rewrites else {'log_line': len(text.splitlines()) + 1}
    if checkpoint is None and ('replacement_count' not in scan or any(e['log_line'] >= scan['log_line'] for e in edits)):
        raise RepairRejected('ECO after scan rewrite or missing actual native replacement')
    fixed = [e for e in exports if 'path' in e and Path(e['path']).name in context.req['fixed_names'] and
             e['log_line'] > edits[-1]['log_line'] and e['log_line'] < scan['log_line'] and 'success' in e]
    post = [e for e in exports if e['log_line'] > scan['log_line'] and 'success' in e]
    if (len(fixed) != 1 or len(post) != (0 if checkpoint else 1) or (post and fixed[0]['path'] == post[0]['path']) or
            any(sum(e.get('path') == x['path'] for e in exports) != 1 for x in fixed + post)):
        raise RepairRejected('Missing/ambiguous/overwritten ECO-before-scan and post-scan exports')
    reports = {}
    for e in events:
        if e['name'].startswith('rpt_') and 'path' in e and e['log_line'] > (edits[-1]['log_line'] if checkpoint else scan['log_line']) and e['design'] == top:
            reports[e['name']] = e
    maps = {}
    for e in events:
        if e.get('mapping') and e['log_line'] < scan['log_line']:
            old, new = e['mapping']
            if old in maps and maps[old] != new:
                raise RepairRejected('Conflicting native ECO scan mapping')
            maps[old] = new
    paths = [log, context.execution, run / 'deliverables' / (rid + '.dofile')]
    paths += [Path(e['path']) for e in events if 'path' in e]
    data = {'case_input': str(context.input_dir.resolve()), 'output_root': str(root), 'run_ref': rid,
            'execution_id': context.execution_id,
            'design': top, 'input_fingerprints': context.inputs, 'script_sha256': _digest(context.script),
            'proposal': context.intent, 'events': events, 'mutations': edits, 'fixed_export': fixed[0],
            'post_export': post[0] if post else None, 'scan': scan, 'reports': reports, 'mappings': maps,
            'phase': 'pre_scan' if checkpoint else 'post_scan',
            'last_mutation_line': edits[-1]['log_line'],
            'mutation_state': 'native execution observed; effect requires exported structure and EQY'}
    return NativeTrace(_ISSUER, context, data, fingerprint_paths(paths), _digest(data))


def assert_trace(t):
    if not isinstance(t, NativeTrace) or t.issuer is not _ISSUER:
        raise RepairRejected('ECO stage must originate from the current native verifier')
    _current(t.context)
    if changed_paths(t.fingerprints) or _digest(t.data) != t.data_digest:
        raise RepairRejected('ECO native script/log/report/export changed after binding')


def drc_state_change(name):
    """Operations invalidating an earlier DRC observation of this ECO state.

    The intended scan rewrite is checked separately against the fixed export,
    EQY and complete object coverage; it is not a new functional ECO operation.
    Ordinary Tcl variables, getters and reports do not change DFT state.
    """
    return (name in MUTATIONS or name in {'load_lib', 'load_netlist', 'load_db', 'load_ctl', 'present_design'} or
            name.startswith(('set_scan_', 'set_current_scan_', 'set_dft_', 'add_scan_partition')))


def native_drc_snapshot(t: NativeTrace) -> dict:
    """Actual native DRC blocks after the last relevant change, never any zero.

    examine_scan_chain performs its own native DRC. Only blocks inside that
    exact executed command interval (or explicit DRC/insertion) are eligible.
    A report of cached DRC cannot by itself prove a fresh post-ECO analysis.
    """
    assert_trace(t)
    events, result = t.data['events'], []
    boundary = max((e['log_line'] for e in events if drc_state_change(e['name'])),
                   default=t.data['last_mutation_line'])
    log = t.context.run / (t.context.rid + '.log')
    native = drc_summaries(log)
    analyses = []
    for e in events:
        if e['log_line'] <= boundary or e['design'] != t.data['design']:
            continue
        if e['name'] not in {'examine_scan_drc', 'examine_scan_chain', 'rpt_scan_drc_violation', 'insert_dft_logic'}:
            continue
        scoped = [s for s in native if e['log_line'] < s['line'] <= s['end_line'] <= e.get('end_log_line', 0)]
        redirected = []
        if 'path' in e:
            path = Path(e['path'])
            headers = re.findall(r'(?m)^\s*Design:\s*(\S+)\s*$', path.read_text())
            # Native DRC reports can omit Design (saved real tool format).
            # Their fresh path, writer command, phase and native present_design
            # bind scope. An explicit contradictory header is still rejected.
            if headers and headers != [t.data['design']]:
                raise RepairRejected('ECO DRC report design is not bound')
            redirected = drc_summaries(path)
        # A native analysis may redirect its only summary to the exact fresh
        # bound path; its stdout need not duplicate that report. A cached
        # rpt_scan_drc_violation still cannot establish a new analysis alone.
        if e['name'] != 'rpt_scan_drc_violation' and (scoped or redirected):
            analyses.append(e)
        if not analyses:
            continue
        for summary in scoped:
            result.append({**summary, 'source': str(log), 'writer_line': e['log_line'],
                           'writer_command': e['name'], 'run_ref': t.context.rid,
                           'design': t.data['design'], 'state_boundary_line': boundary})
        if 'path' in e:
            result += [{**s, 'source': str(path), 'writer_line': e['log_line'],
                        'writer_command': e['name'], 'run_ref': t.context.rid,
                        'design': t.data['design'], 'state_boundary_line': boundary} for s in redirected]
    incomplete = any(s.get('invalid_counts') or sum(s['counts'].values()) != s['total'] for s in result)
    status = ('missing' if not result else 'incomplete' if incomplete else
              'nonzero' if any(s['total'] != 0 or any(s['counts'].values()) for s in result) else 'clean')
    return {'status': status, 'run_ref': t.context.rid, 'design': t.data['design'],
            'execution_id': t.context.execution_id, 'state_boundary_line': boundary,
            'fixed_export_sha256': hashlib.sha256(Path(t.data['fixed_export']['path']).read_bytes()).hexdigest(),
            'summaries': result, 'meaning': 'Same-execution post-change native DRC only; not EQY or task completion'}


def current_drc(t: NativeTrace) -> list[dict]:
    snapshot = native_drc_snapshot(t)
    if snapshot['status'] != 'clean':
        reason = {'missing': 'Missing native post-change DRC proof',
                  'incomplete': 'Incomplete native post-change DRC counts',
                  'nonzero': 'Nonzero native post-change DRC'}[snapshot['status']]
        raise RepairRejected(reason + ' for the adopted ECO state')
    return snapshot['summaries']


def analysis_modes(t):
    d, ctx = t.data, t.context
    record = {}
    signal_report = d['reports'].get('rpt_scan_signal')
    if signal_report is None:
        raise RepairRejected('Missing post-operation native scan-analysis mode signal report')
    signal_path = Path(signal_report['path'])
    if re.findall(r'(?m)^\s*Design:\s*(\S+)\s*$', signal_path.read_text()) != [d['design']]:
        raise RepairRejected('Mode signal report from another design')
    signal_rows = list(report_rows(signal_path, {'Port', 'SignalType', 'ConstantValue'}))
    record['analysis_modes'] = {}
    for port, value in ctx.req['scan_modes'].items():
        selected = [r for r in signal_rows if r['Port'] == port]
        if (len(selected) != 1 or selected[0]['SignalType'].split('(')[0] != 'constant' or
                selected[0]['ConstantValue'] != str(value)):
            raise RepairRejected('Task scan-analysis mode is not proved in native state: ' + port)
        record['analysis_modes'][port] = {'value': value, 'source': str(signal_path), 'line': selected[0]['line']}
    return record['analysis_modes']


def final_tie_handling(t, authority, effective_policy, words_for):
    """Bind the complete *configured-handling* report, not a default rule list.

    Native command manual: rpt_scan_drc_rule_handling lists settings made by
    set_scan_drc_rule_handling. The native default for TIE0/TIE1 is Warning.
    Absence establishes the unoverridden default only with an unfiltered,
    complete same-state table AND a fully bound trace with no such setting.
    This is neither a DRC waiver nor a task requirement to use Ignore.
    """
    assert_trace(t)
    d, ctx = t.data, t.context
    report = d['reports'].get('rpt_scan_drc_rule_handling')
    if report is None:
        raise RepairRejected('Missing current final native TIE handling report')
    last_update = max([d['scan']['log_line'], d['last_mutation_line'],
                       *[e['log_line'] for e in d['events'] if e['name'] == 'set_scan_drc_rule_handling']])
    if report['design'] != d['design'] or report['log_line'] <= last_update:
        raise RepairRejected('TIE handling report predates final operation or handling update')
    # Filtered reports cannot establish the whole design's configured policy.
    args = words_for(report['command'])[1:]
    i = 0; target_count = 0
    while i < len(args):
        option = args[i]
        if option in {'-file', '>'} and i + 1 < len(args):
            target_count += 1; i += 2
        elif option == '-format' and i + 1 < len(args) and args[i + 1] == 'default':
            i += 2
        else:
            raise RepairRejected('Filtered or unknown final TIE handling report scope/format')
    if target_count != 1:
        raise RepairRejected('Ambiguous final TIE handling report target')
    path = Path(report['path']); _real_file(path, ctx.output)
    lines = [line.strip() for line in path.read_text().splitlines() if line.strip()]
    if lines and lines[-1] == '1':
        lines.pop()  # Native Tcl return value in redirection, not a table row.
    columns = ['RuleType', 'DefaultLevel', 'SpecifiedLevel', 'InstRange']
    separator = lambda text: bool(re.fullmatch(r'-{3,}', text))
    if (len(lines) < 5 or lines[0] != 'Design: ' + d['design'] or
            not separator(lines[1]) or lines[2].split() != columns or
            not separator(lines[3]) or not separator(lines[-1])):
        raise RepairRejected('Missing, truncated or wrong-design final TIE handling table')
    rows = []
    for line in lines[4:-1]:
        match = re.fullmatch(r'(DFTR(?:-[A-Z][A-Z0-9]*|[0-9]+))\s+'
            r'(Error|Warning|Info|Ignore)\s+(Error|Warning|Info|Ignore)\s+(\S+)', line)
        if not match or len(rule_codes(match[1])) != 1:
            raise RepairRejected('Unknown or incomplete final TIE handling row')
        rows.append(dict(zip(columns, match.groups())))
    mandatory = required_ignored_rule_codes(ctx.spec)
    policies = []
    for code in authority['codes']:
        selected = [row for row in rows if row['RuleType'].replace('-', '') == code]
        if code in effective_policy:
            if len(selected) != 1 or selected[0]['InstRange'] != 'all':
                raise RepairRejected('Final native TIE handling object scope unknown')
            row = selected[0]; level = row['SpecifiedLevel']
            if row['DefaultLevel'] != 'Warning' or level != effective_policy[code]:
                raise RepairRejected('Final native TIE handling contradicts actual executed configuration')
            basis = 'explicit full-design native setting and final table agree'
        else:
            if selected:
                raise RepairRejected('Final native TIE setting has no corresponding executed operation')
            level = 'Warning'
            basis = 'native documented default; no executed override and complete configured-only report has no override'
        if code in mandatory and level != 'Ignore':
            raise RepairRejected('Task requires final ' + code + ' Ignore for all instances')
        policies.append({'code': code, 'level': level, 'scope': 'all', 'basis': basis})
    return {'policies': policies, 'report': {'source': path.relative_to(ctx.output).as_posix(),
        'sha256': hashlib.sha256(path.read_bytes()).hexdigest(), 'run_ref': ctx.rid,
        'design': d['design'], 'writer_log_line': report['log_line'],
        'complete_unfiltered_table': True}, 'meaning': 'configured-only native report plus actual execution trace; not a DRC or EQY proof'}


def evaluate(t: NativeTrace, words_for, deadline: float, *, native_checks_passed: bool, pre_scan_gate=None) -> dict:
    assert_trace(t)
    ctx, d = t.context, t.data
    home = ctx.output / 'eco' / ctx.rid
    binding = {**{k: d[k] for k in ('case_input', 'output_root', 'run_ref', 'execution_id', 'design', 'input_fingerprints', 'script_sha256')},
               'native_fingerprints': t.fingerprints}
    record = {'required': True, 'status': 'incomplete', 'binding': binding, 'native': d,
              'proof_required': True, 'problems': [], 'equivalence': {'status': 'not_run'}}
    try:
        if not ctx.req['raw_constraints_complete']:
            raise RepairRejected('Task ECO stage/mode/chain requirements remain ambiguous')
        library, before = source_design(ctx.originals, ctx.libs, ctx.spec, ctx.original)
        if before['top'] != d['design']:
            raise RepairRejected('Native ECO design differs from the task/input top')
        fixed = read_design([Path(d['fixed_export']['path'])], library, before['top'])
        after = read_design([Path(d['post_export']['path'])], library, before['top'])
        record['structure'] = structural_fix(before, fixed, library, ctx.req)
        record['native_drc'] = current_drc(t)
        record['analysis_modes'] = analysis_modes(t)
        for name in ('rpt_scan_chain_cell', 'rpt_scan_chain'):
            if name not in d['reports']:
                raise RepairRejected('Missing post-operation native ' + name)
        record['coverage'] = coverage(before, fixed, after, library, ctx.req, d['mappings'],
            Path(d['reports']['rpt_scan_chain_cell']['path']), Path(d['reports']['rpt_scan_chain']['path']),
            d['scan']['replacement_count'], signal_report=Path(d['reports']['rpt_scan_signal']['path']))
        authority = original_tie_authority(ctx.spec, ctx.original, words_for)
        record['tie_authority'] = authority
        effective_policy = {}
        for event in d['events']:
            if 'drc_policy' not in event:
                continue
            policy = event['drc_policy']
            if policy['level'] in {'Ignore', 'Info'}:
                allowed = authorized_ignored_rule_codes(ctx.spec) | (
                    set(authority['codes']) if policy['level'] == 'Ignore' else set())
                if not set(policy['codes']) <= allowed:
                    raise RepairRejected('Native DRC suppression exceeds task/original structural permission')
            effective_policy.update({code: policy['level'] for code in policy['codes']})
        if authority['codes']:
            record['tie_handling'] = final_tie_handling(t, authority, effective_policy, words_for)
            record['tie_policy_meaning'] = 'permission to retain Ignore, not a new requirement to Ignore when native DRC is zero'
        if not native_checks_passed:
            raise RepairRejected('Other required native/task checks failed; EQY not run')
        if pre_scan_gate is not None:
            proof = pre_scan_gate.adopt(t)
            record['equivalence_binding'] = proof['plan']['binding']
            record['pre_scan_checkpoint'] = str(pre_scan_gate.checkpoint)
        else:
            plan = eco_equivalence.prepare(ctx.originals, Path(d['fixed_export']['path']), ctx.libs,
                before, fixed, ctx.req['functional_modes'], ctx.script, words_for, home / 'functional-inputs', binding)
            proof = eco_equivalence.execute(plan, home / 'lec', deadline)
        record.update(status='pass', equivalence=proof,
            mutation_state='exported structural ECO effect checked and exact-version EQY proved')
    except (RepairRejected, CanonicalDeliveryError, OSError, ValueError, KeyError, IndexError) as exc:
        record['problems'].append(str(exc))
    _write(home / 'validation.json', record)
    return record


def failure(context: RunContext, message: str) -> dict:
    record = {'required': True, 'status': 'incomplete', 'proposal': context.intent,
              'run_ref': context.rid, 'proof_required': True, 'mutation_state': 'unknown/unverified',
              'execution_id': context.execution_id, 'case_input': str(context.input_dir),
              'input_fingerprints': context.inputs,
              'problems': [message], 'equivalence': {'status': 'not_run'}}
    log = context.run / (context.rid + '.log')
    if log.is_file():
        record['raw_native_log'] = {'source': log.relative_to(context.output).as_posix(),
                                    'sha256': hashlib.sha256(log.read_bytes()).hexdigest()}
    _write(context.output / 'eco' / context.rid / 'validation.json', record)
    return record


def publish(t: NativeTrace, record: dict) -> dict:
    """Revalidate proof and binding before adopting the actual fixed export."""
    assert_trace(t)
    if record.get('status') != 'pass' or record.get('native') != t.data:
        raise RepairRejected('ECO was not fully validated for this final native run')
    if changed_paths(record['equivalence']['proof_file_fingerprints']):
        raise RepairRejected('Adopted ECO EQY artifacts changed after proof')
    ctx = t.context
    assert_output_directories(ctx.output, ['final_results/deliverables'])
    proof = eco_equivalence.verify(record['equivalence']['plan'], ctx.output / 'eco' / ctx.rid / 'lec', proof_binding(t, record))
    source = Path(t.data['fixed_export']['path'])
    post = ctx.output / 'final_results/deliverables/post_scan.v'
    if post.is_symlink() or not post.is_file() or post.read_bytes() != Path(t.data['post_export']['path']).read_bytes():
        raise RepairRejected('Canonical post_scan.v is not this same native post-scan export')
    target = ctx.output / 'final_results/deliverables/netlist_fixed.v'
    if target.is_symlink():
        raise RepairRejected('Indirect final fixed netlist path')
    if target.exists() and target.read_bytes() != source.read_bytes():
        raise RepairRejected('Conflicting final netlist_fixed.v')
    if not target.exists():
        independent_copy(source, target)
    if target.read_bytes() != source.read_bytes():
        raise RepairRejected('Final fixed netlist differs from proved native export')
    result = {'status': 'published', 'run_ref': ctx.rid, 'fixed_source': str(source),
              'fixed_sha256': hashlib.sha256(source.read_bytes()).hexdigest(), 'target': str(target),
              'binding': record['binding'], 'proof': proof}
    _write(ctx.output / 'final_results/deliverables/eco.manifest.json', result)
    return result


def delivery_proof_paths(t, record, delivery, output, input_dir, rid, originals, libs, changes):
    """Read-only adoption proof for the existing unresolved-audit policy.

    Reuse the same native stage, object and EQY verifiers, not a reason-code
    exception or a serialized success flag. This does not prove a diagnosis.
    """
    assert_trace(t)
    ctx, d = t.context, t.data
    ledger = output / 'eco' / rid / 'validation.json'
    manifest = output / 'final_results/deliverables/eco.manifest.json'
    if (ctx.output != output.resolve() or ctx.input_dir != input_dir.resolve() or ctx.rid != rid or
            ctx.originals != originals or ctx.libs != libs or not isinstance(record, dict) or
            _digest(json.loads(ledger.read_text())) != _digest(record) or record.get('status') != 'pass' or
            record.get('native') != d or record.get('proof_required') is not True):
        raise RepairRejected('ECO delivery is not the current case/run native validation')
    binding = {**{k: d[k] for k in ('case_input', 'output_root', 'run_ref', 'execution_id',
        'design', 'input_fingerprints', 'script_sha256')}, 'native_fingerprints': t.fingerprints}
    if record.get('binding') != binding or changed_paths(record['equivalence']['proof_file_fingerprints']):
        raise RepairRejected('ECO delivery proof binding changed')
    plan = record['equivalence']['plan']
    if (plan['originals'] != list(map(str, originals)) or plan['libraries'] != list(map(str, libs)) or
            plan['fixed'] != d['fixed_export']['path'] or plan['functional_original_top'] != d['design'] or
            plan['modes'] != ctx.req['functional_modes']):
        raise RepairRejected('ECO EQY comparison/design/functional mode differs from the adopted stage')
    proof = eco_equivalence.verify(plan, output / 'eco' / rid / 'lec', proof_binding(t, record))
    library, before = source_design(originals, libs, ctx.spec, ctx.original)
    fixed_source, post_source = Path(d['fixed_export']['path']), Path(d['post_export']['path'])
    fixed = read_design([fixed_source], library, before['top'])
    after = read_design([post_source], library, before['top'])
    if (record.get('structure') != structural_fix(before, fixed, library, ctx.req) or
            record.get('coverage') != coverage(before, fixed, after, library, ctx.req, d['mappings'],
                Path(d['reports']['rpt_scan_chain_cell']['path']), Path(d['reports']['rpt_scan_chain']['path']),
                d['scan']['replacement_count'], signal_report=Path(d['reports']['rpt_scan_signal']['path'])) or record.get('native_drc') != current_drc(t)):
        raise RepairRejected('ECO current-state objects/structure/DRC proof differs')
    fixed_target = output / 'final_results/deliverables/netlist_fixed.v'
    post_target = output / 'final_results/deliverables/post_scan.v'
    expected = {'status': 'published', 'run_ref': rid, 'fixed_source': str(fixed_source),
        'fixed_sha256': hashlib.sha256(fixed_source.read_bytes()).hexdigest(),
        'target': str(fixed_target), 'binding': binding, 'proof': proof}
    # Manifest is a JSON contract: tuple-valued connectivity metadata emitted
    # by the live EQY plan is serialized as arrays. Compare the full canonical
    # JSON value, retaining every key/value and array order; no proof is added.
    if (delivery != expected or _digest(json.loads(manifest.read_text())) != _digest(expected) or
            any(p.is_symlink() for p in [ledger, manifest, fixed_target, post_target]) or
            fixed_target.read_bytes() != fixed_source.read_bytes() or
            post_target.read_bytes() != post_source.read_bytes()):
        raise RepairRejected('ECO publication does not match this adopted fixed/post version')
    native_changes = [c for c in changes if c.get('type') != 'dofile']
    if (len(native_changes) != 1 or native_changes[0].get('origin') != 'native_in_memory_ECO' or
            native_changes[0].get('path') != fixed_source.relative_to(output).as_posix() or
            native_changes[0].get('lec_ref') != 'eco/' + rid + '/lec/eqy.log'):
        raise RepairRejected('ECO adopted change is missing, ambiguous or from another run')
    return [ledger, manifest, fixed_target, post_target, output / native_changes[0]['diff_path'],
            *[Path(p) for p in proof['proof_files']],
            *[Path(p) for p in proof['plan']['input_fingerprints']]]


def change(t: NativeTrace, record: dict) -> dict:
    if record.get('status') != 'pass':
        raise RepairRejected('Unproved ECO change cannot be adopted')
    assert_trace(t)
    ctx = t.context
    original = ''.join(p.read_text() for p in ctx.originals)
    fixed = Path(t.data['fixed_export']['path'])
    text = ''.join(difflib.unified_diff(original.splitlines(True), fixed.read_text().splitlines(True),
        fromfile='actual-original-family', tofile=fixed.relative_to(ctx.output).as_posix()))
    if not text:
        raise RepairRejected('Native ECO change has no retained actual diff')
    diff = ctx.output / 'diffs' / ('eco_' + ctx.rid + '.diff'); diff.parent.mkdir(exist_ok=True)
    diff.write_text(text)
    return {'type': 'netlist', 'path': fixed.relative_to(ctx.output).as_posix(),
            'diff_path': diff.relative_to(ctx.output).as_posix(),
            'lec_ref': ('eco/' + ctx.rid + '/lec/eqy.log'), 'origin': 'native_in_memory_ECO'}


_GATE_BEGIN = '# Agent ECO pre-scan gate'
_GATE_END = '# End agent ECO pre-scan gate'


def instrument(script, run, words_for):
    """Insert a same-process barrier. Never evaluate/rewrite model ECO commands."""
    script = re.sub(r'(?ms)^' + re.escape(_GATE_BEGIN) + r'\n.*?^' + re.escape(_GATE_END) + r'(?:\n|$)', '', script)
    chunks = _chunks(script)
    indices = []
    for index, chunk in enumerate(chunks):
        code = re.sub(r'\\\n\s*', ' ', chunk).strip().rstrip(';').strip()
        if not code or code.startswith('#'):
            continue
        words = words_for(code)
        if words and words[0] in {'insert_dft_logic', '::insert_dft_logic'}:
            indices.append(index)
    if len(indices) != 1:
        raise RepairRejected('ECO pre-scan gate requires one explicit top-level insert_dft_logic; no insertion authorized')
    token = uuid.uuid4().hex
    report = run / 'eco_stage' / 'signal.pre_scan'
    report.parent.mkdir(parents=True, exist_ok=True)
    # All inserted operations are runtime-owned; no Tcl shell/file IPC or altered tool state.
    block = ('\n' + _GATE_BEGIN + '\n' +
        'rpt_scan_signal -file {' + str(report) + '}\n' +
        'puts ECO_PRE_SCAN_READY_' + token + '\nflush stdout\n' +
        'if {[gets stdin] ne "ECO_ALLOW_' + token + '"} {error "ECO pre-scan validation denied"}\n' +
        _GATE_END + '\n')
    chunks[indices[0]] = block + chunks[indices[0]]
    return ''.join(chunks)


def _stage_binding(ctx, design, fixed, checkpoint):
    _current(ctx)
    expected = ctx.output / 'eco' / ctx.rid / 'pre_scan_native.log'
    if checkpoint != expected:
        raise RepairRejected('Pre-scan checkpoint belongs to another case or round')
    _real_file(checkpoint, ctx.output)
    prefix = checkpoint.read_bytes()
    live = ctx.run / (ctx.rid + '.log')
    if not live.read_bytes().startswith(prefix):
        raise RepairRejected('Native pre-scan prefix changed after checkpoint')
    if not re.search(rb'(?m)^ECO_PRE_SCAN_READY_[a-f0-9]{32}\r?$', prefix):
        raise RepairRejected('Pre-scan pause was not observed in native output')
    return {'case_input': str(ctx.input_dir.resolve()), 'output_root': str(ctx.output),
        'run_ref': ctx.rid, 'execution_id': ctx.execution_id, 'design': design,
        'input_fingerprints': ctx.inputs, 'script_sha256': _digest(ctx.script),
        'fixed': str(fixed), 'fixed_sha256': hashlib.sha256(fixed.read_bytes()).hexdigest(),
        'pre_scan_checkpoint': str(checkpoint), 'pre_scan_sha256': hashlib.sha256(prefix).hexdigest()}


def proof_binding(t, record):
    if 'equivalence_binding' not in record:
        return record['binding']  # Existing non-barrier saved proofs remain strict and unchanged.
    bound = _stage_binding(t.context, t.data['design'], Path(t.data['fixed_export']['path']),
                           Path(record.get('pre_scan_checkpoint', '')))
    if bound != record['equivalence_binding']:
        raise RepairRejected('EQY proof is not bound to the adopted pre-scan export')
    return bound


class PreScanGate:
    """Runtime-issued, one-shot same-process pause → structural proof → EQY.

    Paused native output is not reported as a completed run. Unknown/failed
    proof kills the waiting native process before it can insert scan cells.
    """
    def __init__(self, context, words_for, deadline):
        self.context, self.words_for, self.deadline = context, words_for, deadline
        tokens = re.findall(r'(?m)^puts ECO_PRE_SCAN_READY_([a-f0-9]{32})$', context.script)
        if len(tokens) != 1:
            raise RepairRejected('Missing/ambiguous runtime pre-scan barrier')
        self.ready = 'ECO_PRE_SCAN_READY_' + tokens[0]
        self.release = 'ECO_ALLOW_' + tokens[0]
        self.checkpoint = context.output / 'eco' / context.rid / 'pre_scan_native.log'
        self.proof, self.bound, self.called = None, None, False
        self.record = {'status': 'not_reached', 'run_ref': context.rid, 'proof_required': True}
        self._save()

    def _save(self):
        self.checkpoint.parent.mkdir(parents=True, exist_ok=True)
        from runtime_events import atomic
        atomic(self.checkpoint.parent / 'pre_scan_gate.json', self.record)

    def drc_monitor_policy(self, run_dir, run_id):
        """Authorize phase-bound DRC validation for this exact runtime context.

        Repair diagnosis may precede the actual ECO. The pre-scan barrier still
        requires a fresh export, structure/modes and full functional EQY; the
        completed native trace then selects current-state DRC in current_drc.
        A directory-wide union of old diagnosis reports proves neither stage.
        Native command errors remain immediately fatal in the process monitor.
        """
        _current(self.context)
        if (self.context.run != Path(run_dir).absolute() or self.context.rid != run_id or
                self.called or self.record['status'] != 'not_reached'):
            raise RepairRejected('DRC monitoring gate is not this fresh case/round execution')
        return {'validator': 'ECO_current_state', 'run_ref': run_id,
                'execution_id': self.context.execution_id,
                'final_DRC_required': True, 'pre_scan_proof_required': True}

    def check(self):
        from runtime_events import emit as runtime_event
        if self.called:
            raise RepairRejected('Pre-scan gate cannot be released twice')
        self.called = True
        self.record.update(status='checking', checkpoint=str(self.checkpoint), problems=[])
        self._save()
        runtime_event('eco_pre_scan_start', status='checking')
        try:
            self.checkpoint.parent.mkdir(parents=True, exist_ok=True)
            live = self.context.run / (self.context.rid + '.log')
            raw = live.read_bytes()
            if (b'\n' + self.ready.encode() + b'\n') not in raw:
                raise RepairRejected('Native process has not reached its runtime pre-scan barrier')
            if self.checkpoint.exists():
                raise RepairRejected('Preexisting pre-scan checkpoint cannot be reused')
            self.checkpoint.write_bytes(raw)
            t = trace(self.context, {}, self.words_for, checkpoint=self.checkpoint)
            ctx, d = t.context, t.data
            if not ctx.req['raw_constraints_complete']:
                raise RepairRejected('Task ECO requirements remain ambiguous')
            lib, before = source_design(ctx.originals, ctx.libs, ctx.spec, ctx.original)
            if before['top'] != d['design']:
                raise RepairRejected('Pre-scan design differs from task/input')
            fixed_path = Path(d['fixed_export']['path'])
            fixed = read_design([fixed_path], lib, before['top'])
            self.record['structure'] = structural_fix(before, fixed, lib, ctx.req)
            self.record['analysis_modes'] = analysis_modes(t)
            self.bound = _stage_binding(ctx, d['design'], fixed_path, self.checkpoint)
            plan = eco_equivalence.prepare(ctx.originals, fixed_path, ctx.libs, before, fixed,
                ctx.req['functional_modes'], ctx.script, self.words_for,
                self.checkpoint.parent / 'functional-inputs', self.bound)
            self.proof = eco_equivalence.execute(plan, self.checkpoint.parent / 'lec', self.deadline)
            assert_trace(t)
            if _stage_binding(ctx, d['design'], fixed_path, self.checkpoint) != self.bound:
                raise RepairRejected('ECO state changed during paused EQY')
            self.record.update(status='pass', equivalence=self.proof, binding=self.bound)
            return True
        except (RepairRejected, CanonicalDeliveryError, OSError, ValueError, KeyError, IndexError) as exc:
            self.record.update(status='incomplete', problems=[str(exc)], equivalence={'status': 'not_proved'})
            return False
        finally:
            self._save()
            runtime_event('eco_pre_scan_end', status=self.record['status'], reason='; '.join(self.record.get('problems', []))[:800])

    def adopt(self, t):
        assert_trace(t)
        if self.record['status'] != 'pass' or self.context is not t.context or self.proof is None:
            raise RepairRejected('Insertion lacks an accepted current execution pre-scan EQY gate')
        bound = _stage_binding(t.context, t.data['design'], Path(t.data['fixed_export']['path']), self.checkpoint)
        if bound != self.bound:
            raise RepairRejected('Post-scan run is not continuous with the EQY-proved fixed export')
        return eco_equivalence.verify(self.proof['plan'], self.checkpoint.parent / 'lec', bound)


def collect_bound_outputs(t):
    """Copy only fresh native-issued outputs, including generated input/output.

    Original inputs are not collected. Original paths remain immutable and all
    copies have content checks; collision never silently overwrites evidence.
    """
    assert_trace(t)
    run = t.context.run
    copied = []
    for e in t.data['events']:
        if 'path' not in e or not Path(e['path']).is_relative_to(run / 'input'):
            continue
        source = Path(e['path'])
        if source == run / 'eco_stage/signal.pre_scan':
            continue  # Private pre-insertion observation, never a final audit report.
        directory = 'deliverables' if e['name'] == 'dump_netlist' else 'reports'
        target = run / directory / source.name
        target.parent.mkdir(exist_ok=True)
        if target.exists():
            _real_file(target, t.context.output)
            if target.read_bytes() != source.read_bytes():
                raise RepairRejected('Conflicting collected native output: ' + str(target))
        else:
            independent_copy(source, target)
        copied.append(str(target))
    return copied
