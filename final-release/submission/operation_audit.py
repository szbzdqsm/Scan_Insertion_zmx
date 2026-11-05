"""Operation-stage native reports and conjunctive full-insertion audit evidence.

No model or tool is invoked here. Report requests join the existing tool round;
all closure references point to observed commands and actual native report rows.
Unknown Tcl, objects, phases and missing subclaims abstain rather than pass.
"""
from __future__ import annotations

from pathlib import Path, PurePosixPath
from collections import Counter
import difflib
import hashlib
import json
import re

from canonical_delivery import CanonicalDeliveryError, _real_file, _target
from insertion_evidence import _scope
from report_validation import (_COVERAGE_FIELDS, _insertion_summary_blocks,
                               chain_problems, partition_requirements, report_rows)



def _action_command_pattern():
    # Use the same shipped native command vocabulary as the runtime help.
    # A prefix list alone silently omitted insert_dft_logic from compound edits.
    native = json.loads(Path(__file__).with_name('tool_help.json').read_text())
    names = sorted(n for n in native if re.fullmatch(r'[a-z][a-z0-9_]*', n))
    return r'\b(?:' + '|'.join(map(re.escape, names)) + r'|(?:set|load|add|dump|rpt)_[a-z_]+)\b'


def literal_action_transitions(clause: str) -> list[dict]:
    """Separate explicit old/new literal signal options; never execute prose.

    An omitted selector on the right refers to the explicit left-hand object.
    Unknown syntax retains the existing conservative literal-operation check.
    """
    boundary = re.search(r'改为|改成|变更为|\bto\b|\bwith\b|→|->', clause, re.I)
    if not boundary:
        return []
    left, right = clause[:boundary.start()], clause[boundary.end():]
    command = re.findall(r'\b(?:set|load|add|dump|rpt)_[a-z_]+\b', left)
    right_commands = re.findall(r'\b(?:set|load|add|dump|rpt)_[a-z_]+\b', right)
    if (command != ['set_scan_signal'] or right_commands not in ([], command) or
            not re.match(r'\s*[`\s]*(?:set_scan_signal\s+)?-', right)):
        return []
    def pairs(text):
        return re.findall(r'(?<![\w])(-(?:port|type|off_state|usage|constant_value))\s+'
                          r'(\{[^{}]*\}|"[^"\n]*"|[A-Za-z_][\w./]*(?:\[\d+\])?|\d+)(?![\w$./\[])', text)
    old_pairs, new_pairs = pairs(left), pairs(right)
    if (not old_pairs or not new_pairs or len(dict(old_pairs)) != len(old_pairs) or
            len(dict(new_pairs)) != len(new_pairs)):
        return []
    clean = lambda ps: {k: v.strip('"{}') for k, v in ps}
    before, explicit_after = clean(old_pairs), clean(new_pairs)
    after = {**before, **explicit_after}
    if '-port' not in before or '-type' not in before or any(after[k] != before[k] for k in ('-port', '-type')):
        return []  # Object/role replacements retain their existing verifier.
    parameters = {k: {'before': before[k], 'after': v} for k, v in explicit_after.items()
                  if k in before and k not in {'-port', '-type'}}
    if not parameters:
        return []
    return [{'command': command[0], 'object': before['-port'], 'role': before['-type'],
             'before': before, 'after': after, 'parameters': parameters}]


def _bind_action_transition(claim, states, root, current, words_for):
    """Exact cited delta AND prior/repaired/current native execution scope.

    This proves the edit, not the diagnosis or final correctness. Existing
    typed post-operation native report validators must still pass separately.
    """
    from configuration_evidence import _signal_command_trace
    def options(row):
        if not row or row[0] != claim['command'] or len(row) % 2 != 1 or len(set(row[1::2])) != len(row[1::2]):
            return None
        return {k: v.strip('"{}') for k, v in zip(row[1::2], row[2::2])}
    def matches(row, wanted):
        actual = options(row)
        return actual is not None and all(actual.get(k) == v for k, v in wanted.items())
    if any(p['before'] == p['after'] for p in claim['parameters'].values()):
        return False
    candidates = []
    for state in states:
        removed, added = state['removed'], state['added']
        old_rows = list({r for r in removed if matches(r, claim['before'])})
        new_rows = list({r for r in added if matches(r, claim['after'])})
        if len(old_rows) == len(new_rows) == 1:
            candidates.append((state, old_rows[0], new_rows[0]))
    if len(candidates) != 1:
        return False
    state, old_row, new_row = candidates[0]
    traces = [_signal_command_trace(root, rid, words_for) for rid in
              (state['from_run'], state['to_run'], current)]
    if (not all(traces) or len({t['design'] for t in traces}) != 1 or
            not traces[0]['loaded_netlists'] == traces[1]['loaded_netlists'] == traces[2]['loaded_netlists']):
        return False
    events = []
    for index, trace in enumerate(traces):
        # Do not borrow a value from another partition or ignore an override.
        target = [e for e in trace['signals'] if (options(e['words']) or {}).get('-port') == claim['object']]
        if len(target) != 1 or target[0]['errors']:
            return False
        event = target[0]
        if index < 2 and tuple(event['words']) != (old_row if index == 0 else new_row):
            return False
        # The repaired round proves the entire historical command above.
        # The final round must retain this action's changed parameters, not
        # unrelated values merely inherited from its former command context.
        # Dedicated final task/report checks still enforce every final duty.
        current_required = {k: claim['after'][k] for k in ('-port', '-type')}
        current_required.update({k: p['after'] for k, p in claim['parameters'].items()})
        if index == 2 and not matches(event['words'], current_required):
            return False
        events.append(event)
    return len({e['partition'] for e in events}) == 1


def _ordered_edit_commands(clause, states, root, words_for):
    """Prove a cited relative-order change, not mere command membership.

    Explicit command anchors and the existing wrapper style/port vocabulary
    identify both operations. No closest-name or single-candidate guessing.
    Original/repaired scripts AND their native execution must agree.
    """
    match = re.search(r'\b((?:set|load|add|dump|rpt)_[a-z_]+)\b\s+(before|after)\s+(.+)', clause, re.I)
    if not match:
        return set()
    command, relation, suffix = match.groups()
    style = re.fullmatch(r'(?:applying\s+)?(?:the\s+)?([A-Za-z_]\w*)\s+style\s+to\s+([A-Za-z_][\w$./]*(?:\[\d+\])?)\s*', suffix)
    if style:
        anchor = lambda row: row[:1] == ('set_wrapper_cfg',) and all(
            key in row and len(row[row.index(key)+1:]) > 0 and row[row.index(key)+1].strip('{}"') == value
            for key, value in [('-style', style[1]), ('-port', style[2])])
    else:
        literal = tuple(words_for(suffix.strip().strip('`')))
        if not literal or not re.fullmatch(r'(?:set|load|add|dump|rpt)_[a-z_]+', literal[0]):
            return set()
        anchor = lambda row: row == literal
    from dofile_recipe import tcl_chunks
    from plan_provenance import _executed
    from configuration_evidence import _signal_command_trace
    matches = []
    for state in states:
        selected = []
        for key, rid in [('before_script', state['from_run']), ('after_script', state['to_run'])]:
            script = state[key]
            chunks = [tuple(words_for(c.strip())) for c in tcl_chunks(script) if c.strip() and not c.lstrip().startswith('#')]
            left = [(i, row) for i, row in enumerate(chunks) if row[:1] == (command,)]
            right = [(i, row) for i, row in enumerate(chunks) if anchor(row)]
            if len(left) != 1 or len(right) != 1:
                break
            li, lr = left[0]; ri, rr = right[0]
            echoes, _ = _executed(root/'runs'/rid, script, words_for)
            native = [[e for es in echoes.values() for e in es if tuple(words_for(e['command'])) == row] for row in [lr, rr]]
            scope = _signal_command_trace(root, rid, words_for)
            if not scope or any(len(n) != 1 or n[0]['design'] != scope['design'] for n in native):
                break
            # Compare the executed input/library/design initialization, not
            # later tool-generated wrapper-template Verilog reads. Those
            # internal reads are not changes to the input design family.
            initialization = tuple(tuple(words_for(e['command'])) for _, es in sorted(echoes.items())
                for e in es if (words_for(e['command']) or [''])[0] in
                {'load_lib', 'load_netlist', 'present_design'})
            if sum(row[:1] == ('present_design',) for row in initialization) != 1:
                break
            before = li < ri
            if before != (native[0][0]['line'] < native[1][0]['line']):
                break
            selected.append((before, lr, rr, scope['design'], initialization))
        if len(selected) != 2 or selected[0][1:] != selected[1][1:]:
            continue
        wanted = relation.lower() == 'before'
        if selected[0][0] != wanted and selected[1][0] == wanted:
            matches.append(command)
    return {command} if matches == [command] else set()


def fix_action_reference_problems(issue: dict, changes: list[dict], output_dir: Path, words_for) -> list[dict]:
    """Bind explicit command edits to their referenced, byte-verified delta.

    This checks a necessary action antecedent, not arbitrary prose or causal
    truth. A later script containing an earlier edit does not make that edit
    part of the later diff. Original records are never remapped or rewritten.
    """
    from dofile_recipe import tcl_chunks
    attempt = (issue.get('attempts') or [{}])[-1]
    action = str(attempt.get('fix', {}).get('action', ''))
    command_pattern = _action_command_pattern()
    # Ordering/prerequisite mentions are not themselves claimed modifications.
    clauses = re.split(r'[;；。\n]|\.(?![\w$])|\band\s+(?=(?:add|declare|remove|change|set)\b)', action, flags=re.I)
    edits = [clause for clause in clauses if re.search(
        r'\b(?:add(?:ed|ing|s)?|remov(?:e|ed|es|ing)|chang(?:e|ed|es|ing)|'
        r'replac(?:e|ed|es|ing)|configur(?:e|ed|es|ing)|set|declar(?:e|ed|es|ing)|'
        r'exclud(?:e|ed|es|ing)|correct(?:ed|ing|s)?)\b', clause, re.I) or
        re.search(r'\b(?:set|load|add|dump|rpt)_[a-z_]+\s+-[a-z_]+\b', clause) or
        re.search(r'^\s*(?:已)?(?:移除|删除|撤销)\s+`?(?:set|load|add|dump|rpt)_[a-z_]+\b', clause)]
    subject = ' '.join(re.split(r'\bbefore\b|\bafter\b', clause, maxsplit=1, flags=re.I)[0] for clause in edits)
    commands = set(re.findall(command_pattern, subject))
    if not commands:
        return []
    problem = {'reason': 'fix_action_reference_not_bound', 'original_clause': action,
               'required_commands': sorted(commands), 'detail': 'Referenced changes must contain the claimed command edits, not only an inherited final state.'}
    try:
        root = output_dir.absolute(); refs = attempt.get('fix', {}).get('artifact_ref', [])
        selected = [c for ref in refs for c in changes if c.get('change_id') == ref]
        if not refs or len(selected) != len(refs) or len(set(refs)) != len(refs):
            return [problem]
        deltas = []; bindings = []; states = []
        current = str(attempt.get('verify', {}).get('run_ref', ''))
        found = str(issue.get('found', {}).get('run_ref', ''))
        for change in selected:
            if change.get('type') != 'dofile':
                continue
            path = root/str(change.get('path', '')); diff = root/str(change.get('diff_path', ''))
            _real_file(path, root); _real_file(diff, root)
            text = diff.read_text(); header = re.match(r'--- (R[1-9]\d*)\n\+\+\+ (R[1-9]\d*)\n', text)
            if not header or not re.fullmatch(r'R[1-9]\d*', current) or not re.fullmatch(r'R[1-9]\d*', found):
                return [problem]
            old, new = header[1], header[2]
            if not int(found[1:]) <= int(old[1:]) < int(new[1:]) <= int(current[1:]):
                return [problem]
            if path != root/'runs'/new/'deliverables'/(new+'.dofile') or not diff.is_relative_to(root/'diffs'):
                return [problem]
            before = root/'runs'/old/'deliverables'/(old+'.dofile'); _real_file(before, root)
            prior, now = before.read_text(), path.read_text()
            expected = ''.join(difflib.unified_diff(prior.splitlines(True), now.splitlines(True), fromfile=old, tofile=new))
            if text != expected:
                return [problem]
            def parsed(script):
                # A body line can be a referenced edit inside an if/loop too.
                # This proves membership in the real delta, never execution
                # or Tcl equivalence; native verifiers retain that obligation.
                chunks = list(tcl_chunks(script)) + script.splitlines()
                return Counter(tuple(words_for(c.strip().replace('\\\n', ' '))) for c in chunks
                               if c.strip() and not c.lstrip().startswith('#'))
            # Include either side for removal/replacement claims; unchanged
            # commands in a later round cannot support a claimed modification.
            previous, following = parsed(prior), parsed(now)
            deltas.extend((following-previous).elements()); deltas.extend((previous-following).elements())
            states.append({'from_run': old, 'to_run': new,
                           'before_script': prior, 'after_script': now,
                           'removed': list((previous-following).elements()),
                           'added': list((following-previous).elements())})
            bindings.append({'change_id': change['change_id'], 'path': change['path'],
                             'diff_path': change['diff_path'], 'from_run': old, 'to_run': new})
        ordered = set().union(*(_ordered_edit_commands(clause, states, root, words_for) for clause in edits))
        missing = sorted(command for command in commands if command not in ordered and not any(row and row[0] == command for row in deltas))
        # Explicit flags in an action must also occur in its referenced edits.
        # This is a necessary check; typed verifiers still prove values/objects.
        flags = set(re.findall(r'(?<![\w])-([a-z_]+)\b', subject))
        missing_flags = []
        for clause in edits:
            local = re.split(r'\bbefore\b|\bafter\b', clause, maxsplit=1, flags=re.I)[0]
            named = set(re.findall(command_pattern, local))
            for flag in re.findall(r'(?<![\w])-([a-z_]+)\b', local):
                candidates = {row for row in deltas if row and (not named or row[0] in named) and '-'+flag in row}
                # An unnamed global option belongs to its uniquely changed
                # command, not a different named command in the next clause.
                if not named:
                    if re.search(r'\bglobal\b|全局', local, re.I):
                        candidates = {row for row in candidates if not set(row) & {'-port', '-inst', '-partition'}}
                    value = re.search(r'(?<![\w])-' + re.escape(flag) + r'\s+([A-Za-z_][\w./]*|\d+)(?![\w./])', local)
                    if value:
                        candidates = {row for row in candidates if row[row.index('-'+flag)+1:][:1] == (value[1],)}
                    if len(candidates) != 1:
                        candidates = set()
                if not candidates:
                    missing_flags.append(flag)
        missing_flags = sorted(set(missing_flags))
        literal_claims = []; transitions = []
        for clause in edits:
            clause = re.split(r'\bbefore\b|\bafter\b', clause, maxsplit=1, flags=re.I)[0]
            transition = literal_action_transitions(clause)
            if transition:
                transitions.extend(transition)
                continue
            named = list(re.finditer(command_pattern, clause))
            for index, match in enumerate(named):
                segment = (clause if len(named) == 1 else
                           clause[match.start():named[index+1].start() if index+1 < len(named) else len(clause)])
                pairs = re.findall(
                    r'(?<![\w])(-(?:port|type|off_state|usage|constant_value))\s+'
                    r'([A-Za-z_][\w$./]*(?:\[\d+\])?|\d+)(?![\w$./\[])', segment)
                # "from ... to ..." is a description, not an option value.
                pairs = [(key, value) for key, value in pairs if value not in {'from', 'to', 'and', 'with'}]
                if pairs:
                    literal_claims.append((match[0], pairs))
        missing_literals = [{'command': command, 'options': pairs} for command, pairs in literal_claims
                            if not any(row and row[0] == command and all(
                                key in row and row[row.index(key)+1:][:1] == (value,) for key, value in pairs)
                                for row in deltas)]
        missing_transitions = [t for t in transitions if not _bind_action_transition(t, states, root, current, words_for)]
        if missing or missing_flags or missing_literals or missing_transitions:
            problem.update(missing_commands=missing, missing_options=missing_flags,
                           missing_literal_operations=missing_literals, referenced_changes=bindings)
            if missing_transitions:
                problem['unbound_transitions'] = missing_transitions
            return [problem]
    except (OSError, ValueError, TypeError, KeyError, CanonicalDeliveryError):
        return [problem]
    return []


def control_repair_reference_problems(issue: dict, changes: list[dict], output_dir: Path,
                                     current_run: str, words_for) -> list[dict]:
    """Retain an unresolved located reset after the last cited control edit.

    A later unreferenced reset edit and final success cannot establish that the
    cited operation repaired that whole object scope. This reports insufficient
    attribution, not a claim that an earlier contribution did nothing.
    """
    found = issue.get('found', {})
    target = re.search(r"Reset input '([^']+)' of 'DFF' '([^']+)'", str(found.get('excerpt', '')))
    fix = (issue.get('attempts') or [{}])[-1].get('fix', {})
    if not target or not re.search(r'\bset_scan_signal\b.*-type\s+reset\b', str(fix.get('action', ''))):
        return []
    selected = [c for c in changes if c.get('change_id') in fix.get('artifact_ref', []) and c.get('type') == 'dofile']
    ends = [re.fullmatch(r'runs/(R[1-9]\d*)/deliverables/\1.dofile', c.get('path', '')) for c in selected]
    if not ends or not all(ends):
        return []  # The byte/reference guard reports malformed references.
    last = max(int(m[1][1:]) for m in ends)
    if not re.fullmatch(r'R[1-9]\d*', current_run) or last >= int(current_run[1:]):
        return []
    later = []
    for change in changes:
        match = re.fullmatch(r'runs/(R[1-9]\d*)/deliverables/\1.dofile', change.get('path', ''))
        if change.get('type') != 'dofile' or not match or not last < int(match[1][1:]) <= int(current_run[1:]):
            continue
        path = output_dir/change.get('diff_path', '')
        try:
            _real_file(path, output_dir)
            if any(line.startswith('+') and not line.startswith('+++') and
                   re.search(r'\bset_scan_signal\b.*-type\s+reset\b', line) for line in path.read_text().splitlines()):
                later.append(change['change_id'])
        except (OSError, CanonicalDeliveryError):
            return [{'status': 'incomplete', 'reason': 'reset_action_reference_unbound'}]
    if not later:
        return []
    for path in sorted((output_dir/'runs'/f'R{last}'/'reports').glob('*.rpt')):
        with path.open(errors='replace') as stream:
            for line_number, line in enumerate(stream, 1):
                observed = re.search(r"Reset input '([^']+)' of 'DFF' '([^']+)' is uncontrolled", line)
                if observed and observed.groups() == target.groups():
                    return [{'status': 'incomplete', 'reason': 'located_reset_not_covered_by_cited_actions',
                        'object': target[2], 'pin': target[1], 'cited_changes': fix.get('artifact_ref', []),
                        'later_uncited_reset_changes': later, 'native_evidence': {
                            'run_ref': f'R{last}', 'source': path.relative_to(output_dir).as_posix(),
                            'locator': f'L{line_number}', 'excerpt': line.strip()},
                        'detail': 'Bind the actual repair of the located object; final DRC success does not supply the missing action relationship.'}]
    return []


def compound_coverage_claim(claim: dict) -> bool:
    diagnosis = claim.get('diagnosis', {})
    text = ' '.join(str(x) for x in [claim.get('phenomenon', ''), diagnosis,
                                    claim.get('violated_requirement', '')])
    found = claim.get('found', {}).get('excerpt', claim.get('evidence_excerpt', ''))
    return bool(re.search(r'Chain\s+Length\s+Input', str(found)) and
                re.search(r'\bFFs?\b|flip.flop|触发器', text, re.I) and
                re.search(r'replac|cover|替换|覆盖', text, re.I) and
                re.search(r'\bchains?\b|扫描链', text, re.I))


def report_requests(dofile: str, claims: list, words_for) -> list[str]:
    """Only request full-flow evidence for actual mapping/compound audit claims."""
    if not _scope(dofile, words_for):
        return []
    mapping = any(isinstance(c, dict) and re.search(r'\bset_scan_cell_mapping\b',
                  str(c.get('located_object', c.get('diagnosis', {})))) for c in claims)
    compound = any(isinstance(c, dict) and compound_coverage_claim(c) for c in claims)
    return (['rpt_scan_chain_cell', 'rpt_scan_chain', 'rpt_scan_element', 'rpt_insertion_info'] if compound else
            ['rpt_scan_chain_cell'] if mapping else [])


def operation_trace(files: list[Path], output_dir: Path, dofile: str, words_for,
                    *, allow_verbose: bool = False, require_insertion: bool = True, eco_trace=None) -> dict | None:
    """Bind one executed design/full insertion and every report writer to its script."""
    from eco_object_selection import is_context_query
    try:
        root = output_dir.absolute()
        logs = [p for p in files if p.suffix == '.log' and p.name == p.parent.name + '.log']
        if len(logs) != 1:
            return None
        log = logs[0]; run = log.parent; rid = run.name
        if not re.fullmatch(r'R[1-9]\d*', rid) or run != root/'runs'/rid:
            return None
        for path in files:
            _real_file(path, root)
            if not path.is_relative_to(run):
                return None
        script = run/'deliverables'/(rid+'.dofile'); _real_file(script, root)
        if script.read_text() != dofile:
            return None
        native_generated = False
        if eco_trace is not None:
            from eco_evidence import assert_trace
            assert_trace(eco_trace)
            if (eco_trace.context.output != root.resolve() or eco_trace.context.rid != rid or
                    eco_trace.context.script != dofile or eco_trace.data['design'] == '' or
                    eco_trace.data.get('phase') == 'pre_scan'):
                return None
            native_generated = True  # Same immutable native log/script; not a pathname waiver.
        lines = dofile.splitlines(); virtual = None; top = ''; active = []; pending = ''
        variables, reports, mappings, operations, outputs = {}, [], [], [], []
        output_event = None
        completion = False; present_count = 0
        with log.open(errors='replace') as stream:
            for number, line in enumerate(stream, 1):
                if re.search(r'\[(?:ERROR|FATAL)\]', line):
                    return None
                origin = re.search(r'\[SOURCE TCL FILE\]\s+(\S+)\s*:', line)
                if origin:
                    path = PurePosixPath(origin[1]); indexes = [i for i,p in enumerate(path.parts)
                        if p == 'runs' and path.parts[i+1:i+2] == (rid,)]
                    if virtual is not None or len(indexes) != 1 or '..' in path.parts:
                        return None
                    cut = indexes[0]+2; virtual = PurePosixPath(*path.parts[:cut])
                    actual = run.joinpath(*path.parts[cut:]); _real_file(actual, root)
                    if actual.read_bytes() != script.read_bytes():
                        return None
                echo = re.search(r'CMD-0034\]\s+@(\d+):\s*(.*)', line)
                if echo:
                    text = echo[2].strip(); active = words_for(text); pending = ''
                    output_event = None
                    if not active:
                        continue
                    name = active[0]
                    relevant = name in {'present_design', 'insert_dft_logic', 'set_scan_cell_mapping', 'set', 'dump_ctl', 'dump_def', 'dump_scan_def'} or name.startswith('rpt_') or is_context_query(text)
                    if relevant and (int(echo[1]) < 1 or int(echo[1]) > len(lines) or lines[int(echo[1])-1].strip() != text):
                        return None
                    event = {'source': log.relative_to(root).as_posix(), 'locator': f'L{number}',
                             'excerpt': line.strip(), 'command': text, 'script_line': int(echo[1]),
                             'log_line': number, 'run_ref': rid, 'design': top}
                    if name == 'set' and len(active) == 3:
                        pending = active[1]; variables.pop(pending, None)
                    elif name == 'present_design':
                        present_count += 1
                        if present_count != 1 or len(active) != 2 or not re.fullmatch(r'[A-Za-z_$][\w$]*', active[1]):
                            return None
                    elif name == 'set_scan_cell_mapping':
                        if len(active) != 3 or operations:
                            return None
                        mappings.append({**event, 'source_cell': active[1], 'target_cell': active[2]})
                    elif name == 'insert_dft_logic':
                        if not top or (require_insertion and (
                                (active != ['insert_dft_logic'] and not (allow_verbose and active == ['insert_dft_logic','-verbose'])) or operations)):
                            return None
                        operations.append(event)
                    elif name.startswith('rpt_') and len(active) == 3 and active[1] in {'-file', '>'}:
                        if virtual is None:
                            return None
                        target = _target(active[2], variables, virtual, run, words_for, native_generated=native_generated)
                        reports.append({**event, 'path': target, 'kind': name})
                    elif name == 'rpt_scan_element' and len(active) == 5 and active[1:3] == ['-type','all'] and active[3] in {'-file','>'}:
                        if virtual is None:
                            return None
                        reports.append({**event, 'path': _target(active[4],variables,virtual,run,words_for,native_generated=native_generated), 'kind': name})
                    elif name in {'dump_ctl', 'dump_def', 'dump_scan_def'}:
                        # The separate scan-only writer has an explicit native
                        # contract. Unsupported expansion/default forms abstain.
                        if name == 'dump_scan_def' and (len(active) != 3 or active[1] != '-file'):
                            return None
                        value = (active[1] if name == 'dump_ctl' and len(active) == 2 else
                                 active[active.index('-file')+1] if '-file' in active and active[-2:-1] == ['-file'] else None)
                        if value is None or virtual is None:
                            return None
                        output_event = {**event, 'kind': 'dump_def' if name == 'dump_scan_def' else name,
                                        'native_command_name': name,
                                        'path': _target(value, variables, virtual, run, words_for,native_generated=native_generated)}
                        outputs.append(output_event)
                    continue
                if output_event:
                    ctl = re.search(r"CTL-O-0001\]\s+Dump CTL file '([^']+)' successfully\.", line)
                    if ((output_event['kind'] == 'dump_def' and line.strip() == '1') or
                            (output_event['kind'] == 'dump_ctl' and ctl and
                             _target(ctl[1], variables, virtual, run, words_for,native_generated=native_generated) == output_event['path'])):
                        output_event['completion'] = {'source': log.relative_to(root).as_posix(),
                            'locator': f'L{number}', 'excerpt': line.strip()}
                if pending:
                    value = line.strip()
                    if value and not value.startswith('[') and not re.search(r'[$\[\]\\;]', value):
                        variables[pending] = value
                    pending = ''
                design = re.search(r"CMD-1300\]\s+Present design is '([^']+)'", line)
                if design:
                    if active != ['present_design', design[1]]:
                        if not (top == design[1] and is_context_query(event['command'])):
                            return None
                    top = design[1]
                replacement = re.search(r"SCAN-7600\]\s+There were (\d+) 'D' flip-flops that have been replaced\.", line)
                if replacement:
                    if require_insertion and ((active != ['insert_dft_logic'] and not (allow_verbose and active == ['insert_dft_logic','-verbose'])) or len(operations) != 1 or 'replacement' in operations[0]):
                        return None
                    if not operations:
                        return None
                    operations[-1]['replacement'] = {'source': log.relative_to(root).as_posix(),
                        'locator': f'L{number}', 'excerpt': line.strip(), 'count': int(replacement[1]), 'log_line': number}
                if 'CMD-0042' in line and 'Thank you' in line:
                    completion = True
        if (not completion or not top or require_insertion and (len(operations) != 1 or
                operations[0]['design'] != top or 'replacement' not in operations[0])):
            return None
        return {'run_ref':rid, 'design':top, 'operation':operations[-1] if operations else None, 'reports':reports, 'mappings':mappings, 'outputs':outputs}
    except (CanonicalDeliveryError, OSError, ValueError, KeyError, TypeError, IndexError):
        return None


def post_operation_report(path: Path, kind: str, trace: dict | None, output_dir: Path) -> dict | None:
    if not trace:
        return None
    def same_bytes(left, right):
        try:
            _real_file(left, output_dir.absolute())
            _real_file(right, output_dir.absolute())
            with left.open('rb') as a, right.open('rb') as b:
                while True:
                    x,y=a.read(1048576),b.read(1048576)
                    if x!=y:
                        return False
                    if not x:
                        return True
        except (CanonicalDeliveryError, OSError):
            return False
    writers = [r for r in trace['reports'] if r['path'] == path or
               path.parent == output_dir/'runs'/trace['run_ref']/'reports' and
               r['path'].name == path.name and same_bytes(r['path'],path)]
    if len(writers) != 1:
        return None
    report = writers[0]; operation = trace['operation']
    if (report['kind'] != kind or report['design'] != trace['design'] or
            report['log_line'] <= operation['replacement']['log_line']):
        return None
    try:
        _real_file(path, output_dir.absolute())
        with path.open(errors='replace') as stream:
            header = ''.join(next(stream,'') for _ in range(5))
        if re.findall(r'(?m)^\s*Design\s*:\s*(\S+)\s*$',header) != [trace['design']]:
            return None
    except (CanonicalDeliveryError, OSError, ValueError):
        return None
    return {**{k:v for k,v in report.items() if k != 'path'},
            'native_report':report['path'].relative_to(output_dir).as_posix(),
            'collected_report':path.relative_to(output_dir).as_posix()}


def compound_check(issue: dict, files: list[Path], output_dir: Path, dofile: str,
                   task_spec: str, words_for) -> dict:
    """Require each native coverage/partition/object subclaim, never a lone count."""
    result = {'applicable': compound_coverage_claim(issue), 'status':'incomplete', 'subchecks':[]}
    if not result['applicable']:
        return result
    def add(name, passed, references=(), detail=''):
        result['subchecks'].append({'name':name,'passed':bool(passed),'evidence':list(references),'detail':detail})
    def ref(path, first, last=None):
        text = path.read_text(errors='replace').splitlines(); last=last or first
        return {'source':path.relative_to(output_dir).as_posix(),'locator':f'L{first}' if first==last else f'L{first}-L{last}',
                'excerpt':'\n'.join(text[first-1:last])}
    def objects_ref(path, rows):
        # Keep native row ranges and an exact set fingerprint without copying
        # thousands of instance rows into every audit record/model feedback.
        if not rows:
            return ref(path,1)
        first,last=min(r['line'] for r in rows),max(r['line'] for r in rows)
        return {**ref(path,first), 'locator':f'L{first}-L{last}',
                'object_count':len(rows), 'instance_set_sha256':hashlib.sha256(
                    '\n'.join(sorted(r['InstanceName'] for r in rows)).encode()).hexdigest()}
    trace = operation_trace(files,output_dir,dofile,words_for); scope = _scope(dofile,words_for)
    found = issue.get('found',{}); old = output_dir/str(found.get('source',''))
    match = re.fullmatch(r'L(\d+)(?:-L(\d+))?',str(found.get('locator','')))
    try:
        _real_file(old,output_dir.absolute())
        original = old.read_text().splitlines(); old_run = found.get('run_ref','')
        valid_found = (trace and scope and found.get('verified') is True and match and
            re.fullmatch(r'R[1-9]\d*',old_run) and int(old_run[1:]) < int(trace['run_ref'][1:]) and
            old.is_relative_to(output_dir/'runs'/old_run) and
            found['excerpt'] in '\n'.join(original[int(match[1])-1:int(match[2] or match[1])]))
    except (CanonicalDeliveryError, OSError, ValueError, KeyError, TypeError):
        valid_found = False
    top = trace['design'] if trace else ''
    claims = str(issue.get('diagnosis',{}).get('located_object',''))
    named = re.search(r'\bdesign\s+([\w$]+)',claims,re.I)
    add('design_and_operation',valid_found and (not named or named[1]==top) and scope[0]==top if scope else False,
        [trace['operation'],trace['operation']['replacement']] if trace else [],
        'One source-bound later full insertion for the discovered design is required.')
    selected = {}
    for kind in ['rpt_scan_chain','rpt_scan_chain_cell','rpt_scan_element','rpt_insertion_info']:
        writers = [r for r in (trace or {}).get('reports',[]) if r['kind']==kind]
        latest = max(writers,key=lambda r:r['log_line']) if writers else None
        matches=[(p,post_operation_report(p,kind,trace,output_dir)) for p in files if p.suffix=='.rpt']
        matches=[(p,b) for p,b in matches if b and latest and b['log_line']==latest['log_line']]
        selected[kind] = matches[0] if len(matches)==1 else None
        add('post_operation_'+kind,bool(selected[kind]),[selected[kind][1]] if selected[kind] else [],
            'Exactly one same-design native report generated after replacement; missing/ambiguous/early reports cannot substitute.')
    if not all(c['passed'] for c in result['subchecks']):
        result['missing']=[c['name'] for c in result['subchecks'] if not c['passed']];return result
    chainpath=selected['rpt_scan_chain'][0];cellpath=selected['rpt_scan_chain_cell'][0]
    elementpath=selected['rpt_scan_element'][0];infopath=selected['rpt_insertion_info'][0]
    chains=list(report_rows(chainpath,{'Chain','Length','Input','Output','ScanEnable','Clocks','Partition'}))
    # Tcl redirection includes the native command's final numeric return value.
    # It is not a chain row. Keep malformed populated rows so they still fail
    # validation; only omit the isolated return value with no other fields.
    chains=[r for r in chains if re.fullmatch(r'I\s+\S+|\d+',r['Chain']) and
            any(r[k] for k in ['Length','Input','Output','ScanEnable','Clocks','Partition'])]
    lengths_ok=bool(chains) and all(r['Length'].isdigit() for r in chains)
    cells=list(report_rows(cellpath,{'InstanceName','RefName','Clocks'}))
    cells=[r for r in cells if (r['RefName'] or r['Clocks'] or
           r['InstanceName'] and not r['InstanceName'].isdigit())]
    elements=list(report_rows(elementpath,{'Type','Length','InstanceName','ObjState'}))
    elements=[r for r in elements if r['InstanceName']]
    requirements=partition_requirements(task_spec)
    partition_ok=bool(requirements) and lengths_ok and not chain_problems(chains,task_spec)
    partition_ok=partition_ok and len({(r['Chain'],r['Partition']) for r in chains})==len(chains)
    for name,wanted in requirements.items():
        actual=[r for r in chains if r['Partition']==name]
        clock=wanted.get('划分（-clocks）',wanted.get('-clocks','')).strip('`{}')
        enable=wanted.get('scan_enable','').strip('`')
        partition_ok = partition_ok and len(actual)==int(wanted['chain_count']) and all(
            r['Length'].isdigit() and 0<int(r['Length'])<=int(wanted['max_length']) and
            r['ScanEnable']==enable and r['Clocks']==clock for r in actual)
    partition_ok = partition_ok and {r['Partition'] for r in chains}==set(requirements)
    add('task_partitions_clocks_enables_and_counts',partition_ok,
        [ref(chainpath,min(r['line'] for r in chains),max(r['line'] for r in chains))] if chains else [],
        'Every task table partition, count, max length, clock and enable must match; total chains alone is insufficient.')
    old_rows = list(report_rows(old,{'Chain','Length','Input','Output','ScanEnable','Clocks','Partition'}))
    old_rows = [r for r in old_rows if re.fullmatch(r'I\s+\S+|\d+',r['Chain']) and r['Length'].isdigit()]
    old_design = re.findall(r'(?m)^\s*Design\s*:\s*(\S+)\s*$',old.read_text())
    old_bound = (old_design == [top] and old_rows and all(
        int(match[1]) <= r['line'] <= int(match[2] or match[1]) for r in old_rows))
    add('discovered_deficit_and_later_increase', old_bound and lengths_ok and
        sum(int(r['Length']) for r in old_rows) < sum(int(r['Length']) for r in chains),
        [ref(old,int(match[1]),int(match[2] or match[1]))],
        'The complete cited original same-design table must demonstrate the actual deficit; a header or already-complete table cannot discover it.')
    values=[]
    for block in _insertion_summary_blocks(infopath):
        if block['design']==top and not block['conflicts'] and not block['invalid'] and set(block['values'])==set(_COVERAGE_FIELDS):
            values.append(block)
    coverage_ok=len(values)==1
    if coverage_ok:
        v=values[0]['values']
        coverage_ok= lengths_ok and v['Scannable FF Bit Count']>0 and v['Scannable FF Bit Count']==v['Scan Chain Cell Bit Count']+v['Wrapper Chain Cell Bit Count'] and v['Total FF Bit Count']==v['Scannable FF Bit Count']+v['Nonscannable FF Bit Count'] and v['Wrapper Chain Cell Bit Count']==v['Shared Wrapper Cell Bit Count']+v['Dedicated Wrapper Cell Bit Count'] and v['Wrapper Chain Cell Bit Count']==0 and sum(int(r['Length']) for r in chains)==v['Scannable FF Bit Count']
    add('native_ff_accounting',coverage_ok,[ref(infopath,1,len(infopath.read_text().splitlines()))],
        'All native FF-bit identities and sum of actual chain lengths must agree. This proves native accounting, not independent physical eligibility.')
    names=[r['InstanceName'] for r in cells]; scan=[r for r in elements if r['ObjState']=='scannable']
    expanded=[]
    for row in scan:
        if row['Length']=='1':expanded.append(row['InstanceName'])
        else:expanded.append(None) # Multi-bit/segment expansion is outside this narrow proof.
    object_ok=bool(cells and scan) and None not in expanded and len(set(names))==len(names) and len(set(expanded))==len(expanded) and set(names)==set(expanded) and all(r['RefName'] and r['Clocks'] for r in cells)
    if coverage_ok:object_ok=object_ok and len(names)==v['Scannable FF Bit Count']
    add('all_native_scannable_objects_in_chain_cells',object_ok,[objects_ref(elementpath,scan),objects_ref(cellpath,cells)],
        'Exact full native scannable instance set must equal complete chain-cell set; missing, duplicate and extra objects reject.')
    targets={m['target_cell'] for m in trace['mappings']};seen={r['RefName'] for r in cells}
    replacement_ok=bool(targets) and targets<=seen and trace['operation']['replacement']['count']>0
    add('executed_mapping_and_native_replacement',replacement_ok,
        [*trace['mappings'],trace['operation']['replacement']],
        'Actual pre-operation mapping targets must occur in post-operation cell rows, with native positive replacement. Unreplaced natural/segment cells are not inferred equivalent.')
    result['missing']=[c['name'] for c in result['subchecks'] if not c['passed']]
    if not result['missing']:
        result['status']='pass'; result['evidence']={**ref(chainpath,min(r['line'] for r in chains),max(r['line'] for r in chains)),
            'subchecks':result['subchecks'],'task_requirement_source':'input/task_spec.md',
            'task_requirement_excerpt': '\n'.join(line for line in task_spec.splitlines() if '|' in line and any(name in line for name in requirements))}
    return result


def _connection_action_context(issue, root, input_dir, words_for):
    """Actual discovered clock object and its immediate original ICG cone.

    Identity is from authenticated native DRC + original netlist + Liberty;
    a descriptive suffix, shared leaf name or one remaining candidate is not
    used to infer a connection. This helper proves no repair action.
    """
    from completion_policy import _reference
    from eco_structure import source_design
    try:
        found=issue['found'];rid=found['run_ref'];_reference(root,found,{rid})
        match=re.search(r"Clock input '([^']+)' of 'DFF' '([^']+)'",found['excerpt'])
        if not match:return None
        from scan_agent import get_task_artifacts
        task,spec,nets,libs,original=get_task_artifacts(input_dir)
        library,design=source_design(nets,libs,spec,original.read_text() if original else '')
        from configuration_evidence import _signal_command_trace
        discovery=_signal_command_trace(root,rid,words_for)
        if not discovery or discovery['design']!=design['top'] or set(discovery['loaded_input_netlists'])!=set(map(str,nets)):return None
        name,pin=match[2],match[1];cell=design['cells'].get(name)
        if not cell or not library[cell['type']]['ffs'] or pin not in cell['pins']:return None
        endpoint=name+'/'+pin;targets=[endpoint];clock=design['graph'].resolve(cell['pins'][pin])
        for obj,c in design['cells'].items():
            shape=library[c['type']]
            if not shape['icg']:continue
            outs=[p for p,v in shape['pins'].items() if v.get('direction')=='output']
            if not any(design['graph'].resolve(c['pins'].get(p))==clock for p in outs):continue
            targets += [obj+'/'+p for p,v in shape['pins'].items() if v.get('direction')=='input' and v.get('clock_gate_test_pin')=='true']
        location=issue['diagnosis']['located_object']
        if not any(location==p or location.startswith(p+' ') or location.startswith(p+'（') or location.startswith(p+'(') for p in targets):return None
        return {'object':endpoint,'FF':name,'targets':sorted(set(targets)),'design':design['top'],
            'found':dict(found),'inputs':list(map(str,nets)),'libraries':list(map(str,libs)),
            'case_input':str(input_dir.resolve()),'task_spec_sha256':hashlib.sha256(spec.encode()).hexdigest()}
    except (OSError,ValueError,KeyError,TypeError,IndexError):return None


def _cited_connection_changes(issue, changes, root, current):
    """Byte-verified cited deltas; authentication is distinct from support."""
    refs=issue['attempts'][-1]['fix']['artifact_ref'];selected=[]
    if not refs or len(set(refs))!=len(refs):raise ValueError('Missing/duplicate action citation')
    found=issue['found']['run_ref']
    for ref in refs:
        matches=[c for c in changes if c.get('change_id')==ref]
        if len(matches)!=1:raise ValueError('Unknown action citation')
        c=matches[0];p=root/c['path'];d=root/c['diff_path'];_real_file(p,root);_real_file(d,root)
        rid=p.relative_to(root).parts[1]
        if not re.fullmatch(r'R[1-9]\d*',rid) or not int(found[1:])<int(rid[1:])<=int(current[1:]):raise ValueError('Cross-round action citation')
        if c.get('type')=='dofile':
            text=d.read_text();m=re.match(r'--- (R[1-9]\d*)\n\+\+\+ (R[1-9]\d*)\n',text)
            if not m or m[2]!=rid or not int(found[1:])<=int(m[1][1:])<int(rid[1:]):raise ValueError('Invalid cited delta identity')
            prior=root/'runs'/m[1]/'deliverables'/(m[1]+'.dofile');_real_file(prior,root)
            if p!=root/'runs'/rid/'deliverables'/(rid+'.dofile') or text!=''.join(difflib.unified_diff(prior.read_text().splitlines(True),p.read_text().splitlines(True),fromfile=m[1],tofile=rid)):raise ValueError('Cited script delta changed')
        elif c.get('origin')=='native_in_memory_ECO':
            if c.get('lec_ref')!='eco/'+rid+'/lec/eqy.log':raise ValueError('Native action citation/proof round mismatch')
        else:raise ValueError('Unsupported connection action citation')
        selected.append({'change':c,'run_ref':rid,**({'from_run':m[1]} if c.get('type')=='dofile' else {})})
    return selected


def _connection_action_claim(action):
    """Finite operand-role syntax, independent of family applicability.

    All explicit role values participate. Source-plan evidence is not license
    to ignore a contradictory adopted description or an unparsed role slot.
    """
    claims={};conflicts={};parsed={'functional':0,'test':0,'consumer_net':0,'test_source':0,'mode':0}
    def put(role,value):
        value=value.rstrip('.') if isinstance(value,str) else value
        if role in claims and claims[role]!=value:
            conflicts.setdefault(role,[claims[role]])
            if value not in conflicts[role]:conflicts[role].append(value)
        else:claims[role]=value
    ident=r'([A-Za-z_][\w$./\[\]*?-]*)'
    constants=list(re.finditer(r'test branch\s+(?:ties?\s+to\s+)?logic\s*([01])\b',action,re.I))
    for m in constants:put('test_constant',int(m[1]));parsed['test']+=1
    for m in re.finditer(r'\bConnect\s+([A-Za-z_][\w$]*)\s+port\s+to\s+([\w$./\[\]-]+)',action,re.I):
        put('test',m[1]);put('consumer',m[2])
    if re.search(r'\bdirect(?:ly)?\s+connect\b|直接(?:连接|改接)',action,re.I):claims['direct']=True
    boundary=r'(?=$|[\s,;:()])'
    for m in re.finditer(r'\btest source\s+'+ident+boundary,action,re.I):
        put('test',m[1]);parsed['test_source']+=1
    for pattern in [r'\b([^\s,;:()]+)-selected\s+MUX\b',r'\bS\s*=\s*([^\s,;()]+)']:
        for m in re.finditer(pattern,action,re.I):
            value=m[1].rstrip('.')
            if re.fullmatch(r'[A-Za-z_][\w$]*',value):put('mode',value);parsed['mode']+=1
    patterns={
        'functional':r'\bfunctional branch\s+(?:keeps?|uses?)\s+'+ident,
        'test':r'\btest branch\s+(?:keeps?|uses?)\s+(?:(?:scan\s+)?(?:clock|signal|port|pin)\s+)?'+ident,
        'consumer_net':r'\boutput\s+drives?\s+'+ident,
    }
    for role,pattern in patterns.items():
        for m in re.finditer(pattern+boundary,action,re.I):put(role,m[1]);parsed[role]+=1
    markers={'functional':r'\bfunctional branch\b','test':r'\btest branch\b','consumer_net':r'\boutput\s+drives?\b',
             'test_source':r'\btest source\b','mode':r'\b[^\s,;:()]+-selected\s+MUX\b|\bS\s*='}
    unknown=[role for role,pattern in markers.items() if len(re.findall(pattern,action,re.I))>parsed[role]]
    if conflicts:claims['conflicting_roles']=conflicts
    if unknown:claims['unparsed_roles']=unknown
    return claims


def _connection_action_roles_match(claims, operation):
    if claims.get('conflicting_roles') or claims.get('unparsed_roles'):return False
    parent=operation.get('native_readback',{}).get('hierarchy_parent',operation.get('instance','').rpartition('/')[0])
    for role,key in [('functional','driver'),('test','test'),('mode','mode'),('consumer','consumer'),('consumer_net','consumer_net')]:
        if role not in claims:continue
        expected=operation.get(key);value=claims[role]
        if not expected or not (value==expected or parent+'/'+value==expected):return False
    if 'test_constant' in claims and claims['test_constant']!=operation.get('verified_test_constant'):return False
    # An explicitly direct connection is not this compiled MUX action.
    return not claims.get('direct')


def _typed_cited_mode_mux(selected, root, words_for):
    """A typed changed plan comes from cited compiler source, never prose."""
    from plan_provenance import source_mode_mux_operations, _source_mode_mux_declarations
    from model_script_view import model_owned_script
    def signature(op):
        return (tuple(words_for(op['source_command'])),
                tuple((role,tuple(words_for(dep['command']))) for role,dep in sorted(op['dependencies'].items())))
    result=[]
    for citation in selected:
        sources=source_mode_mux_operations(root/'runs'/citation['run_ref'],words_for)
        old=[]
        if citation['change'].get('origin')!='native_in_memory_ECO':
            prior=root/'runs'/citation['from_run']/'deliverables'/(citation['from_run']+'.dofile')
            old=_source_mode_mux_declarations(model_owned_script(prior.read_text()),words_for)
        old_signatures={signature(o) for o in old}
        result.extend(s for s in sources if citation['change'].get('origin')=='native_in_memory_ECO' or signature(s) not in old_signatures)
    # A script and a native export may cite the same full source intent.
    unique={}
    for source in result:
        key=(source['run_ref'],source['operation_id'],source['source_sha256'])
        unique[key]=source
    return list(unique.values())


def _mode_mux_dependency_match(source, operation, context, words_for):
    """Bind all four source roles to a real later completed operation.

    Only the consumer query's refused numeric-bus spelling may acquire its
    already-native-discovered identity from a later, explicitly corrected query.
    That records a query repair, NOT prior Tcl evaluation or prior execution.
    Functional/test/mode identities cannot change under the old action cite.
    """
    actual=operation.get('source_binding',{})
    def inputs(rows):
        if not isinstance(rows,dict) or not rows:return None
        result={}
        for value in rows.values():
            if not isinstance(value,dict) or set(value)!={'resolved','sha256'}:return None
            path,digest=value['resolved'],value['sha256']
            if not isinstance(path,str) or not isinstance(digest,str) or not re.fullmatch(r'[0-9a-f]{64}',digest):return None
            if path in result and result[path]!=digest:return None
            result[path]=digest
        return result
    before_inputs=inputs(source['source_input_fingerprints'])
    after_inputs=inputs(actual.get('source_input_fingerprints'))
    if (not before_inputs or before_inputs!=after_inputs or source['design']!=operation['design'] or source['design']!=context['design'] or
            source['task_spec_sha256']!=operation['task_spec_sha256'] or
            source['task_spec_sha256']!=context['task_spec_sha256'] or
            source['contract']!=operation['contract'] or
            words_for(source['source_command'])!=words_for(operation['source_command'])):
        return None
    bindings={}
    for role in ['driver','consumer','test','mode']:
        before=source['dependencies'].get(role,{});after=actual.get('dependencies',{}).get(role,{})
        expected=before.get('selection');observed=after.get('selection')
        if expected and observed and expected==observed and expected['name']==operation[role]:
            bindings[role]={'kind':'same_literal_query_identity','object':operation[role],
                            'source_reference':before['command'],'executed_reference':after['command']}
        elif (role=='consumer' and observed and observed.get('kind')=='pin' and
                before.get('getter')==after.get('getter')=='get_obj_pins' and
                before.get('unresolved_bus_spelling')==observed['name']==operation[role] and
                operation[role] in context['targets']):
            bindings[role]={'kind':'refused_query_repaired_before_actual_execution','object':operation[role],
                            'source_reference':before['command'],'executed_reference':after['command'],
                            'prior_query_execution_not_claimed':True,'independent_identity_basis':context['found']}
        elif (role=='test' and before.get('constant_source') and after.get('constant_source') and
                before['constant_source']['instance']==after['constant_source']['instance'] and
                before['constant_source']['value']==after['constant_source']['value']=='1' and
                operation.get('verified_test_constant')==1):
            bindings[role]={'kind':'same_created_constant_unique_native_output','object':operation[role],
                            'instance':before['constant_source']['instance'],'value':1}
        else:return None
    return bindings


def connection_action_assessment(issue, changes, root, current, words_for, input_dir):
    """A cited connection delta needs a uniquely executed operation/readback.

    Applicable unknown is explicit and cannot fall through to a DRC summary.
    This checks the adopted action, not every past sentence or final delivery.
    """
    action=str(issue.get('attempts',[{}])[-1].get('fix',{}).get('action',''))
    claims=_connection_action_claim(action)
    # Explicit operands create a verification obligation even when their
    # citation is missing. A missing compiler source is never not-applicable.
    typed=bool(claims) or bool(re.search(r'\b(?:MUX|mode_mux|connect\w*|splice)\b|连接|改接|接到|插入\s*mux',action,re.I))
    clock=bool(re.search(r"Clock input '[^']+' of 'DFF' '[^']+'",str(issue.get('found',{}).get('excerpt',''))))
    if not clock:return {'applicable':False,'status':'not_applicable','problems':[]}
    # The cited compiler contract is an independent applicability producer.
    # Do not depend on a spelling such as "MUX" to activate typed plan checks.
    typed_sources=[];source_error=None;selected=[]
    try:
        selected=_cited_connection_changes(issue,changes,root,current)
        typed_sources=_typed_cited_mode_mux(selected,root,words_for)
    except (OSError,ValueError,KeyError,TypeError,IndexError,CanonicalDeliveryError) as exc:
        source_error=str(exc)
        # This is dispatch only. Recovered source cannot prove execution;
        # unreadable/indirect/outside-root references are never followed.
        from model_script_view import model_owned_script
        from dofile_recipe import tcl_chunks
        for c in changes:
            if c.get('change_id') not in issue.get('attempts',[{}])[-1].get('fix',{}).get('artifact_ref',[]):continue
            try:
                path=root/c['path'];_real_file(path,root)
                typed=typed or any(words_for(code.strip().rstrip(';'))[:2]==['eco_link','mode_mux']
                                   for code in tcl_chunks(model_owned_script(path.read_text())))
            except (OSError,ValueError,TypeError,KeyError,CanonicalDeliveryError):pass
    if not typed and not typed_sources:return {'applicable':False,'status':'not_applicable','problems':[]}
    problem={'reason':'fix_action_reference_not_bound','original_clause':action,
        'detail':'A connection claim needs its cited, uniquely executed source operation and native readback; final DRC/EQY does not prove that action.'}
    result={'applicable':True,'status':'incomplete','problems':[problem],'claims':claims}
    try:
        from plan_provenance import executed_mode_mux_operations
        if source_error:raise ValueError(source_error)
        context=_connection_action_context(issue,root,input_dir,words_for)
        if context is None:raise ValueError('Discovered/located connection object is not bound')
        operations=[]
        for item in selected:
            c=item['change']
            if c.get('origin')=='native_in_memory_ECO':
                fixed=root/c['path'];delta=root/c['diff_path']
                expected=''.join(difflib.unified_diff(''.join(Path(n).read_text() for n in context['inputs']).splitlines(True),fixed.read_text().splitlines(True),fromfile='actual-original-family',tofile=c['path']))
                if delta.read_text()!=expected:raise ValueError('Native cited change differs from actual original-to-export delta')
        # A source plan can be introduced before a prerequisite query is
        # corrected. Only actual completed receipts in this bounded lineage
        # prove execution; a changed test/functional/mode dependency cannot
        # inherit the earlier action merely because the OP text/hash matches.
        first=min(int(s['run_ref'][1:]) for s in selected)
        lineage_runs=[p for p in (root/'runs').iterdir() if p.is_dir() and
                      re.fullmatch(r'R[1-9]\d*',p.name) and first<=int(p.name[1:])<=int(current[1:])]
        for run in sorted(lineage_runs,key=lambda p:int(p.name[1:])):
            try:operations+=executed_mode_mux_operations(run,words_for)
            except (OSError,ValueError,KeyError,TypeError):pass  # Explicit missing proof, never a success.
        matches=[]
        for op in operations:
            applicable_sources=[source for source in typed_sources
                                if int(source['run_ref'][1:])<=int(op['run_ref'][1:])]
            source_matches=[(source,_mode_mux_dependency_match(source,op,context,words_for))
                            for source in applicable_sources]
            source_matches=[(source,binding) for source,binding in source_matches if binding is not None]
            if not source_matches:continue
            if op['design']!=context['design'] or op['consumer'] not in context['targets'] or op['task_spec_sha256']!=context['task_spec_sha256']:continue
            from configuration_evidence import _signal_command_trace
            native_input=_signal_command_trace(root,op['run_ref'],words_for)
            if not native_input or native_input['design']!=context['design'] or set(native_input['loaded_input_netlists'])!=set(context['inputs']):continue
            log=(root/'runs'/op['run_ref']/(op['run_ref']+'.log')).read_text()
            loaded_libraries=re.findall(r"LIB-I-0011\].*liberty file '([^']+)' is read successfully",log,re.I)
            if set(loaded_libraries)!=set(context['libraries']):continue
            if not _connection_action_roles_match(claims,op):continue
            # Bind explicit actual Liberty input roles, without assuming A0/A1.
            bad=False;recognized=bool(claims) or bool(source_matches)
            for role in ['functional','test','select']:
                pin=op['contract'][role]
                m=re.search(r'([A-Za-z_][\w$./]*)\s*(?:接|(?:connect(?:ed)?\s+)?to)\s*'+re.escape(pin)+r'\b',action,re.I)
                if m:
                    recognized=True;expected=op[{'functional':'driver','test':'test','select':'mode'}[role]]
                    value=m[1];parent=op.get('native_readback',{}).get('hierarchy_parent',op['instance'].rpartition('/')[0])
                    if value!=expected and parent+'/'+value!=expected:bad=True
            if not bad and recognized:
                matches.append({**op,'cited_source_bindings':[{'source':source,'roles':binding} for source,binding in source_matches]})
        result['cited_operations']=operations;result['claims']=claims
        result['cited_source_operations']=typed_sources
        # The source producer owns this scope. Reproduced again before any
        # independent delivery proof can be issued; it is not a reason whitelist.
        problem['assessment_scope']={'kind':'native_connection_action','producer':'connection_action_assessment',
            'case_output':str(root.resolve()),'current_run':current,'object':context['object'],'FF':context['FF'],
            'design':context['design'],'allowed_connection_targets':context['targets'],'context':context,
            'citations':selected,'claims':claims,'cited_source_operations':typed_sources,'status':'incomplete'}
        problem['cited_executed_operations']=[{'run_ref':o['run_ref'],'operation_id':o['operation_id'],'source_command':o['source_command'],'evidence':o['evidence']} for o in operations]
        # Re-execution of the same proven action after a clean reload is not
        # an ambiguous second source action. Retain the earliest actual receipt
        # and every later agreeing receipt; different role identities stay out.
        unique={}
        for op in matches:
            key=(op['design'],op['consumer'],op['driver'],op['test'],op['mode'],
                 tuple(sorted(op['contract'].items())),op['instance'])
            unique.setdefault(key,[]).append(op)
        if len(unique)==1:
            receipts=next(iter(unique.values()))
            result.update(status='pass',problems=[],evidence=receipts[0],agreeing_executions=receipts);return result
        problem['missing']='No unique cited operation supports all adopted action roles' if not matches else 'Multiple operations support action, scope ambiguous'
    except (OSError,ValueError,TypeError,KeyError,IndexError,CanonicalDeliveryError) as exc:problem['missing']=str(exc)
    return result


def connection_action_delivery_condition(issue, conflicts, changes, root, rid, words_for, input_dir, trace, validation):
    """Prove final affected-object delivery without reassigning the action cite."""
    try:
        if len(conflicts)!=1 or trace is None or not validation or validation.get('status')!='pass':return None
        assessment=connection_action_assessment(issue,changes,root,rid,words_for,input_dir)
        if assessment['problems']!=conflicts:return None
        scope=conflicts[0].get('assessment_scope',{})
        if scope.get('kind')!='native_connection_action' or scope.get('producer')!='connection_action_assessment':return None
        if scope['case_output']!=str(root.resolve()) or scope['current_run']!=rid or scope['design']!=trace.data['design']:return None
        import eco_evidence
        eco_evidence.assert_trace(trace)
        # Real physical FF mapping and structural route are separately rebuilt
        # by delivery_proof_paths in the caller. Do not trust located prose.
        mapping=validation['coverage']['object_mapping']
        if scope['FF'] not in mapping:return None
        routes=[r for r in validation['structure']['changed_routes'] if r['consumer'] in scope['allowed_connection_targets']]
        if not routes:return None
        path=Path(trace.data['fixed_export']['path'])
        return ({'kind':'native_ECO_delivery_object','design':scope['design'],'run_ref':rid,
            'located_object':issue['diagnosis']['located_object'],
            'object':{'kind':'native_clock_object_and_affected_connection','discovered_object':scope['object'],
                'FF_mapping':mapping[scope['FF']],'routes':routes},
            'action_remains_unproved':True,'original_citations':scope['citations']},
            [path,*[root/s['change'][k] for s in scope['citations'] for k in ['path','diff_path']]])
    except (OSError,ValueError,KeyError,TypeError,IndexError):return None
