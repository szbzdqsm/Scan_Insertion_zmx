"""Conjunctive, source-bound evidence for multi-parameter scan configuration.

This reads actual commands/reports only. It neither executes Tcl nor rewrites a
diagnosis. Unknown scopes or missing fields remain unverified.
"""
import copy
import difflib
import hashlib
import json
import re
from pathlib import Path, PurePosixPath

from canonical_delivery import CanonicalDeliveryError, _real_file
from dofile_recipe import tcl_chunks
from operation_audit import compound_check, compound_coverage_claim, operation_trace, post_operation_report
from command_error_evidence import (command_proof_kind, failed_command, grouped_signal_evidence,
                                    load_input_evidence, mapping_command_evidence, mismatched_signal_target,
                                    netlist_export_evidence)
from report_validation import _full_insertion_designs, chain_problems, partition_requirements, report_rows, scan_formats

# Native rpt_scan_cfg parameter names, not issue IDs, case names or instance lists.
PARAMETERS = frozenset('chain_count max_length mix_edges mix_clocks internal_clocks '
    'mix_internal_clocks add_lockup add_test_retiming_flops insert_terminal_lockup '
    'replace respect_sff_se_connection si_port_format so_port_format'.split())


def _setup_claim(issue, words_for):
    """One supported scalar setup contract, never an inferred default value.

    An actual typed action/parameter is the applicability anchor. Ordinary
    additions without an adopted historical insufficiency assertion do not
    acquire a new diagnostic obligation.
    """
    diagnosis = issue.get('diagnosis', {})
    action = str((issue.get('attempts') or [{}])[-1].get('fix', {}).get('action', ''))
    command = 'set_scan_drc_cfg'; parameter = 'clock_gating_init_cycles'
    if command not in action and parameter not in action:
        return None
    claims = []
    for field in ('root_cause', 'summary'):
        text = str(diagnosis.get(field, ''))
        prior_context = bool(re.search(r'\b(?:default|original|prior|previous|initial)\b|默认|原(?:始|先)|修改前', text, re.I))
        # A true observation about this setting cannot absorb another adopted
        # prior-parameter assertion. This is a finite clause split, not a
        # guess that all nearby "default" words name the action's parameter.
        for clause in re.split(r'[.;；。\n]|,\s*(?:and|but)\s+|\s+(?:and|but)\s+|，(?:且|并且)', text, flags=re.I):
            prior = re.search(r'\b(?:default|original|prior|previous|initial)\b|默认|原(?:始|先)|修改前', clause, re.I)
            insufficient = re.search(r'\binsufficient\b|\binadequate\b|\btoo\s+(?:few|low|small)\b|不足|不够', clause, re.I)
            if not insufficient or not prior_context:
                continue
            named_parameter = bool(re.search(r'(?<![\w])'+parameter+r'(?![\w])|\b'+command+r'\b|'
                r'\bclock[-_ ]gating[-_ ]+(?:init(?:ialization)?[-_ ]+)cycles\b|时钟门控初始化周期', clause, re.I))
            other_parameters = [name for name in PARAMETERS if '_' in name and re.search(
                r'(?<![\w])'+re.escape(name).replace('_', r'[-_ ]')+r'(?![\w])', clause, re.I)]
            other_commands = set(re.findall(r'\b(?:set|rpt)_[a-z_0-9]+\b', clause)) - {command}
            bound = bool(prior) and named_parameter and not other_parameters and not other_commands
            claims.append({'field': field, 'original_clause': clause.strip(),
                'state_kind': 'default' if re.search(r'\bdefault\b|默认', clause, re.I) else 'effective_prior',
                'property_binding': 'native_configuration_parameter' if bound else 'unresolved_parameter_identity',
                'prior_context_only': not bool(prior),
                'other_parameters': sorted(other_parameters), 'other_commands': sorted(other_commands)})
    if not claims:
        return None
    matches = []
    for match in re.finditer(r'\b'+command+r'\b', action):
        body = re.split(r'[;；。\n]|\b(?:set|load|add|rpt|dump)_[a-z_]+\b', action[match.end():])[0]
        words = words_for((command+' '+body).strip().rstrip('.'))
        if (len(words) == 3 and words[0] == command and words[1] == '-'+parameter and
                re.fullmatch(r'[1-9]\d*', words[2])):
            matches.append(words)
    unique = {tuple(words) for words in matches}
    return {'command': command, 'parameter': parameter, 'claims': claims,
            'action_words': list(next(iter(unique))) if len(unique) == 1 else None}


def _setup_requirement(spec):
    """Use the actual task's depth AND one-level propagation statement."""
    text = str(spec).replace('*', '')
    depths = re.findall(r'级联深度\s*(?:为|[:：=])\s*(\d+)\s*层', text)
    one_level = re.search(r'每个?\s*(?:仿真)?周期[^。\n]{0,45}(?:只能)?传播\s*(?:一|1)\s*级', text)
    if len(set(depths)) != 1 or not one_level or not re.search(r'初始化周期', text):
        return None
    minimum = int(depths[0])
    if minimum < 1:
        return None
    return {'parameter': 'clock_gating_init_cycles', 'minimum': minimum,
            'basis': 'Task states N cascaded levels and one level per simulation cycle.',
            'depth_evidence': next(m[0] for m in re.finditer(r'级联深度\s*(?:为|[:：=])\s*\d+\s*层', text)),
            'propagation_evidence': one_level[0],
            'task_spec_sha256': hashlib.sha256(str(spec).encode()).hexdigest()}


def _setup_trace(root, rid, words_for):
    """Authenticate literal setup setters in one real script/native context.

    No getter or Tcl is executed. An absent setter leaves the effective
    default UNKNOWN. Dynamic/failed/unevaluated or late setters abstain.
    """
    root = root.absolute(); context = _signal_command_trace(root, rid, words_for)
    if not context or not context['loaded_input_netlists']:
        return None
    run = root/'runs'/rid; script = run/'deliverables'/(rid+'.dofile'); native = run/(rid+'.log')
    physical = script.read_text().splitlines(); command = 'set_scan_drc_cfg'
    wanted = []
    for chunk in tcl_chunks(script.read_text().replace('\\\n', ' ')):
        text = chunk.strip()
        if not text or text.startswith('#'):
            continue
        words = words_for(text)
        if not re.search(r'\b'+command+r'\b', text):
            continue
        if (len(words) != 3 or words[:2] != [command, '-clock_gating_init_cycles'] or
                not re.fullmatch(r'[1-9]\d*', words[2]) or ';' in text):
            return None
        wanted.append(words)
    lines = native.read_text().splitlines(); setters = []; checks = []; insertion = []
    design = ''; partition = 'Default_Partition'; netlist_loads = 0
    for number, line in enumerate(lines, 1):
        echo = re.search(r'CMD-0034\]\s+@(\d+):\s*(.*)', line)
        if not echo:
            continue
        words = words_for(echo[2].strip())
        if not words:
            continue
        if words[0] == 'load_netlist':
            netlist_loads += 1
        if words[0] in {'load_db', 'read_db', 'reset_design', 'remove_design', 'clear_design', 'reset_state'}:
            return None  # No evidence that these operations preserve prior setup state.
        if words[0] == 'present_design':
            design = words[1] if len(words) == 2 else ''; partition = 'Default_Partition'
        elif words[0] == 'set_current_scan_partition':
            partition = words[1].strip('"{}') if len(words) == 2 else ''
        if words[0] in {'examine_scan_drc', 'insert_dft_logic'}:
            (checks if words[0] == 'examine_scan_drc' else insertion).append(number)
        if words[0] != command:
            continue
        if (words not in wanted or not design or not partition or
                not 0 < int(echo[1]) <= len(physical) or physical[int(echo[1])-1].strip() != echo[2].strip()):
            return None
        result = []
        for later in lines[number:]:
            if 'CMD-0034]' in later:
                break
            result.append(later)
        if (any(re.search(r'\[(?:ERROR|FATAL)\]', value) for value in result) or
                '1' not in [value.strip() for value in result] or '0' in [value.strip() for value in result]):
            return None
        result_line = next(number+j+1 for j, value in enumerate(result) if value.strip() == '1')
        setters.append({'run_ref': rid, 'source': native.relative_to(root).as_posix(),
            'locator': 'L'+str(number), 'excerpt': line, 'words': words,
            'value': int(words[2]), 'design': design, 'partition': partition,
            'result': {'run_ref': rid, 'source': native.relative_to(root).as_posix(),
                'locator': 'L'+str(result_line), 'excerpt': lines[result_line-1]}})
    if (netlist_loads != 1 or len(checks) != 1 or len(setters) != len(wanted) or
            [event['words'] for event in setters] != wanted or
            any(int(event['locator'][1:]) >= checks[0] for event in setters) or
            insertion and checks[0] >= min(insertion)):
        return None
    return {**context, 'setters': setters, 'check_log_line': checks[0],
            'script': script.relative_to(root).as_posix(), 'native': native.relative_to(root).as_posix(),
            'script_sha256': hashlib.sha256(script.read_bytes()).hexdigest(),
            'native_sha256': hashlib.sha256(native.read_bytes()).hexdigest()}


def _setup_action(issue, changes, root, current, words_for, action_words):
    """Bind cited historical delta and the actual successful setup operation."""
    matches = []; refs = (issue.get('attempts') or [{}])[-1].get('fix', {}).get('artifact_ref', [])
    if not refs or len(refs) != len(set(refs)):
        return None
    selected = [change for change in changes if change.get('change_id') in refs]
    if (len(selected) != len(refs) or len({c.get('change_id') for c in selected}) != len(refs) or
            any(change.get('type') != 'dofile' for change in selected)):
        return None
    for change in selected:
        path = root/str(change.get('path', '')); delta = root/str(change.get('diff_path', ''))
        _real_file(path, root); _real_file(delta, root)
        header = re.match(r'--- (R[1-9]\d*)\n\+\+\+ (R[1-9]\d*)\n', delta.read_text())
        if not header:
            return None
        before_run, after_run = header[1], header[2]
        if not int(issue['found']['run_ref'][1:]) <= int(before_run[1:]) < int(after_run[1:]) <= int(current[1:]):
            return None
        before = root/'runs'/before_run/'deliverables'/(before_run+'.dofile'); _real_file(before, root)
        if (path != root/'runs'/after_run/'deliverables'/(after_run+'.dofile') or
                delta.read_text() != ''.join(difflib.unified_diff(before.read_text().splitlines(True),
                    path.read_text().splitlines(True), fromfile=before_run, tofile=after_run))):
            return None
        old, new = _setup_trace(root, before_run, words_for), _setup_trace(root, after_run, words_for)
        if (not old or not new or old['design'] != new['design'] or
                old['loaded_input_netlists'] != new['loaded_input_netlists']):
            return None
        events = [event for event in new['setters'] if event['words'] == action_words]
        if len(events) == 1 and not any(event['words'] == action_words for event in old['setters']):
            matches.append({'change_id': change['change_id'], 'from_run': before_run, 'to_run': after_run,
                'diff_source': delta.relative_to(root).as_posix(), 'native_command': events[0],
                'before_trace': old, 'after_trace': new})
    # Every cited record must participate. This bounded scalar action needs
    # one unique historical transition, not a convenient subset of references.
    return matches[0] if len(matches) == len(refs) == 1 else None


def _setup_object_binding(issue, root, prior, spec, input_dir, words_for):
    """Bind a task-defined ICG type role to the actual loaded source design.

    A task placeholder is used only to select candidate module definitions;
    actual reachable Liberty ICG cells/pin roles then establish the relation.
    No fuzzy object-name matching or prefix-only gate classification occurs.
    """
    if not input_dir:
        return None
    input_dir = input_dir.absolute(); label = str(issue.get('diagnosis', {}).get('located_object', ''))
    command = 'set_scan_drc_cfg'; parameter = 'clock_gating_init_cycles'
    action = _setup_claim(issue, words_for)
    formal_label = (label in {command, parameter, '-'+parameter} or
                    bool(action and action['action_words'] and words_for(label) == action['action_words']))
    templates = []
    for number, line in enumerate(spec.splitlines(), 1):
        if not re.search(r'\bICG\b|时钟门控|clock[-_ ]gating', line, re.I):
            continue
        for match in re.finditer(r'(?:类型|type)\s*[:：]?\s*`([A-Za-z_$][\w$]*_xxx)`', line, re.I):
            template = match[1]; stem = template[:-4]
            if formal_label or re.fullmatch(r'(?:Cascaded\s+)?'+re.escape(stem)+r'\s+(?:instances|cells|modules)', label, re.I):
                templates.append({'template': template, 'stem': stem, 'line': number, 'excerpt': line})
    if len(templates) != 1:
        return None
    task_type = templates[0]
    def actual_input(name, role):
        virtual = PurePosixPath(name)
        if virtual.parts[:3] == ('/', 'input', role):
            path = input_dir.joinpath(*virtual.parts[2:])
        else:
            path = Path(name)
        if (not path.is_absolute() or '..' in path.parts or not path.is_file() or
                not path.resolve().is_relative_to((input_dir/role).resolve())):
            return None
        return path.resolve()  # Round-local aliases are provenance, not content identity.
    netlists = [actual_input(name, 'netlist') for name in prior['loaded_input_netlists']]
    lib_names = re.findall(r"LIB-I-0011\]\s+Liberty file '([^']+)' is read successfully\.",
                           (root/prior['native']).read_text())
    libraries = [actual_input(name, 'lib') for name in sorted(set(lib_names))]
    if not netlists or not libraries or any(path is None for path in netlists+libraries):
        return None
    from partial_insertion_validation import _libraries, _modules, _flatten
    library, errors = _libraries(libraries)
    modules, source_errors = _modules(netlists, library)
    if errors or source_errors or prior['design'] not in modules:
        return None
    leaves, _, unknown, _ = _flatten(modules, library, prior['design'])
    if unknown:
        return None
    pattern = re.compile(re.escape(task_type['stem'])+r'_[A-Za-z0-9_$]+\Z')
    matched_modules = {name for name in modules if pattern.fullmatch(name)}
    if not matched_modules:
        return None
    definitions = []
    for name in sorted(matched_modules):
        module = modules[name]
        gates = [cell for cell in module['cells'] if library.get(cell['type'], {}).get('icg')]
        if module['unknown'] or len(gates) != 1:
            return None
        cell = gates[0]; shape = library[cell['type']]; roles = {}
        for role, direction in [('clock', 'input'), ('enable', 'input'), ('test', 'input'), ('out', 'output')]:
            names = [pin for pin, props in shape['pins'].items()
                     if props.get('clock_gate_'+role+'_pin') == 'true' and props.get('direction') == direction]
            if len(names) != 1 or names[0] not in cell['pins']:
                return None
            roles[role] = {'pin': names[0], 'module_net': cell['pins'][names[0]]}
        definitions.append({'module': name, 'ports': module['ports'], 'cell': cell,
                            'actual_liberty_cell': cell['type'], 'native_pin_roles': roles})
    wrappers = []
    def walk(name, prefix, ancestors):
        if name in ancestors:
            raise ValueError('Recursive ICG role hierarchy')
        for cell in modules[name]['cells']:
            if cell['type'] not in modules:
                continue
            full = prefix+cell['instance']
            if cell['type'] in matched_modules:
                wrappers.append({'instance': full, 'module': cell['type'], 'source': cell['source'],
                                 'line': cell['line'], 'connections': cell['pins']})
            walk(cell['type'], full+'/', ancestors|{name})
    walk(prior['design'], '', set())
    gates = [dict(instance=path, cell_type=cell['type']) for path, cell in leaves.items()
             if library.get(cell['type'], {}).get('icg')]
    if (not wrappers or not gates or any(not any(gate['instance'].startswith(w['instance']+'/')
            for w in wrappers) for gate in gates)):
        return None
    fingerprints = {str(path): hashlib.sha256(path.read_bytes()).hexdigest() for path in netlists+libraries}
    return {'kind': 'task_template_actual_global_ICG_role', 'design': prior['design'],
        'located_object': label, 'location_binding': {
            'kind': 'native_global_parameter_identity' if formal_label else 'task_type_template_role_label',
            'command': command, 'parameter': parameter},
        'task_type_template': task_type, 'actual_module_definitions': definitions,
        'actual_wrapper_instances': wrappers, 'actual_ICG_instances': gates, 'actual_ICG_count': len(gates),
        'input_fingerprints': fingerprints,
        'native_input_paths': {'netlists': prior['loaded_input_netlists'], 'libraries': lib_names},
        'source_unknowns': [],
        'meaning': 'Actual task type and complete reachable Liberty-typed ICG roles; not a diagnosis-cause or EQY proof.'}


def prior_configuration_claim_assessment(issue, changes, root, current, words_for, input_dir=None):
    """Four-state prior configuration verdict, not current delivery proof."""
    claim = _setup_claim(issue, words_for)
    result = {'applicable': bool(claim), 'status': 'not_applicable', 'claims': [], 'problems': []}
    if not claim:
        return result
    result.update(status='incomplete', claims=claim['claims'])
    problem = {'status': 'incomplete', 'reason': 'prior_configuration_state_unproved',
        'parameter': claim['parameter'], 'claims': claim['claims'],
        'detail': 'A later setter/clean DRC does not establish the original effective/default value or cause.'}
    result['problems'] = [problem]
    if any(c['property_binding'] != 'native_configuration_parameter' for c in claim['claims']):
        problem.update(unknown_components=['parameter_identity'],
            detail='An adopted prior configuration assertion does not uniquely name this native parameter; related repair evidence cannot substitute.')
        return result  # Applicable important premise, but no diagnostic-only escape scope.
    try:
        from completion_policy import _reference
        rid = issue['found']['run_ref']; root = root.absolute()
        if not re.fullmatch(r'R[1-9]\d*', current) or int(rid[1:]) >= int(current[1:]):
            return result
        _reference(root, issue['found'], {rid})
        prior = _setup_trace(root, rid, words_for)
        action = _setup_action(issue, changes, root, current, words_for, claim['action_words']) if claim['action_words'] else None
        if not prior or not action or prior['design'] != action['after_trace']['design']:
            return result
        spec_files = [input_dir/name for name in ('task_spec.md', 'limitations.md') if input_dir and (input_dir/name).is_file()]
        spec = '\n'.join(path.read_text() for path in spec_files)
        requirement = _setup_requirement(spec)
        if not requirement:
            return result  # Current task scope is not established by a vague ICG noun.
        object_binding = _setup_object_binding(issue, root, prior, spec, input_dir, words_for)
        if not object_binding:
            problem.update(unknown_components=['object_role'],
                detail='The diagnosis object is not bound to the actual task-defined loaded-design ICG role.')
            return result
        help_path = Path(__file__).with_name('tool_help.json')
        help_text = json.loads(help_path.read_text()).get(claim['command'], '')
        parameter_line = [line for line in help_text.splitlines()
            if re.match(r'\s*-'+claim['parameter']+r'\s+', line)]
        if len(parameter_line) != 1:
            return result
        default_match = re.search(r'default(?:\s+value)?\s*[:=]\s*(\d+)', parameter_line[0], re.I)
        default = int(default_match[1]) if default_match else None
        explicit = prior['setters'][-1] if prior['setters'] else None
        default_claimed = any(c['state_kind'] == 'default' for c in claim['claims'])
        value = (default if default_claimed and not explicit else
                 explicit['value'] if not default_claimed and explicit else default if not explicit else None)
        # The help describes ADDITIONAL pulses. A numeric comparison cannot
        # establish the base schedule or that this setting caused the original
        # clock failure. Keep that historical causal premise explicitly open.
        status = 'incomplete'
        numeric = {'status': 'unknown' if value is None else 'below_task_depth' if value < requirement['minimum'] else 'at_least_task_depth',
                   'value': value, 'task_depth': requirement['minimum'],
                   'is_historical_causal_proof': False}
        result.update(status=status, prior_state={'kind': 'explicit' if explicit else 'default',
            'effective_value': explicit['value'] if explicit else default,
            'documented_default': default, 'claimed_value_supported': value,
            'native_command': explicit, 'default_not_inferred_from_omission': True},
            task_requirement=requirement, numeric_comparison=numeric,
            action_binding={k:v for k,v in action.items() if k not in {'before_trace','after_trace'}})
        scope = {'kind': 'prior_native_configuration_premise', 'producer': 'prior_configuration_claim_assessment',
            'case_output': str(root.resolve()), 'run_ref': rid, 'design': prior['design'],
            'object_role': 'design_global_configuration', 'command': claim['command'],
            'parameter': claim['parameter'], 'loaded_inputs': prior['loaded_input_netlists'],
            'assessment_status': 'contradicted' if status == 'fail' else 'incomplete',
            'unknown_components': (['effective_prior_value'] if value is None else [])+['historical_causal_support'],
            'script': prior['script'], 'native': prior['native'],
            'script_sha256': prior['script_sha256'], 'native_sha256': prior['native_sha256'],
            'task_requirement': requirement, 'object_binding': object_binding,
            'help_sha256': hashlib.sha256(help_path.read_bytes()).hexdigest(),
            'meaning': 'Bound prior configuration diagnosis only; no current task success or arbitrary causal proof.'}
        problem.update(status=status, assessment_scope=scope, prior_state=result['prior_state'],
            action_binding=result['action_binding'], numeric_comparison=numeric,
            help_evidence={'path': str(help_path), 'text': help_text},
            native_evidence=[dict(issue['found']), action['native_command'], action['native_command']['result']])
        return result
    except (OSError, ValueError, KeyError, TypeError, IndexError, CanonicalDeliveryError):
        return result


def prior_configuration_scope(conflicts):
    """Producer-owned diagnostic scope, never a reason-string whitelist."""
    return bool(conflicts) and all(
        p.get('status') in {'incomplete', 'fail'} and isinstance(p.get('assessment_scope'), dict) and
        p['assessment_scope'].get('kind') == 'prior_native_configuration_premise' and
        p['assessment_scope'].get('producer') == 'prior_configuration_claim_assessment' and
        p['assessment_scope'].get('object_role') == 'design_global_configuration' and
        p['assessment_scope'].get('command') == 'set_scan_drc_cfg' and
        p['assessment_scope'].get('parameter') == 'clock_gating_init_cycles' and
        p['assessment_scope'].get('assessment_status') == ('contradicted' if p['status'] == 'fail' else 'incomplete') and
        p['assessment_scope'].get('unknown_components') in (
            ['historical_causal_support'], ['effective_prior_value','historical_causal_support']) and
        p['assessment_scope'].get('object_binding', {}).get('kind') == 'task_template_actual_global_ICG_role' and
        p['assessment_scope']['object_binding'].get('design') == p['assessment_scope'].get('design') and
        p['assessment_scope']['object_binding'].get('actual_ICG_instances') and
        p['assessment_scope']['object_binding'].get('input_fingerprints') and
        p.get('native_evidence') and p.get('action_binding') and p.get('prior_state')
        for p in conflicts)


def prior_configuration_delivery_condition(issue, conflicts, root, rid, spec, files, dofile, words_for,
                                           *, changes=None, input_dir=None):
    """Actual final setup and task relation; caller owns all other hard gates."""
    try:
        if (not prior_configuration_scope(conflicts) or
                prior_configuration_claim_assessment(issue, changes or [], root, rid, words_for, input_dir)['problems'] != conflicts):
            return None
        root = root.absolute(); native = _setup_trace(root, rid, words_for)
        phase = operation_trace(files, root, dofile, words_for, allow_verbose=True)
        settings = _settings(dofile, words_for); requirement = _setup_requirement(spec)
        if not native or not phase or not settings or not requirement or not native['setters']:
            return None
        if (native['design'] != phase['design'] or native['design'] != settings[0] or
                any(p['assessment_scope']['design'] != native['design'] or
                    p['assessment_scope']['loaded_inputs'] != native['loaded_input_netlists'] or
                    p['assessment_scope']['case_output'] != str(root.resolve()) or
                    int(p['assessment_scope']['run_ref'][1:]) >= int(rid[1:]) for p in conflicts)):
            return None
        event = native['setters'][-1]
        if event['value'] < requirement['minimum']:
            return None
        final_binding = _setup_object_binding(issue, root, native, spec, input_dir, words_for)
        if not final_binding or any(final_binding['input_fingerprints'] != p['assessment_scope']['object_binding']['input_fingerprints']
                                    for p in conflicts):
            return None
        condition = {k:event[k] for k in ('run_ref','source','locator','excerpt')}
        paths = [root/native['script'], root/native['native'], Path(__file__).with_name('tool_help.json')]
        if input_dir:
            paths += [input_dir/name for name in ('task_spec.md','limitations.md') if (input_dir/name).is_file()]
        paths += [Path(path) for path in final_binding['input_fingerprints']]
        for problem in conflicts:
            scope = problem['assessment_scope']; action = problem['action_binding']
            paths += [root/scope['script'], root/scope['native'], root/action['diff_source'],
                root/'runs'/action['from_run']/'deliverables'/(action['from_run']+'.dofile'),
                root/'runs'/action['to_run']/'deliverables'/(action['to_run']+'.dofile'),
                root/action['native_command']['source']]
        return ({'kind': 'native_task_configuration_parameter', 'design': native['design'], 'run_ref': rid,
            'located_object': issue['diagnosis']['located_object'], 'prior_checks': conflicts,
            'original_run_ref': issue['found']['run_ref'], 'task_requirement': requirement,
            'object_binding': final_binding,
            'final_parameter_evidence': {'command': 'set_scan_drc_cfg', 'parameter': 'clock_gating_init_cycles',
                'value': event['value'], 'native_command': event, 'before_actual_DRC': True,
                'no_later_setter': True, 'native_result': event['result']},
            'native_command': event, 'final_condition': condition,
            'meaning': 'Actual final task setup independently bound; prior default/cause remains unresolved.'}, paths)
    except (OSError, ValueError, KeyError, TypeError, IndexError, CanonicalDeliveryError):
        return None


def defect_text(issue):
    """The asserted defect/action, separately from its task-requirement citation."""
    diagnosis = issue.get('diagnosis', {})
    fields = ([diagnosis.get(k, '') for k in ('summary', 'located_object', 'root_cause')]
              if isinstance(diagnosis, dict) else
              [diagnosis, issue.get('located_object', ''), issue.get('root_cause', '')])
    attempts = issue.get('attempts') or [{}]
    return ' '.join(str(x) for x in [issue.get('phenomenon', ''), *fields,
        attempts[-1].get('fix', {}).get('action', issue.get('fix', ''))])


def claim_parameters(issue):
    text = defect_text(issue)
    names = {name for name in PARAMETERS if re.search(r'(?<![\w])'+name+r'(?![\w])',text)}
    # "replace" is also an ordinary operation verb. Only parameter syntax
    # (a flag, typed value, or explicit parameter noun) asserts this option.
    if 'replace' in names and not re.search(
            r'(?<![\w])-replace\b|\breplace\s*(?:[:=]\s*)?(?:true|false)\b|'
            r'\b(?:parameter|option)\s+[`\'\"]?replace\b|'
            r'\breplace\s+(?:parameter|option)\b', text, re.I):
        names.remove('replace')
    return names


def signal_operations(issue):
    """Literal command options in the object/action, never task citations.

    A command mention is not evaluated as Tcl. Unbound/dynamic operands keep
    an obligation but cannot supply an object or a successful proof.
    """
    diagnosis = issue.get('diagnosis', {})
    action = (issue.get('attempts') or [{}])[-1].get('fix', {}).get('action', '')
    texts = [str(diagnosis.get('located_object', '')), str(action)]
    operations = []
    for text in texts:
        current = []
        for match in re.finditer(r'\bset_scan_signal\b', text):
            # Stop at the next actual command, while retaining coordinated
            # options. Literal operands only: no object inferred from prose.
            body = re.split(r'[;\n。；]|\b(?:set|rpt|dump|load|add)_[a-z_]+\b', text[match.end():])[0]
            options = {}
            for option in re.finditer(r'(?<![\w])-(type|port|off_state|usage|constant_value)\s+'
                                     r'(\{[^{}]*\}|"[^"\n]*"|[^\s,，;；。]+)', body):
                value = option[2].strip('`"{}').rstrip('.')
                if re.fullmatch(r'[A-Za-z_][\w$]*(?:\[\d+\])?|[01]', value) and '$' not in value:
                    options[option[1]] = value
            # A coordinated declaration may state the port operands immediately
            # before its command, e.g. "Declared a and b as resets with ...".
            # Parse only that explicit subject grammar, never nearby diagnostic
            # objects, task citations, or ports guessed from a final report.
            subjects = _declaration_subjects(text[:match.start()], options)
            expanded = [dict(options, port=port, subject_source='explicit_declaration_description')
                        for port in subjects] if subjects else [options]
            for operation in expanded:
                if operation not in current:
                    current.append(operation)
        # A literal replacement may legitimately change the old role. The old
        # declaration remains a diagnostic premise, not a second final role.
        replaced = {o['port'] for o in current if 'port' in o}
        operations = [o for o in operations if o.get('port') not in replaced] + current
    return operations


def _declaration_subjects(prefix, options):
    if options.get('port') or options.get('type') not in {'clock', 'reset', 'scan_enable', 'constant'}:
        return []
    # Any disagreement between the typed noun and literal command is unknown.
    role = {'clock': r'clocks?', 'reset': r'resets?',
            'scan_enable': r'scan[ _-]?enables?', 'constant': r'constants?'}[options['type']]
    name = r'`?[A-Za-z_][\w$]*(?:\[\d+\])?`?'
    subjects = name + r'(?:\s*(?:,\s*(?:and\s+)?|\band\s+)' + name + r')*'
    match = re.fullmatch(r'\s*(?:Declared?|Configured?|Registered?)\s+(' + subjects +
                      r')\s+as\s+(?:(active[ -](?:low|high))\s+)?' + role +
                      r'\s+(?:with|using)\s*$', prefix, re.I)
    if not match:
        return []
    values = [v.strip().strip('`') for v in re.split(r'\s*(?:,\s*(?:and\s+)?|\band\s+)\s*', match[1])]
    # Repeated or dynamic subjects never become an inferred unique object list.
    if len(values) != len(set(values)) or any('$' in v for v in values):
        return []
    if match[2]:
        off = '1' if match[2].lower().replace(' ', '-') == 'active-low' else '0'
        if options.get('off_state') != off:
            return []
    return values


def _association_only_mentions(issue):
    """Only defer mentions that explicitly carry this association operation.

    An additional unbound signal mention remains a separate obligation.
    This is routing, not proof of the port, pins or their relationship.
    """
    texts = [str(issue.get('diagnosis', {}).get('located_object', '')),
             str((issue.get('attempts') or [{}])[-1].get('fix', {}).get('action', ''))]
    bodies = []
    for text in texts:
        for match in re.finditer(r'\bset_scan_signal\b', text):
            body = re.split(r'[;\n。；]|\b(?:set|rpt|dump|load|add)_[a-z_]+\b', text[match.end():])[0]
            bodies.append(body)
    return bool(bodies) and all('-associated_internal_clocks' in b for b in bodies)


def _signal_command_trace(root, rid, words_for, *, include_rule_commands=False):
    """Read literal native control commands, including a failed original run."""
    from eco_object_selection import is_context_query
    run = root/'runs'/rid
    script = run/'deliverables'/(rid+'.dofile'); log = run/(rid+'.log')
    _real_file(script, root); _real_file(log, root)
    lines = script.read_text().splitlines()
    design = ''; partition = 'Default_Partition'; active = None; origin = None
    signals = []; designs = []; loaded = []; loaded_inputs = []; loading_input = False; rule_commands = []
    with log.open(errors='replace') as stream:
        for number, line in enumerate(stream, 1):
            source = re.search(r'\[SOURCE TCL FILE\]\s+(\S+)\s*:', line)
            if source:
                parts = PurePosixPath(source[1]).parts
                cuts = [i for i, name in enumerate(parts) if name == 'runs' and parts[i+1:i+2] == (rid,)]
                if origin is not None or len(cuts) != 1 or '..' in parts:
                    return None
                origin = run.joinpath(*parts[cuts[0]+2:]); _real_file(origin, root)
                if origin.suffix != '.dofile' or origin.read_bytes() != script.read_bytes():
                    return None
            echo = re.search(r'CMD-0034\]\s+@(\d+):\s*(.*)', line)
            if echo:
                text = echo[2].strip(); words = words_for(text); active = None
                loading_input = bool(words and words[0] == 'load_netlist')
                if not words or text.startswith('#'):
                    continue
                if words[0] in {'source', 'eval', 'uplevel', 'interp', 'namespace',
                                'proc', 'rename', 'trace', 'exec', 'load_ctl'}:
                    return None
                if words[0] in {'if', 'for', 'foreach', 'while'} and not is_context_query(text) and re.search(
                        r'\b(?:present_design|set_current_scan_partition|set_scan_signal|load_netlist' +
                        (r'|set_scan_drc_rule_handling' if include_rule_commands else '') + r')\b', text):
                    return None
                if words[0] in ({'present_design', 'set_current_scan_partition', 'set_scan_signal'} |
                               ({'set_scan_drc_rule_handling'} if include_rule_commands else set())):
                    if not 0 < int(echo[1]) <= len(lines) or lines[int(echo[1])-1].strip() != text:
                        return None
                if words[0] == 'present_design':
                    if len(words) != 2 or not re.fullmatch(r'[A-Za-z_]\w*', words[1]):
                        return None
                    design = words[1]; designs.append(design); partition = 'Default_Partition'
                elif words[0] == 'set_current_scan_partition':
                    if len(words) != 2 or not re.fullmatch(r'[A-Za-z_]\w*', words[1].strip('"{}')):
                        return None
                    partition = words[1].strip('"{}')
                elif words[0] == 'set_scan_signal':
                    if not design or len(words) % 2 != 1 or len(set(words[1::2])) != len(words[1::2]):
                        return None
                    active = {'words': words, 'design': design, 'partition': partition,
                              'script_line': int(echo[1]), 'source': log.relative_to(root).as_posix(),
                              'locator': f'L{number}', 'excerpt': line.strip(), 'run_ref': rid, 'errors': []}
                    signals.append(active)
                elif include_rule_commands and words[0] == 'set_scan_drc_rule_handling':
                    if not design:
                        return None
                    active = {'words': words, 'design': design, 'partition': partition,
                              'script_line': int(echo[1]), 'source': log.relative_to(root).as_posix(),
                              'locator': f'L{number}', 'excerpt': line.strip(), 'run_ref': rid, 'errors': []}
                    rule_commands.append(active)
            elif active is not None and '[ERROR]' in line:
                active['errors'].append({'line': number, 'text': line.rstrip('\n')})
            loaded_file = re.search(r"VRLG-I-0001\]\s+Read Verilog file '([^']+)' successfully\.", line)
            if loaded_file:
                loaded.append(loaded_file[1])
                if loading_input:loaded_inputs.append(loaded_file[1])
    if origin is None or len(designs) != 1 or not loaded:
        return None
    result = {'design': design, 'signals': signals, 'loaded_netlists': loaded,
              'loaded_input_netlists': loaded_inputs}
    if include_rule_commands:
        result['rule_commands'] = rule_commands
    return result


def _signal_port_correction(issue, files, root, dofile, words_for, changes):
    """Prove a missing-port argument correction, NOT a netlist object rename.

    Exact original command, explicit repair pair, byte-bound change, executed
    replacement and native pre-existing port row are all necessary. Hierarchy,
    bus/dynamic operands, actual netlist renames and ambiguous deltas abstain.
    """
    result = {'status': 'incomplete', 'missing': [], 'kind': 'missing_port_argument_correction'}
    def stop(reason):
        result['missing'].append(reason); return result
    try:
        found = issue.get('found', {}); old = str(found.get('run_ref', ''))
        failure = re.fullmatch(r"\[ERROR\]\s+\[\s*SCAN-\d+\]\s+Port '([A-Za-z_]\w*)' does not exist in the design\..*",
                               str(found.get('excerpt', '')).strip())
        action = str(issue['attempts'][-1]['fix']['action'])
        request = re.fullmatch(r'(?:Chang(?:e|ed)|Replac(?:e|ed)|Correct(?:ed)?)\s+-port\s+'
                               r'([A-Za-z_]\w*)\s+(?:to|with|→)\s+-port\s+([A-Za-z_]\w*)\.?', action, re.I)
        logs = [p for p in files if p.suffix == '.log' and p.name == p.parent.name+'.log']
        if not failure or not request or request[1] != failure[1] or request[1] == request[2] or len(logs) != 1:
            return stop('A native missing-port error and one explicit literal old/new argument pair are required')
        current = logs[0].parent.name
        if not re.fullmatch(r'R[1-9]\d*', old) or not re.fullmatch(r'R[1-9]\d*', current) or int(old[1:]) >= int(current[1:]):
            return stop('Correction must reference a prior actual run')
        failed = words_for(failed_command(found, root) or '')
        located = words_for(str(issue.get('diagnosis', {}).get('located_object', '')))
        if (failed[:1] != ['set_scan_signal'] or len(failed) % 2 != 1 or
                len(set(failed[1::2])) != len(failed[1::2]) or located[:1] != ['set_scan_signal'] or len(located) % 2 != 1):
            return stop('The located declaration and actual failed command must be literal')
        options = dict(zip(failed[1::2], failed[2::2])); named = dict(zip(located[1::2], located[2::2]))
        if (set(options) != {'-type', '-port', '-off_state'} or options.get('-type') not in {'clock', 'reset'} or
                options['-off_state'] not in {'0', '1'} or options['-port'] != request[1] or
                named.get('-port') != request[1] or any(options.get(k) != v for k, v in named.items())):
            return stop('The original object/type/options are not bound, or the repair exceeds port correction')
        new_words = list(failed); new_words[new_words.index('-port')+1] = request[2]
        refs = issue['attempts'][-1]['fix'].get('artifact_ref', [])
        selected = [c for c in changes or [] if c.get('change_id') in refs]
        if len(refs) != 1 or len(selected) != 1 or selected[0].get('type') != 'dofile':
            return stop('One actual cited Dofile correction is required')
        change = selected[0]; delta = root/str(change.get('diff_path', '')); target = root/str(change.get('path', ''))
        _real_file(delta, root); _real_file(target, root)
        header = re.match(r'--- (R[1-9]\d*)\n\+\+\+ (R[1-9]\d*)\n', delta.read_text())
        if (not header or header[1] != old or not int(old[1:]) < int(header[2][1:]) <= int(current[1:]) or
                target != root/'runs'/header[2]/'deliverables'/(header[2]+'.dofile') or not delta.is_relative_to(root/'diffs')):
            return stop('The cited correction belongs to another object/run or has an invalid diff')
        before = root/'runs'/old/'deliverables'/(old+'.dofile'); _real_file(before, root)
        expected = ''.join(difflib.unified_diff(before.read_text().splitlines(True), target.read_text().splitlines(True),
                                               fromfile=old, tofile=header[2]))
        if delta.read_text() != expected:
            return stop('The cited diff does not match the retained actual scripts')
        parsed = lambda text: [words_for(c.strip().replace('\\\n', ' ')) for c in tcl_chunks(text)
                               if c.strip() and not c.lstrip().startswith('#')]
        prior, repaired = parsed(before.read_text()), parsed(target.read_text())
        if (prior.count(failed) != 1 or new_words in prior or failed in repaired or
                repaired.count(new_words) != 1):
            return stop('The old/new command replacement is absent, ambiguous or includes other changes')
        original_trace = _signal_command_trace(root, old, words_for)
        fixed_trace = _signal_command_trace(root, header[2], words_for)
        now_trace = _signal_command_trace(root, current, words_for)
        if (not original_trace or not fixed_trace or not now_trace or
                len({t['design'] for t in [original_trace, fixed_trace, now_trace]}) != 1 or
                not original_trace['loaded_netlists'] == fixed_trace['loaded_netlists'] == now_trace['loaded_netlists']):
            return stop('Prior/repaired/current native designs or loaded input paths differ or are unknown')
        old_events = [e for e in original_trace['signals'] if e['words'] == failed]
        new_events = [e for e in now_trace['signals'] if e['words'] == new_words]
        fixed_events = [e for e in fixed_trace['signals'] if e['words'] == new_words]
        locator = re.fullmatch(r'L(\d+)(?:-L(\d+))?', str(found.get('locator', '')))
        if (len(old_events) != 1 or len(new_events) != 1 or len(fixed_events) != 1 or not locator or
                not any(int(locator[1]) <= e['line'] <= int(locator[2] or locator[1]) and found['excerpt'] in e['text']
                        for e in old_events[0]['errors']) or new_events[0]['errors'] or fixed_events[0]['errors'] or
                len({e['partition'] for e in [old_events[0], fixed_events[0], new_events[0]]}) != 1):
            return stop('Actual failed/replacement commands, error locator or partitions do not correspond')
        work = copy.deepcopy(issue); work['diagnosis']['located_object'] = 'ports '+request[2]
        proof = grouped_signal_evidence(work, files, root, dofile, words_for, allow_reset=True)
        trace = operation_trace(files, root, dofile, words_for, allow_verbose=True)
        writer = post_operation_report(root/proof['source'], 'rpt_scan_signal', trace, root) if proof else None
        if not writer or trace['design'] != original_trace['design']:
            return stop('A current same-design post-operation signal report is required')
        rows = [r for r in report_rows(root/proof['source'], {'Port', 'PortProperty'}) if r['Port'] == request[2]]
        if len(rows) != 1 or rows[0]['PortProperty'] != 'pre_existing':
            return stop('The replacement must be an exact pre-existing top-level port, not a created alias')
        result.update(status='pass', evidence=proof, old_port=request[1], new_port=request[2],
                      design=trace['design'], original_command=old_events[0], replacement_command=new_events[0],
                      change_ref=change['change_id'], diff_source=change['diff_path'], native_report_operation=writer,
                      netlist_rename_proven=False)
        return result
    except (OSError, ValueError, TypeError, KeyError, IndexError, CanonicalDeliveryError):
        return stop('Port correction evidence could not be safely bound')


def evidence_requirements(issue, output_dir, words_for):
    """Select every asserted family; a requirement citation does not add faults."""
    intent = copy.deepcopy(issue)
    if isinstance(intent.get('diagnosis'), dict):
        intent['diagnosis'].pop('violated_requirement', None)
    intent.pop('violated_requirement', None)
    text = defect_text(issue)
    failed = words_for(failed_command(issue.get('found', {}), output_dir) or '')
    located = str(issue.get('diagnosis', {}).get('located_object', '')).strip()
    match = re.fullmatch(r'ports?\s+([\w$,\s]+)', located, re.I)
    targets = sorted(set(re.findall(r'[A-Za-z_][\w$]*', match[1]))) if match else []
    signal_error = bool(failed and failed[0] == 'set_scan_signal' and
                        '-type' in failed and failed[failed.index('-type')+1:][:1] == ['scan_enable'])
    if signal_error and not targets and '-port' in failed:
        port = failed[failed.index('-port')+1:][:1]
        if port:
            port = port[0].strip('"{}')
            named = words_for(located)
            exact_name = re.fullmatch(r'(?:port\s+)?'+re.escape(port), located, re.I)
            explicit_command = (named[:1] == ['set_scan_signal'] and '-port' in named and
                                named[named.index('-port')+1:][:1] == [port])
            if re.fullmatch(r'[A-Za-z_][\w$]*', port) and (exact_name or explicit_command):
                targets = [port]
    families = set()
    if signal_error or targets and re.search(r'off_state|active_state|\busage\b|set_scan_signal|scan[_ -]?enable|扫描使能', text, re.I):
        families.add('signal')
    operations = signal_operations(issue)
    mode_targets = sorted({o['port'] for o in operations if o.get('type') == 'constant' and 'port' in o})
    controls = [o for o in operations if o.get('type') in {None, 'scan_enable', 'reset', 'clock'}]
    control_targets = {o['port'] for o in controls if 'port' in o}
    if controls:
        families.add('signal')
        # A located multi-object scope remains authoritative. An action on a
        # different port cannot silently replace that scope.
        if not targets:
            targets = sorted(control_targets)
    if any(o.get('type') == 'constant' for o in operations):
        families.add('mode')
    parameters = claim_parameters(issue)
    found = issue.get('found', {}); old_run = str(found.get('run_ref', ''))
    source = output_dir.absolute()/str(found.get('source', ''))
    native_configuration = False
    if (source.suffix in {'.rpt', '.report', '.txt'} and
            not any(p.startswith('.env') or p in {'answers', 'golden.dofile', 'preset_issues.json'} for p in source.parts) and
            re.fullmatch(r'R[1-9]\d*', old_run) and source.is_relative_to(output_dir.absolute()/'runs'/old_run)):
        try:
            _real_file(source, output_dir.absolute())
            with source.open(errors='replace') as stream:
                header = stream.read(8192)
            native_configuration = ('ScanConfigurationParameter' in header and
                _reference_bound(found, [source], output_dir.absolute(), old_run))
        except (OSError, ValueError, CanonicalDeliveryError):
            pass
    if parameters or native_configuration:
        families.add('configuration')
    action = str((issue.get('attempts') or [{}])[-1].get('fix', {}).get('action', issue.get('fix', '')))
    association_assignment = re.search(r'\bset_scan_signal\b[^;\n]*\s-associated_internal_clocks\b', action)
    association_addition = re.search(
        r'\b(?:add\w*|enabl\w*|set|specif\w*|assign\w*)\b[^.;\n]{0,100}'
        r'(?<![\w])associated_internal_clocks\b', action, re.I)
    if association_assignment or association_addition:
        # A compound repair cannot prove an asserted clock-pin association
        # solely by its other configuration value or by a clean DRC total.
        # Merely removing a rejected association is a different operation; its
        # existing command-failure/clock-row proof must not require adding pins.
        families.add('clock_association')
        # The association verifier binds the primary clock, complete internal
        # pin set and native executed declaration. An otherwise empty signal
        # mention is not an additional, unbound port operation. Explicit
        # control/mode operands still retain their own checks in mixed claims.
        if not targets and operations and all(not op for op in operations) and _association_only_mentions(issue):
            families.discard('signal')
    if compound_coverage_claim(intent):
        families.add('coverage')
    commands = set(re.findall(r'\b(?:set_scan_cell_mapping|dump_netlist|load_lib|load_netlist)\b', text))
    located_commands = set(re.findall(r'\b(?:set_scan_cell_mapping|load_lib|load_netlist)\b', located))
    kind = command_proof_kind(issue, output_dir, words_for)
    # These existing command proofs include their initialization prerequisites.
    # A repair action that loads a library is not a second failed load command.
    # Independently named command subjects still retain separate obligations.
    if kind == 'mapping' and not located_commands & {'load_lib', 'load_netlist'}:
        commands -= {'load_lib', 'load_netlist'}
    if failed and failed[0] in {'load_lib', 'load_netlist'} and 'set_scan_cell_mapping' not in located_commands:
        commands.discard('set_scan_cell_mapping')
    if kind == 'mapping' or 'set_scan_cell_mapping' in commands:
        families.add('mapping')
    if kind == 'netlist_export' or 'dump_netlist' in commands:
        families.add('netlist_export')
    if commands & {'load_lib', 'load_netlist'} or failed and failed[0] in {'load_lib', 'load_netlist'}:
        families.add('load')
    output_commands = sorted(set(re.findall(r'\b(?:rpt_[a-z_]+|dump_netlist|dump_ctl|dump_def)\b', action)))
    diagnosis = issue.get('diagnosis', {})
    fault = ' '.join(str(x) for x in [issue.get('phenomenon', ''),
                      *(diagnosis.get(k, '') for k in ('summary', 'located_object', 'root_cause'))])
    # A report named as the verification method of a configuration/control
    # repair is not itself a failed output operation. Keep actual compound
    # output defects and literal failed/located output commands.
    output_fault = bool(re.search(r'\b(?:rpt_[a-z_]+|dump_netlist|dump_ctl|dump_def)\b', located) or
                        failed and failed[0] in output_commands or
                        re.search(r'\b(?:missing|absent|no)\b.{0,40}\b(?:files?|reports?|outputs?)\b|'
                                  r'(?:缺少|缺失|未生成|未输出).{0,30}(?:文件|报告|输出)|'
                                  r'(?:文件|报告|输出).{0,20}(?:缺失|未生成)', fault, re.I))
    auxiliary = bool(families & {'configuration', 'signal', 'mode', 'mapping', 'load', 'coverage', 'clock_association'})
    if output_commands and output_commands != ['dump_netlist'] and (output_fault or not auxiliary):
        families.add('outputs')
    elif auxiliary and not output_fault:
        output_commands = []
    # Preserve the existing single-parameter specialized verifiers. A single
    # configuration parameter in a mixed claim must still be checked as a part.
    applicable = bool(native_configuration or len(parameters) > 1 or
                      families & {'coverage', 'signal', 'mode', 'outputs', 'netlist_export', 'load', 'clock_association'} or len(families) > 1)
    return {'applicable': applicable, 'families': sorted(families),
            'configuration_parameters': sorted(parameters), 'signal_targets': targets,
            'mode_targets': mode_targets, 'output_commands': output_commands,
            'unbound_signal_operations': [o for o in operations if not o.get('type') or not o.get('port')],
            'native_configuration_discovery': native_configuration,
            'native_failed_command': failed_command(issue.get('found', {}), output_dir),
            'task_reference_is_not_defect_scope': True}


def _reference_bound(proof, files, output_dir, rid):
    if not proof:
        return False
    try:
        path = output_dir / proof['source']
        if (path.suffix not in {'.log', '.rpt', '.report', '.txt'} or
                any(p.startswith('.env') or p in {'answers', 'golden.dofile', 'preset_issues.json'} for p in path.parts)):
            return False
        _real_file(path, output_dir)
        if path not in files or not path.is_relative_to(output_dir/'runs'/rid):
            return False
        m = re.fullmatch(r'L([1-9]\d*)(?:-L([1-9]\d*))?', proof['locator'])
        if not m or not proof['excerpt']:
            return False
        first, last = int(m[1]), int(m[2] or m[1]); fragment = []
        with path.open(errors='replace') as stream:
            for number, line in enumerate(stream, 1):
                if number > last:break
                if number >= first:fragment.append(line.rstrip('\r\n'))
        return last >= first and len(fragment) == last-first+1 and proof['excerpt'] in '\n'.join(fragment)
    except (OSError, ValueError, KeyError, TypeError, CanonicalDeliveryError):
        return False


def _signal_fault_binding(issue, targets, output_dir, before, words_for):
    """Bind explicit signal-option claims, without inferring new targets.

    This is a bounded syntax-fault check, not a free-text diagnosis parser.
    Task citations and the replacement action are not old faulty commands.
    """
    diagnosis = issue.get('diagnosis', {})
    texts = [('phenomenon', issue.get('phenomenon', '')),
             ('summary', diagnosis.get('summary', '')),
             ('root_cause', diagnosis.get('root_cause', ''))]
    claims = []
    for field, text in texts:
        for clause in re.split(r'[;。；\n]|\.(?![\w$])', str(text)):
            omitted = bool(re.search(r'\b(?:miss\w*|lack\w*|omitt\w*)\b|缺少|缺失|未声明|未指定', clause, re.I)
                           and not re.search(r'\bnot\s+(?:missing|lack\w*|omitt\w*|all|both)\b|并非(?:所有|全部)', clause, re.I))
            if not omitted and not re.search(r'\b(?:invalid|unknown|unsupported|nonexistent)\b|非法|无效|不支持|不存在', clause, re.I):
                continue
            for match in re.finditer(r'(?<![\w])-?(active_state|off_state|usage)\b', clause, re.I):
                prefix = re.search(r'\b(not\s+)?(?:invalid|unknown|unsupported|nonexistent)\s+(?:option\s+)?[`\'\"]?$',
                                   clause[:match.start()], re.I)
                value = re.match(r'\s*(?:value\s*)?(?:[:=]\s*)?[`\'\"]?(-?\d+)\b', clause[match.end():], re.I)
                tail = clause[match.end()+(value.end() if value else 0):]
                suffix = re.match(r'\s+(?:is\s+)?(?:invalid|unknown|unsupported|nonexistent)\b', tail, re.I)
                # Bind absence to this option (including coordinated option
                # lists). "usage scan, missing clock_gating coverage" asserts
                # insufficient coverage, not an absent -usage declaration.
                before_option = clause[:match.start()]
                after_option = clause[match.end():]
                omission_prefix = re.search(
                    r'(?:\b(?:miss\w*|lack\w*|omitt\w*)\s+'
                    r'(?:(?:the|required|explicit|both|option|parameter)\s+)*'
                    r'(?:(?:-?(?:off_state|usage))\s*(?:,|and|/)\s*)*|'
                    r'(?:缺少|缺失|未声明|未指定)\s*'
                    r'(?:(?:-?(?:off_state|usage))\s*(?:、|和|及)\s*)*)$', before_option, re.I)
                omission_suffix = re.match(
                    r'\s*(?:(?:option|parameter)\s+)?(?:(?:is|was)\s+)?'
                    r'(?:missing|omitted|absent)\b|\s*(?:未声明|未指定|缺失)', after_option, re.I)
                missing_option = (omitted and match[1].lower() in {'off_state', 'usage'} and
                                  bool(omission_prefix or omission_suffix))
                if not (prefix and not prefix[1] or suffix or missing_option):
                    continue
                claims.append({'field': field, 'clause': clause.strip(), 'option': '-'+match[1].lower(),
                               'value': value[1] if value else None,
                               'kind': 'omitted_option' if missing_option else 'invalid_option_or_value'})
    result = {'status': 'pass', 'claims': [], 'missing': []}
    if not claims:
        return result
    rid = issue['found']['run_ref']; log = output_dir/'runs'/rid/(rid+'.log')
    try:
        _real_file(log, output_dir)
        commands = {}; known = set(); number = 1
        for chunk in tcl_chunks(before.read_text()):
            words = words_for(chunk.strip().replace('\\\n', ' '))
            if words[:1] == ['set_scan_signal'] and len(words) % 2 == 1:
                options = dict(zip(words[1::2], (x.strip('"{}') for x in words[2::2])))
                ports = options.get('-port', '').split()
                if ports and all(re.fullmatch(r'[A-Za-z_][\w$]*', port) for port in ports):
                    known.update(ports); commands[number] = (words, options)
            number += chunk.count('\n')
        failures = []; executed = []; active = None
        with log.open(errors='replace') as stream:
            for number, line in enumerate(stream, 1):
                echo = re.search(r'CMD-0034\]\s+@(\d+):\s*(.*)', line)
                if echo:
                    saved = commands.get(int(echo[1])); active = None
                    if saved and words_for(echo[2]) == saved[0]:
                        active = (saved[1], int(echo[1]))
                        executed.append({'options': active[0], 'script_line': active[1],
                            'evidence': {'run_ref': rid, 'source': log.relative_to(output_dir).as_posix(),
                                         'locator': f'L{number}', 'excerpt': line.strip()}})
                elif active and '[ERROR]' in line:
                    failures.append({'options': active[0], 'script_line': active[1],
                        'evidence': {'run_ref': rid, 'source': log.relative_to(output_dir).as_posix(),
                                     'locator': f'L{number}', 'excerpt': line.strip()}})
        for claim in claims:
            clause = claim['clause']
            symbols = re.findall(r'[A-Za-z_][\w$]*(?:[/.][A-Za-z_][\w$]*)*(?:\[\d+\])?', clause)
            named = {symbol for symbol in symbols if symbol in known or any(
                symbol.endswith('/'+port) or symbol.endswith('.'+port) or symbol.startswith(port+'[')
                for port in known)}
            explicit = set(re.findall(r'\b(?:port|signal)\s+[`\'\"]?([A-Za-z_][\w$]*)', clause, re.I))
            named |= explicit
            universal = bool(re.search(r'\b(?:all|both)\s+(?:the\s+)?(?:scan[_ -]?enable\s+)?(?:ports?|signals?)\b|'
                                       r'(?:所有|全部)(?:的)?(?:扫描使能)?(?:端口|信号)', clause, re.I) and
                             not re.search(r'\bnot\s+(?:all|both)\b|并非(?:所有|全部)', clause, re.I))
            scope = named or set(targets)
            ambiguous = not named and len(targets) > 1 and claim['field'] != 'phenomenon' and not universal
            proofs = []
            for port in sorted(scope):
                if claim['kind'] == 'omitted_option':
                    # An omitted flag is a syntax fact, not proof of a fault.
                    # The existing native-default contradiction check still runs.
                    matching = [row for row in executed if port in row['options'].get('-port', '').split() and
                        row['options'].get('-type') == 'scan_enable' and claim['option'] not in row['options']]
                else:
                    matching = [row for row in failures if port in row['options'].get('-port', '').split() and
                        row['options'].get('-type') == 'scan_enable' and claim['option'] in row['options'] and
                        re.search(r'(?<![\w])-?'+re.escape(claim['option'][1:])+r'(?![\w])', row['evidence']['excerpt']) and
                        (claim['value'] is None or row['options'][claim['option']] == claim['value'] and
                         re.search(r"['\"]"+re.escape(claim['value'])+r"['\"]", row['evidence']['excerpt']))]
                if len(matching) == 1:
                    proofs.append({'object': port, **matching[0]})
            # A short phenomenon is a group heading; its explicitly wrong
            # options still need actual support within the declared scope.
            heading = claim['field'] == 'phenomenon' and not named and not universal
            complete = bool(proofs) if heading else len(proofs) == len(scope)
            checked = {**claim, 'objects': sorted(scope), 'native_support': proofs,
                       'complete': complete and not ambiguous and scope <= set(targets)}
            result['claims'].append(checked)
            if not checked['complete']:
                reason = ('Claim names objects outside the declared signal scope' if not scope <= set(targets) else
                          'Literal fault lacks an unambiguous object within the multi-object diagnosis' if ambiguous else
                          'No matching executed native command/failure for this option/value on the required signal objects')
                result['missing'].append({'option': claim['option'], 'value': claim['value'],
                    'objects': sorted(scope), 'reason': reason})
    except (OSError, ValueError, KeyError, CanonicalDeliveryError):
        result['missing'].append({'reason': 'Prior signal fault commands/log cannot be bound'})
    if result['missing']:
        result['status'] = 'incomplete'
    return result


def _signal_check(issue, files, output_dir, dofile, words_for, targets, *, constant=False):
    result = {'status': 'incomplete', 'missing': [], 'targets': targets, 'diagnosis_conflicts': []}
    def stop(reason):
        result['missing'].append(reason);return result
    if not targets:
        return stop('Literal signal object scope is missing or ambiguous')
    work = copy.deepcopy(issue)
    work['diagnosis']['located_object'] = 'ports ' + ', '.join(targets)
    if mismatched_signal_target({'located_object': work['diagnosis']['located_object']},
                                issue.get('found', {}), output_dir, words_for):
        return stop('Signal discovery belongs to a different actual port')
    proof = grouped_signal_evidence(work, files, output_dir, dofile, words_for,
                                    allow_reset=True, allow_constant=constant)
    if not proof:
        return stop('All signal objects, roles, values, designs and partitions need matching native rows')
    trace = operation_trace(files, output_dir, dofile, words_for, allow_verbose=True)
    writer = post_operation_report(output_dir/proof['source'], 'rpt_scan_signal', trace, output_dir)
    if not writer:
        return stop('Signal report is not bound to this executed script/design/operation')
    old_run = str(issue.get('found', {}).get('run_ref', ''))
    try:
        before = output_dir/'runs'/old_run/'deliverables'/(old_run+'.dofile')
        _real_file(before, output_dir)
        if _full_insertion_designs(before.read_text()) != {trace['design']}:
            return stop('Prior signal discovery and current proof belong to different or unknown designs')
    except (OSError, ValueError, CanonicalDeliveryError):
        return stop('Prior signal script is not bound')
    result['observed_signal_evidence'] = proof
    result['native_report_operation'] = writer
    # An uncontrolled clock does not discover an absent mode or SE declaration.
    # Existing faulty declarations remain eligible for their typed/DRC repair.
    prior_script = before.read_text()
    old_ports = set()
    for chunk in tcl_chunks(prior_script):
        text = chunk.strip().replace('\\\n', ' ')
        if not text or text.startswith('#'):
            continue
        words = words_for(text)
        if words[:1] == ['set_scan_signal'] and '-port' in words:
            value = words[words.index('-port')+1:][:1]
            if value and re.fullmatch(r'[A-Za-z_][\w$]*', value[0].strip('"{}')):
                old_ports.add(value[0].strip('"{}'))
    failed = words_for(failed_command(issue.get('found', {}), output_dir) or '')
    if (not set(targets) <= old_ports and failed[:1] != ['set_scan_signal'] and
            re.search(r'\bDFTR[-\w]*', str(issue.get('found', {}).get('excerpt', ''))) and
            (constant or any(o.get('type') == 'scan_enable' and o.get('port') in targets
                             for o in signal_operations(issue)))):
        return stop('DRC discovery does not establish the missing signal/mode declaration; prior native discovery is required')
    # A successful later row cannot prove that an already-legal default was
    # defective. Only contradict explicit missing-option assertions, with the
    # actual old typed row and the later identical state retained as evidence.
    diagnosis = issue.get('diagnosis', {})
    actions = issue.get('attempts') or [{}]
    texts = [diagnosis.get('summary', ''), diagnosis.get('root_cause', ''),
             actions[-1].get('fix', {}).get('action', '')]
    clauses = [clause for text in texts for clause in re.split(r'[.;。；\n]', str(text))]
    missing_targets = {port for port in targets if any(
        (re.search(r'(?<![\w$])'+re.escape(port)+r'(?![\w$])', clause) or
         re.search(r'\b(?:all|both)\s+(?:the\s+)?(?:scan[_ -]?enable\s+)?(?:ports?|signals?)\b|'
                   r'(?:所有|全部)(?:的)?(?:扫描使能)?(?:端口|信号)', clause, re.I) and
         not re.search(r'\bnot\s+(?:all|both)\b|并非(?:所有|全部)', clause, re.I)) and
        re.search(r'off_state|\busage\b', clause, re.I) and
        re.search(r'\b(?:miss\w*|lack\w*|omitt\w*)\b|缺少|缺失|未声明|未指定', clause, re.I) and
        not re.search(r'\bnot\s+(?:missing|lack\w*|omitt\w*)\b', clause, re.I)
        for clause in clauses)}
    if missing_targets:
        if not trace or not re.fullmatch(r'R[1-9]\d*', old_run) or int(old_run[1:]) >= int(trace['run_ref'][1:]):
            return stop('A prior actual run is required for signal diagnosis comparison')
        current_rows = {r['Port']: r for r in report_rows(output_dir/proof['source'],
                        {'Port', 'SignalType', 'OffState', 'Usage', 'OwnerPartition'}) if r['Port'] in targets}
        for path in sorted((output_dir/'runs'/old_run/'reports').glob('*signal*.rpt')):
            try:
                _real_file(path, output_dir)
                lines = path.read_text().splitlines()
                if re.findall(r'(?m)^\s*Design:\s*(\S+)\s*$', '\n'.join(lines)) != [trace['design']]:
                    continue
                old_rows = list(report_rows(path, {'Port', 'SignalType', 'OffState', 'Usage', 'OwnerPartition'}))
                for port in sorted(missing_targets):
                    rows = [r for r in old_rows if r['Port'] == port]
                    if len(rows) != 1:continue
                    row, now = rows[0], current_rows[port]
                    if (row['SignalType'].split('(')[0] == 'scan_enable' and
                            all(row[k] == now[k] for k in ('SignalType', 'OffState', 'Usage', 'OwnerPartition'))):
                        result['diagnosis_conflicts'].append({'object': port,
                            'reason': 'Claimed missing attributes already had the same legal native state',
                            'prior': {'run_ref': old_run, 'source': path.relative_to(output_dir).as_posix(),
                                      'locator': f"L{row['line']}", 'excerpt': lines[row['line']-1]},
                            'current': proof})
            except (OSError, ValueError, KeyError, CanonicalDeliveryError):
                return stop('Prior signal evidence cannot be safely bound')
    if result['diagnosis_conflicts']:
        return stop('Correct the contradicted diagnosis using the retained prior/current native evidence; no repair inferred for legal defaults')
    binding = _signal_fault_binding(issue, targets, output_dir, before, words_for)
    result['fault_claim_binding'] = binding
    if binding['status'] != 'pass':
        return stop('Correct the signal diagnosis object/option/value scope using the retained native commands/failures; final state alone cannot prove it')
    result.update(status='pass', evidence=proof)
    return result


def output_operation_check(issue, files, root, dofile, words_for, commands):
    """Bind every claimed output operation, not a generic DRC condition."""
    result = {'status': 'incomplete', 'missing': [], 'operations': []}
    failed = words_for(failed_command(issue.get('found', {}), root) or '')
    if not failed or failed[0] not in commands:
        result['missing'].append('Discovery does not identify the claimed output operation')
        return result
    trace = operation_trace(files, root, dofile, words_for, allow_verbose=True)
    if not trace:
        result['missing'].append('One completed same-design operation is required')
        return result
    for command in commands:
        proofs = []
        if command == 'dump_netlist':
            proof = netlist_export_evidence(issue, files, root, dofile, words_for)
            if proof:
                proofs.append(proof)
        elif command.startswith('rpt_'):
            for path in files:
                bound = post_operation_report(path, command, trace, root)
                if bound:
                    proofs.append({**bound, 'source': bound['source'], 'locator': bound['locator'],
                                   'excerpt': bound['excerpt']})
        else:
            for event in trace.get('outputs', []):
                if event['kind'] != command or not event.get('completion'):
                    continue
                path = event['path']
                try:
                    _real_file(path, root)
                    with path.open(errors='replace') as stream:
                        header = stream.read(8192)
                    name = re.escape(trace['design'])
                    typed = (bool(re.search(r'(?m)^\s*DESIGN\s+'+name+r'\s*;', header)) if command == 'dump_def'
                             else bool(re.search(r'\bSTIL\s+1\.0', header) and
                                       re.search(r'Title\s+"Design\s+\''+name+r'\'"', header)))
                    if (typed and event['design'] == trace['design'] and
                            event['log_line'] > trace['operation']['replacement']['log_line']):
                        proofs.append({**event['completion'], 'output_path': path.relative_to(root).as_posix()})
                except (OSError, CanonicalDeliveryError):
                    pass
        if len(proofs) != 1:
            result['missing'].append(command)
        else:
            result['operations'].append({'command': command, 'evidence': proofs[0]})
    if not result['missing'] and result['operations']:
        result.update(status='pass', evidence=result['operations'][0]['evidence'])
    return result


def selected_evidence_check(issue, files, output_dir, dofile, task_spec, words_for, *, file_changes=None):
    """Conjoin selected families; a failed part never falls through to an easy one."""
    scope = evidence_requirements(issue, output_dir, words_for)
    result = {**scope, 'status': 'incomplete', 'checks': {}, 'missing': []}
    if not scope['applicable']:return result
    root = output_dir.absolute()
    logs = [p for p in files if p.name == p.parent.name+'.log' and p.suffix == '.log']
    if len(logs) != 1 or not re.fullmatch(r'R[1-9]\d*', logs[0].parent.name):
        result['missing'].append('One current native run is required');return result
    rid = logs[0].parent.name
    found = issue.get('found', {});old = str(found.get('run_ref', ''))
    if (not re.fullmatch(r'R[1-9]\d*', old) or int(old[1:]) >= int(rid[1:]) or
            not found.get('verified') or not _reference_bound(found,
                [root/str(found.get('source', ''))], root, old)):
        result['missing'].append('Real source-bound discovery from a prior run required');return result
    # A typed declaration can still name the pre-correction object. Let the
    # existing command-bound proof decide whether a real correction occurred.
    if scope['families'] == ['signal'] and file_changes is not None:
        correction = _signal_port_correction(issue, files, root, dofile, words_for, file_changes)
        if correction['status'] == 'pass':
            result.update(status='pass', checks={'signal': correction}, missing=[], evidence=correction['evidence'],
                          signal_targets=[correction['new_port']], unbound_signal_operations=[])
            return result
        if scope['unbound_signal_operations']:
            result['port_correction_check'] = correction
    association = (_clock_association_check(issue, files, root, dofile, words_for, file_changes=file_changes)
                   if 'clock_association' in scope['families'] else None)
    same_association = bool(association and association.get('status') == 'pass' and
        association.get('action_subject_binding') and _association_only_mentions(issue) and
        scope['unbound_signal_operations'] == [{'type':'clock'}] and not scope['signal_targets'])
    if same_association:
        result['unbound_signal_operations'] = []
        result['signal_targets'] = [association['evidence']['clock_port']]
    for family in scope['families']:
        if family == 'configuration':
            check = (configuration_check(issue, files, root, dofile, task_spec, words_for, allow_single=True)
                     if scope['configuration_parameters'] else
                     {'status': 'incomplete', 'missing': ['Native configuration discovery needs an explicit defect/repair parameter scope']})
        elif family == 'coverage':
            check = compound_check(issue, files, root, dofile, task_spec, words_for)
        elif family == 'signal' and same_association:
            check = {'status':'pass', 'evidence':association['evidence'],
                     'kind':'typed clock and related pins from the same cited executed association',
                     'action_subject_binding':association['action_subject_binding']}
        elif family == 'signal':
            check = (_signal_check(issue, files, root, dofile, words_for, scope['signal_targets'])
                     if not scope['unbound_signal_operations'] else
                     {'status': 'incomplete', 'missing': ['Literal signal type/object binding is incomplete']})
        elif family == 'mode':
            check = (_signal_check(issue, files, root, dofile, words_for, scope['mode_targets'], constant=True)
                     if not scope['unbound_signal_operations'] else
                     {'status': 'incomplete', 'missing': ['Literal constant type/object binding is incomplete']})
        elif family == 'outputs':
            check = output_operation_check(issue, files, root, dofile, words_for, scope['output_commands'])
        elif family == 'clock_association':
            check = association
        else:
            function = {'mapping': mapping_command_evidence, 'netlist_export': netlist_export_evidence,
                        'load': load_input_evidence}[family]
            proof = function(issue, files, root, dofile, words_for)
            check = {'status': 'pass' if proof else 'incomplete', 'evidence': proof}
        described = [o for o in signal_operations(issue)
                     if o.get('subject_source') == 'explicit_declaration_description' and
                     ((family == 'mode' and o.get('type') == 'constant') or
                      (family == 'signal' and o.get('type') != 'constant'))]
        if described and check.get('status') != 'pass':
            # Parsing an explicit subject is not proof of its actual role or
            # scope. Preserve the existing strict completion boundary until
            # ALL described objects have same-state native evidence.
            result['unbound_signal_operations'] = (result['unbound_signal_operations'] or described)
        if family == 'clock_association' and check.get('status') == 'pass':
            # Discharge only the deferred association mention. Other explicit
            # or incomplete signal operations retain their original obligation.
            if scope['unbound_signal_operations'] and all(not o for o in scope['unbound_signal_operations']) and 'signal' not in scope['families']:
                result['unbound_signal_operations'] = []
                result['signal_targets'] = [check['evidence']['clock_port']]
        elif family == 'clock_association':
            # A literal primary port does not bind its associated endpoints.
            # Propagate the unresolved relation to the existing strict scope
            # boundary instead of classifying it as mere missing audit prose.
            result['unbound_signal_operations'] = (result['unbound_signal_operations'] or
                [{'type': 'clock', 'associated_internal_clocks': None}])
        result['checks'][family] = check
        if check.get('status') != 'pass' or not _reference_bound(check.get('evidence'), files, root, rid):
            result['missing'].append(family)
    if not result['missing'] and result['checks']:
        result.update(status='pass', evidence=next(iter(result['checks'].values()))['evidence'])
    return result


def _clock_discovery_relation(issue, root, trace, port, pins, words_for):
    """Bind native clock-fault sinks to the claimed physical output drivers.

    The existing hierarchy/Liberty readers supply direction and connectivity.
    This is a bounded object relation, not a proof of arbitrary diagnostic
    causality. Configuration-only discoveries use their native configuration
    proof and do not invent a DFF relationship.
    """
    import hashlib
    from eco_structure import read_design
    from partial_insertion_validation import _libraries
    from netlist_repair import RepairRejected
    found = issue.get('found', {})
    faults = re.findall(r"Clock input '([^']+)' of 'DFF' '([^']+)' is uncontrolled", str(found.get('excerpt', '')))
    if not faults:
        return {'status': 'not_applicable'}
    def stop(message):
        return {'status': 'incomplete', 'missing': message}
    try:
        old = str(found['run_ref']); rid = trace['run_ref']; top = trace['design']
        prior = _signal_command_trace(root, old, words_for)
        current = _signal_command_trace(root, rid, words_for)
        if not prior or not current or prior['design'] != top or current['design'] != top:
            return stop('Original and final clock relationship design is unbound')
        netlists = sorted((root/'runs'/old/'input/netlist').glob('*.v'))
        libraries = sorted((root/'runs'/old/'input/lib').glob('*.lib'))
        if not netlists or not libraries:
            return stop('Original clock relationship inputs/library are unavailable')
        materials = []
        for path in netlists + libraries:
            later = root/'runs'/rid/'input'/path.parent.name/path.name
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            if not later.is_file() or hashlib.sha256(later.read_bytes()).hexdigest() != digest:
                return stop('Clock relationship input version changed or is unknown')
            for run in (old, rid):
                log = (root/'runs'/run/(run+'.log')).read_text()
                pattern = (r"Read Verilog file '([^']+)' successfully" if path in netlists else
                           r"Liberty file '([^']+)' is read successfully")
                if str(path.resolve()) not in re.findall(pattern, log):
                    return stop('Clock relationship material has no bound native load')
            materials.append({'source': str(path.resolve()), 'sha256': digest})
        library, problems = _libraries(libraries)
        if problems:
            return stop('Clock relationship Liberty is ambiguous')
        original = read_design(netlists, library, top)
        cells = original['cells']; graph = original['graph']; related = []
        output_drivers = set()
        for pin in pins:
            instance, sep, leaf = pin.rpartition('/')
            if not sep or instance not in cells:
                return stop('Associated output full hierarchy is absent')
            cell = cells[instance]; shape = library[cell['type']]
            if shape['pins'].get(leaf, {}).get('direction') != 'output':
                return stop('Associated clock endpoint is not a proven output')
            driver = graph.resolve(cell['pins'].get(leaf))
            if driver is None:
                return stop('Associated clock output driver is ambiguous or undriven')
            output_drivers.add(driver)
        located = str(issue.get('diagnosis', {}).get('located_object', ''))
        def mentioned(name):
            return bool(re.search(r'(?<![\w$./\[\]])'+re.escape(name)+r'(?![\w$./\[\]])', located))
        fault_objects = {name for _, name in faults}
        if not all(mentioned(name) for name in fault_objects):
            return stop('Located primary object does not include the native clock-fault object')
        subjects = {name for name, cell in cells.items() if library[cell['type']]['ffs'] and mentioned(name)}
        if not fault_objects <= subjects:
            return stop('Native clock-fault primary object hierarchy is not resolved')
        for name in sorted(subjects):
            cell = cells[name]; shape = library[cell['type']]
            clocks = {f['properties'].get('clocked_on') for f in shape['ffs']}
            if len(clocks) != 1:
                return stop('Primary object clock role is ambiguous')
            clock = next(iter(clocks))
            if shape['pins'].get(clock, {}).get('direction') != 'input':
                return stop('Primary object clock is not a literal Liberty input')
            if any(pin != clock for pin, obj in faults if obj == name):
                return stop('Native fault pin does not match the Liberty clock role')
            driver = graph.resolve(cell['pins'].get(clock))
            if driver not in output_drivers:
                return stop('Associated output does not drive the located primary clock input')
            related.append({'object': name, 'pin': clock, 'driver': driver,
                            'source': cell['source'], 'line': cell['line']})
        return {'status': 'pass', 'design': top, 'primary_clock': port,
                'associated_outputs': pins, 'native_fault_sinks': related,
                'input_materials': materials, 'found_run': old, 'final_run': rid}
    except (OSError, ValueError, KeyError, TypeError, RepairRejected, CanonicalDeliveryError):
        return stop('Clock discovery relationship cannot be safely established')


def _association_action_subject(issue, changes, root, current, pins, words_for):
    """Derive an omitted primary subject only from the cited real native delta.

    No nearest-name or single-clock fallback. Both delta sides, native executed
    declarations, current state and physical discovery relation remain required.
    """
    from netlist_repair import RepairRejected
    try:
        refs = issue['attempts'][-1]['fix'].get('artifact_ref', [])
        selected = [c for ref in refs for c in changes or [] if c.get('change_id') == ref]
        found = issue['found']['run_ref']; matches = []
        if not refs or len(set(refs)) != len(refs) or len(selected) != len(refs):
            return None
        def opts(words):
            if (words[:1] != ['set_scan_signal'] or len(words) % 2 != 1 or
                    len(set(words[1::2])) != len(words[1::2])):
                return None
            return {k:v.strip('"{}') for k,v in zip(words[1::2], words[2::2])}
        for change in selected:
            if change.get('type') != 'dofile':
                continue
            path = root/str(change['path']); delta = root/str(change['diff_path'])
            _real_file(path, root); _real_file(delta, root)
            header = re.match(r'--- (R[1-9]\d*)\n\+\+\+ (R[1-9]\d*)\n', delta.read_text())
            if not header:
                return None
            old, new = header[1], header[2]
            if not int(found[1:]) <= int(old[1:]) < int(new[1:]) <= int(current[1:]):
                return None
            before = root/'runs'/old/'deliverables'/(old+'.dofile'); _real_file(before, root)
            if path != root/'runs'/new/'deliverables'/(new+'.dofile') or not delta.is_relative_to(root/'diffs'):
                return None
            if delta.read_text() != ''.join(difflib.unified_diff(before.read_text().splitlines(True),
                    path.read_text().splitlines(True), fromfile=old, tofile=new)):
                return None
            traces = [_signal_command_trace(root, rid, words_for) for rid in [old,new,current]]
            if (not all(traces) or len({t['design'] for t in traces}) != 1 or
                    not traces[0]['loaded_input_netlists'] or
                    not traces[0]['loaded_input_netlists'] == traces[1]['loaded_input_netlists'] == traces[2]['loaded_input_netlists']):
                return None
            for event in traces[1]['signals']:
                after = opts(event['words'])
                if (not after or after.get('-type') != 'clock' or
                        set(after.get('-associated_internal_clocks','').split()) != set(pins)):
                    continue
                port = after.get('-port'); prior = [e for e in traces[0]['signals'] if (opts(e['words']) or {}).get('-port') == port]
                final = [e for e in traces[2]['signals'] if (opts(e['words']) or {}).get('-port') == port]
                if len(prior) != 1 or len(final) != 1 or any(e['errors'] for e in [prior[0],event,final[0]]):
                    continue
                pre, post = opts(prior[0]['words']), opts(final[0]['words'])
                if (not pre or not post or pre.get('-type') != 'clock' or
                        set(pre.get('-associated_internal_clocks','').split()) == set(pins) or
                        post.get('-type') != 'clock' or set(post.get('-associated_internal_clocks','').split()) != set(pins) or
                        len({e['partition'] for e in [prior[0],event,final[0]]}) != 1):
                    continue
                matches.append({'port':port,'change_id':change['change_id'], 'diff_source':change['diff_path'],
                    'from_run':old,'to_run':new,'current_run':current,
                    'executed_declarations':[e for e in [prior[0],event,final[0]]]})
        return matches[0] if len(matches) == 1 else None
    except (OSError, ValueError, KeyError, TypeError, IndexError, CanonicalDeliveryError, RepairRejected):
        return None


def _clock_association_check(issue, files, root, dofile, words_for, *, file_changes=None):
    """Bind an asserted association operation, not just its eventual DRC effect.

    This bounded verifier handles one explicitly identified clock and a literal
    complete pin list. Ambiguous prose/dynamic scopes remain unverified; it does
    not invent paths or revise a diagnosis to match a different successful fix.
    """
    from eco_object_selection import is_context_query
    result = {'status': 'incomplete', 'missing': []}
    def stop(reason):
        result['missing'].append(reason)
        return result
    try:
        trace = operation_trace(files, root, dofile, words_for, allow_verbose=True)
        if not trace:
            return stop('A source-bound completed same-design operation is required')
        declarations = {}; design = ''; partition = 'Default_Partition'; offsets = {}; number = 1
        for chunk in tcl_chunks(dofile):
            text = chunk.strip().replace('\\\n', ' ')
            words = words_for(text) if text and not text.startswith('#') else []
            line = number; number += chunk.count('\n')
            if is_context_query(text):continue
            scoped = {'present_design', 'set_current_scan_partition', 'set_scan_signal'}
            if (text and not text.startswith('#') and
                    (words[:1] in [['source'], ['eval'], ['uplevel'], ['interp'], ['namespace']] or
                     (not words or words[0] not in scoped) and
                     re.search(r'\b(?:present_design|set_current_scan_partition|set_scan_signal)\b', text))):
                return stop('Dynamic clock/design/partition scope cannot be inferred')
            if not words:
                continue
            if words[0] == 'present_design':
                design = words[1]; partition = 'Default_Partition'
            elif words[0] == 'set_current_scan_partition':
                partition = words[1].strip('"{}')
            elif words[0] == 'set_scan_signal':
                if len(words) % 2 != 1 or len(set(words[1::2])) != len(words[1::2]):
                    return stop('Ambiguous signal declaration')
                options = {k: v.strip('"{}') for k, v in zip(words[1::2], words[2::2])}
                if options.get('-type') not in {'clock', 'wrapper_clock'}:
                    continue
                port = options.get('-port', '')
                if not re.fullmatch(r'[A-Za-z_]\w*', port) or port in declarations:
                    return stop('A unique literal clock-port declaration is required')
                declarations[port] = (options, design, partition)
                offsets[line] = words
        action = str(issue['attempts'][-1]['fix']['action'])
        named = set(re.findall(r'-port\s+([A-Za-z_]\w*)\b', action))
        if not named:
            # Bind the action's explicit subject, never pick the only clock
            # mentioned elsewhere in a diagnosis or the only native candidate.
            named = set(re.findall(r'(?:\bclock|时钟)\s+([A-Za-z_]\w*)\b', action, re.I))
            named.update(re.findall(r'(?<![\w$./])([A-Za-z_]\w*)\s*的\s*set_scan_signal\b', action))
        lists = re.findall(r'-associated_internal_clocks\s+(\{[^{}]+\}|"[^"\n]+"|[^\s;,。；，]+)', action)
        if len(lists) != 1:
            return stop('The claimed full clock-pin scope is ambiguous; do not infer paths from short instance names')
        expected = lists[0].strip('"{}').split()
        if not named and _association_only_mentions(issue):
            binding = _association_action_subject(issue, file_changes, root, trace['run_ref'], expected, words_for)
            if binding:
                named = {binding['port']}
                result['action_subject_binding'] = binding
        if len(named) != 1 or not named <= declarations.keys():
            return stop('One complete, unambiguous clock-port subject is required')
        port = next(iter(named)); options, design, partition = declarations[port]
        actual = options.get('-associated_internal_clocks', '').split()
        if not actual or len(set(actual)) != len(actual):
            return stop('The effective clock declaration does not retain the claimed associations')
        if (not expected or len(set(expected)) != len(expected) or
                any(not re.fullmatch(r'[A-Za-z_]\w*(?:\[\d+\])?(?:/[A-Za-z_]\w*(?:\[\d+\])?)*', pin)
                    for pin in expected) or set(actual) != set(expected) or design != trace['design']):
            return stop('The complete literal pin list/design differs from the claimed operation')
        relationship = _clock_discovery_relation(issue, root, trace, port, expected, words_for)
        if relationship['status'] not in {'pass', 'not_applicable'}:
            return stop(relationship['missing'])
        result['discovery_relationship'] = relationship
        log = root/'runs'/trace['run_ref']/(trace['run_ref']+'.log')
        executed = []
        for number, line in enumerate(log.read_text().splitlines(), 1):
            echo = re.search(r'CMD-0034\]\s+@(\d+):\s*(.*)', line)
            if echo and offsets.get(int(echo[1])) == words_for(echo[2]):
                command = offsets[int(echo[1])]
                if command[command.index('-port')+1].strip('"{}') == port:
                    executed.append(number)
        if len(executed) != 1 or executed[0] >= trace['operation']['replacement']['log_line']:
            return stop('The claimed declaration must execute once before the actual operation')
        writers = [w for w in trace['reports'] if w['kind'] == 'rpt_scan_signal']
        latest = max((w['log_line'] for w in writers), default=0)
        for path in files:
            bound = post_operation_report(path, 'rpt_scan_signal', trace, root) if path.suffix in {'.rpt', '.txt', '.report'} else None
            if not bound or bound['log_line'] != latest or bound['log_line'] <= executed[0]:
                continue
            rows = [r for r in report_rows(path, {'Port', 'SignalType', 'AssociatedInternal', 'OwnerPartition'}) if r['Port'] == port]
            if len(rows) != 1:
                continue
            row = rows[0]; owner = row['OwnerPartition']
            if (row['SignalType'].split('(')[0] != options['-type'] or
                    set(row['AssociatedInternal'].split()) != set(expected) or
                    owner != partition and not (partition == 'Default_Partition' and not owner)):
                continue
            lines = path.read_text().splitlines()
            result.update(status='pass', evidence={'source': path.relative_to(root).as_posix(),
                'locator': f"L{row['line']}", 'excerpt': lines[row['line']-1],
                'clock_port': port, 'associated_pins': expected, 'native_report_operation': bound})
            return result
        return stop('A post-operation same-design/scope native row must prove every associated pin')
    except (OSError, ValueError, KeyError, IndexError, TypeError, CanonicalDeliveryError):
        return stop('Clock association evidence cannot be safely bound')


def _settings(script, words_for, *, partial=False):
    from eco_object_selection import is_context_query
    values={};top='';partition='Default_Partition';inserted=False
    for chunk in tcl_chunks(script.replace('\\\n',' ')):
        text=chunk.strip()
        if not text or text.startswith('#'):continue
        w=words_for(text)
        if not w:return None
        if w[0]=='exit':break
        scoped={'present_design','set_current_scan_partition','set_scan_cfg','insert_dft_logic'}
        if w[0] not in scoped:
            if is_context_query(text):continue  # Exact native read, no settings hidden.
            if re.search(r'\b(?:present_design|set_current_scan_partition|set_scan_cfg|insert_dft_logic)\b',text):return None
            continue
        if ';' in text or inserted:return None
        if w[0]=='present_design':
            if top or len(w)!=2:return None
            top=w[1].strip('"{}');partition='Default_Partition'
        elif w[0]=='set_current_scan_partition':
            if len(w)!=2 or not re.fullmatch(r'[A-Za-z_]\w*',w[1].strip('"{}')):return None
            partition=w[1].strip('"{}')
        elif w[0]=='set_scan_cfg':
            if not top or len(w[1:])%2:return None
            for key,value in zip(w[1::2],w[2::2]):
                key=key.removeprefix('-');value=value.strip('"{}')
                if key not in PARAMETERS:continue
                if re.search(r'[$\[\]\\;\s]',value):return None
                values.setdefault(partition,{})[key]=value.lower() if value.lower() in {'true','false'} else value
        else:
            if partial:
                if w not in [['insert_dft_logic','-connect_icg_only'],['insert_dft_logic','-replace_only'],['insert_dft_logic','-replace_unscan']]:return None
                inserted=w==['insert_dft_logic','-replace_unscan']
            else:
                if w not in [['insert_dft_logic'],['insert_dft_logic','-verbose']]:return None
                inserted=True
    return (top,values) if top and inserted else None


def configuration_check(issue, files, output_dir, dofile, task_spec, words_for, *, allow_single=False):
    needed=claim_parameters(issue)
    result={'applicable':len(needed)>1 or allow_single and bool(needed),
            'status':'incomplete','parameters':sorted(needed),'missing':[]}
    if not result['applicable']:return result
    def stop(message):
        result['missing'].append(message);return result
    try:
        root=output_dir.absolute();found=issue.get('found',{});rid=found.get('run_ref','')
        old=root/str(found.get('source',''));_real_file(old,root)
        m=re.fullmatch(r'L(\d+)(?:-L(\d+))?',str(found.get('locator','')))
        if (not found.get('verified') or not re.fullmatch(r'R[1-9]\d*',rid) or not m or
                not old.is_relative_to(root/'runs'/rid)):return stop('source-bound discovery required')
        lines=old.read_text().splitlines();first,last=int(m[1]),int(m[2] or m[1])
        if not 1<=first<=last<=len(lines) or not found.get('excerpt') or found['excerpt'] not in '\n'.join(lines[first-1:last]):
            return stop('discovery locator/excerpt mismatch')
        discovered_rows=[row for row in report_rows(old,{'Chain','Length','Input','Output','Partition'})
            if first<=row['line']<=last and row['Length'].isdigit()]
        if not discovered_rows and not re.search(r'ScanConfigurationParameter|set_scan_cfg',found['excerpt']):
            return stop('discovery does not describe the claimed configuration')
        previous=root/'runs'/rid/'deliverables'/(rid+'.dofile');_real_file(previous,root)
        current=_settings(dofile,words_for);before=_settings(previous.read_text(),words_for)
        trace=operation_trace(files,root,dofile,words_for,allow_verbose=True)
        if not current or not before or not trace or current[0]!=before[0] or current[0]!=trace['design']:
            return stop('one executed same-design literal configuration scope required')
        if int(trace['run_ref'][1:])<=int(rid[1:]):return stop('later actual run required')
        diagnosis=issue.get('diagnosis',{});action=issue['attempts'][-1]['fix']['action']
        location=str(diagnosis.get('located_object',''))
        named_design=re.search(r'\bdesign\s+([A-Za-z_]\w*)',location,re.I)
        if named_design and named_design[1]!=current[0]:return stop('claimed design differs from actual design')
        named=re.search(r'\bpartition\s+([A-Za-z_]\w*)',location,re.I)
        if re.search(r'\bglobal\b|全局',location+' '+action,re.I):scopes={'Default_Partition'}
        elif named:scopes={named[1]}
        else:
            scopes={name for name,settings in current[1].items() if any(
                key in settings and settings[key]!=before[1].get(name,{}).get(key) for key in needed)}
        if not scopes or not scopes<=set(current[1]):return stop('claimed partition/object is absent or unchanged')
        explicit={key:value.strip('"{}.,;') for key,value in re.findall(
            r'-([a-z_]+)\s+(\{[^{}]+\}|"[^"\n]+"|[\w%]+)',action) if key in needed}
        formats=scan_formats(task_spec)
        if {'si_port_format','so_port_format'} & needed:
            if not formats:return stop('task-grounded port format pair required')
            explicit.update({k:v for k,v in zip(['si_port_format','so_port_format'],formats) if k in needed})
        # Bind every literal configuration/scope echo to the retained script.
        run=root/'runs'/trace['run_ref'];log=run/(trace['run_ref']+'.log');loglines=log.read_text().splitlines()
        scriptlines=dofile.splitlines();last_config=0
        for number,line in enumerate(loglines,1):
            echo=re.search(r'CMD-0034\]\s+@(\d+):\s*(.*)',line)
            if echo and words_for(echo[2])[:1] in [['set_scan_cfg'],['set_current_scan_partition']]:
                if not 1<=int(echo[1])<=len(scriptlines) or scriptlines[int(echo[1])-1].strip()!=echo[2].strip():
                    return stop('configuration command/executed script mismatch')
                last_config=number
        writers=[w for w in trace['reports'] if w['kind']=='rpt_scan_cfg' and w['design']==current[0]
            and w['log_line']>max(last_config,trace['operation']['replacement']['log_line'])]
        if not writers:return stop('post-configuration native report writer required')
        writer=max(writers,key=lambda w:w['log_line']);native=writer['path'];_real_file(native,root)
        candidates=[p for p in files if p.suffix=='.rpt' and (p==native or
            p.parent==run/'reports' and p.name==native.name and p.read_bytes()==native.read_bytes())]
        if len(candidates)!=1:return stop('ambiguous or missing same-operation configuration report')
        report=candidates[0];reportlines=report.read_text().splitlines();blocks={};partition=None;active=False
        for number,line in enumerate(reportlines,1):
            header=re.fullmatch(r'Scan partition:\s*(\S+)\s*',line)
            if header:
                partition=header[1]
                if partition in blocks:return stop('duplicate configuration partition')
                blocks[partition]={};active=False
            elif 'ScanConfigurationParameter' in line and 'Value' in line:active=True
            elif active and partition:
                pair=re.fullmatch(r'\s*([a-z_]+)\s+(\S+)\s*',line)
                if pair and pair[1] in PARAMETERS:
                    if pair[1] in blocks[partition]:return stop('duplicate parameter row')
                    blocks[partition][pair[1]]=(pair[2],number)
        proofs=[]
        for scope in sorted(scopes):
            for key in sorted(needed):
                setting=current[1].get(scope,{}).get(key);row=blocks.get(scope,{}).get(key)
                if setting is None or not row or row[0].lower()!=setting.lower() or key in explicit and setting!=explicit[key]:
                    result['missing'].append(scope+'.'+key);continue
                proofs.append({'parameter':key,'partition':scope,'value':row[0],
                    'source':report.relative_to(root).as_posix(),'locator':f'L{row[1]}','excerpt':reportlines[row[1]-1]})
        if result['missing']:return result
        # A chain count or port naming claim also requires the actual chain
        # result, not solely a configuration intent or a report success message.
        chainproof=[]
        if needed & {'chain_count','max_length','si_port_format','so_port_format'}:
            chainwriters=[w for w in trace['reports'] if w['kind']=='rpt_scan_chain' and
                w['design']==current[0] and w['log_line']>trace['operation']['replacement']['log_line']]
            if not chainwriters:return stop('post-operation complete chain report required')
            path=max(chainwriters,key=lambda w:w['log_line'])['path'];_real_file(path,root)
            rows=[row for row in report_rows(path,{'Chain','Length','Input','Output','ScanEnable','Clocks','Partition'})
                if re.fullmatch(r'I\s+\S+|\d+',row['Chain']) and row['Length'].isdigit()]
            if (not rows or re.findall(r'(?m)^\s*Design\s*:\s*(\S+)\s*$',path.read_text())!=[current[0]] or
                    chain_problems(rows,task_spec)):return stop('actual chain results do not meet task requirements')
            if len({(row['Chain'],row['Partition']) for row in rows})!=len(rows):return stop('duplicate chain objects')
            parts=partition_requirements(task_spec)
            for scope in scopes:
                selected=rows if scope=='Default_Partition' and parts else [x for x in rows if x['Partition']==scope]
                settings=current[1][scope]
                if not selected:return stop('no actual chains for claimed partition')
                if 'chain_count' in needed and (not settings['chain_count'].isdigit() or len(selected)!=int(settings['chain_count'])):
                    return stop('actual chain count differs from claimed configuration')
                for key,col in [('si_port_format','Input'),('so_port_format','Output')]:
                    if key in needed and (settings[key].count('%d')!=1 or any(not re.fullmatch(
                        re.escape(settings[key]).replace('%d',r'\d+'),row[col]) for row in selected)):
                        return stop('actual port objects differ from claimed format')
                if 'max_length' in needed and (not settings['max_length'].isdigit() or any(
                    int(x['Length'])>int(settings['max_length']) for x in selected)):return stop('actual chain exceeds claimed max_length')
            chainlines=path.read_text().splitlines();lo,hi=min(x['line'] for x in rows),max(x['line'] for x in rows)
            chainproof=[{'source':path.relative_to(root).as_posix(),'locator':f'L{lo}-L{hi}','excerpt':'\n'.join(chainlines[lo-1:hi])}]
        lo,hi=min(int(p['locator'][1:]) for p in proofs),max(int(p['locator'][1:]) for p in proofs)
        result.update(status='pass',evidence={'source':report.relative_to(root).as_posix(),
            'locator':f'L{lo}-L{hi}','excerpt':'\n'.join(reportlines[lo-1:hi]),
            'parameter_evidence':proofs,'chain_evidence':chainproof,
            'native_report_operation':{k:v for k,v in writer.items() if k!='path'}})
        # A chain deficit proves the observed deficit, not a missing GLOBAL
        # parameter as its cause. Per-partition task requirements do not invent
        # a mandatory global chain_count. Preserve the observed fix/results,
        # but leave this unsupported diagnosis unclosed rather than fabricate
        # causality from a newly added optional setting.
        global_diagnosis=bool(re.search(r'\bglobal\b|全局',
            str(diagnosis.get('root_cause',''))+' '+str(diagnosis.get('summary','')),re.I))
        if discovered_rows and partition_requirements(task_spec) and global_diagnosis:
            result['status']='incomplete'
            result['observed_configuration_and_chain_evidence']=result.pop('evidence')
            result['missing'].append('Chain deficit does not substantiate the claimed global parameter cause; task specifies per-partition configuration')
        return result
    except (OSError,ValueError,TypeError,KeyError,IndexError,CanonicalDeliveryError):
        return stop('unparseable or unbound configuration evidence')
