"""Bind a contradicted command-edit attribution separately from real delivery.

This does not repair a diagnosis, rewrite an attempt, execute Tcl or prove EQY.
It consumes the existing byte-checked delta, native execution and dedicated final
condition checks. Unknown objects/commands/rounds abstain rather than pass.
"""
import hashlib
import difflib
from pathlib import Path


def retained_command_condition(issue, conflicts, root, runs, trace, validation, words_for, *, changes=None):
    from canonical_delivery import _real_file
    from plan_provenance import _executed
    import eco_evidence
    try:
        rid = runs[-1]['run_id']; found = issue['found']['run_ref']
        if (len(conflicts) != 1 or conflicts[0].get('reason') != 'fix_action_reference_not_bound' or
                issue['attempts'][-1]['verify']['run_ref'] != rid or trace is None or
                not validation or validation.get('status') != 'pass'):
            return None
        eco_evidence.assert_trace(trace)
        design = trace.data['design']
        required = words_for(issue['diagnosis']['located_object'])
        if (not required or set(conflicts[0].get('missing_commands', [])) != {required[0]} or
                conflicts[0].get('missing_options') or conflicts[0].get('missing_literal_operations')):
            return None
        bindings = conflicts[0].get('referenced_changes', [])
        refs = issue['attempts'][-1]['fix']['artifact_ref']
        bound_ids = [b['change_id'] for b in bindings]
        if (not bindings or len(set(refs)) != len(refs) or
                bound_ids != [ref for ref in refs if ref in bound_ids] or
                any(b['from_run'] != found or b['to_run'] != rid for b in bindings)):
            return None  # Do not reassign an earlier/later edit to a wrong F reference.
        extra = [ref for ref in refs if ref not in bound_ids]
        extra_paths = []
        # An additional native ECO citation cannot prove command removal.
        # Keep the claim false, and validate that citation against this adopted
        # export/delta/proof instead of mistaking it for a missing artifact.
        for ref in extra:
            selected = [c for c in (changes or []) if c.get('change_id') == ref]
            if len(selected) != 1:
                return None
            c = selected[0]; fixed = Path(trace.data['fixed_export']['path'])
            if (c.get('type') != 'netlist' or c.get('origin') != 'native_in_memory_ECO' or
                    c.get('path') != fixed.relative_to(root).as_posix() or
                    c.get('lec_ref') != 'eco/' + rid + '/lec/eqy.log'):
                return None
            delta = root/c.get('diff_path', ''); _real_file(delta, root)
            _real_file(fixed, root)
            expected = ''.join(difflib.unified_diff(
                ''.join(p.read_text() for p in trace.context.originals).splitlines(True),
                fixed.read_text().splitlines(True), fromfile='actual-original-family',
                tofile=fixed.relative_to(root).as_posix()))
            if delta.read_text() != expected:
                return None
            extra_paths += [delta, fixed]
        commands = []; evidence = []; paths = []
        prior_trace = None
        for run_id in [found, rid]:
            run = root/'runs'/run_id; source = run/'deliverables'/(run_id+'.dofile')
            _real_file(source,root)
            script = source.read_text()
            matching = [(number,line) for number,line in enumerate(script.splitlines(),1)
                        if words_for(line.strip()) == required]
            if len(matching) != 1:
                return None
            number,line = matching[0]
            if required[0] == 'set_scan_drc_rule_handling':
                from configuration_evidence import _signal_command_trace
                history = _signal_command_trace(root, run_id, words_for, include_rule_commands=True)
                if (not history or history['design'] != design or
                        history['loaded_netlists'] != list(map(str, trace.context.originals)) or
                        prior_trace is not None and history['loaded_netlists'] != prior_trace['loaded_netlists']):
                    return None
                prior_trace = history
                observed = [e for e in history['rule_commands'] if e['words'] == required]
                if len(observed) != 1 or observed[0]['errors']:
                    return None
                event = observed[0]
                native = [{'line': int(event['locator'][1:]), 'design': event['design']}]
                if commands and event['partition'] != commands[0]['partition']:
                    return None
                partition = event['partition']
            else:
                echoes,_ = _executed(run,script,words_for)
                native = echoes.get(number,[]); partition = None
            if len(native) != 1 or native[0]['design'] != design:
                return None
            commands.append({'run_ref':run_id,'script_line':number,'command':line.strip(),
                             'log_line':native[0]['line'],'design':design,'partition':partition})
            for path,n in [(source,number),(run/(run_id+'.log'),native[0]['line'])]:
                lines=path.read_text().splitlines()
                evidence.append({'run_ref':run_id,'source':path.relative_to(root).as_posix(),
                    'locator':f'L{n}','excerpt':lines[n-1]})
                paths.append(path)
        head = required[0]
        if head == 'set_scan_drc_rule_handling':
            # Reuse the native configured-policy proof already produced by the
            # task/ECO validator. The model cannot introduce a policy obligation.
            if len(required) != 3:
                return None
            codes = eco_evidence.rule_codes(required[1].strip('{}'))
            handling = validation.get('tie_handling',{})
            policies = {p['code']:p for p in handling.get('policies',[])}
            if (not codes or not set(codes) <= set(policies) or
                    any(policies[c]['scope'] != 'all' or policies[c]['level'] != required[2] for c in codes)):
                return None
            final = handling['report']; condition = {'kind':'native_configured_policy',
                'policies':[policies[c] for c in sorted(codes)],'report':final,
                'authority':validation['tie_authority']}
            native = trace.data['reports']['rpt_scan_drc_rule_handling']
        elif head.startswith('rpt_') and head in trace.data['reports']:
            native = trace.data['reports'][head]
            if words_for(native['command']) != required:
                return None
            condition = {'kind':'native_report_generation','writer':head,
                'path':Path(native['path']).relative_to(root).as_posix(),
                'sha256':hashlib.sha256(Path(native['path']).read_bytes()).hexdigest()}
        else:
            return None
        path = Path(native['path']); _real_file(path,root)
        if (native['evidence']['run_ref'] != rid or native['design'] != design or
                native['log_line'] <= trace.data['last_mutation_line'] or not path.stat().st_size):
            return None
        if head == 'set_scan_drc_rule_handling':
            final = condition['report']
            if (final['run_ref'] != rid or final['design'] != design or
                    final['source'] != path.relative_to(root).as_posix() or
                    final['sha256'] != hashlib.sha256(path.read_bytes()).hexdigest() or
                    final['writer_log_line'] != native['log_line'] or not final['complete_unfiltered_table']):
                return None
        condition['writer_log_line'] = native['log_line']
        paths.append(path)
        paths += extra_paths
        for b in bindings:
            paths += [root/b['path'],root/b['diff_path']]
        return {'kind':'native_command_delivery_condition','design':design,'run_ref':rid,
            'located_object':issue['diagnosis']['located_object'],
            'action_assessment':{'status':'contradicted_by_retained_native_operation',
                'scope':'The named edit attribution is contradicted; whole diagnostic causality remains unproved.',
                'commands':commands,'references':bindings,'evidence':evidence},
            'actual_condition':condition},paths
    except (OSError,ValueError,TypeError,KeyError,IndexError,eco_evidence.RepairRejected):
        return None
