"""Separate honest audit incompleteness from native/task/process failure.

Guide sections 5.4, 5.5 and 8.1 permit failed-attempt records and score audit
coverage separately. Exit 0 below means a conforming artifact delivery, never a
claim of full audit closure or contest score. All existing task checks remain.
"""
from pathlib import Path
from dataclasses import dataclass
import hashlib
import json
import re


_DELIVERY_ISSUER = object()


def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False,
                                    separators=(',', ':')).encode()).hexdigest()


def _delivery_materials(root, rid):
    paths = []
    for folder in [root/'runs'/rid, root/'final_results']:
        for p in folder.rglob('*'):
            rel = p.relative_to(folder)
            if rel.parts[0] == 'input' or p.name.startswith('llm_'):
                continue
            if p.is_file():
                _file(root, p.relative_to(root).as_posix())
                paths.append(p)
    return tuple(sorted(str(p) for p in paths))


@dataclass(frozen=True)
class _DeliveryProof:
    """In-process result of runtime validation, never accepted from model JSON.

    Metadata binds a finished validation to this case/root/input/final state.
    The original diagnostic verdict remains an independent input.
    """
    issuer: object
    root: str
    input_root: str
    task: str
    runs: str
    changes: str
    canonical: str
    issues: str
    materials: tuple
    fingerprints: tuple
    mounts: tuple
    conditions: tuple


def _capture_delivery_proof(root, input_root, task, runs, changes, canonical, issues,
                            paths, conditions):
    """Internal runtime-only sink AFTER existing native/hard validation.

    No public success flag or serializable proof blob can enable this route.
    Do not call this instead of the runtime's prepare_scope_delivery_proof.
    """
    from netlist_repair import fingerprint_paths
    root, input_root = root.resolve(strict=True), input_root.resolve(strict=True)
    mount_root = root/'runs'/runs[-1]['run_id']/'input'
    if task == 'task1' and not mount_root.exists():mount_root = input_root
    required = list(_delivery_materials(root, runs[-1]['run_id']))
    bound = fingerprint_paths([Path(p) for p in set(required + [str(p) for p in paths])])
    return _DeliveryProof(_DELIVERY_ISSUER, str(root), str(input_root), task,
        _digest(runs), _digest(changes), _digest(canonical), _digest(issues), tuple(required),
        tuple((name, v['resolved'], v['sha256']) for name, v in sorted(bound.items())),
        tuple((str(mount_root/name), str((mount_root/name).resolve(strict=True)))
              for name in ['lib', 'netlist']),
        tuple(json.dumps(c, ensure_ascii=False, sort_keys=True) for c in conditions))


def _delivery_proof_bound(proof, root, task, runs, changes, canonical, issues):
    from netlist_repair import fingerprint_paths
    def decline(reason):
        from runtime_events import atomic
        try:
            (root/'delivery_verification').mkdir(parents=True,exist_ok=True)
            atomic(root/'delivery_verification'/'binding.json',{
                'status':'not_bound','reason':reason,'case_output':str(root),'task':task,
                'run_ref':list(runs)[-1] if runs else None,'proof_supplied':proof is not None,
                'proof_runtime_type':type(proof).__name__,'formal_evidence':False})
        except OSError:
            pass  # A diagnostic cannot issue, replace or waive a proof.
        return False
    if (not isinstance(proof, _DeliveryProof) or proof.issuer is not _DELIVERY_ISSUER or
            proof.root != str(root.resolve()) or proof.task != task or
            proof.runs != _digest(list(runs.values())) or proof.changes != _digest(list(changes.values())) or
            proof.canonical != _digest(canonical) or proof.issues != _digest(issues) or not proof.conditions):
        return decline('scope_identity_or_digest')
    try:
        if any(str(Path(name).resolve(strict=True)) != resolved for name, resolved in proof.mounts):
            return decline('mount_changed')
        if _delivery_materials(root.resolve(), list(runs)[-1]) != proof.materials:
            return decline('material_set_changed')
        actual = fingerprint_paths([Path(x[0]) for x in proof.fingerprints])
        bound = all(actual[name] == {'resolved': resolved, 'sha256': digest}
                   for name, resolved, digest in proof.fingerprints)
        return True if bound else decline('material_content_changed')
    except (OSError, ValueError, KeyError):
        return decline('binding_evidence_unreadable')


def _file(root,source):
    p=Path(str(source))
    if (not source or p.is_absolute() or '..' in p.parts or
            any(x in {'.env','golden.dofile','preset_issues.json'} or x.startswith('.env.') for x in p.parts)):
        raise ValueError('Unsafe or absent record source')
    actual=root/p
    if (not actual.is_file() or not actual.stat().st_size or not actual.resolve().is_relative_to(root.resolve()) or
            any(x.is_symlink() for x in [actual,*actual.parents] if x.is_relative_to(root))):
        raise ValueError('Missing or unbound record source')
    return actual


def _reference(root,ref,runs,*,unresolved=False):
    rid=ref.get('run_ref')
    source=Path(str(ref.get('source','')))
    structural=(not unresolved and source.parts==('structural_checks',str(rid)+'.json') and
                ref.get('structural_check_ref')==source.as_posix())
    if rid not in runs or not structural and source.parts[:2]!=('runs',rid):
        raise ValueError('Reference belongs to an unknown or different run')
    path=_file(root,ref.get('source'))
    if structural and json.loads(path.read_text()).get('status')!='pass':
        raise ValueError('Structural verification source is not a passing saved proof')
    if unresolved:
        if ref.get('resolved') is not False or ref.get('locator')!='' or ref.get('excerpt')!='':
            raise ValueError('Unresolved reference must preserve official empty evidence fields')
        return
    m=re.fullmatch(r'L([1-9]\d*)(?:-L([1-9]\d*))?',str(ref.get('locator','')))
    if not m or not ref.get('excerpt'):raise ValueError('Positive reference lacks real locator/excerpt')
    lo,hi=int(m[1]),int(m[2] or m[1]);lines=[];count=0
    with path.open(errors='replace') as f:
        for count,line in enumerate(f,1):
            if count>hi:break
            if count>=lo:lines.append(line)
    if hi<lo or count<hi or ref['excerpt'] not in ''.join(lines):raise ValueError('Reference text/locator mismatch')


def _pending_disposition(root, issue, runs, changes, *, delivery_bound=False, delivery_condition=None):
    """Classify trusted runtime checks; never repair/withdraw a model claim.

    Guide 5.5.2 scores wrong diagnoses/closure separately, and 8.1 permits
    honest false attempts. Unknown reasons and ambiguous delivery object scope
    remain blocking. This does not replace the caller's task/EQY/integrity gates.
    """
    verify = issue['attempts'][-1]['verify']
    conflicts = verify.get('diagnosis_check', {}).get('problems', [])
    closure = verify.get('closure_check', {})
    checks = closure.get('checks', {})
    selection = verify.get('evidence_selection', {})
    row = {'issue_id': issue['issue_id'], 'categories': [], 'blocking': False,
           'reason_codes': [p.get('reason') for p in conflicts],
           'resolved': False, 'basis': 'Guide 5.5.2 / 8.1; existing delivery policy'}

    def block(category, detail):
        row['categories'].append(category)
        row.update(blocking=True, detail=detail)
        return row

    # A native whole-task proof can separate unresolved historical scope from
    # final roles. It is issued by the normal runtime, never model JSON.
    if delivery_bound and delivery_condition and delivery_condition.get('kind') == 'independent_native_task_delivery':
        condition=delivery_condition;basis=condition.get('diagnostic_basis',{});actual=condition.get('actual_task',{})
        if (condition.get('diagnostic_check_sha256') != _digest(conflicts) or
                basis.get('conflicts') != conflicts or condition.get('run_ref') != verify['run_ref'] or
                condition.get('located_object') != issue['diagnosis']['located_object'] or
                basis.get('prior_run') != issue['found']['run_ref'] or
                actual.get('kind') != 'complete_native_task_scope' or not actual.get('roles') or
                actual.get('run_ref') != verify['run_ref'] or not actual.get('input_fingerprints') or
                not actual.get('final_export_sha256') or
                actual.get('chain_counted_members') != actual.get('kept_count') or
                not actual.get('original_FF_sha256') or not actual.get('kept_sha256') or
                basis.get('status') not in {'diagnostic_incomplete','contradicted_action'} or
                not closure or closure.get('status') not in {'incomplete','fail'} or
                checks.get('diagnosis_and_action',{}).get('problems') != conflicts or
                checks.get('operation_binding',{}).get('status') != 'pass'):
            return block('delivery_proof_insufficient','Independent native task scope or prior binding is incomplete')
        for ref in basis.get('native_evidence',[]):_reference(root,ref,runs)
        if not basis.get('native_evidence'):return block('delivery_proof_insufficient','No original native reference')
        row['categories'].append('action_description_contradicted' if basis['status']=='contradicted_action' else 'diagnostic_scope_unproven')
        row['meaning']='Current task roles, full kept/excluded object sets and chain membership independently verified; historical diagnosis/action remains false.'
        return row

    if delivery_bound and delivery_condition and delivery_condition.get('kind')=='independent_partial_task_delivery':
        c=delivery_condition;b=c.get('diagnostic_basis',{});a=c.get('actual_task',{})
        if (c.get('diagnostic_check_sha256')!=_digest(conflicts) or b.get('conflicts')!=conflicts or
                c.get('run_ref')!=verify['run_ref'] or c.get('located_object')!=issue['diagnosis']['located_object'] or
                b.get('prior_run')!=issue['found']['run_ref'] or
                a.get('status')!='pass' or a.get('problems') or a.get('unknown') or
                a.get('requirements',{}).get('applicable') is not True or
                not a.get('counts') or not b.get('structural_evidence') or
                checks.get('diagnosis_and_action',{}).get('problems')!=conflicts or
                checks.get('operation_binding',{}).get('status')!='pass'):
            return block('delivery_proof_insufficient','Partial task proof or diagnostic binding incomplete')
        for ref in b.get('native_evidence',[]):_reference(root,ref,runs)
        if not b.get('native_evidence'):return block('delivery_proof_insufficient','No prior native reference')
        row['categories'].append('diagnostic_scope_unproven')
        row['meaning']='Partial task structure independently rechecked; prior gating/cause remains unresolved.'
        return row

    if selection.get('unbound_signal_operations'):
        return block('delivery_proof_insufficient', 'Final signal type/object scope is not bound')
    if closure:
        if (closure.get('status') not in {'fail', 'incomplete'} or
                set(checks) != {'diagnosis_and_action', 'operation_binding',
                                'selected_families', 'positive_evidence'} or
                any(c.get('status') not in {'pass', 'fail', 'incomplete', 'not_applicable'}
                    for c in checks.values())):
            return block('unclassified_audit_failure', 'Unknown or inconsistent closure result')
        if (checks['operation_binding']['status'] != 'pass' or
                checks['selected_families']['status'] == 'fail'):
            return block('delivery_proof_insufficient', 'Operation/final-condition proof is not established')
    if not conflicts:
        if closure and checks['diagnosis_and_action']['status'] != 'pass':
            return block('unclassified_audit_failure', 'Missing explanation for diagnosis verdict')
        row['categories'].append('audit_evidence_incomplete')
        return row  # Existing honest-pending path, subject to all delivery gates.

    # A real reference can be authentic yet fail to prove the described edit.
    # Keep that audit failure false. It is not evidence that the delivered ECO
    # is bad, nor can this reason code alone establish that delivery is good.
    if all(p.get('reason') == 'fix_action_reference_not_bound' for p in conflicts):
        if (not delivery_bound or not delivery_condition or
                delivery_condition.get('kind') not in {'native_ECO_delivery_object','native_command_delivery_condition'} or
                delivery_condition.get('diagnostic_check_sha256') != _digest(conflicts) or
                delivery_condition.get('located_object') != issue['diagnosis']['located_object'] or
                delivery_condition.get('run_ref') != verify['run_ref'] or not closure or
                closure['status'] != 'incomplete' or
                checks['diagnosis_and_action'] != {'status': 'incomplete', 'problems': conflicts}):
            return block('delivery_proof_insufficient', 'Current delivery/object and rejected action attribution are not independently bound')
        if delivery_condition['kind'] == 'native_command_delivery_condition':
            assessment = delivery_condition.get('action_assessment', {})
            if (assessment.get('status') != 'contradicted_by_retained_native_operation' or
                    not assessment.get('evidence') or not delivery_condition.get('actual_condition')):
                return block('delivery_proof_insufficient', 'Command attribution/final condition is not independently bound')
            for evidence in assessment['evidence']:
                _reference(root, evidence, runs)
            row['categories'].append('action_description_contradicted')
            row['meaning'] = 'Actual delivery independently verified; the described edit did not occur as claimed and remains unresolved.'
        else:
            row['categories'].append('repair_action_evidence_incomplete')
        return row

    # This diagnosis scope remains unproved. Only a separately validated,
    # same-state delivery result can distinguish it from unknown task scope.
    if (len(conflicts) == 1 and conflicts[0].get('reason') == 'correction_original_scope_unproven' and
            conflicts[0].get('status') == 'incomplete'):
        if (not closure or closure.get('status') != 'incomplete' or
                checks['diagnosis_and_action'] != {'status': 'incomplete', 'problems': conflicts} or
                conflicts[0].get('original_clause') != issue['phenomenon'] or not delivery_bound):
            return block('delivery_proof_insufficient', 'Separate current-case delivery proof is absent, stale or incomplete')
        row['categories'].append('diagnostic_scope_unproven')
        return row  # Does not alter false or claim the original cause is true.

    from configuration_evidence import prior_configuration_scope
    if prior_configuration_scope(conflicts):
        # A producer-owned historical configuration gap cannot be proved by
        # the successful repair. Require a separately sealed, current task
        # condition and all the original strict delivery checks instead.
        expected = 'fail' if any(p.get('status') == 'fail' for p in conflicts) else 'incomplete'
        if (not delivery_bound or not delivery_condition or not closure or
                closure.get('status') != expected or
                checks['diagnosis_and_action'] != {'status': expected, 'problems': conflicts} or
                any(checks[k]['status'] not in {'pass', 'not_applicable'} for k in
                    ['operation_binding', 'selected_families', 'positive_evidence']) or
                delivery_condition.get('kind') != 'native_task_configuration_parameter' or
                delivery_condition.get('diagnostic_check_sha256') != _digest(conflicts) or
                delivery_condition.get('prior_checks') != conflicts or
                delivery_condition.get('run_ref') != verify['run_ref'] or
                delivery_condition.get('original_run_ref') != issue['found']['run_ref'] or
                delivery_condition.get('located_object') != issue['diagnosis']['located_object'] or
                not delivery_condition.get('final_parameter_evidence') or
                not delivery_condition.get('task_requirement')):
            return block('delivery_proof_insufficient', 'Prior configuration premise and independent final task condition are not bound')
        for ref in [delivery_condition['final_condition'], delivery_condition['native_command']]:
            _reference(root, ref, runs)
        row['categories'].append('diagnosis_contradicted' if expected == 'fail' else 'diagnostic_scope_unproven')
        row['meaning'] = 'Historical effective configuration/cause remains unresolved; final task parameter and complete delivery independently verified. Audit remains false.'
        return row

    from drc_validation import aggregate_drc_scope
    if aggregate_drc_scope(conflicts):
        # The producer owns the historical scope verdict. This branch only
        # separates it from a fresh, object-bound current task delivery proof.
        expected = 'fail' if any(p.get('status') == 'fail' for p in conflicts) else 'incomplete'
        independent_native_scope = bool(delivery_condition and
            delivery_condition.get('condition_scope') == 'complete_task_native_role_and_object_set' and
            all(p['assessment_scope'].get('universal_claims') for p in conflicts))
        required_positive = ['operation_binding'] if independent_native_scope else ['operation_binding', 'selected_families', 'positive_evidence']
        if (not delivery_bound or not delivery_condition or not closure or
                closure.get('status') != expected or
                checks['diagnosis_and_action'] != {'status': expected, 'problems': conflicts} or
                any(checks[k]['status'] not in {'pass', 'not_applicable'} for k in required_positive) or
                delivery_condition.get('kind') != 'native_task_drc_scope' or
                delivery_condition.get('run_ref') != verify['run_ref'] or
                delivery_condition.get('original_run_ref') != issue['found']['run_ref'] or
                delivery_condition.get('located_object') != issue['diagnosis']['located_object'] or
                delivery_condition.get('diagnostic_check_sha256') != _digest(conflicts) or
                delivery_condition.get('prior_checks') != conflicts or
                not delivery_condition.get('object_binding') or
                not delivery_condition.get('final_export_sha256')):
            return block('delivery_proof_insufficient', 'Aggregate diagnostic scope and actual current task/object scope are not independently bound')
        for ref in [delivery_condition['final_condition'], delivery_condition['native_command']]:
            _reference(root, ref, runs)
        row['categories'].append('diagnosis_contradicted' if expected == 'fail' else 'diagnostic_scope_unproven')
        row['meaning'] = 'Original aggregate claim remains unresolved; actual final task, object scope and all delivery conditions are independently verified.'
        return row

    from command_error_evidence import command_parameter_scope
    if command_parameter_scope(conflicts):
        # The runtime issuer reruns the producing validator and all delivery
        # gates. An arbitrary reason string or model-supplied pass cannot issue
        # this opaque same-case/current-state proof.
        if (not delivery_bound or not delivery_condition or not closure or
                closure['status'] != 'fail' or
                checks['diagnosis_and_action'] != {'status': 'fail', 'problems': conflicts} or
                any(checks[k]['status'] not in {'pass', 'not_applicable'} for k in
                    ['operation_binding', 'selected_families', 'positive_evidence']) or
                delivery_condition.get('kind') != 'native_task_command_parameter' or
                delivery_condition.get('run_ref') != verify['run_ref'] or
                delivery_condition.get('located_object') != issue['diagnosis']['located_object'] or
                delivery_condition.get('diagnostic_check_sha256') != _digest(conflicts) or
                delivery_condition.get('prior_checks') != conflicts):
            return block('delivery_proof_insufficient', 'Prior parameter premise and actual final task condition are not independently bound')
        _reference(root, delivery_condition['final_condition'], runs)
        for p in conflicts:
            for ref in p['native_evidence']:
                _reference(root, ref, runs)
        row['categories'].append('diagnosis_contradicted')
        if any(p['status'] == 'incomplete' for p in conflicts):
            row['categories'].append('diagnostic_scope_unproven')
            row['meaning'] = 'A parameter-order representation is refuted; another representation of the same bound native property retains an unparsed diagnostic predicate. Actual task policy and delivery are independently verified; neither representation is promoted to resolved.'
        else:
            row['meaning'] = 'Parameter-legality premise is contradicted; actual task policy and complete delivery are independently verified. Diagnosis remains false.'
        return row

    from drc_validation import prior_signal_scope, library_relation_scope
    if prior_signal_scope(conflicts):
        # The producing verifier scopes this to a prior premise. A runtime-
        # issued proof must independently recheck actual final task role and
        # every other delivery condition; the reason string does not grant it.
        if (not delivery_bound or not delivery_condition or not closure or
                closure.get('status') != 'incomplete' or
                checks['diagnosis_and_action'] != {'status':'incomplete','problems':conflicts} or
                delivery_condition.get('kind') != 'native_task_signal_role' or
                delivery_condition.get('diagnostic_check_sha256') != _digest(conflicts) or
                delivery_condition.get('located_object') != issue['diagnosis']['located_object'] or
                delivery_condition.get('run_ref') != verify['run_ref'] or
                delivery_condition.get('prior_diagnostic_scopes') != [p['assessment_scope'] for p in conflicts]):
            return block('delivery_proof_insufficient', 'Prior diagnostic scope and current native task role are not separately bound')
        for evidence in [delivery_condition['signal_condition'], delivery_condition['native_command']]:
            _reference(root, evidence, runs)
        contradicted = all(p['assessment_scope'].get('assessment_status') == 'contradicted' for p in conflicts)
        row['categories'].append('diagnosis_contradicted' if contradicted else 'diagnostic_scope_unproven')
        row['meaning'] = ('Prior role declaration is contradicted; final task role and complete delivery independently verified.'
                          if contradicted else 'Prior role premise remains false/unproved; final task role and complete delivery independently verified.')
        return row

    from drc_validation import prior_exclusion_scope
    if prior_exclusion_scope(conflicts):
        expected='fail' if any(p.get('status')=='fail' for p in conflicts) else 'incomplete'
        if (not delivery_bound or not delivery_condition or not closure or
                closure.get('status')!=expected or checks['diagnosis_and_action']!={'status':expected,'problems':conflicts} or
                any(checks[k]['status'] not in {'pass','not_applicable'} for k in ['operation_binding','selected_families','positive_evidence']) or
                delivery_condition.get('kind')!='native_task_exclusion_condition' or
                delivery_condition.get('diagnostic_check_sha256')!=_digest(conflicts) or
                delivery_condition.get('prior_checks')!=conflicts or
                delivery_condition.get('located_object')!=issue['diagnosis']['located_object'] or
                delivery_condition.get('run_ref')!=verify['run_ref'] or not delivery_condition.get('object_binding')):
            return block('delivery_proof_insufficient','Prior exclusion premise and current task exclusion are not separately bound')
        for ref in [delivery_condition['final_condition'],delivery_condition['native_command']]:_reference(root,ref,runs)
        row['categories'].append('diagnosis_contradicted' if expected=='fail' else 'diagnostic_scope_unproven')
        row['meaning']='Real final task exclusion independently proved; historical antecedent/cause is not established by its later success. Diagnosis remains false.'
        return row

    from drc_validation import eco_gate_diagnostic_scope
    if eco_gate_diagnostic_scope(conflicts) and delivery_condition and delivery_condition.get('kind')=='native_ECO_library_diagnostic':
        expected='fail' if any(p.get('status')=='fail' for p in conflicts) else 'incomplete'
        if (not delivery_bound or not closure or closure.get('status')!=expected or
                checks['diagnosis_and_action']!={'status':expected,'problems':conflicts} or
                delivery_condition.get('diagnostic_check_sha256')!=_digest(conflicts) or
                delivery_condition.get('prior_checks')!=conflicts or
                delivery_condition.get('original_run_ref')!=issue['found']['run_ref'] or
                delivery_condition.get('run_ref')!=verify['run_ref'] or
                delivery_condition.get('located_object')!=issue['diagnosis']['located_object'] or
                not delivery_condition.get('object_binding',{}).get('final_FF_mapping') or
                not delivery_condition.get('object_binding',{}).get('final_task_routes') or
                not delivery_condition.get('final_export_sha256')):
            return block('delivery_proof_insufficient','Original gate diagnostic and current ECO delivery binding are incomplete')
        row['categories'].append('diagnosis_contradicted' if expected=='fail' else 'diagnostic_scope_unproven')
        row['meaning']='Original gate diagnosis/action remain unresolved; current object coverage, functional proof and task delivery are independently bound.'
        return row

    from drc_validation import library_relation_scope
    if library_relation_scope(conflicts):
        expected = 'fail' if any(p.get('status') == 'fail' for p in conflicts) else 'incomplete'
        if (not delivery_bound or not delivery_condition or not closure or
                closure.get('status') != expected or
                checks['diagnosis_and_action'] != {'status':expected,'problems':conflicts} or
                any(checks[k]['status'] not in {'pass','not_applicable'} for k in
                    ['operation_binding','selected_families','positive_evidence']) or
                delivery_condition.get('kind') != 'native_library_premise_and_delivery' or
                delivery_condition.get('diagnostic_check_sha256') != _digest(conflicts) or
                delivery_condition.get('prior_checks') != conflicts or
                delivery_condition.get('located_object') != issue['diagnosis']['located_object'] or
                delivery_condition.get('run_ref') != verify['run_ref'] or
                delivery_condition.get('original_run_ref') != issue['found']['run_ref'] or
                not delivery_condition.get('object_binding') or
                not delivery_condition.get('final_export_sha256')):
            return block('delivery_proof_insufficient', 'Library counterevidence and independent current delivery are not bound')
        for ref in [delivery_condition['final_condition'], delivery_condition['native_command']]:
            _reference(root, ref, runs)
        row['categories'].append('diagnosis_contradicted' if expected == 'fail' else 'diagnostic_scope_unproven')
        row['meaning'] = 'Object-bound library premise retains its refuted or incomplete verdict; final task conditions independently hold. Diagnosis remains false; repair success is not causal proof.'
        return row

    known = {'leaf_inactive_fact_contradicted': ('fail', 'diagnosis_contradicted'),
             'signal_absence_contradicted': ('fail', 'diagnosis_contradicted'),
             'located_reset_not_covered_by_cited_actions': ('incomplete', 'repair_action_evidence_incomplete')}
    if (not closure or checks['diagnosis_and_action'].get('problems') != conflicts or
            any(p.get('reason') not in known or p.get('status') != known[p['reason']][0]
                for p in conflicts)):
        return block('unclassified_audit_failure', 'Diagnostic reason is not covered by this bounded policy')
    expected_status = 'fail' if any(p['status'] == 'fail' for p in conflicts) else 'incomplete'
    if (closure['status'] != expected_status or
            checks['diagnosis_and_action']['status'] != expected_status or
            any(checks[k]['status'] not in {'pass', 'not_applicable'}
                for k in ['operation_binding', 'selected_families', 'positive_evidence'])):
        return block('delivery_proof_insufficient', 'An independent required condition proof is still incomplete')
    condition = closure.get('condition_evidence')
    if not condition or condition.get('run_ref') != verify['run_ref']:
        return block('delivery_proof_insufficient', 'Missing current-run condition evidence')
    _reference(root, condition, runs)  # Authenticity, NOT proof of the rejected diagnosis.
    for problem in conflicts:
        reason = problem['reason']
        if reason == 'leaf_inactive_fact_contradicted':
            fact = problem.get('native_fact', {})
            if (fact.get('inactive_level') not in {0, 1} or
                    fact.get('instance') != problem.get('object') or
                    fact.get('pin') != problem.get('pin') or
                    not all(fact.get(k) for k in ['source', 'locator', 'excerpt', 'instance_evidence'])):
                return block('unclassified_audit_failure', 'Native fact binding is absent')
            # The native input/Liberty interpretation is supplied by the existing
            # runtime verifier; absolute input paths are not re-read here.
        else:
            native = problem.get('native_evidence')
            native = native if isinstance(native, list) else [native]
            if not native or not all(isinstance(ref, dict) for ref in native):
                return block('unclassified_audit_failure', 'Native diagnostic evidence is absent')
            for ref in native:
                _reference(root, ref, runs)
                if int(ref['run_ref'][1:]) >= int(verify['run_ref'][1:]):
                    return block('unclassified_audit_failure', 'Diagnostic evidence is not from an earlier actual run')
            if reason == 'located_reset_not_covered_by_cited_actions':
                cited, later = problem.get('cited_changes', []), problem.get('later_uncited_reset_changes', [])
                if (cited != issue['attempts'][-1]['fix']['artifact_ref'] or not later or
                        any(identity not in changes or identity in cited for identity in later)):
                    return block('unclassified_audit_failure', 'Actual failed/later repair references are not bound')
        row['categories'].append(known[reason][1])
    row['categories'] = sorted(set(row['categories']))
    return row


def completion_outcome(output_dir, task, run_records, issues, changes, *,
                       tool_checks_passed, audit_problems, audit_stop_events,
                       canonical_delivery, within_limit, delivery_proof=None):
    """Conservative final disposition; never edits issues or suppresses failures."""
    errors=[];pending=[];dispositions=[];expected_problems=set()
    try:
        runs={r['run_id']:r for r in run_records}
        if len(runs)!=len(run_records) or not runs:raise ValueError('Invalid actual run list')
        final=run_records[-1]
        if final.get('exit_status')!='completed' or final.get('returncode')!=0:
            raise ValueError('Final native process did not complete successfully')
        for rid in runs:
            if not re.fullmatch(r'R[1-9]\d*',rid):raise ValueError('Invalid run identity')
            _file(output_dir,runs[rid]['log_file'])
        if task=='task2' and not issues:raise ValueError('Task2 requires nonempty issue records')
        refs={c['change_id']:c for c in changes}
        if len(refs)!=len(changes):raise ValueError('Duplicate change identity')
        for change in changes:
            _file(output_dir,change['path']);_file(output_dir,change['diff_path'])
        ids=set()
        for issue in issues:
            try:
                iid=issue['issue_id']
                if iid in ids or not re.fullmatch(r'I[1-9]\d*',iid):raise ValueError('Invalid issue identity')
                ids.add(iid)
                if not issue.get('phenomenon') or not all(issue.get('diagnosis',{}).get(k) for k in ['summary','located_object','root_cause']):
                    raise ValueError('Incomplete issue diagnosis')
                found=issue['found'];_reference(output_dir,found,runs)
                if found.get('verified') is not True:raise ValueError('Discovery not verified')
                attempts=issue.get('attempts')
                if not attempts:raise ValueError('No actual repair/verification attempt')
                for attempt in attempts:
                    fix=attempt['fix'];links=fix.get('artifact_ref',[])
                    if not fix.get('action') or not links or any(x not in refs for x in links):raise ValueError('Broken repair/change reference')
                    verify=attempt['verify']
                    if type(verify.get('resolved')) is not bool:raise ValueError('Verification result must be a boolean')
                    _reference(output_dir,verify,runs,unresolved=not verify['resolved'])
                    if int(verify['run_ref'][1:])<=int(found['run_ref'][1:]):raise ValueError('Verification is not a later actual run')
                    if verify['resolved'] and (verify.get('diagnosis_check', {}).get('problems') or
                            verify.get('closure_check') and (
                                verify['closure_check'].get('status') != 'pass' or
                                any(c.get('status') not in {'pass', 'not_applicable'}
                                    for c in verify['closure_check'].get('checks', {}).values()))):
                        raise ValueError('Positive resolution contradicts its runtime semantic checks')
                if not attempts[-1]['verify']['resolved']:
                    pending.append(iid)
                    conflicts=attempts[-1]['verify'].get('diagnosis_check', {}).get('problems', [])
                    if conflicts:
                        expected_problems.add(f'{iid} diagnosis/action has an unsupported claim: ' +
                            '; '.join(str(p.get('original_clause', p.get('detail', p['reason']))) for p in conflicts))
                    else:
                        expected_problems.add(f'{iid} lacks positive verification evidence from a later tool run')
                    from drc_validation import prior_signal_scope, library_relation_scope, prior_exclusion_scope, aggregate_drc_scope, eco_gate_diagnostic_scope
                    from command_error_evidence import command_parameter_scope
                    from configuration_evidence import prior_configuration_scope
                    independent_native_condition = (isinstance(delivery_proof, _DeliveryProof) and
                        any(json.loads(c).get('issue_id') == iid and json.loads(c).get('kind') in {'independent_native_task_delivery','independent_partial_task_delivery'}
                            for c in delivery_proof.conditions))
                    delivery_bound = ((independent_native_condition or any(p.get('reason') in {'correction_original_scope_unproven',
                                                             'fix_action_reference_not_bound'} for p in conflicts) or
                                       prior_signal_scope(conflicts) or command_parameter_scope(conflicts) or
                                       prior_configuration_scope(conflicts) or
                                       library_relation_scope(conflicts) or prior_exclusion_scope(conflicts) or aggregate_drc_scope(conflicts) or eco_gate_diagnostic_scope(conflicts)) and
                        tool_checks_passed is True and within_limit is True and
                        _delivery_proof_bound(delivery_proof, output_dir, task, runs, refs, canonical_delivery, issues))
                    conditions = ([json.loads(c) for c in delivery_proof.conditions
                                   if json.loads(c)['issue_id'] == iid] if delivery_bound else [])
                    disposition = _pending_disposition(output_dir, issue, runs, refs, delivery_bound=delivery_bound,
                        delivery_condition=conditions[0] if len(conditions) == 1 else None)
                    if delivery_bound and not disposition['blocking']:
                        disposition['delivery_binding'] = {
                            'run_ref': run_records[-1]['run_id'], 'case_output': delivery_proof.root,
                            'case_input': delivery_proof.input_root,
                            'material_fingerprint_sha256': _digest(delivery_proof.fingerprints),
                            'conditions': [json.loads(c) for c in delivery_proof.conditions
                                           if json.loads(c)['issue_id'] == iid]}
                    dispositions.append(disposition)
            except (OSError,ValueError,TypeError,KeyError,IndexError) as error:
                identity = issue.get('issue_id','unknown') if isinstance(issue,dict) else 'unknown'
                errors.append(str(identity)+': '+str(error))
                continue  # Diagnose every saved issue; one bad record cannot hide later blockers.
        if set(audit_problems)!=expected_problems:
            raise ValueError('Audit contains unexplained or structural failure beyond classified unresolved items')
        for disposition in dispositions:
            if disposition['blocking']:
                errors.append(disposition['issue_id'] + ': ' + disposition['detail'])
        for event in audit_stop_events:
            if event.get('reason') not in {'repeated_execution_request','consecutive_audit_stall'}:
                raise ValueError('Unsupported early-stop reason')
    except (OSError,ValueError,TypeError,KeyError,IndexError) as error:
        errors.append(str(error))
    if tool_checks_passed is not True:errors.append('Required native/task/integrity/equivalence checks did not pass')
    if within_limit is not True:errors.append('Case time limit exceeded or unverified')
    if not canonical_delivery or canonical_delivery.get('status')!='published':errors.append('Native canonical delivery incomplete')
    success=not errors
    return {'exit_code':0 if success else 2,
            'status':'completed_with_unresolved_audit' if success and pending else 'completed' if success else 'incomplete',
            'artifact_delivery_complete':success,'full_audit_complete':success and not pending,
            'unresolved_issue_ids':pending,'blocking_reasons':errors,
            'audit_disposition':dispositions,
            'meaning':'Process delivery status; unresolved issues remain false, and no formal score or full correctness is claimed.'}
