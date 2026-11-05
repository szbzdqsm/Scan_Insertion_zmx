"""Read-only failed-ECO observations and bounded repeated *observed* failures.

These records are diagnostics, never NativeTrace, EQY, task or audit positives.
Unknown connectivity is never equal-state evidence. Repeated bound failure to
collect evidence has a separate fail-closed diagnostic budget. No port or repair
is prescribed.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import PurePosixPath
import posixpath
import re

from canonical_delivery import _real_file
from eco_structure import MUTATIONS, read_design, source_design
from partial_insertion_validation import _boolean

_ECHO = re.compile(r'CMD-0034\]\s+@(\d+):\s*(.*)')
_MAX_LOG = 8 * 1024 * 1024

def _sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()
def _digest(value): return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()

def _plain(value):
    if isinstance(value, dict): return {k: _plain(v) for k, v in value.items() if k not in {'line', 'source', 'unknown'}}
    if isinstance(value, (list, tuple)): return [_plain(v) for v in value]
    return value

def _ref(path, root, line=None):
    return {'source': path.relative_to(root).as_posix(), 'sha256': _sha(path), **({'line': line} if line else {})}

def _output(raw, variables, virtual, run, suffixes=('.v','.vg')):
    """Observed set values only; never evaluate Tcl, search basenames or accept other rounds."""
    literal = raw.startswith('{') and raw.endswith('}')
    value = raw[1:-1] if raw[:1] in {'"', '{'} else raw
    if not literal:
        value = re.sub(r'\$(?:\{([A-Za-z_]\w*)\}|([A-Za-z_]\w*))',
                       lambda m: variables.get(m[1] or m[2], '$UNKNOWN'), value)
    if not value or re.search(r'[$\[\]\\;\r\n]', value): raise ValueError('Unresolved export path')
    native = PurePosixPath(posixpath.normpath(str(virtual / value)))
    if not native.is_relative_to(virtual): raise ValueError('Export outside this native run')
    target = run.joinpath(*native.relative_to(virtual).parts)
    # Input/output is allowed ONLY for failed diagnostics, never publication.
    if target.suffix not in suffixes: raise ValueError('Unsupported diagnostic file type')
    return target

def _net_value(design, library, net, constants, depth=0, seen=frozenset()):
    driver = design['graph'].resolve(net)
    if driver is None or depth > 16 or driver in seen:
        return {'value': None, 'sources': ['unknown'], 'driver': driver}
    name, parity = driver
    if name in {'$0', '$1'}: return {'value': int(name[-1]) ^ parity, 'sources': [], 'driver': driver}
    prefix = design['top'] + '::'
    if name.startswith(prefix) and name[len(prefix):] in constants:
        return {'value': constants[name[len(prefix):]] ^ parity, 'sources': [], 'driver': driver}
    index=design.get('_diagnostic_output_index')
    if index is None:
        index={prefix+instance+'.'+pin:(cell,pin) for instance,cell in design['cells'].items()
               for pin,props in library[cell['type']]['pins'].items() if props.get('direction')=='output'}
        design['_diagnostic_output_index']=index
    if name in index:
        cell,pin=index[name]; shape = library[cell['type']]
        expression = shape['pins'].get(pin, {}).get('function')
        truth = _boolean(expression) if expression and not shape['ffs'] and not shape['icg'] else None
        if truth is not None:
            inputs = {p: _net_value(design, library, cell['pins'].get(p), constants, depth + 1, seen | {driver}) for p in truth[0]}
            reduced = _boolean(expression, {p: v['value'] for p, v in inputs.items() if v['value'] is not None})
            if reduced is not None:
                vals = set(reduced[1])
                if len(vals) == 1:
                    return {'value': next(iter(vals)) ^ parity, 'sources': [], 'driver': driver}
                return {'value': None, 'sources': sorted({s for p in reduced[0] for s in inputs[p]['sources']}), 'driver': driver}
    return {'value': None, 'sources': [name], 'driver': driver}


def contract_information(record, original):
    """Identity only from bound native records; novel wording/aliases are not progress."""
    known=set(original['cells']) | set(original['modules'][original['top']]['ports'])
    aliases={}
    for row in record.get('new_design_objects',{}).get('cells',[]):
        aliases[row['object']]='NEW:'+row['type']
    def stable(value):
        if isinstance(value,dict):return {k:stable(v) for k,v in value.items()}
        if isinstance(value,list):return [stable(v) for v in value]
        value=str(value)
        for a,b in sorted(aliases.items(),key=lambda x:-len(x[0])):value=value.replace(a,b)
        value=re.sub(r'__eco_sel_[0-9a-f]+_\d+_', 'GUARD_', value)
        value=re.sub(r'_dbColl\d+', 'COLLECTION',value)
        return value
    facts=[]
    for row in record.get('object_contract',[]):
        # Successful generic guard reads are not new diagnoses. Failed checked
        # operations retain kind/context/count/class/identity and actual drivers.
        if row.get('state') in {'observed_types_only','unknown'}:continue
        expr=row.get('query_expression') or row.get('expression','')
        identities=sorted(n for n in known if n in expr)
        q=row.get('query_result',{})
        fact={'operation':row.get('command','').split(' ',1)[0], 'role':row.get('option'),
              'getter':re.findall(r'get_obj_\w+',expr),'known_objects':identities,
              'state':row.get('state'),'actual':{k:q.get(k) for k in ['design','n','classes','names','drivers','state']}}
        # Original full names stay exact. Arbitrarily renamed new or missing
        # objects do not create unlimited information merely through spelling.
        for k in ['names','drivers']:
            val=fact['actual'].get(k)
            if isinstance(val,str):
                fact['actual'][k]=' '.join(v if any(n in v for n in known) else aliases.get(v,'NEW_OR_UNKNOWN') for v in val.split())
        facts.append(_digest(stable(fact)))
    return sorted(set(facts))


class Observer:
    def __init__(self):
        self.cached = None
        self.seen = {}
        self.information = set()
        self.previous_connections = None
        self.previous_structure = None
        self.preparation_seen = set()
        self.evidence_failures = {}
        self.evidence_information = set()
        from eco_plan_semantics import DefectLedger
        self.defects = DefectLedger()

    def observe(self, context, result, words_for, *, current_check, required_problems=(), native_trace=None):
        """current_check is eco_evidence._current; no caller-provided pass booleans."""
        record = {'kind': 'failed_ECO_diagnostic_not_adoption', 'run_ref': context.rid,
                  'case_input': str(context.input_dir), 'execution_id': context.execution_id,
                  'status': 'unknown', 'stop': False, 'proof_required': True,
                  'required_stage_problems': list(required_problems),
                  'instruction': 'Evaluate actual test-mode controllability AND original functional-mode logic. '
                    'A mode-selected MUX test constant may be valid; a direct scan-enable wire is not required. '
                    'These observations do not establish EQY, task completion or audit closure.'}
        bound_context=False
        try:
            current_check(context)
            bound_context=True
            self._observe(record, context, result, words_for)
        except (OSError, ValueError, KeyError, RuntimeError, TypeError) as exc:
            record.update(status='unknown', stop=False, unknown_reason=str(exc)[:800])
            self._evidence_failure(record, context, words_for)
        if bound_context:
            try:
                from eco_evidence import native_drc_snapshot
                if native_trace is None or native_trace.context is not context:
                    raise ValueError('No same-execution native ECO trace; current DRC is unproved')
                record['current_native_drc'] = native_drc_snapshot(native_trace)
            except (OSError,ValueError,KeyError,RuntimeError) as exc:
                record['current_native_drc'] = {'status':'unknown','run_ref':context.rid,'reason':str(exc)}
            try:
                record['repair_worklist']=self.defects.observe(context,record,words_for)
            except (OSError,ValueError,KeyError,RuntimeError,TypeError) as exc:
                record['repair_worklist']={'status':'unknown','reason':str(exc)[:800],
                    'meaning':'No closure inferred; original defect records retained in the observer.'}
        path = context.output / 'eco' / context.rid / 'failure_feedback.json'
        path.parent.mkdir(parents=True, exist_ok=True)
        from runtime_events import atomic
        atomic(path, record)
        record['record_ref'] = path.relative_to(context.output).as_posix()
        return record

    def _evidence_failure(self, record, ctx, words_for):
        # Separate fail-closed diagnostic budget: NOT a claim of equal graphs.
        # No raw script-text equality, violation-count equality, or success.
        if not record.get('source_binding') or not record.get('native_errors'):
            return
        errors=record['native_errors']
        try:
            library,original=source_design(ctx.originals,ctx.libs,ctx.spec,ctx.original)
        except (OSError,ValueError,RuntimeError):return
        text=' '.join(e['text'] for e in errors)
        objects=sorted(n for n in original['cells'] if n in text)
        codes=sorted(set(re.findall(r'[A-Z]+-\d+',text)))
        key=_digest({'inputs':ctx.inputs,'designs':record.get('designs'), 'codes':codes,'original_objects':objects})
        # Allow actual fresh query information and uniquely successful steps.
        # Rename-only variants of new objects are canonicalized by library type.
        aliases={}
        from eco_object_selection import restore
        for chunk in restore(ctx.script).splitlines():
            w=words_for(chunk.strip())
            if len(w)==3 and w[0]=='add_inst':aliases[w[1].strip('{}')]='NEW:'+w[2].strip('{}')
            if len(w)==2 and w[0]=='add_net':aliases[w[1].strip('{}')]='NEW_NET'
        def canonical(value):
            value=str(value)
            for a,b in sorted(aliases.items(),key=lambda v:-len(v[0])):value=value.replace(a,b)
            return re.sub(r'_dbColl\d+','COLLECTION',value)
        facts=[]
        for q in record.get('native_queries',[]): facts.append(canonical(q))
        for q in record.get('object_contract',[]):
            facts.append(canonical({k:q.get(k) for k in ['state','actual_full_names','query_result']}))
        for step in record.get('ECO_steps',[]):
            if step['outcome']=='native_success_message':facts.append(canonical(step['command']))
        facts += contract_information(record,original)
        information={_digest(f) for f in facts}
        fresh={(key,f) for f in information}-self.evidence_information
        new_information=bool(fresh)
        self.evidence_information.update((key,f) for f in information)
        count=1 if new_information else self.evidence_failures.get(key,0)+1
        self.evidence_failures[key]=count
        record['evidence_collection']={'classification':'native_pre_export_evidence_unavailable',
            'design_change':'unknown','repeated_bound_failure_count':count,'new_native_information':new_information,
            'scope':'Same bound native failure with no new verified query/operation evidence; not equal connectivity.'}
        record['stop']=count>=3
        record['progress']={'action':'stop_failed_evidence_unavailable' if count>=3 else 'collect_missing_evidence',
            'basis':'bounded inability to establish current state, not task success or Tcl equivalence'}
        record['feedback']='No adoptable pre-scan export. Current connectivity remains unknown; collect a fresh failure snapshot and native driver queries before repeating the operation.'

    def _observe(self, record, ctx, result, words_for):
        log = ctx.run / (ctx.rid + '.log'); _real_file(log, ctx.output)
        if log.stat().st_size > _MAX_LOG: raise ValueError('Native log exceeds bounded diagnostic scope')
        from eco_object_contract import bound_record
        object_checks, contract_export = bound_record(ctx, log.read_text())
        record['object_contract'] = object_checks
        physical = ctx.script.splitlines(); lines = log.read_text().splitlines()
        guard_lines, in_guard = set(), False
        for n, line in enumerate(physical, 1):
            if line in {'# Agent ECO object contract', '# Agent ECO object selection'}: in_guard = True
            if in_guard: guard_lines.add(n)
            if line in {'# End agent ECO object contract', '# End agent ECO object selection'}: in_guard = False
        origin = [re.search(r'\[SOURCE TCL FILE\]\s+(\S+)\s*:', l)[1]
                  for l in lines if re.search(r'\[SOURCE TCL FILE\]\s+(\S+)\s*:', l)]
        if len(origin) != 1: raise ValueError('Unknown/multiple native origins')
        native = PurePosixPath(origin[0]); indices = [i for i,p in enumerate(native.parts)
            if p == 'runs' and native.parts[i+1:i+2] == (ctx.rid,)]
        if len(indices) != 1 or '..' in native.parts: raise ValueError('Native origin is another round')
        cut = indices[0] + 2; virtual = PurePosixPath(*native.parts[:cut])
        executed = ctx.run.joinpath(*native.parts[cut:]); _real_file(executed, ctx.output)
        if executed != ctx.execution or executed.read_text() != ctx.script: raise ValueError('Native script mismatch')
        events, active = [], None
        for n, line in enumerate(lines, 1):
            echo = _ECHO.search(line)
            if echo:
                lineno, code = int(echo[1]), echo[2].strip()
                if lineno < 1 or lineno > len(physical): raise ValueError('Invalid native script line')
                observed = physical[lineno-1].strip()
                if code != observed: raise ValueError('Native/script line mismatch')
                w = words_for(code)
                active = {'line': n, 'script_line': lineno, 'command': code, 'words': w, 'output': []}
                events.append(active)
            elif active is not None:
                active['output'].append({'line': n, 'text': line})
        variables, designs, exports, steps, errors, controls, reports, queries = {}, [], [], [], [], [], [], []
        mutations, insertion, native_reports, loaded_libs, loaded_netlists = [], [], [], set(), set()
        report_writers = {}
        native_successes, extra_information = [], []
        information_scope_unknown = False
        for e in events:
            w = e['words']; name = w[0] if w else ''
            relevant = MUTATIONS | {'set','load_lib','load_netlist','present_design','insert_dft_logic',
                'dump_netlist','examine_scan_drc','rpt_scan_drc_violation','set_scan_signal','set_scan_cfg'}
            if name and name not in relevant:
                matches = [cmd for cmd in relevant if cmd.startswith(name)]
                if len(matches)==1: name=matches[0]
                elif len(matches)>1: raise ValueError('Ambiguous abbreviated native operation')
            if name == 'set' and len(w) == 3:
                vals = [x['text'].strip() for x in e['output'] if x['text'].strip()]
                if vals and not vals[0].startswith('[') and not re.search(r'[$\[\]\\;]', vals[0]): variables[w[1]] = vals[0]
                else: variables.pop(w[1], None)
            if name in {'load_lib','load_netlist'}:
                from eco_evidence import bound_loaded_inputs
                paths = bound_loaded_inputs(ctx, name, w[1:], variables, virtual, words_for)
                (loaded_libs if name == 'load_lib' else loaded_netlists).update(paths)
            for x in e['output']:
                if re.search(r'\[\s*CMD-\d+\]\s+Successfully (?:added|deleted|disconnected|connected)',x['text']):
                    native_successes.append({'evidence':_ref(log,ctx.output,x['line']),
                        'message':x['text'],'enclosing_echo_script_line':e['script_line'],
                        'note':'A loop completion echo is not a unique inner-command locator.'})
                if e['script_line'] not in guard_lines and re.search(r'CMD-1300\]\s+Present design is', x['text']):
                    design = re.search(r"Present design is '([^']+)'", x['text'])[1]
                    designs.append(design)
                if re.search(r'\[(?:ERROR|FATAL)\]', x['text']):
                    code = re.search(r'\[\s*([A-Z]+-\d+)\]', x['text'])
                    category = {'COM-3008':'object_query_or_empty_collection','CMD-3238':'hierarchy_mismatch',
                                'DM-1344':'multiple_drivers'}.get(code[1] if code else '', 'native_error')
                    errors.append({'category': category, 'command': e['command'], 'script_line': e['script_line'],
                                   'evidence': _ref(log, ctx.output, x['line']), 'text': x['text'][:900]})
            if name in MUTATIONS:
                successes = [x for x in e['output'] if re.search(r'Successfully (?:added|deleted|disconnected|connected)', x['text'])]
                failures = [x for x in e['output'] if re.search(r'\[(?:ERROR|FATAL)\]', x['text'])]
                scalar = [x for x in e['output'] if x['text'].strip() in {'0','1'}]
                steps.append({'command': e['command'], 'script_line': e['script_line'],
                    'echo': _ref(log, ctx.output, e['line']),
                    'outcome': 'native_error' if failures else 'native_success_message' if successes else 'effect_not_individually_proven',
                    'native_returns': [{'line':x['line'],'value':x['text'].strip()} for x in scalar],
                    'native_messages': successes[:20] + failures[:4]})
                mutations.append(e['line'])
            if name == 'insert_dft_logic': insertion.append(e['line'])
            if name.startswith(('set_scan_', 'set_current_scan_', 'add_scan_partition', 'set_dft_')):
                controls.append(e['command'])
            if e['script_line'] not in guard_lines and re.search(r'\b(?:get_obj_\w+|get_property|get_attribute|sizeof_collection)\b', e['command']):
                out = [re.sub(r'_dbColl\d+', '_dbColl', x['text']) for x in e['output']
                       if x['text'] and not x['text'].startswith('[agent]')]
                queries.append({'command': e['command'], 'native_output': out[:12]})
            if name.startswith('rpt_') or name.startswith('examine_scan_'):
                # Newly obtained read-only native information must get a chance,
                # even when it has not changed the exported connectivity yet.
                stdout=[re.sub(r'_dbColl\d+','_dbColl',x['text']) for x in e['output'] if not x['text'].startswith('[agent]')]
                extra_information.append({'command':name,'native_stdout':stdout[:64]})
                if len(w)>=3 and w[-2] in {'-file','>'}:
                    try:
                        probe=_output(w[-1],variables,virtual,ctx.run,('.rpt','.report','.txt','.pre_scan'))
                        if probe.is_file() and probe.stat().st_size and str(probe.absolute()) not in ctx.before_files:
                            _real_file(probe,ctx.output)
                            if probe.stat().st_size>1024*1024: information_scope_unknown=True
                            else: extra_information.append({'command':name,'native_file_sha256':_sha(probe)})
                    except (ValueError,RuntimeError): information_scope_unknown=True
            if name == 'dump_netlist' and len(w) == 3 and w[1] == '-file':
                success = [x for x in e['output'] if 'VRLG-O-0009' in x['text'] and 'Write Netlist successfully.' in x['text']]
                if success:
                    target = _output(w[2], variables, virtual, ctx.run); _real_file(target, ctx.output)
                    if str(target.absolute()) in ctx.before_files: raise ValueError('Export predates this native execution')
                    exports.append({'path':target, 'echo_line':e['line'], 'success':success[-1]['line'],
                                    'script_line':e['script_line'], 'pre_scan':not insertion})
            if name in {'examine_scan_drc','rpt_scan_drc_violation'} and len(w) == 3 and w[1] in {'-file','>'}:
                p = _output(w[2],variables,virtual,ctx.run,('.rpt','.report'))
                if p.is_file() and p.stat().st_size and str(p.absolute()) not in ctx.before_files:
                    _real_file(p,ctx.output); native_reports.append(p); report_writers[p] = e['line']
        if contract_export is not None and not insertion:
            exports.append(contract_export)
        record['export_attempts'] = {'successful_pre_exports':len([x for x in exports if x['pre_scan']]),
            'script_exports_proposed':len(re.findall(r'(?m)^dump_netlist\b',ctx.script)),
            'native_exports_reached':sum(e['words'][:1]==['dump_netlist'] for e in events),
            'note':'Not reached, reached without success, and successful binding are distinct.'}
        record['native_errors'] = errors[:12]
        record['ECO_steps'] = steps[:32]
        record['native_success_operations'] = native_successes[:32]
        record['designs'] = designs
        record['source_binding'] = {'script': _ref(executed, ctx.output), 'log': _ref(log, ctx.output),
                                    'input_fingerprints':ctx.inputs}
        record['native_queries'] = queries[:16]
        if not designs or len(designs) != 1: raise ValueError('Design switching/unknown design in failed run')
        if loaded_libs != {p.resolve() for p in ctx.libs} or loaded_netlists != {p.resolve() for p in ctx.originals}:
            raise ValueError('Incomplete loaded input/library binding')
        if ctx.intent['dynamic_mutation_unknown']:
            raise ValueError('Dynamic mutation scope unknown; diagnostic export stage cannot authorize stopping')
        if sum(e['words'][:1] in [['load_netlist'],['load_db']] for e in events) != 1:
            raise ValueError('Reloaded/unknown design state')
        record['native_inputs_and_design_bound']=True
        record['actual_control_commands']=controls[:40]
        from eco_evidence import drc_state_change
        state_boundary = max((e['line'] for e in events if e['words'] and
                              drc_state_change(e['words'][0].removeprefix('::'))), default=0)
        report_refs = {p:{**_ref(p,ctx.output), 'writer_line':report_writers[p],
                         'phase':'before_later_state_change' if report_writers[p] <= state_boundary else 'after_last_state_change'}
                       for p in sorted(set(native_reports))}
        record['native_diagnostic_report_sources']=list(report_refs.values())
        candidates = [e for e in exports if e['pre_scan']]
        if not candidates: raise ValueError('No native pre-scan export; connectivity unknown')
        export = candidates[-1]
        if any(n > export['success'] for n in mutations):
            raise ValueError('Export predates later design mutation; current connections unknown')
        if len([e for e in exports if e['path'] == export['path']]) != 1:
            raise ValueError('Export target overwritten; stage binding unknown')
        key = _digest(ctx.inputs)
        if self.cached is None or self.cached[0] != key:
            library, original = source_design(ctx.originals, ctx.libs, ctx.spec, ctx.original)
            self.cached = key, library, original
            self.seen.clear(); self.information.clear(); self.previous_connections=None
        _, library, original = self.cached
        if designs[0] != original['top']: raise ValueError('Export/native design mismatch')
        current = read_design([export['path']], library, original['top'])
        record['top_level_ports'] = current['modules'][current['top']]['ports']
        constraints, scan_controls = {}, []
        for command in controls:
            w = words_for(command)
            if w[:1] != ['set_scan_signal'] or len(w) % 2 != 1: continue
            opts = dict(zip(w[1::2],w[2::2])); port = opts.get('-port','')
            if re.fullmatch(r'[A-Za-z_]\w*',port):
                if opts.get('-type') == 'constant' and opts.get('-constant_value') in {'0','1'}: constraints[port] = int(opts['-constant_value'])
                if opts.get('-type') == 'scan_enable': scan_controls.append(port)
        from eco_structure import requirements
        req = requirements(ctx.spec)
        mode_known = bool(req['scan_modes']) and all(constraints.get(p) == v for p,v in req['scan_modes'].items())
        pin_facts, changes, resolved = [], [], {}
        for name, cell in current['cells'].items():
            resolved[name] = {'type':cell['type'],'pins':{p:current['graph'].resolve(net) for p,net in cell['pins'].items()}}
            for pin, net in cell['pins'].items():
                before = original['cells'].get(name,{}).get('pins',{}).get(pin)
                if before != net and name in original['cells']:
                    changes.append({'object':name+'/'+pin,'original_net':before,'exported_net':net,
                                    'direction':library[cell['type']]['pins'].get(pin,{}).get('direction'),
                                    'source':_ref(export['path'],ctx.output,cell['line']),
                                    'actual_export_driver':current['graph'].resolve(net)})
            shape = library[cell['type']]
            if not shape['icg'] or len(pin_facts)>=16: continue
            for pin, prop in shape['pins'].items():
                if prop.get('clock_gate_test_pin') != 'true': continue
                old_net = original['cells'].get(name,{}).get('pins',{}).get(pin)
                actual = _net_value(current,library,cell['pins'].get(pin),constraints if mode_known else {})
                original_function = _net_value(original,library,old_net,req['functional_modes'])
                fixed_function = _net_value(current,library,cell['pins'].get(pin),req['functional_modes'])
                pin_facts.append({'object':name+'/'+pin,'cell_type':cell['type'],'direction':prop.get('direction'),
                    'exported_source':_ref(export['path'],ctx.output,cell['line']),
                    'original_source':{'source':original['cells'].get(name,{}).get('source'),
                                       'line':original['cells'].get(name,{}).get('line')},
                    'original_driver':original['graph'].resolve(old_net), 'exported_driver':current['graph'].resolve(cell['pins'].get(pin)),
                    'scan_mode_constraints_observed':constraints, 'task_scan_modes_present':mode_known,
                    'test_mode_value_observation':actual,'original_functional_mode_observation':original_function,
                    'exported_functional_mode_observation':fixed_function,
                    'functional_logic_leaf_sources_equal':original_function['sources']==fixed_function['sources'],
                    'note':'Combinational observation only; equal leaves are NOT functional equivalence. No direct control port mandated.'})
        for p in sorted(set(native_reports)):
            if p.stat().st_size > 1024*1024: continue
            text = p.read_text(errors='replace')
            relevant = [{'line':i,'text':l} for i,l in enumerate(text.splitlines(),1)
                        if re.search(r'DFTR(?:\d+|TIE[01])|Total violations:|same violation',l)]
            if relevant: reports.append({'ref':report_refs[p],'native_findings':relevant[:64],
                'phase':report_refs[p]['phase'],
                'meaning':'historical diagnosis, not current DRC' if report_refs[p]['phase']=='before_later_state_change' else 'report requires a fresh same-state native analysis',
                'full_object_list_available':not bool(re.search(r'other cells with the same violation',text))})
        record.update(status='observed_failed_state_not_validated', fixed_export={
            **_ref(export['path'],ctx.output),'native_success_line':export['success'], 'stage':'after_observed_ECO_before_scan'},
            ICG_test_pin_observations=pin_facts[:16], changed_original_connections=changes[:24],
            DRC_observations=reports[:8], actual_control_commands=controls[:40])
        record['new_design_objects'] = {
            'cells':[{ 'object':n, 'type':c['type'], 'pins':c['pins'],
                       'source':_ref(export['path'],ctx.output,c['line'])}
                      for n,c in current['cells'].items() if n not in original['cells']][:16],
            'nets_or_ports':[{ 'module':name, 'object':net, 'width':width,
                               'direction':m['ports'].get(net,'internal_net')}
                for name,m in current['modules'].items() for net,width in m['widths'].items()
                if net not in original['modules'].get(name,{}).get('widths',{})][:24]}
        fanin = {}
        def visit(net, depth=0):
            if depth>8 or len(fanin)>=24: return
            driver = current['graph'].resolve(net)
            if driver is None: return
            for obj,c in current['cells'].items():
                if obj in fanin: continue
                if not driver[0].startswith(current['top']+'::'+obj+'.'): continue
                shape = library[c['type']]
                fanin[obj]={'type':c['type'],'pins':c['pins'], 'pin_semantics':shape['pins'],
                            'source':_ref(export['path'],ctx.output,c['line'])}
                if not shape['ffs'] and not shape['icg']:
                    for pin,props in shape['pins'].items():
                        if props.get('direction')=='input': visit(c['pins'].get(pin),depth+1)
        for name,c in current['cells'].items():
            shape=library[c['type']]
            if shape['icg']:
                for pin,props in shape['pins'].items():
                    if props.get('direction')=='input': visit(c['pins'].get(pin))
        # Bind available plan operands to this actual exported design, task and
        # Liberty. This is a selectable menu, never automatic plan adoption.
        from eco_plan_semantics import gate_control_contract
        roles=gate_control_contract(ctx.spec,ctx.script,words_for,current,library,ctx.libs)
        record['gate_control_contract']=roles
        known_leaves={current['top']+'::'+n for n in current['modules'][current['top']]['ports']}
        known_leaves.update(current['top']+'::'+n+'.'+p for n,c in current['cells'].items()
            if library[c['type']]['ffs'] for p,v in library[c['type']]['pins'].items() if v.get('direction')=='output')
        controls={current['top']+'::'+p for p in roles['candidate_control_port_levels']}
        options=[]
        for gate in roles['icg_test_controls']:
            if gate['status']!='complete':continue
            for pin in gate['test_pins']:
                observation=next((x for x in pin_facts if x['object']==pin['object']),None)
                if observation is None:continue
                leaves=observation['test_mode_value_observation']['sources']
                disconnected=bool(leaves) and all(x in known_leaves for x in leaves) and not set(leaves)&controls
                observation['declared_controls_proven_absent_from_test_cone']=disconnected
                if disconnected:
                    observation['actionable_scope']='Declared scan-enable polarity cannot control this unchanged functional-only test cone. Select a real function-preserving test-control splice; do not replace functional feedback with a constant.'
                drv=pin['original_driver']
                if drv is None or drv[1]!=0 or not drv[0].startswith(current['top']+'::') or '.' not in drv[0]:continue
                endpoint=drv[0].split('::',1)[1].rsplit('.',1)
                options.append({'consumer':pin['object'],'current_driver':endpoint[0]+'/'+endpoint[1],
                    'original_consumer_net':pin['original_net'],'required_test_levels':pin['guaranteed_clock_propagating_levels'],
                    'test_source_choices':pin['legal_declared_port_choices'],'functional_modes':roles['functional_modes'],
                    'library_basis':gate['library'],'current_export':record['fixed_export'],
                    'query_contract':'eco_ref uses exact output driver, input consumer, chosen test source and task mode; mode_mux owns fresh MUX/net creation, then queries and checks all objects before mutation.',
                    'choice_required':True,'automatic_connection_executed':False,
                    'meaning':'Actual connected gate with finite proven clock-propagating levels; not a preselected answer or proof of completion.'})
        record['control_plan_options']=options
        record['actual_ICG_fanin'] = fanin
        connections = _digest(resolved)
        record['connections_equal_to_previous_observed_export'] = (
            self.previous_connections == connections if self.previous_connections else None)
        self.previous_connections = connections
        zero_connects = [s for s in steps if s['command'].startswith(('connect_net ','connect_pin '))
                         and any(x['value']=='0' for x in s['native_returns'])]
        if record['connections_equal_to_previous_observed_export'] and zero_connects:
            record['feedback'] = ('The saved exported pin-driver graph is unchanged from the preceding observed export. '
                'The listed connection commands returned 0 without proving the intended effect. Configuration changes '
                'are not proof that the failing physical route changed. Inspect these actual drivers and native errors; '
                'do not assume a polarity change repairs an unchanged route.')
        else:
            record['feedback'] = 'Use the bound actual connections and per-command native outcomes below; unproven effects remain unknown.'
        # A completed scan rewrite does not invalidate the immutable pre-scan
        # snapshot. This is a PHASE diagnostic, not current post-scan adoption.
        record['observation_scope'] = 'bound_ECO_pre_scan_snapshot_not_post_scan_state'
        snapshot = relevant_connections(original, current, library)
        structure_signature = _digest(snapshot)
        changed_relevant = structure_signature != self.previous_structure
        # Retain counts for earlier failed states: oscillating back is not new progress.
        self.previous_structure = structure_signature
        # A bounded preparation opportunity for actual new combinational cell
        # shapes / net widths allows build → wire → connect. Renaming or adding
        # further unused copies of the same preparation cannot keep resetting.
        preparations = set()
        if any(s['outcome'] == 'native_success_message' for s in steps):
            for name, cell in current['cells'].items():
                shape = library[cell['type']]
                if name not in original['cells'] and not shape['ffs'] and not shape['icg']:
                    preparations.add(('new_combinational_preparation',))
            for name, module in current['modules'].items():
                for net, width in module['widths'].items():
                    if net not in original['modules'].get(name,{}).get('widths',{}):
                        preparations.add(('new_net_preparation',))
        new_preparation = preparations - self.preparation_seen
        self.preparation_seen.update(preparations)
        # New error WORDING, export paths, instance aliases, config polarity or
        # repeated reports are not new diagnostic information. New native rule
        # identifiers/known original objects or actual query results get a turn.
        findings = sorted(set(re.findall(r'DFTR(?:\d+|TIE[01])',
            json.dumps(reports))))
        categories = sorted(set(e['category'] for e in errors))
        known_objects = sorted(n for n in original['cells'] if any(n in e['text'] for e in errors))
        information_facts = set(contract_information(record, original))
        information_facts.update(_digest({'rule':v}) for v in findings)
        information_facts.update(_digest({'error_category':v}) for v in categories)
        information_facts.update(_digest({'original_object':v}) for v in known_objects)
        information_facts.update(_digest({'query':v}) for v in canonical_queries(queries, original))
        if record['required_stage_problems']: information_facts.add(_digest({'stage_required':True}))
        new_information = bool(information_facts - self.information)
        self.information.update(information_facts)
        record['native_information_facts'] = sorted(information_facts)
        eligible = bool((errors or findings or record['required_stage_problems']) and
            not ctx.intent['dynamic_mutation_unknown'] and not information_scope_unknown)
        if sum(bool(library[c['type']]['icg']) for c in current['cells'].values()) > 16:
            eligible = False
            record['scope_limit'] = 'More than 16 ICGs: diagnostic sample only, no stagnation stop.'
        state = _digest({'case':str(ctx.output),'inputs':ctx.inputs,'design':designs[0],
            'relevant_connections':snapshot, 'rules':findings, 'errors':categories,
            'required_stage_failed':bool(record['required_stage_problems'])})
        count = self.seen.get(state, 0) + 1 if eligible and not new_information and not new_preparation else 1
        if eligible: self.seen[state] = count
        else: self.seen.clear()
        record['progress'] = {'eligible':eligible, 'state_sha256':state,
            'relevant_connection_sha256':structure_signature,
            'relevant_connections_changed':changed_relevant,
            'new_preparation_opportunity':sorted(map(str,new_preparation)),
            'new_native_information':new_information,
            'same_observed_state_count':count if eligible else None,
            'basis':'Original functional pin/output driver cones, native rule/object identities and bounded preparation stages. '
                'Not Tcl equivalence, EQY or a claim that disconnected objects implement a repair.',
            'action':'stop_failed_no_progress' if eligible and count>=3 else 'targeted_feedback' if eligible and count>=2 else 'continue_or_unknown'}
        record['stop'] = bool(eligible and count>=3)
        if record['stop']:
            record['feedback'] += ' This same bound failed state has recurred three times without new native information; stop as incomplete, never success.'

def bounded_context(record):
    """Only current related facts; never append the whole historical trajectory."""
    selected = {k:v for k,v in record.items() if k in {'kind','run_ref','status','instruction','designs',
        'feedback','unknown_reason','progress','record_ref','top_level_ports','evidence_collection','export_attempts','repair_worklist','control_plan_options'}}
    if record.get('object_contract'):
        checks = sorted(record['object_contract'], key=lambda row:
            row.get('state') not in {'empty', 'wrong_type', 'ambiguous_source', 'unresolved',
                                    'stale_reference', 'hierarchy_mismatch','preparation_collision','occupied_target','driver_mismatch','native_operation_failed','plan_required','test_clock_mismatch'})
        selected['object_contract'] = [{key: (value[:1000] if isinstance(value, str) else value)
            for key, value in row.items()} for row in checks[:4]]
    for key, maximum in [('native_errors',6),('ICG_test_pin_observations',4),('DRC_observations',4),
                         ('ECO_steps',8),('changed_original_connections',8),('actual_ICG_fanin',8),('new_design_objects',16)]:
        value = record.get(key)
        if value is None: continue
        if isinstance(value,list): value=value[-maximum:] if key=='ECO_steps' else value[:maximum]
        if isinstance(value,dict): value=dict(list(value.items())[:maximum])
        if len(json.dumps({**selected,key:value},ensure_ascii=False))<=16000: selected[key]=value
    success=record.get('native_success_operations',[])[:4]
    if len(json.dumps({**selected,'native_success_operations':success},ensure_ascii=False))<=16000:
        selected['native_success_operations']=success
    return json.dumps(selected,ensure_ascii=False)


def relevant_connections(original, current, library):
    """Reuse the flattened native graph; no full-netlist equivalence inference.

    Keep original object identity; canonicalize only NEW combinational objects
    by type/pin topology so arbitrary instance aliases cannot reset progress.
    """
    prefix = current['top'] + '::'
    outputs = {prefix+n+'.'+p:(n,c,p) for n,c in current['cells'].items()
        for p,props in library[c['type']]['pins'].items() if props.get('direction') == 'output'}
    def cone(net, seen=frozenset(), depth=0):
        driver = current['graph'].resolve(net)
        if driver is None or depth > 16 or driver in seen:
            return ('unknown_or_cycle',)
        key, parity = driver
        if key not in outputs:
            return ('boundary',key,parity)
        name, cell, pin = outputs[key]
        if name in original['cells']:
            return ('original_cell',name,pin,parity)
        shape = library[cell['type']]
        if shape['ffs'] or shape['icg']:
            return ('new_sequential',cell['type'],pin,parity)
        return ('new_comb',cell['type'],pin,parity,tuple((p,cone(cell['pins'].get(p),seen|{driver},depth+1))
            for p,v in sorted(shape['pins'].items()) if v.get('direction') == 'input'))
    result = {}
    for name, cell in original['cells'].items():
        actual = current['cells'].get(name)
        if actual is None or actual['type'] != cell['type']:
            result[name] = ('missing_or_type_changed',actual['type'] if actual else None)
            continue
        for pin, props in library[cell['type']]['pins'].items():
            if props.get('direction') == 'input':
                result[name+'/'+pin] = cone(actual['pins'].get(pin))
    module = original['modules'][original['top']]
    for port, direction in module['ports'].items():
        if direction == 'output':
            width = module['widths'].get(port)
            for bit in range(min(width), max(width)+1) if width else [None]:
                name = port + ('['+str(bit)+']' if bit is not None else '')
                result['output:'+name] = cone(prefix+name)
    return result


def canonical_queries(queries, original):
    values=[]
    for query in queries:
        # Only an original object query is a justified new inspection opportunity.
        # Drop volatile collection IDs, paths, and source line decorations.
        objects=sorted(n for n in original['cells'] if re.search(r'(?<![\w/])'+re.escape(n)+r'(?![\w/])',query['command']))
        if not objects: continue
        text='\n'.join(query['native_output'])
        text=re.sub(r'/[^\s"{}]+','<path>',text)
        text=re.sub(r'@(\d+):','@:',text)
        values.append({'objects':objects,'result':text})
    return values
