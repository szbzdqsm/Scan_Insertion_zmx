"""Bind source ECO operations to their actual lowered Tcl, never to success.

This is annotation provenance only. Task/ECO/DRC/EQY/publication checks remain
independent. No evaluation of Tcl, native command execution or model call.
"""
from __future__ import annotations
import copy
import hashlib
import json
from pathlib import Path
import re

from eco_object_selection import BEGIN, END, ORIGINAL
from clock_association_recipe import _chunks


def _sha(value):
    return hashlib.sha256(value if isinstance(value, bytes) else value.encode()).hexdigest()


def _plain_file(path):
    if path.is_symlink() or not path.is_file():
        raise ValueError('Missing or indirect provenance file')
    return path.read_bytes()


def build(plan, script, run, words_for):
    """Called by the existing production bind_plan after all lowering stages.

    The compiler-owned hex originals delimit exact expansion regions. The
    contract plan supplies source positions and object IDs; the actual script
    hash binds every generated command and intervening query/guard byte.
    """
    rid = run.name
    if not re.fullmatch(r'R[1-9]\d*', rid) or plan.get('script_sha256') != _sha(script):
        raise ValueError('Compiler plan/current round or script mismatch')
    source = plan.get('source_sha256')
    if source and _sha(_plain_file(run/'eco_plan.source.dofile')) != source:
        raise ValueError('Compiler source content changed')
    if plan.get('source_input_fingerprints'):
        from netlist_repair import changed_paths
        if changed_paths(plan['source_input_fingerprints']):
            raise ValueError('Compiler input/library content or path changed')
    operations = []
    pattern = re.compile(r'(?ms)^'+re.escape(BEGIN)+r'\n.*?^'+re.escape(END)+r'(?:\n|$)')
    for match in pattern.finditer(script):
        rows = [line[len(ORIGINAL):] for line in match[0].splitlines() if line.startswith(ORIGINAL)]
        if not rows:
            continue  # Epoch changes and setup have no source operation.
        if len(rows) != 1:
            raise ValueError('Ambiguous compiler source marker')
        command = bytes.fromhex(rows[0]).decode()
        code = command.strip().rstrip(';').strip()
        ids=set(re.findall(r'ECO_OBJECT_OBSERVATION_BEGIN\|(C\d+)\b',match[0]))
        checks = [c for c in plan.get('checks', []) if c.get('id') in ids]
        if not checks or {c['id'] for c in checks} != ids or any(c.get('command')!=code for c in checks):
            raise ValueError('Compiler object operation IDs do not bind the source block')
        source_lines={c['original_line'] for c in checks}
        connections = [c for c in plan.get('connections', []) if c.get('original_command') == code
                       and c.get('original_line') in source_lines]
        locations = {c['original_line'] for c in [*checks, *connections]}
        if len(locations) != 1:
            raise ValueError('Source operation has no unique compiler position')
        first = script.count('\n', 0, match.start())+1
        lines = match[0].splitlines();last = first+len(lines)-1
        # Static present_design at a top-level line is not the runtime design
        # proof. Execution resolution below rechecks native present_design.
        designs = []
        for line in script[:match.start()].splitlines():
            w = words_for(line.strip())
            if w[:1] == ['present_design']:
                value=w[1].strip('{}"') if len(w)==2 else ''
                if not re.fullmatch(r'[A-Za-z_][\w$]*', value):
                    raise ValueError('Unresolved compilation design')
                designs.append(value)
        if not designs or len(set(designs)) != 1:
            raise ValueError('Ambiguous compilation design')
        native = []
        for n,line in enumerate(lines,first):
            w = words_for(line.strip())
            if w and w[0] in {'add_inst','add_net','add_port','connect_net','disconnect_net','connect_pin','connect_pg_net'}:
                native.append({'script_line':n,'command':line.strip()})
        operations.append({'operation_id':'OP'+str(len(operations)+1),
            'source_command':code,'source_line':next(iter(locations)),
            'source_command_sha256':_sha(code),'check_ids':[c['id'] for c in checks],
            'design':designs[-1],'compiled_first':first,'compiled_last':last,
            'compiled_sha256':_sha(match[0]),'native_commands':native})
    return {'version':1,'run_ref':rid,'run_root':str(run.absolute()),
        'case_output':str(run.parent.parent.absolute()),'source_sha256':source,
        'source_basis':'compiler source and exact expansion markers' if source else 'saved bound compiler contract and exact expansion markers',
        'compiled_script_sha256':_sha(script),'contract_sha256':_sha(json.dumps(plan,sort_keys=True,separators=(',',':'))),
        'source_input_fingerprints':plan.get('source_input_fingerprints',{}),
        'task_spec_sha256':plan.get('task_spec_sha256'),
        'operations':operations,'meaning':'source-to-generated-code binding only; not an ECO or EQY success proof'}


def bind(plan, script, run, words_for):
    from runtime_events import atomic
    record = build(plan,script,run,words_for)
    atomic(run/'eco_plan_provenance.json',record)
    return record


def _executed(run, script, words_for, *, allow_later_errors=False):
    """Check real current script origin and echo line identities; not topology."""
    log = run/(run.name+'.log');text = _plain_file(log).decode(errors='replace')
    physical = script.splitlines();sources=[];echoes={};design='';requested=''
    for number,line in enumerate(text.splitlines(),1):
        m = re.search(r'\[SOURCE TCL FILE\]\s+(\S+)\s*:',line)
        if m:
            source=Path(m[1])
            if not source.is_relative_to(run) or _plain_file(source) != script.encode():
                raise ValueError('Native script origin is not this round/version')
            sources.append(str(source))
        m = re.search(r'CMD-0034\]\s+@(\d+):\s*(.*)',line)
        if not m:
            present=re.search(r"CMD-1300\].*Present design is '([^']+)'",line)
            if present:
                if present[1]!=requested:raise ValueError('Native present design differs from compiled scope')
                design=present[1]
            continue
        n,code=int(m[1]),m[2].strip()
        if n<1 or n>len(physical) or physical[n-1].strip()!=code:
            raise ValueError('Native echo/current script line mismatch')
        words=words_for(code)
        if words[:1]==['present_design']:
            requested=words[1].strip('{}"') if len(words)==2 else '';design=''
        echoes.setdefault(n,[]).append({'line':number,'command':code,'design':design})
    if len(sources)!=1 or (not allow_later_errors and re.search(r'\[(?:ERROR|FATAL)\]',text)):
        raise ValueError('Native execution absent, ambiguous or contains error')
    return echoes,{'source':str(log),'sha256':_sha(log.read_bytes())}


def project(task, mappings, script, run, words_for, literal_locator, *, native=False):
    """Optional Task2 annotations cannot supply or veto task correctness.

    Invalid annotations retain their raw text/reason and are NOT published as
    valid mappings. Task1 requirements remain mandatory. A source ECO command
    can map to multiple exact emitted Tcl commands via the compiler ledger.
    """
    result={'task':task,'run_ref':run.name,'compiled_script_sha256':_sha(script),
            'adopted':[],'annotations':[],'required_problems':[],
            'meaning':'annotation binding only; independent task/objects/DRC/EQY and publication still required'}
    if not isinstance(mappings,list):
        result['annotations'].append({'raw':copy.deepcopy(mappings),'status':'not_adopted','reason':'mapping field is not an array'})
        if task=='task1':result['required_problems'].append('Task 1 mapping must be an array')
        return result
    ledger=None;ledger_error=None
    try:
        plan=json.loads(_plain_file(run/'eco_object_contract.plan.json'))
        ledger=json.loads(_plain_file(run/'eco_plan_provenance.json'))
        if ledger!=build(plan,script,run,words_for):
            raise ValueError('Provenance/current script/round/design binding mismatch')
    except (OSError,ValueError,KeyError,TypeError) as exc:
        ledger=None
        ledger_error=str(exc)
    for index,item in enumerate(mappings):
        review={'index':index,'raw':copy.deepcopy(item),'status':'not_adopted'}
        try:
            if not isinstance(item,dict) or not isinstance(item.get('requirement'),str) or not item['requirement'].strip() or not isinstance(item.get('dft_config'),str):
                raise ValueError('Mapping needs a requirement and string dft_config')
            configuration=item['dft_config'];parts=[p.strip().rstrip(';').strip() for p in _chunks(configuration) if p.strip()]
            uses_plan=any((words_for(p) or [''])[0].removeprefix('::') in {'eco_link','eco_ref'} for p in parts)
            if not uses_plan:
                locator=literal_locator(script,configuration)
                if not locator:raise ValueError('No actual literal Tcl locator')
                entry={'requirement':item['requirement'],'dft_config':configuration,
                       'config_ref':{'source':'final_results/deliverables/final.dofile','locator':locator}}
                review.update(status='adopted_literal',locator=locator)
            else:
                if ledger is None:raise ValueError('Compiled source binding unavailable: '+str(ledger_error))
                selected=[]
                for part in parts:
                    signature=words_for(part)
                    matches=[op for op in ledger['operations'] if words_for(op['source_command'])==signature]
                    if len(matches)!=1 or not matches[0]['native_commands']:
                        raise ValueError('Source plan operation missing/ambiguous or has no executable connection')
                    selected.append(matches[0])
                commands=[c for op in selected for c in op['native_commands']]
                if len({op['operation_id'] for op in selected})!=len(selected):
                    raise ValueError('Repeated/ambiguous source plan operation')
                if native:
                    echoes,log=_executed(run,script,words_for)
                    for op in selected:
                        for cmd in op['native_commands']:
                            rows=echoes.get(cmd['script_line'],[])
                            if len(rows)!=1 or rows[0]['command']!=cmd['command'] or rows[0]['design']!=op['design']:
                                raise ValueError('Generated connection was not uniquely executed in this design/round')
                    review['native_log']=log
                first,last=min(c['script_line'] for c in commands),max(c['script_line'] for c in commands)
                locator=f'L{first}' if first==last else f'L{first}-L{last}'
                entry={'requirement':item['requirement'],'dft_config':'\n'.join(c['command'] for c in commands),
                       'config_ref':{'source':'final_results/deliverables/final.dofile','locator':locator}}
                review.update(status='adopted_compiled_source' if native else 'bound_source_pending_execution',
                    locator=locator,operation_ids=[op['operation_id'] for op in selected],
                    design=selected[0]['design'],provenance_sha256=_sha(_plain_file(run/'eco_plan_provenance.json')))
            result['adopted'].append(entry)
        except (OSError,ValueError,KeyError,TypeError,IndexError) as exc:
            review['reason']=str(exc)
            if task=='task1':result['required_problems'].append(f'requirement_mapping[{index}]: {exc}')
        result['annotations'].append(review)
    if task=='task1' and not result['adopted']:
        result['required_problems'].append('Task 1 requires nonempty valid requirement_mapping')
    return result


def _source_mode_mux_declarations(text, words_for):
    """Read compiler source operands without executing or repairing Tcl.

    Literal roles are separate from query spelling. An unbraced numeric bus
    word is retained only as an unresolved spelling, never a Tcl literal or
    evidence that its getter executed.
    """
    from eco_object_selection import _literal_argument
    def literal_data(word):
        if word.startswith('{') and word.endswith('}'):
            value=word[1:-1]
            return value if not any(c in value for c in '{}\r\n') else None
        if not _literal_argument(word):return None
        if word.startswith('"') and word.endswith('"'):word=word[1:-1]
        # The same finite inert escapes accepted by the query compiler. This
        # decodes Tcl data only, never substitution, patterns or command text.
        return re.sub(r'\\(.)',lambda m:m[1],word)
    definitions={};result=[]
    roles=['driver','consumer','test','mode']
    for chunk in _chunks(text):
        code=chunk.strip().rstrip(';').strip()
        w=words_for(code) if code and not code.startswith('#') else []
        if not w:continue
        if w[0] in {'load_lib','load_netlist','load_db','present_design'}:definitions.clear()
        if w[0]=='set' and len(w)>1:definitions.pop(w[1],None)
        if w[0]=='eco_ref' and len(w)==3:
            row={'reference':w[1],'command':code,'query':w[2],'selection':None}
            q=words_for(w[2][1:-1]) if w[2].startswith('{') and w[2].endswith('}') else []
            if len(q)==3 and q[0] in {'get_obj_pins','get_obj_ports','get_obj_nets'} and q[1]=='-exact':
                name=literal_data(q[2]);row['getter']=q[0]
                if name is not None:row['selection']={'kind':q[0][8:-1],'name':name}
                elif re.fullmatch(r'[A-Za-z_][\w$./-]*(?:\[\d+\][\w$./-]*)+',q[2]):
                    row['unresolved_bus_spelling']=q[2]
            definitions[w[1]]=row
        if w[:2]!=['eco_link','mode_mux'] or len(w)!=9:continue
        names=[v[1:] for v in w[2:6] if re.fullmatch(r'\$[A-Za-z_]\w*',v)]
        dependencies={role:copy.deepcopy(definitions[name]) for role,name in zip(roles,names) if name in definitions} if len(names)==4 else {}
        result.append({'source_command':code,'dependencies':dependencies})
    return result


def source_mode_mux_operations(run, words_for):
    """Authenticated typed source intents; these are NOT execution evidence."""
    script=_plain_file(run/'deliverables'/(run.name+'.dofile')).decode()
    plan=json.loads(_plain_file(run/'eco_object_contract.plan.json'))
    ledger=json.loads(_plain_file(run/'eco_plan_provenance.json'))
    if (not ledger.get('source_sha256') or not ledger.get('source_input_fingerprints') or
            not ledger.get('task_spec_sha256') or ledger!=build(plan,script,run,words_for)):
        raise ValueError('Mode-MUX source provenance is not this script/run/input/task')
    declarations=_source_mode_mux_declarations(_plain_file(run/'eco_plan.source.dofile').decode(),words_for)
    result=[]
    for c in plan.get('connections',[]):
        if c.get('operation')!='mode_mux':continue
        ops=[op for op in ledger['operations'] if op['source_command']==c['original_command'] and op['source_line']==c['original_line']]
        deps=[x for x in declarations if x['source_command']==c['original_command']]
        if len(ops)!=1 or len(deps)!=1:raise ValueError('Mode-MUX source operation/dependencies are ambiguous')
        op=ops[0];dependencies=deps[0]['dependencies']
        if set(dependencies)!={'driver','consumer','test','mode'}:raise ValueError('Mode-MUX source dependencies are unresolved')
        for dep in dependencies.values():
            checks=[x for x in plan.get('checks',[]) if x.get('command')==dep['command'] and x.get('option')=='query']
            if len(checks)!=1:raise ValueError('Source reference has no unique compiler query')
            if checks[0].get('constant_source'):dep['constant_source']=copy.deepcopy(checks[0]['constant_source'])
        result.append({'run_ref':run.name,'operation_id':op['operation_id'],'source_command':op['source_command'],
            'source_line':op['source_line'],'source_sha256':ledger['source_sha256'],
            'compiled_script_sha256':ledger['compiled_script_sha256'],'design':op['design'],
            'source_input_fingerprints':ledger['source_input_fingerprints'],
            'task_spec_sha256':ledger['task_spec_sha256'],'contract':c['contract'],
            'dependencies':dependencies,
            'proof_paths':[str(run/n) for n in ['eco_plan.source.dofile','eco_plan_provenance.json','eco_object_contract.plan.json','deliverables/'+run.name+'.dofile']],
            'meaning':'Compiler-bound source intent only; no getter or operation execution is inferred.'})
    return result


def executed_mode_mux_operations(run, words_for):
    """Authenticate completed compiler operations, not a whole repair verdict.

    A later failure cannot erase a completed historical operation. Conversely
    source membership/echo alone cannot turn an unexecuted plan into evidence.
    Native begin/end, every generated command and fresh readback are required.
    """
    from eco_object_contract import staged_observations
    script=_plain_file(run/'deliverables'/(run.name+'.dofile')).decode()
    plan=json.loads(_plain_file(run/'eco_object_contract.plan.json'))
    ledger=json.loads(_plain_file(run/'eco_plan_provenance.json'))
    if (not ledger.get('source_sha256') or not ledger.get('source_input_fingerprints') or not ledger.get('task_spec_sha256') or
            ledger!=build(plan,script,run,words_for)):
        raise ValueError('Plan provenance is not this actual source/script/run/input/task')
    echoes,log=_executed(run,script,words_for,allow_later_errors=True)
    lines=_plain_file(run/(run.name+'.log')).decode(errors='replace').splitlines()
    observations=staged_observations('\n'.join(lines),plan)
    sources=source_mode_mux_operations(run,words_for)
    result=[]
    for connection in plan.get('connections',[]):
        if connection.get('operation')!='mode_mux':continue
        matches=[op for op in ledger['operations'] if op['source_command']==connection['original_command'] and op['source_line']==connection['original_line']]
        if len(matches)!=1:raise ValueError('Nonunique source operation')
        op=matches[0];rows=[r for r in observations if r.get('id') in op['check_ids']]
        by_role={r.get('option'):r for r in rows}
        roles=['driver','consumer','test','mode','preserve_function_mode_splice']
        if (len(rows)!=5 or set(by_role)!=set(roles) or any(r.get('state')!='observed_types_only' or
                r.get('actual_count')!=1 or r.get('current_design')!=op['design'] for r in rows)):continue
        block='\n'.join(script.splitlines()[op['compiled_first']-1:op['compiled_last']])
        names=set(re.findall(r'ECO_PLAN_BEGIN\|([^|]+)\|driver=',block))
        if len(names)!=1:raise ValueError('Nonunique compiled operation token')
        token=names.pop();begin=[(n,l) for n,l in enumerate(lines,1) if l.startswith('ECO_PLAN_BEGIN|'+token+'|')]
        end=[(n,l) for n,l in enumerate(lines,1) if l=='ECO_PLAN_END|'+token+'|consumers_preserved=structural_only|EQY_required=true']
        if len(begin)!=1 or len(end)!=1 or begin[0][0]>=end[0][0]:continue
        if any(re.search(r'\[(ERROR|FATAL)\]',l) for l in lines[begin[0][0]-1:end[0][0]]):continue
        native=[]
        for command in op['native_commands']:
            entries=echoes.get(command['script_line'],[])
            if len(entries)!=1 or entries[0]['design']!=op['design'] or not begin[0][0]<entries[0]['line']<end[0][0]:break
            native.append(entries[0])
        else:
            if not native:continue
            observed={k:by_role[k]['actual_full_names'] for k in ['driver','consumer','test','mode']}
            values=by_role['preserve_function_mode_splice']['query_result']
            expected_begin='ECO_PLAN_BEGIN|'+token+'|driver='+observed['driver']+'|consumer='+observed['consumer']+'|net='
            suffix='|functional_mode='+connection['contract']['mode']+'='+str(connection['contract']['value'])
            if not begin[0][1].startswith(expected_begin) or not begin[0][1].endswith(suffix):continue
            consumer_net=begin[0][1][len(expected_begin):-len(suffix)]
            if not consumer_net or '|' in consumer_net:continue
            expected_readback=('ECO_PLAN_READBACK|'+token+'|all_mux_sources_checked=true|instance='+values.get('resolved_instance','')+
                '|functional_net='+values.get('resolved_wire','')+'|consumer_net='+consumer_net+'|EQY_required=true')
            readbacks=[n for n,line in enumerate(lines,1) if line==expected_readback]
            if len(readbacks)!=1 or not begin[0][0]<readbacks[0]<end[0][0]:continue
            if values.get('drivers')!=values.get('resolved_instance','')+'/'+connection['contract']['output']:continue
            if by_role['preserve_function_mode_splice']['native_log_lines'][-1]>=end[0][0]:continue
            constants=[r for r in observations if r.get('option')=='query' and r.get('constant_source') and
                r.get('state')=='observed_types_only' and r.get('current_design')==op['design'] and
                r.get('actual_full_names')==observed['test'] and r.get('query_result',{}).get('instance_n')=='1' and
                r['query_result'].get('instance_ref')=='UNIT_VirtualTieHigh' and r['query_result'].get('output_direction')=='out']
            result.append({'run_ref':run.name,'design':op['design'],'operation_id':op['operation_id'],
                **({'verified_test_constant':1} if len(constants)==1 else {}),
                'source_command':op['source_command'],'source_line':op['source_line'],'source_sha256':ledger['source_sha256'],
                'task_spec_sha256':ledger['task_spec_sha256'],
                'compiled_script_sha256':ledger['compiled_script_sha256'],'contract':connection['contract'],**observed,
                'source_binding':next(s for s in sources if s['operation_id']==op['operation_id']),
                'instance':values['resolved_instance'],'consumer_net':consumer_net,'native_commands':native,'native_readback':values,
                'native_plan_readback_line':readbacks[0],
                'native_log_sha256':log['sha256'],'evidence':{'run_ref':run.name,'source':str((run/(run.name+'.log')).relative_to(run.parent.parent)),
                    'locator':'L'+str(end[0][0]),'excerpt':end[0][1]},
                'proof_paths':[str(run/n) for n in ['eco_plan.source.dofile','eco_plan_provenance.json','eco_object_contract.plan.json',run.name+'.log','deliverables/'+run.name+'.dofile']],
                'meaning':'Executed source operation and readback only, not diagnosis/functional EQY/final task proof'})
    return result
