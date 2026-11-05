"""Task/configuration clock roles and a diagnostic defect worklist.

Neither component proves repair, equivalence or delivery. Clock choices are
restricted only where task text, literal configuration and original objects
establish a role; opaque/derived sources remain unproven for native DRC.
"""
from __future__ import annotations
import hashlib
import json
import re
from pathlib import Path
from clock_association_recipe import _chunks, _literal

IDENT = r'[A-Za-z_][\w$]*(?:\[\d+\])?'


def clock_contract(spec, script, words_for, original=None, library=None):
    clean = spec.replace('**', '')
    wanted = set(); evidence = []
    patterns = [r'(?:扫描时钟(?:配置|设置|指定)?(?:为|是|端口)?|scan clock(?: port)?(?: is|:|=)?)[ \t：:]*`('+IDENT+r')`',
                r'`('+IDENT+r')`\s*(?:为|是)\s*扫描时钟',
                r'`('+IDENT+r')`[（(]\s*扫描时钟\s*[）)]']
    for n,line in enumerate(clean.splitlines(),1):
        if re.search(r'^\s*>|例如|示例|example|禁止|不得|不能|不允许|\b(?:not|never|optional|may)\b|不是扫描时钟',line,re.I): continue
        names={m[1] for pattern in patterns for m in re.finditer(pattern,line,re.I)}
        for command in re.findall(r'`(set_scan_signal[^`\n]+)`',line):
            w=words_for(command)
            if len(w)%2==1:
                opts=dict(zip(w[1::2],w[2::2]))
                if opts.get('-type')=='clock' and re.fullmatch(IDENT,opts.get('-port','')):names.add(opts['-port'])
        if names: wanted.update(names);evidence.append({'task_line':n,'text':line,'ports':sorted(names)})
    exclusive=bool(wanted and any(re.search(r'单时钟域|single[- ]clock domain|only (?:one )?scan clock|仅(?:使用|允许)?[^\n。]{0,12}扫描时钟',line,re.I) and not re.search(r'不是|非单|\bnot\b',line,re.I) for line in clean.splitlines()))
    configured=set();declarations=[];known=True
    for n,chunk in enumerate(_chunks(script),1):
        code=chunk.strip().rstrip(';').strip();w=words_for(code) if code and not code.startswith('#') else []
        if not w:continue
        if w[0]=='set_scan_signal':
            values=[_literal(v) for v in w[1:]]
            if len(values)%2 or any(v is None for v in values):known=False;continue
            opts=dict(zip(values[::2],values[1::2]))
            if '-type' not in opts or '-port' not in opts:known=False
            if opts.get('-type') not in {'clock','reset','scan_enable','constant','clock_gating','scan_data_in','scan_data_out'}:known=False
            if opts.get('-type')=='clock':
                ports=opts.get('-port','').split()
                if not ports or not all(re.fullmatch(IDENT,p) for p in ports):known=False;continue
                configured.update(ports);declarations.append({'command':code,'ports':ports,'scope':'literal candidate declaration; native reports still required'})
        elif re.search(r'\bset_scan_signal\b',code) or ('set_scan_signal'.startswith(w[0]) and w[0].startswith('set_scan_')):known=False
    allowed=configured & wanted if exclusive else configured
    clock_pins=set()
    if original is not None and library is not None:
        for name,cell in original['cells'].items():
            shape=library[cell['type']]
            pins={x for ff in shape['ffs'] for x in re.findall(r'[A-Za-z_]\w*',ff['properties'].get('clocked_on',''))}
            pins.update(p for p,v in shape['pins'].items() if v.get('clock_gate_clock_pin')=='true')
            clock_pins.update(name+'/'+p for p in pins if shape['pins'].get(p,{}).get('direction')=='input')
    return {'task_scan_clocks':sorted(wanted),'task_clock_evidence':evidence,'exclusive_task_clock_domain':exclusive,
            'configured_scan_clocks':sorted(configured),'configuration_literal_scope_known':known,
            'legal_literal_clock_port_choices':sorted(allowed),'clock_consumer_pins':sorted(clock_pins),
            'declarations':declarations,'meaning':'Task and candidate declaration roles only; not native DRC or functional proof'}


def reference_selection(code, words_for):
    w=words_for(code)
    if len(w)!=3 or w[0]!='eco_ref' or not(w[2].startswith('{') and w[2].endswith('}')):return None
    q=words_for(w[2][1:-1])
    if len(q)!=3 or q[0] not in {'get_obj_ports','get_obj_pins'} or q[1]!='-exact':return None
    name=_literal(q[2])
    if name is None or re.search(r'[*?]',name):return None
    return {'kind':'port' if q[0]=='get_obj_ports' else 'pin','name':name}


def clock_choice_problem(consumer, source, contract):
    if not consumer or not source or consumer['name'] not in contract['clock_consumer_pins'] or source['kind']!='port':return None
    name=source['name'];reason=None
    if contract['exclusive_task_clock_domain'] and name not in contract['task_scan_clocks']:
        reason='outside the explicit task scan-clock domain'
    elif contract['configuration_literal_scope_known'] and name not in contract['configured_scan_clocks']:
        reason='not declared as a scan clock in this candidate'
    if reason:
        return ('ECO plan test-clock source '+name+' is '+reason+'. Consumer='+consumer['name']+
                '; task scan clocks='+str(contract['task_scan_clocks'])+
                '; candidate clock declarations='+str(contract['configured_scan_clocks'])+
                '; legal literal port choices='+str(contract['legal_literal_clock_port_choices'])+
                '. Keep the functional branch and consumer net; choose the test source from task/config/native evidence. No ECO executed.')
    return None


def native_clock_guard(b, handles, contract):
    """Fresh native names/types checked immediately before any splice mutation.

    Derived pin sources are not guessed equivalent to a clock; existing native
    DRC/structural/EQY gates still determine their validity.
    """
    if not contract.get('clock_consumer_pins'):return ''
    _,c,t,_=handles
    literal=lambda names:' '.join('{'+n+'}' for n in names)
    tests=[]
    if contract['exclusive_task_clock_domain']:
        tests.append(f'${t}names ni {{{literal(contract["task_scan_clocks"])}}}')
    if contract['configuration_literal_scope_known']:
        tests.append(f'${t}names ni {{{literal(contract["configured_scan_clocks"])}}}')
    if not tests:return ''
    return f'''if {{${b}state eq "observed_types_only" && ${c}names in {{{literal(contract['clock_consumer_pins'])}}} && ${t}classes eq "port" && ({' || '.join(tests)})}} {{set {b}state test_clock_mismatch}}
puts "ECO_PLAN_CLOCK_ROLE|{b}|consumer=${c}names|test=${t}names|allowed={','.join(contract['legal_literal_clock_port_choices'])}|status=${b}state"
'''


def _sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def _digest(v):return hashlib.sha256(json.dumps(v,sort_keys=True).encode()).hexdigest()


class DefectLedger:
    """Observed DRC groups persist across partial/unknown rounds. Not audit items."""
    def __init__(self):self.key=None;self.source=None;self.items={}

    def observe(self,ctx,record,words_for):
        from eco_structure import source_design
        key=_digest({'inputs':ctx.inputs,'output':str(ctx.output),'input':str(ctx.input_dir)})
        if self.key!=key:
            self.source=source_design(ctx.originals,ctx.libs,ctx.spec,ctx.original)
            self.items={};self.key=key
        library,original=self.source
        if record.get('native_inputs_and_design_bound') is not True or record.get('designs')!=[original['top']]:
            return self.view(ctx,record,False,words_for)
        reports=record.get('native_diagnostic_report_sources',[])
        current=[];zero_reports=[]
        snapshot=record.get('current_native_drc',{})
        if snapshot.get('status')=='clean' and snapshot.get('run_ref')==ctx.rid:
            zero_reports.extend(snapshot.get('summaries',[]))
        for ref in reports:
            p=ctx.output/ref['source']
            if not p.is_file() or p.is_symlink() or _sha(p)!=ref['sha256']:continue
            if p.stat().st_size>1024*1024:continue
            text=p.read_text(errors='replace');lines=text.splitlines()
            totals=re.findall(r'(?m)^Total violations:\s*(\d+)',text)
            historical = ref.get('phase')=='before_later_state_change'
            # A report may contain cached results. Only the bound native
            # post-change snapshot above establishes current DRC clear.
            for n,line in enumerate(lines,1):
                match=re.search(r"Clock input '([^']+)' of 'DFF' '([^']+)' .*?\((DFTR\d+)-\d+\)",line)
                if not match:continue
                pin,name,rule=match.groups();cell=original['cells'].get(name)
                if cell is None or not library[cell['type']]['ffs'] or pin not in cell['pins']:continue
                clock=original['graph'].resolve(cell['pins'][pin]);members=[]
                for obj,c in original['cells'].items():
                    clocks={x for ff in library[c['type']]['ffs'] for x in re.findall(r'[A-Za-z_]\w*',ff['properties'].get('clocked_on',''))}
                    for cp in clocks:
                        if original['graph'].resolve(c['pins'].get(cp))==clock:members.append(obj+'/'+cp)
                group=_digest({'design':original['top'],'rule':rule,'original_clock_driver':clock})
                native_count=None
                following=lines[n:n+1]
                if following and (same:=re.search(r'There were (\d+) other cells with the same violation',following[0])):native_count=int(same[1])+1
                icgs=[]
                for obj,c in original['cells'].items():
                    shape=library[c['type']]
                    if not shape['icg']:continue
                    outs=[p for p,v in shape['pins'].items() if v.get('direction')=='output']
                    if not any(original['graph'].resolve(c['pins'].get(p))==clock for p in outs):continue
                    icgs.append({'object':obj,'cell':c['type'],'source':{'path':c['source'],'line':c['line']},
                        'input_pins':[{'object':obj+'/'+p,'net':c['pins'].get(p),'driver':original['graph'].resolve(c['pins'].get(p)),
                          'Liberty':v} for p,v in shape['pins'].items() if v.get('direction')=='input'],
                        'meaning':'Actual source gate pins/drivers, not a preselected repair endpoint'})
                evidence={'source':ref['source'],'sha256':ref['sha256'],'line':n,'excerpt':line,'run_ref':ctx.rid,'design':original['top']}
                entry=self.items.setdefault(group,{'group':group,'rule':rule,'representative':name+'/'+pin,'original_clock_driver':clock,
                    'connected_original_FF_clock_pins':sorted(members),'native_group_count':native_count,
                    'group_expansion':'same original clock driver; not claimed a complete native object list' if native_count!=len(members) else 'native group count agrees with exact original clock-net membership',
                    'related_ICGs':icgs,'library_sources':[{'path':str(p),'sha256':_sha(p)} for p in ctx.libs],'first_observed':evidence})
                entry.update(last_observed=evidence,last_seen_round=ctx.rid)
                if not historical:current.append(group)
        for k,v in self.items.items():
            v['current_DRC_observation']='reported_unresolved' if k in current else 'native_DRC_clear_separate_proof_required' if zero_reports and not current else 'not_reobserved_not_proven_resolved'
            if zero_reports and not current:v['latest_native_clear']={'run_ref':ctx.rid,'reports':zero_reports}
        return self.view(ctx,record,True,words_for)

    def view(self,ctx,record,bound,words_for):
        # Proposed plans stay separate from native completed plans and DRC.
        from eco_object_selection import restore
        refs={};proposed=[]
        for chunk in _chunks(restore(ctx.script)):
            code=chunk.strip().rstrip(';').strip();w=words_for(code) if code and not code.startswith('#') else []
            if w[:1]==['eco_ref'] and (sel:=reference_selection(code,words_for)):refs[w[1]]=sel
            if w[:2]==['eco_link','mode_mux'] and len(w)==9:
                proposed.append({'command':code,'consumer':refs.get(w[3].lstrip('$')),'test_source':refs.get(w[4].lstrip('$')),
                    'scope':'proposed, not native execution'})
        native=[]
        allowed_operations={}
        prefix=re.search(r'(?m)^set (__eco_sel_[0-9a-f]{12}_)epoch 0$',ctx.script)
        if prefix:
            for check in record.get('object_contract',[]):
                if check.get('option')=='preserve_function_mode_splice' and check.get('state')=='observed_types_only' and re.fullmatch(r'C[1-9]\d*',check.get('id','')):
                    allowed_operations[prefix[1]+check['id'][1:]+'_']=check
        log=ctx.run/(ctx.rid+'.log')
        if bound and log.is_file():
            lines=log.read_text(errors='replace').splitlines();opened={}
            for n,line in enumerate(lines,1):
                m=re.fullmatch(r'ECO_PLAN_BEGIN\|([^|]+)\|driver=([^|]+)\|consumer=([^|]+)\|net=([^|]+)\|functional_mode=(.+)',line)
                if m and m[1] in allowed_operations:opened[m[1]]={'driver':m[2],'consumer':m[3],'net':m[4],'begin_line':n}
                m=re.fullmatch(r'ECO_PLAN_END\|([^|]+)\|.*',line)
                if m and m[1] in opened:native.append({**opened[m[1]],'end_line':n,'log':str(log.relative_to(ctx.output)),'run_ref':ctx.rid})
        rows=[]
        for e in self.items.values():
            targets=set(e['connected_original_FF_clock_pins']) | {p['object'] for g in e['related_ICGs'] for p in g['input_pins']}
            p=[x for x in proposed if x['consumer'] and x['consumer']['name'] in targets]
            operations=[x for x in native if x['consumer'] in targets]
            rows.append({**e,'proposed_operations':p,'native_completed_operations':operations,
                'state':('unresolved_DRC' if e['last_seen_round']==ctx.rid and e['current_DRC_observation']=='reported_unresolved' else 'native_DRC_clear_separate_proof_required' if e.get('latest_native_clear',{}).get('run_ref')==ctx.rid else 'unknown_current_not_closed') if bound else 'unknown_current_not_closed',
                'next_evidence_needed':('Native DRC is clear in this round; retain this candidate and independently verify the bound pre-scan export, full EQY, coverage and delivery. Worklist clearing is not a functional proof.' if bound and e.get('latest_native_clear',{}).get('run_ref')==ctx.rid else 'Task-valid current control/clock selection and real ECO on affected connection; fresh native DRC and bound pre-scan export, then full EQY. Configuration/polarity edits alone do not prove connection repair.')})
        return {'kind':'native_defect_worklist_not_audit_closure','current_round':ctx.rid,'current_native_input_binding':bound,
                'groups':rows,'current_candidate_clock_roles':clock_contract(ctx.spec,restore(ctx.script),words_for,self.source[1],self.source[0]) if self.source else None,
                'all_defects_proven_repaired':False,'meaning':'A completed splice is only an operation; every observed defect remains open until fresh native evidence and existing final checks prove completion. Unknown never deletes history.'}


def gate_control_contract(spec, script, words_for, design, library, libs):
    """Finite actual Liberty gate truth + task/config levels; no selected repair.

    Enumerates all other input combinations for a complete low/high clock
    cycle with actual hold state. Unknown/duplicate/inverting semantics abstain.
    """
    from itertools import product
    from eco_structure import requirements
    from eco_equivalence import _nodes,_cells,_arguments,_state_table
    from partial_insertion_validation import _boolean
    req=requirements(spec)
    result={'icg_test_controls':[],'candidate_control_port_levels':{},'functional_modes':req['functional_modes'],
            'meaning':'Facts and selectable operands only. Fresh native references/driver checks, real splice, EQY and DRC remain required.'}
    if not req['required'] or design is None:return result
    levels={};ambiguous=set()
    for chunk in _chunks(script):
        w=words_for(chunk.strip())
        if w[:1]!=['set_scan_signal'] or len(w)%2!=1:continue
        vals=[_literal(x) for x in w[1:]]
        if any(x is None for x in vals):continue
        o=dict(zip(vals[::2],vals[1::2]));p=o.get('-port');level=None
        if o.get('-type')=='constant' and o.get('-constant_value') in {'0','1'}:level=int(o['-constant_value'])
        if o.get('-type')=='scan_enable' and o.get('-usage') in {'all','clock_gating'} and o.get('-off_state') in {'0','1'}:level=1-int(o['-off_state'])
        if p and level is not None:
            if p in levels:ambiguous.add(p)
            levels[p]={'level':level,'command':chunk.strip(),'kind':o['-type']}
    levels={k:v for k,v in levels.items() if k not in ambiguous};result['candidate_control_port_levels']=levels
    types={c['type'] for c in design['cells'].values() if library[c['type']]['icg']};definitions={}
    for path in libs:
        for cell in _cells(_nodes(path.read_text())):
            names=_arguments(cell['args'])
            if len(names)==1 and names[0] in types:definitions.setdefault(names[0],[]).append((path,cell))
    for name,cell in sorted(design['cells'].items()):
        shape=library[cell['type']]
        if not shape['icg']:continue
        row={'instance':name,'cell_type':cell['type'],'status':'unknown','source':{'path':cell['source'],'line':cell['line']},'test_pins':[]}
        try:
            defs=definitions.get(cell['type'],[])
            if len(defs)!=1:raise ValueError('Library definition not unique')
            path,definition=defs[0];pins={_arguments(n['args'])[0]:n['props'] for n in definition['children'] if n['name']=='pin'}
            clocks=[p for p,v in pins.items() if v.get('clock_gate_clock_pin')=='true'];outs=[p for p,v in pins.items() if v.get('clock_gate_out_pin')=='true'];tests=[p for p,v in pins.items() if v.get('clock_gate_test_pin')=='true'];tables=[n for n in definition['children'] if n['name']=='statetable']
            if len(clocks)!=1 or len(outs)!=1 or not tests or len(tables)!=1:raise ValueError('Unsupported gate role/table shape')
            _,_,sem=_state_table(tables[0],[p for p,v in pins.items() if v.get('direction')=='input']);factor=sem.get('transparent_enable_factorization');clock=clocks[0];out=outs[0]
            if not factor or factor['enable_pin']!=clock:raise ValueError('Unsupported clock hold semantics')
            phase=factor['enable_value'];expression=pins[out].get('function',pins[out].get('state_function',''))
            for test in tests:
                legal=[];checks=[]
                for level in (0,1):
                    good=True;other=[p for p in sem['inputs'] if p not in {clock,test}]
                    if len(other)>6:raise ValueError('Gate enumeration exceeds finite scope')
                    for values in product((0,1),repeat=len(other)):
                        data={**dict(zip(other,values)),test:level};a={**data,clock:phase};b={**data,clock:1-phase};low=sem['truth'][''.join(str(a[p]) for p in sem['inputs'])];hold=sem['truth'][''.join(str(b[p]) for p in sem['inputs'])]
                        if low not in {'L','H'} or hold!='N':good=False;break
                        bit=int(low=='H');ys=[_boolean(expression,{**v,sem['state']:bit}) for v in (a,b)]
                        if any(y is None or y[0] for y in ys) or [y[1][0] for y in ys]!=[phase,1-phase]:good=False;break
                    if good:legal.append(level)
                driver=design['graph'].resolve(cell['pins'].get(test))
                choices=[{'kind':'port','name':p,'test_level':v['level'],'declaration':v['command']} for p,v in levels.items() if v['level'] in legal]
                row['test_pins'].append({'object':name+'/'+test,'direction':pins[test]['direction'],'original_net':cell['pins'].get(test),'original_driver':driver,'guaranteed_clock_propagating_levels':legal,'legal_declared_port_choices':choices})
            row.update(status='complete',library={'path':str(path),'sha256':_sha(path)},state_semantics=sem,
                output={'pin':out,'state_function':expression},mode_constraints={'functional':req['functional_modes'],'scan':req['scan_modes']})
        except (ValueError,KeyError,TypeError,IndexError,RuntimeError) as exc:row['unknown_reason']=str(exc)
        result['icg_test_controls'].append(row)
    return result


def control_choice_problem(consumer, source, contract):
    if not consumer or not source or source.get('kind')!='port':return None
    tests=[p for g in contract.get('icg_test_controls',[]) if g['status']=='complete' for p in g['test_pins'] if p['object']==consumer['name']]
    if len(tests)!=1:return None
    levels=contract.get('candidate_control_port_levels',{});value=levels.get(source['name'])
    if value is not None and value['level'] not in tests[0]['guaranteed_clock_propagating_levels']:
        return ('Selected test-control level does not propagate the actual Liberty clock for '+consumer['name']+
            '; source='+source['name']+' level='+str(value['level'])+'; proven acceptable levels='+str(tests[0]['guaranteed_clock_propagating_levels'])+
            '; task/config-derived port choices='+str(tests[0]['legal_declared_port_choices'])+'. Preserve functional driver and consumer net using mode_mux; no connection executed.')
    return None


def native_control_guard(b, handles, contract):
    _,consumer,test,_=handles;parts=[]
    for gate in contract.get('icg_test_controls',[]):
        if gate['status']!='complete':continue
        for pin in gate['test_pins']:
            bad=[p for p,v in contract.get('candidate_control_port_levels',{}).items()
                 if v['level'] not in pin['guaranteed_clock_propagating_levels']]
            if not bad:continue
            names=' '.join('{'+p+'}' for p in bad)
            parts.append(f'if {{${b}state eq "observed_types_only" && ${consumer}names eq {{{pin["object"]}}} && ${test}classes eq "port" && ${test}names in {{{names}}}}} {{set {b}state test_control_level_mismatch}}')
    return '\n'.join(parts)+'\n' if parts else ''
