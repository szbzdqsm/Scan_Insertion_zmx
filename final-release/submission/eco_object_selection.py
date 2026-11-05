"""Bounded internal query/reference/connection compiler, not a repair oracle.

Only native read-only queries establish type/count/identity. Every connection
gets a fresh checked handle. Unknown expressions never fall back to raw Tcl.
"""
from __future__ import annotations

import hashlib
import re
from clock_association_recipe import _chunks
from eco_structure import MUTATIONS

BEGIN = '# Agent ECO object selection'
END = '# End agent ECO object selection'
ORIGINAL = '# Original ECO command hex: '
BAD = {'empty', 'wrong_type', 'ambiguous_source', 'unresolved', 'stale_reference', 'hierarchy_mismatch', 'driver_mismatch', 'occupied_target', 'mode_constraint_missing', 'preparation_collision', 'native_operation_failed', 'plan_required', 'test_clock_mismatch', 'test_control_level_mismatch'}
READ_ONLY = {'get_obj_pins', 'get_obj_ports', 'get_obj_nets', 'list', 'lindex', 'format'}


def is_context_query(code):
    """Exact generated read-only query, never a design change or config body."""
    return bool(re.fullmatch(r'if \{\[catch \{set ((?:__eco_sel_[0-9a-f]{12}_\d+_|__agent_icg_protection_))design '
        r'\[get_property \[present_design\] full_name\]\}\]\} \{set \1state unresolved\}', code.strip()))


def restore(script):
    def original(m):
        rows = [l[len(ORIGINAL):] for l in m[0].splitlines() if l.startswith(ORIGINAL)]
        return bytes.fromhex(rows[0]).decode() if len(rows) == 1 else ''
    return re.sub(r'(?ms)^'+re.escape(BEGIN)+r'\n.*?^'+re.escape(END)+r'(?:\n|$)', original, script)


def _literal_argument(word):
    r"""Recognize inert Tcl punctuation escapes without interpreting them.

    Preserve the complete native expression: Tcl, then the getter's -exact
    option, decide its value and matching semantics. Unescaped substitution,
    composite quoting, continuation and other escape forms stay unresolved.
    In particular, path[0] is not silently converted into path\\[0\\].
    """
    if word.startswith('"') and word.endswith('"') and len(word) >= 2:
        word = word[1:-1]
    index = 0
    while index < len(word):
        char = word[index]
        if char == '\\':
            index += 1
            if index == len(word) or word[index] not in '\\[]$;{}" *?':
                return False
        elif char in '$[];{}"\r\n':
            return False
        index += 1
    return True


def _readonly(expr, words_for):
    """Whitelist nested immutable expressions; never eval or run Python Tcl."""
    if re.fullmatch(r'\$(?:[A-Za-z_]\w*|\{[A-Za-z_]\w*\})', expr):
        return True
    if not (expr.startswith('[') and expr.endswith(']')):
        return False
    w = words_for(expr[1:-1])
    if not w or w[0] not in READ_ONLY:
        return False
    for word in w[1:]:
        if word.startswith('{') and word.endswith('}'):
            continue
        if word.startswith('['):
            if not _readonly(word, words_for): return False
        elif re.fullmatch(r'\$(?:[A-Za-z_]\w*|\{[A-Za-z_]\w*\})', word):
            continue
        elif not _literal_argument(word):
            return False
    return True


def _physical(text):
    return ''.join(c if c.lstrip().startswith('#') else c.strip().replace('\n', '; ')+'\n' for c in _chunks(text))


def _selector(expr, words_for):
    return _readonly(expr, words_for) and bool(re.search(r'\[get_obj_(?:pins|ports|nets)\b', expr))


def instrument(script, words_for, *, failure_snapshot, library=None, task_spec="", protected_drivers=(), original_design=None, control_roles=None):
    if BEGIN in script or re.search(r'[{}\r\n]', str(failure_snapshot)):
        raise ValueError('Invalid/repeated object selection compilation')
    chunks=_chunks(script)
    def canonical(name):
        name=name.removeprefix('::')
        targets=[x for x in ['connect_pin','connect_net','disconnect_net','connect_pg_net','eco_ref','eco_link'] if x.startswith(name)]
        return targets[0] if len(targets)==1 else name
    heads=[words_for(c.strip().rstrip(';').strip())[0] for c in chunks
           if c.strip() and not c.lstrip().startswith('#') and words_for(c.strip().rstrip(';').strip())]
    if not (re.search(r'\b(?:connect_pin|connect_net|disconnect_net|eco_ref|eco_link)\b', script) or
            any(canonical(h) in {'connect_pin','connect_net','disconnect_net','eco_ref','eco_link'} or re.search(r'[$\[]',h) or
                h.removeprefix('::') in {'connect','connect_','connect_p'} for h in heads)):
        return script, {'checks': [], 'unknown': [], 'selector_version': 2, 'failure_snapshot': str(failure_snapshot)}
    p = '__eco_sel_'+hashlib.sha256(script.encode()).hexdigest()[:12]+'_'
    if '__eco_sel_' in script:
        raise ValueError('Reserved selection state cannot be supplied by model')
    plan = {'checks': [], 'unknown': [], 'connections': [], 'selector_version': 2, 'failure_snapshot': str(failure_snapshot),
            'source_sha256':hashlib.sha256(script.encode()).hexdigest(),
            'meaning': 'Fresh native objects and legal argument contract only, NOT topology/EQY/task success'}
    from eco_constant_source import intent_plan, creation, lookup
    constant_creations, constant_queries = intent_plan(chunks, words_for)
    from eco_plan_ownership import declarations, preflight, FIELDS,HIERARCHY_FIELDS
    preparation_declarations, preparation_plans = declarations(chunks, words_for)
    if preparation_plans:plan['preparation_ownership'] = {'policy':'mode_mux is the sole creator; exact unused source declarations defer, no native existing-object adoption','plans':list(preparation_plans.values())}
    counter = 0
    def block(original, body):
        return BEGIN+'\n'+(ORIGINAL+original.encode().hex()+'\n' if original else '')+_physical(body)+END+'\n'
    def obs(e, b):
        fields='design n classes names drivers state'+(' '+FIELDS+' '+HIERARCHY_FIELDS if e.get('preparation_group') else '')+(' instance_n instance_name instance_ref all_pin_names all_pin_directions output_direction' if e.get('constant_source') else '')
        return f'''puts ECO_OBJECT_OBSERVATION_BEGIN|{e['id']}
foreach {b}field {{{fields}}} {{
 if {{![info exists {b}${b}field]}} {{set {b}${b}field unknown}}
 binary scan [encoding convertto utf-8 [set {b}${b}field]] H* {b}hex
 puts "ECO_OBJECT_OBSERVATION|{e['id']}|${b}field|${b}hex"
}}
if {{${b}state in {{empty wrong_type ambiguous_source unresolved stale_reference hierarchy_mismatch driver_mismatch occupied_target mode_constraint_missing preparation_collision native_operation_failed plan_required test_clock_mismatch}}}} {{
 puts OBJECT_FAILURE_BEGIN_{e['id']}
 dump_netlist -file {{{failure_snapshot}}}
 puts OBJECT_FAILURE_END_{e['id']}
 puts [format {{%cERROR%c %cAGENT-ECO-OBJECT%c {e['id']} %s}} 91 93 91 93 ${b}state]
 flush stdout
 exit
}}
'''
    def query(expression, command, role, required, *, ref=False, unknown=False, emit=True, constant=None):
        nonlocal counter
        counter += 1; b=p+str(counter)+'_'
        e={'id':'C'+str(counter),'command':command,'original_line':line,'option':role,
           'expression':expression,'query_expression':expression if not ref else None,
           'required_types':required,'single_source':True,'static_state':'requires_native_resolution',
           'reference_operand':ref}
        if constant:
            e['constant_source']=constant
            e['source_expression']=expression
            e['query_expression']=f'[get_obj_pins -of ${b}instance -filter {{direction == out}}]'
            e['resolution_basis']='explicit new constant source role; query actual unique output, no getter fallback'
        plan['checks'].append(e)
        body=f'''set {b}state observed_types_only
set {b}design unknown
set {b}n unknown
set {b}classes {{}}
set {b}names {{}}
set {b}h {{}}
if {{[catch {{set {b}design [get_property [present_design] full_name]}}]}} {{set {b}state unresolved}}
'''
        if constant:
            body+=lookup(b,p,constant)
        elif unknown:
            body+=f'set {b}state unresolved\n'
            plan['unknown'].append({**e,'reason':'Expression/scope cannot be resolved without arbitrary evaluation; no raw fallback'})
        elif ref:
            body+=f'''if {{[catch {{set {b}token {expression}}}] || ![dict exists ${p}refs ${b}token]}} {{
 set {b}state unresolved
}} else {{
 set {b}r [dict get ${p}refs ${b}token]
 if {{[lindex ${b}r 0] != ${p}epoch || [lindex ${b}r 1] ne ${b}design}} {{
  set {b}state stale_reference
 }} else {{
  set {b}priorclass [lindex ${b}r 2]
  set {b}priorname [lindex ${b}r 3]
  if {{${b}priorclass eq "pin"}} {{set {b}h [get_obj_pins -exact [list ${b}priorname]]}} elseif {{${b}priorclass eq "port"}} {{set {b}h [get_obj_ports -exact [list ${b}priorname]]}} elseif {{${b}priorclass eq "net"}} {{set {b}h [get_obj_nets -exact [list ${b}priorname]]}} else {{set {b}state unresolved}}
 }}
}}
'''
        else:
            body+=f'if {{[catch {{set {b}h {expression}}}]}} {{set {b}state unresolved}}\n'
        body+=f'''if {{${b}state eq "observed_types_only"}} {{
 if {{[catch {{set {b}n [sizeof_collection ${b}h]}}]}} {{set {b}state unresolved}}
 if {{${b}n eq "0"}} {{set {b}state empty}}
 if {{[string is integer -strict ${b}n] && ${b}n > 1}} {{set {b}state ambiguous_source}}
 if {{${b}n eq "1"}} {{
  if {{[catch {{set {b}classes [get_property ${b}h object_class]; set {b}names [get_property ${b}h full_name]}}]}} {{set {b}state unresolved}}
  if {{${b}state eq "observed_types_only" && ${b}classes ni {{{' '.join(required)}}}}} {{set {b}state wrong_type}}
 }}
}}
'''
        if constant:
            body+=f'''if {{${b}state eq "observed_types_only" && ![string is integer -strict ${b}n]}} {{set {b}state unresolved}}
if {{${b}state eq "observed_types_only" && ${b}n eq "1"}} {{
 if {{[catch {{set {b}output_direction [get_property ${b}h direction]}}]}} {{set {b}state unresolved}}
 if {{${b}state eq "observed_types_only" && ${b}output_direction ne "out"}} {{set {b}state wrong_type}}
}}
'''
        if ref:
            body+=f'''if {{${b}state eq "observed_types_only" && (${b}classes ne ${b}priorclass || ${b}names ne ${b}priorname)}} {{set {b}state stale_reference}}
'''
        return e,b,body+(obs(e,b) if emit else '')

    def unresolved(original):
        e,b,body=query('{}',original.strip(),'operation',[],unknown=True)
        return block(original,body)

    # Redefinition, nested operations and computed command names cannot evade
    # the bounded compiler. This is unresolved, not proof of a bad topology.
    unsafe=bool(re.search(r'(?:^|[\n;{\[])\s*(?:::)?(?:proc|rename|interp|source|eval|uplevel|namespace|trace|apply|exec)\b',script))
    scope_reasons=[]; scope_offset=0
    for c in chunks:
        code=c.strip().rstrip(';').strip();w=words_for(code) if code and not code.startswith('#') else []
        scope_line=script[:scope_offset + len(c)-len(c.lstrip())].count('\n')+1
        scope_offset += len(c)
        if w and (re.search(r'[$\[]',w[0]) or w[0].removeprefix('::') in {'connect','connect_','connect_p'} or
                    (canonical(w[0]) not in {'connect_pin','connect_net','disconnect_net','eco_ref','eco_link'} and
                     re.search(r'\b(?:connect_pin|connect_net|disconnect_net|eco_ref|eco_link)\b',code))):
            unsafe=True
            scope_reasons.append({'source_line':scope_line,'command':code[:1600],
                'command_sha256':hashlib.sha256(code.encode()).hexdigest(),
                'reason':'Nested/computed connection scope cannot be safely resolved by the bounded compiler'})
    line=1
    if unsafe:
        plan['scope_unresolved'] = True
        plan['rejected_scope_fragments'] = scope_reasons[:4]
        return unresolved(script),plan
    setup=f'set {p}epoch 0\nset {p}session [format {{%s_%s}} [pid] [clock clicks]]\nset {p}refs {{}}\n'
    if constant_creations:setup+=f'set {p}constants {{}}\n'
    result=[block('',setup)]
    from eco_plan_semantics import clock_contract, reference_selection, clock_choice_problem
    semantic_roles=clock_contract(task_spec,script,words_for,original_design,library)
    if control_roles:semantic_roles.update(control_roles)
    plan['clock_role_contract']=semantic_roles
    references={}
    bindings={};declared=set();position=0
    for chunk_index,c in enumerate(chunks):
        code=c.strip().rstrip(';').strip();line=script[:position].count('\n')+1;position+=len(c)
        w=words_for(code) if code and not code.startswith('#') else []
        if not w:result.append(c);continue
        name=canonical(w[0])
        if name=='set' and len(w)>=2:
            bindings.pop(w[1],None);declared.discard(w[1]);references.pop(w[1],None)
            if len(w)==3 and _selector(w[2],words_for):bindings[w[1]]=w[2]
            elif len(w)==3 and re.fullmatch(r'\$[A-Za-z_]\w*',w[2]) and w[2][1:] in bindings:
                bindings[w[1]]=bindings[w[2][1:]]
        elif name=='if':
            # The common pure cardinality/error guard does not reassign Tcl
            # collection variables; other evaluated bodies invalidate origins.
            if re.search(r'\b(?:set|unset|append|lappend|incr|foreach|for|while|eval|source)\b',code):bindings.clear()
        elif name in {'present_design','load_netlist','load_db','delete_inst','delete_net','delete_port'}:
            bindings.clear()
        if chunk_index in preparation_declarations:
            info=preparation_declarations[chunk_index]
            body=''
            for group in info['groups']:
                e,b,q=query('{}',code,'plan_owned_preparation',[],emit=False)
                e['preparation_group']=group
                e['meaning']='Declaration deferred; not executed; plan will create only after full native group check'
                body+=f'''set {b}state observed_types_only
set {b}design unknown
set {b}n unknown
set {b}classes {{}}
set {b}names {{}}
if {{[catch {{set {b}design [get_property [present_design] full_name]}}]}} {{set {b}state unresolved}}
'''+f'set {b}preparation_instruction {{source declaration deferred; no creation or connection executed; resolve parent and check entire group at mode_mux with fresh native endpoint references}}\n'+obs(e,b)
            if info['remaining_nets']:
                body+='add_net {'+' '.join(info['remaining_nets'])+'}\n'+f'incr {p}epoch\n'
            result.append(block(c,body));continue
        if chunk_index in constant_creations:
            counter+=1; b=p+str(counter)+'_'; info=constant_creations[chunk_index]
            e={'id':'C'+str(counter),'command':code,'original_line':line,
               'option':'create_virtual_constant','required_types':['cell'],
               'constant_source':info,'single_source':True,'static_state':'requires_native_resolution'}
            plan['checks'].append(e)
            result.append(block(c,creation(b,p,info,code,obs(e,b))))
            continue
        if name=='eco_ref':
            if len(w)!=3 or not re.fullmatch(r'[A-Za-z_]\w*',w[1]) or not (w[2].startswith('{') and w[2].endswith('}')):
                result.append(unresolved(c));continue
            expression='['+w[2][1:-1]+']'
            info=constant_queries.get(chunk_index)
            e,b,body=query(expression,code,'query',['pin'] if info else ['pin','port','net'],
                unknown=not _selector(expression,words_for),constant=info)
            body+=f'''set {b}token [format {{%s_%s}} ${p}session {{{e['id']}}}]
dict set {p}refs ${b}token [list ${p}epoch ${b}design ${b}classes ${b}names]
set {w[1]} ${b}token
foreach {b}field {{token}} {{
 if {{![info exists {b}${b}field]}} {{set {b}${b}field unknown}}
 binary scan [encoding convertto utf-8 [set {b}${b}field]] H* {b}hex
 puts "ECO_OBJECT_REFERENCE|{e['id']}|${b}field|${b}hex"
}}
puts "ECO_OBJECT_REFERENCE|{e['id']}|epoch|${p}epoch"
'''
            result.append(block(c,body));declared.add(w[1]);bindings.pop(w[1],None);references[w[1]]=reference_selection(code,words_for)
            if info:references[w[1]]={'kind':'pin','virtual_constant':info}
            continue
        if name=='eco_link' and len(w)>1 and w[1]=='mode_mux':
            if len(w)!=9:
                raise ValueError('eco_link mode_mux DRIVER_REF CONSUMER_REF TEST_REF MODE_REF CELL INSTANCE FUNCTIONAL_NET')
            from eco_connection_plan import mux_contract, splice
            roles=mux_contract(w[6].strip('{}'), library or {}, task_spec)
            consumer=references.get(w[3].lstrip('$'));source=references.get(w[4].lstrip('$'))
            # Known literal original ports can be rejected before any native call.
            # Dynamic selectors keep their fresh runtime name/type check below.
            if original_design and source and source['kind']=='port' and source['name'] in original_design['modules'][original_design['top']]['ports']:
                problem=clock_choice_problem(consumer,source,semantic_roles)
                if problem:raise ValueError(problem)
            from eco_plan_semantics import control_choice_problem
            problem=control_choice_problem(consumer,source,semantic_roles)
            if problem:raise ValueError(problem)
            handles=[];body=''
            for expression,role,types in zip(w[2:6],['driver','consumer','test','mode'],[['pin'],['pin'],['pin','port'],['port']]):
                e,b,q=query(expression,code,role,types,ref=True)
                body+=q;handles.append(b)
            e,b,q=query(w[3],code,'preserve_function_mode_splice',['pin'],ref=True,emit=False)
            body+=q
            e['preparation_group']=preparation_plans[chunk_index]
            e['plan_semantics']={k:v for k,v in semantic_roles.items() if k!='clock_consumer_pins'}
            e['hierarchy_policy']='bare resources local to unique native common endpoint parent; explicit paths checked; shared definitions rejected'
            body+=splice(b,handles,*[v.strip('{}') for v in w[6:9]],roles,obs(e,b),semantic_roles,constant_source=bool(source and source.get('virtual_constant')),expected_design=original_design.get('top') if original_design else None,registry=p)
            body+=f'incr {p}epoch\n'
            plan['connections'].append({'operation':'mode_mux','original_command':code,'original_line':line,
                'contract':roles,'generated_by':'task-mode and Liberty truth table; native single driver/consumer binding'})
            result.append(block(c,body));continue
        isref=name=='eco_link'
        if isref:
            if len(w)!=4 or w[1] not in {'connect_pin','connect_net'}:
                result.append(unresolved(c));continue
            kind,a,b=w[1:];options=[]
        elif name=='connect_pin':
            if w.count('-from')!=1 or w.count('-to')!=1:
                result.append(unresolved(c));continue
            pairs=w[1:];opts={};options=[];valid=True
            while pairs:
                option=pairs.pop(0)
                if option=='-verbose':options.append('-verbose');continue
                if option not in {'-from','-to','-port_name'} or not pairs:valid=False;break
                value=pairs.pop(0)
                if option in opts:valid=False;break
                opts[option]=value
                if option=='-port_name':
                    if re.search(r'[$\[\]\\;{}\r\n]',value):valid=False;break
                    options+=['-port_name',value]
            if not valid:result.append(unresolved(c));continue
            kind,a,b=name,opts['-from'],opts['-to']
        elif name in {'connect_net','disconnect_net'}:
            if len(w)!=3:result.append(unresolved(c));continue
            kind,a,b=name,w[1],w[2];options=[]
        else:
            result.append(c)
            if (name in MUTATIONS or name in {'load_lib','load_netlist','present_design','insert_dft_logic'} or
                    re.search(r'\b(?:'+'|'.join(sorted(MUTATIONS))+r')\b',code)):
                result.append(block('',f'incr {p}epoch\n'))
            continue
        def resolve(value,net=False):
            if isref:return value,False
            var=re.fullmatch(r'\$(?:([A-Za-z_]\w*)|\{([A-Za-z_]\w*)\})',value)
            if var:
                queryexpr=bindings.get(var[1] or var[2])
                # Refresh the original pure selector after intervening edits.
                # Never reuse or trust an unproven opaque collection handle.
                return queryexpr or '{}', queryexpr is None
            if net and not re.search(r'[$\[\]\\;\s{}"]',value):return '[get_obj_nets -exact {'+value+'}]',False
            return value,not _selector(value,words_for)
        ax,au=resolve(a,kind in {'connect_net','disconnect_net'});bx,bu=resolve(b)
        ae,ab,body=query(ax,code,'net' if kind in {'connect_net','disconnect_net'} else '-from',['net'] if kind in {'connect_net','disconnect_net'} else ['pin','port'],ref=isref,unknown=au)
        be,bb,more=query(bx,code,'objects' if kind in {'connect_net','disconnect_net'} else '-to',['pin','port'],ref=isref,unknown=bu,emit=kind not in {'connect_net','disconnect_net'})
        body+=more
        if kind in {'connect_net','disconnect_net'}:
            # Only issued eco_ref operands have been checked for current
            # design/epoch and refreshed by -exact [list $priorname], then
            # compared with their original native class/full_name. A literal
            # star in that identity is data, never a pattern or Tcl source.
            # Keep the original name restriction for raw selectors; execute
            # the checked collections and compute owners from unchanged names.
            name_pattern = (r'^[A-Za-z0-9_$/\.\[\]*-]+$' if isref
                            else r'^[A-Za-z0-9_$/\.\[\]-]+$')
            body+=fr'''if {{${bb}state eq "observed_types_only"}} {{
if {{![regexp {{{name_pattern}}} ${ab}names] || ![regexp {{{name_pattern}}} ${bb}names]}} {{set {bb}state unresolved}}
set {ab}owner [file dirname ${ab}names]
set {bb}owner [file dirname ${bb}names]
if {{${bb}classes eq "pin"}} {{set {bb}owner [file dirname ${bb}owner]}}
if {{${ab}owner ne ${bb}owner}} {{set {bb}state hierarchy_mismatch}}
}}
'''+obs(be,bb)
            native=f'{kind} ${ab}h ${bb}h\n'
        else:native=f'connect_pin -from ${ab}h -to ${bb}h'+(' '+' '.join(options) if options else '')+'\n'
        plan['connections'].append({'original_command':code,'original_line':line,'operation':kind,
            'generated_command':native.strip(),'left_check':ae['id'],'right_check':be['id'],
            'topology_selection':'explicit model operands; no net-to-pin, leaf, or member selection'})
        from eco_connection_plan import drivers
        topo=bb+'topo_'
        if kind=='connect_pin':
            body+=drivers(topo,bb+'h')
            body+=f'''set {bb}drivers ${topo}drivers
if {{(${ab}classes eq "pin" && [get_property ${ab}h direction] ne "out") || (${ab}classes eq "port" && [get_property ${ab}h direction] ne "in") || (${bb}classes eq "pin" && [get_property ${bb}h direction] ne "in") || (${bb}classes eq "port" && [get_property ${bb}h direction] ne "out")}} {{set {bb}state wrong_type}}
if {{[llength ${topo}drivers] > 0 && ${topo}drivers ne [list ${ab}names]}} {{set {bb}state {"plan_required" if protected_drivers else "occupied_target"}}}
'''+obs(be,bb)
        else:
            body+=f'''set {bb}drivers {{}}
foreach_in_collection {topo}p [get_obj_pins -leaf -of ${ab}h -filter {{direction == out}}] {{lappend {bb}drivers [get_property ${topo}p full_name]}}
foreach_in_collection {topo}p [get_obj_ports -of ${ab}h -filter {{direction == in}}] {{lappend {bb}drivers [get_property ${topo}p full_name]}}
if {{[get_property ${bb}h direction] eq "out" && [llength ${bb}drivers] > 0 && ${bb}drivers ne [list ${bb}names]}} {{set {bb}state {"plan_required" if protected_drivers else "occupied_target"}}}
'''+obs(be,bb)
        if protected_drivers:
            protected_literal = ' '.join('{'+v+'}' for v in sorted(protected_drivers))
            body+=f'set {bb}protected [list {protected_literal}]\n'
            if kind in {'connect_net','disconnect_net'}:
                body+=f'''if {{${bb}names in ${bb}protected && [get_property ${bb}h direction] eq "out"}} {{
set {bb}existing [get_obj_nets -of ${bb}h]
if {{[sizeof_collection ${bb}existing] > 0}} {{
set {bb}drivers [list ${bb}names]
if {{{'1' if kind=='disconnect_net' else '[get_property $'+bb+'existing full_name] ne $'+ab+'names'}}} {{set {bb}state plan_required}}
}}
}}
'''+obs(be,bb)
            elif kind=='connect_pin':
                body+=f'if {{${bb}state eq "occupied_target"}} {{set {bb}state plan_required}}\n'+obs(be,bb)
        # Keep the actual operation as a top-level native echo. Wrapping it
        # in `set result [connect...]` hides the mutation from strict stage trace.
        body+=native
        if kind=='connect_pin':
            post=bb+'after_'
            body+=drivers(post,bb+'h')
            body+=f'set {bb}drivers ${post}drivers\nif {{${post}drivers ne [list ${ab}names]}} {{set {bb}state native_operation_failed}}\n'
        else:
            body+=f'set {bb}after_nets [get_obj_nets -of ${bb}h]\nset {bb}after_names {{}}\nif {{[sizeof_collection ${bb}after_nets] > 0}} {{set {bb}after_names [get_property ${bb}after_nets full_name]}}\n'
            body+=f'if {{${ab}names {"in" if kind=="disconnect_net" else "ni"} ${bb}after_names}} {{set {bb}state native_operation_failed}}\n'
        body+=obs(be,bb)+f'incr {p}epoch\n'

        result.append(block(c,body))
    return ''.join(result),plan
