"""Single creator for literal, unused mode_mux preparation declarations.

No existing native object adoption. Low-level declarations owned by a plan are
lowered to read-only absence checks; the plan alone performs their creation.
Original text/positions remain in the production compiler provenance.
"""
import re
NAME=re.compile(r'^[A-Za-z_][A-Za-z0-9_/.]*$')
FIELDS='prep_instance_count prep_instance_names prep_instance_types prep_pin_connections prep_net_count prep_net_names prep_net_members preparation_instruction'
HIERARCHY_FIELDS='hierarchy_parent hierarchy_module hierarchy_instances hierarchy_ancestors hierarchy_error driver_instance consumer_instance resolved_instance resolved_wire creation_steps created_pin_names created_pin_directions hierarchy_instruction'

def resolve_parent(b,handles,instance,wire,expected_design=None):
    """Names suggest a scope; native ownership and instance/module queries prove it.

    A leaf resource name is local to the unique common parent of the selected
    driver/consumer. A supplied path is explicit and must match that parent.
    Shared module definitions are conservatively unsupported, never uniquified.
    """
    d,c,_,_=handles
    body=f'''set {b}state observed_types_only
set {b}creation_steps {{}}
set {b}hierarchy_ancestors {{}}
set {b}hierarchy_instances {{}}
set {b}hierarchy_instruction {{leaf plan resource names are local to the verified common parent; explicit resource paths must match it. No context switch, flattening, driver move or module uniquification is inferred.}}
'''
    if expected_design:
        body+=f'if {{${b}design ne {{{expected_design}}}}} {{set {b}state hierarchy_mismatch}}\n'
    body+=f'''if {{${b}state eq "observed_types_only" && [catch {{
 set {b}di [get_obj_insts -of ${d}h]
 set {b}ci [get_obj_insts -of ${c}h]
 if {{[sizeof_collection ${b}di] != 1 || [sizeof_collection ${b}ci] != 1}} {{error {{nonunique native endpoint instance}}}}
 set {b}driver_instance [get_property ${b}di full_name]
 set {b}consumer_instance [get_property ${b}ci full_name]
 if {{[get_property ${b}di object_class] ne "cell" || [get_property ${b}ci object_class] ne "cell" || [file dirname ${d}names] ne ${b}driver_instance || [file dirname ${c}names] ne ${b}consumer_instance}} {{error {{endpoint instance identity mismatch}}}}
 set {b}hierarchy_parent [file dirname ${b}driver_instance]
 if {{[file dirname ${b}consumer_instance] ne ${b}hierarchy_parent}} {{set {b}state hierarchy_mismatch}}
 set {b}hierarchy_module ${b}design
 set {b}scope ${b}hierarchy_parent
 set {b}all_instances [get_obj_insts -hier]
 while {{${b}state eq "observed_types_only" && ${b}scope ne "."}} {{
  set {b}parent_object [get_obj_insts -exact [list ${b}scope]]
  if {{[sizeof_collection ${b}parent_object] != 1 || [get_property ${b}parent_object object_class] ne "cell" || [get_property ${b}parent_object full_name] ne ${b}scope}} {{error {{parent instance unresolved}}}}
  set {b}definition [get_property ${b}parent_object ref_name]
  if {{${b}definition eq ""}} {{error {{parent definition unknown}}}}
  set {b}uses {{}}
  foreach_in_collection {b}a ${b}all_instances {{
   if {{[get_property ${b}a ref_name] eq ${b}definition}} {{lappend {b}uses [get_property ${b}a full_name]}}
  }}
  lappend {b}hierarchy_ancestors [list ${b}scope ${b}definition ${b}uses]
  if {{${b}scope eq ${b}hierarchy_parent}} {{set {b}hierarchy_module ${b}definition; set {b}hierarchy_instances ${b}uses}}
  if {{[llength ${b}uses] != 1 || [lindex ${b}uses 0] ne ${b}scope}} {{set {b}state hierarchy_mismatch; set {b}hierarchy_instruction {{shared module definition requires an explicit separately validated per-instance plan; no shared-definition mutation or implicit uniquification executed}}}}
  set {b}scope [file dirname ${b}scope]
 }}
 set {b}resolved_instance {{{instance}}}
 set {b}resolved_wire {{{wire}}}
 foreach {b}field {{resolved_instance resolved_wire}} {{
  set {b}v [set {b}${b}field]
  if {{[file dirname ${b}v] eq "."}} {{
   if {{${b}hierarchy_parent ne "."}} {{set {b}${b}field "${b}hierarchy_parent/${b}v"}}
  }} elseif {{[file dirname ${b}v] ne ${b}hierarchy_parent}} {{set {b}state hierarchy_mismatch}}
 }}
}} {b}hierarchy_error]}} {{set {b}state unresolved}}
'''
    return body

def literal(word):
    value=word[1:-1] if word.startswith('{') and word.endswith('}') else word
    return value if NAME.fullmatch(value) else None

def declarations(chunks,words_for):
    rows=[];scope=0
    for index,chunk in enumerate(chunks):
        code=chunk.strip().rstrip(';').strip();w=words_for(code) if code and not code.startswith('#') else []
        if w and w[0] in {'load_lib','load_netlist','load_db','present_design'}:scope+=1
        rows.append((code,w,scope))
    owners={};plans={}
    for index,(code,w,scope) in enumerate(rows):
        if len(w)!=9 or w[:2]!=['eco_link','mode_mux']:continue
        cell,inst,wire=[literal(x) for x in w[6:9]]
        if not all([cell,inst,wire]):continue # existing compiler rejects unsafe names
        group={'cell':cell,'instance':inst,'wire':wire,'plan_index':index,'scope':scope,'declarations':[]}
        for kind,name in [('instance',inst),('net',wire)]:
            key=(scope,kind,name)
            if key in owners:raise ValueError('mode_mux has duplicate preparation ownership for '+name+'; submit one plan per group, refresh references after design reload; no operation executed')
            owners[key]=index
        plans[index]=group
    declared={}
    for index,(code,w,scope) in enumerate(rows):
        kind=None;names=[];cell=None
        if len(w)==3 and w[0]=='add_inst' and literal(w[1]) and literal(w[2]):kind='instance';names=[literal(w[1])];cell=literal(w[2])
        elif len(w)==2 and w[0]=='add_net':
            text=w[1][1:-1] if w[1].startswith('{') and w[1].endswith('}') else w[1]
            names=text.split()
            if not names or not all(NAME.fullmatch(n) for n in names):continue
            kind='net'
        if kind is None:continue
        matches=[];remaining=[]
        for name in names:
            pi=owners.get((scope,kind,name))
            if pi is None:remaining.append(name);continue
            group=plans[pi]
            if index>=pi:raise ValueError('mode_mux owns '+name+'; a second low-level creation after the plan is not allowed; no operation executed')
            if kind=='instance' and cell!=group['cell']:raise ValueError('mode_mux preparation type differs: '+name+' declared '+str(cell)+' but plan requires '+group['cell']+'; no object adopted')
            for j in range(index+1,pi):
                other,ow,ss=rows[j]
                if not ow or ss!=scope or ow[0] in {'add_net','add_inst'}:continue
                if re.search(r'(?<![\w/.$])'+re.escape(name)+r'(?=$|[\s{}/\]";])',other):
                    raise ValueError('mode_mux preparation '+name+' is used before the plan at source chunk '+str(j)+'; cannot defer a real dependency; use a single creator and explicit references')
                if re.search(r'\b(?:get_obj_\w+|get_property|sizeof_collection)\b',other):
                    safe=False
                    if len(ow)==3 and ow[0]=='eco_ref' and ow[2].startswith('{') and ow[2].endswith('}'):
                        q=words_for(ow[2][1:-1])
                        selector=(q[2][1:-1] if len(q)==3 and q[2].startswith('{') and q[2].endswith('}') else '')
                        inert=bool(selector and re.fullmatch(r'[A-Za-z_][A-Za-z0-9_./\[\]-]*',selector)) or (len(q)==3 and literal(q[2]) is not None)
                        safe=len(q)==3 and q[0] in {'get_obj_pins','get_obj_ports','get_obj_nets'} and q[1] in {'-exact','-of'} and inert
                    if not safe:raise ValueError('mode_mux preparation '+name+' may be observed by a broad/dynamic query before the plan; cannot safely defer; choose one creator')

            matches.append(group);group['declarations'].append({'index':index,'kind':kind,'name':name,'original_command':code})
        if matches:
            declared[index]={'groups':list({g['plan_index']:g for g in matches}.values()),'remaining_nets':remaining if kind=='net' else [],'kind':kind}
    return declared,plans


def preflight(b,group,*,resolved=False):
    """Read whole group before any disconnect/create/connect, no pattern query."""
    inst,wire=group['instance'],group['wire']
    inst_arg=f'[list ${b}resolved_instance]' if resolved else '{'+inst+'}'
    wire_arg=f'[list ${b}resolved_wire]' if resolved else '{'+wire+'}'
    return f'''set {b}prep_instance_count unknown
set {b}prep_instance_names {{}}
set {b}prep_instance_types {{}}
set {b}prep_pin_connections {{}}
set {b}prep_net_count unknown
set {b}prep_net_names {{}}
set {b}prep_net_members {{}}
set {b}preparation_instruction {{mode_mux owns creation of instance {inst} and functional net {wire}; no plan connection has executed at this checkpoint. Existing objects are not implicitly adopted. Remove duplicate creation or use a fresh original design; any unrelated manual ECO remains explicit.}}
if {{${b}state eq "observed_types_only" && [catch {{
 set {b}prep_i [get_obj_insts -no_info -exact {inst_arg}]
 set {b}prep_instance_count [sizeof_collection ${b}prep_i]
 set {b}prep_w [get_obj_nets -no_info -exact {wire_arg}]
 set {b}prep_net_count [sizeof_collection ${b}prep_w]
 foreach_in_collection {b}q ${b}prep_i {{
  lappend {b}prep_instance_names [get_property ${b}q full_name]
  lappend {b}prep_instance_types [get_property ${b}q ref_name]
  foreach_in_collection {b}pin [get_obj_pins -of ${b}q] {{
   set {b}pn [get_obj_nets -of ${b}pin]
   set {b}pn_names {{}}
   if {{[sizeof_collection ${b}pn] > 0}} {{set {b}pn_names [get_property ${b}pn full_name]}}
   lappend {b}prep_pin_connections [list [get_property ${b}pin full_name] [get_property ${b}pin direction] ${b}pn_names]
  }}
 }}
 foreach_in_collection {b}q ${b}prep_w {{
  lappend {b}prep_net_names [get_property ${b}q full_name]
  set {b}members [get_obj_pins -of ${b}q]
  if {{[sizeof_collection ${b}members] > 0}} {{lappend {b}prep_net_members [get_property ${b}members full_name]}}
 }}
}}]}} {{set {b}state unresolved}}
if {{${b}state eq "observed_types_only"}} {{
 if {{![string is integer -strict ${b}prep_instance_count] || ![string is integer -strict ${b}prep_net_count]}} {{set {b}state unresolved}} elseif {{${b}prep_instance_count != 0 || ${b}prep_net_count != 0}} {{set {b}state preparation_collision}}
}}
'''


def created(b,contract,cell,registry):
    """Resolve exact created objects and roles before touching a functional net."""
    body=f'''set {b}created_pin_names {{}}
set {b}created_pin_directions {{}}
if {{[catch {{
 set {b}created_instance [get_obj_insts -exact [list ${b}resolved_instance]]
 set {b}created_wire [get_obj_nets -exact [list ${b}resolved_wire]]
 if {{[sizeof_collection ${b}created_instance] != 1 || [sizeof_collection ${b}created_wire] != 1 || [get_property ${b}created_instance full_name] ne ${b}resolved_instance || [get_property ${b}created_instance ref_name] ne {{{cell}}} || [get_property ${b}created_wire full_name] ne ${b}resolved_wire || [get_property ${b}created_wire object_class] ne "net"}} {{error {{created object location/type mismatch}}}}
'''
    for role in ['functional','test','select','output']:
        direction='out' if role=='output' else 'in'
        body+=f''' set {b}{role}_pin [get_obj_pins -exact [list [format {{%s/{contract[role]}}} ${b}resolved_instance]]]
 if {{[sizeof_collection ${b}{role}_pin] != 1 || [get_property ${b}{role}_pin object_class] ne "pin" || [get_property ${b}{role}_pin direction] ne "{direction}" || [get_property [get_obj_insts -of ${b}{role}_pin] full_name] ne ${b}resolved_instance}} {{error {{created pin location/type/role mismatch}}}}
 lappend {b}created_pin_names [get_property ${b}{role}_pin full_name]
 lappend {b}created_pin_directions [get_property ${b}{role}_pin direction]
'''
    body+=f'''}}]}} {{set {b}state native_operation_failed}}
'''
    if registry:
        # Internal references have exactly the same design/session/epoch binding
        # as eco_ref and are signed only after the entire created group validates.
        body+=f'if {{${b}state eq "observed_types_only"}} {{\n'
        for role in ['functional','test','select','output']:
            body+=f''' set {b}{role}_token [format {{%s_{b}{role}}} ${registry}session]
 dict set {registry}refs ${b}{role}_token [list ${registry}epoch ${b}design pin [get_property ${b}{role}_pin full_name]]
 puts "ECO_PLAN_CREATED_REFERENCE|{b}|{role}|${b}{role}_token|[get_property ${b}{role}_pin full_name]"
'''
        body+='}\n'
    return body

def readback(b,handles,instance,wire,contract):
    """All native pins and all chosen sources, not just total object counts."""
    from eco_connection_plan import drivers
    d,c,t,m=handles
    body=''
    for role in ['functional','test','select','output']:
        body+=f'''set {b}{role}_pin [get_obj_pins -exact [list [format {{%s/{contract[role]}}} ${b}resolved_instance]]]
if {{[sizeof_collection ${b}{role}_pin] != 1}} {{set {b}state native_operation_failed}}
'''
    body+=f'''if {{[get_property [get_obj_nets -of ${b}functional_pin] full_name] ne ${b}resolved_wire || [get_property [get_obj_nets -of ${d}h] full_name] ne ${b}resolved_wire}} {{set {b}state driver_mismatch}}
'''
    for role,source in [('test',t),('select',m)]:
        body+=drivers(b+role+'_',b+role+'_pin')
        body+=f'''if {{${b}{role}_drivers ne [list ${source}names]}} {{set {b}state driver_mismatch}}
'''
    body+=drivers(b+'functional_',b+'functional_pin')
    body+=f'''if {{${b}functional_drivers ne [list ${d}names]}} {{set {b}state driver_mismatch}}
puts "ECO_PLAN_READBACK|{b}|all_mux_sources_checked=true|instance=${b}resolved_instance|functional_net=${b}resolved_wire|consumer_net=${b}oldnet|EQY_required=true"
'''
    return body
