"""Lower a selected new virtual constant's output intent, never a getter fallback.

Only a literal -logic 1 creation followed by an explicit source-role selection
qualifies. Runtime creation, cell identity, direction and uniqueness still have
to be observed. No endpoint name is supplied by this compiler.
"""
import re


def literal(word):
    if word.startswith('{') and word.endswith('}'):
        value=word[1:-1]
        return value if value and not any(c in value for c in '{}\\\r\n') else None
    return word if re.fullmatch(r'[A-Za-z_][A-Za-z0-9_./-]*',word) else None


def intent_plan(chunks, words_for):
    created={};refs={};creations={};queries={}
    for index,chunk in enumerate(chunks):
        code=chunk.strip().rstrip(';').strip();w=words_for(code) if code and not code.startswith('#') else []
        if not w:continue
        name=w[0].removeprefix('::')
        if name in {'load_lib','load_netlist','load_db','present_design','delete_inst'}:
            created.clear();refs.clear()
        if name=='set' and len(w)>1:refs.pop(w[1],None)
        if name=='add_inst' and len(w)==4 and w[2:]==['-logic','1']:
            owner=literal(w[1])
            if owner:created[owner]={'instance':owner,'value':'1','creation_index':index}
        if name=='eco_ref' and len(w)==3 and w[2].startswith('{') and w[2].endswith('}'):
            q=words_for(w[2][1:-1]);owner=None
            if len(q)==3 and q[:2]==['get_obj_pins','-exact']:
                path=literal(q[2])
                if path and '/' in path:owner=path.rsplit('/',1)[0]
            elif len(q) in {3,5} and q[:2]==['get_obj_pins','-of']:
                if len(q)==3 or q[3]=='-filter' and re.fullmatch(r'\{\s*direction\s*==\s*out\s*\}',q[4]):owner=literal(q[2])
            refs[w[1]]=(index,created.get(owner))
        selected=[]
        if name=='eco_link' and len(w)==9 and w[1]=='mode_mux':selected=[w[4]]
        elif name=='eco_link' and len(w)==4 and w[1]=='connect_pin':selected=[w[2]]
        elif name=='eco_link' and len(w)==4 and w[1]=='connect_net':selected=[w[3]]
        for ref in selected:
            if not re.fullmatch(r'\$[A-Za-z_]\w*',ref):continue
            qindex,spec=refs.get(ref[1:],(None,None))
            if not spec:continue
            spec={**spec,'intent':'unique output of explicitly created logic 1 source',
                  'selected_by_operation':code,'query_index':qindex}
            queries[qindex]=spec;creations[spec['creation_index']]=spec
    return creations,queries


def creation(b,p,spec,original,emit):
    owner='{'+spec['instance']+'}'
    body=f'''set {b}state observed_types_only
set {b}design unknown
set {b}n unknown
set {b}classes {{}}
set {b}names {{}}
set {b}instance_name unknown
set {b}instance_ref unknown
if {{[catch {{set {b}design [get_property [present_design] full_name]}}]}} {{set {b}state unresolved}}
if {{[catch {{set {b}before [get_obj_insts -no_info -exact {owner}]; set {b}n [sizeof_collection ${b}before]}}]}} {{set {b}state unresolved}}
if {{${b}state eq "observed_types_only" && ![string is integer -strict ${b}n]}} {{set {b}state unresolved}}
if {{${b}state eq "observed_types_only" && ${b}n != 0}} {{set {b}state preparation_collision}}
'''+emit+original.strip()+'\n'+f'''set {b}n unknown
if {{[catch {{set {b}h [get_obj_insts -exact {owner}]; set {b}n [sizeof_collection ${b}h]}}]}} {{set {b}state unresolved}}
if {{${b}state eq "observed_types_only" && ![string is integer -strict ${b}n]}} {{set {b}state unresolved}}
if {{${b}state eq "observed_types_only" && ${b}n eq "0"}} {{set {b}state empty}}
if {{[string is integer -strict ${b}n] && ${b}n > 1}} {{set {b}state ambiguous_source}}
if {{${b}n eq "1"}} {{
 if {{[catch {{set {b}classes [get_property ${b}h object_class]; set {b}names [get_property ${b}h full_name]; set {b}instance_ref [get_property ${b}h ref_name]}}]}} {{set {b}state unresolved}}
 set {b}instance_name ${b}names
 if {{${b}state eq "observed_types_only" && (${b}classes ne "cell" || ${b}names ne {owner} || ${b}instance_ref ne "UNIT_VirtualTieHigh")}} {{set {b}state wrong_type}}
}}
'''+emit+f'''dict set {p}constants {owner} [list ${b}design ${b}names ${b}instance_ref]
incr {p}epoch
'''
    return body


def lookup(b,p,spec):
    owner='{'+spec['instance']+'}'
    return f'''set {b}instance_n unknown
set {b}instance_name unknown
set {b}instance_ref unknown
set {b}owner_class unknown
set {b}all_pin_names {{}}
set {b}all_pin_directions {{}}
set {b}output_direction unknown
if {{![dict exists ${p}constants {owner}]}} {{set {b}state stale_reference}}
if {{${b}state eq "observed_types_only"}} {{
 if {{[catch {{set {b}instance [get_obj_insts -exact {owner}]; set {b}instance_n [sizeof_collection ${b}instance]}}]}} {{set {b}state unresolved}}
 if {{${b}state eq "observed_types_only" && ![string is integer -strict ${b}instance_n]}} {{set {b}state unresolved}}
 if {{${b}state eq "observed_types_only" && ${b}instance_n eq "0"}} {{set {b}state empty}}
 if {{[string is integer -strict ${b}instance_n] && ${b}instance_n > 1}} {{set {b}state ambiguous_source}}
 if {{${b}instance_n eq "1"}} {{
  if {{[catch {{set {b}instance_name [get_property ${b}instance full_name]; set {b}instance_ref [get_property ${b}instance ref_name]; set {b}owner_class [get_property ${b}instance object_class]}}]}} {{set {b}state unresolved}}
  if {{${b}state eq "observed_types_only" && (${b}owner_class ne "cell" || ${b}instance_name ne {owner} || ${b}instance_ref ne "UNIT_VirtualTieHigh")}} {{set {b}state wrong_type}}
  if {{${b}state eq "observed_types_only" && [dict get ${p}constants {owner}] ne [list ${b}design ${b}instance_name ${b}instance_ref]}} {{set {b}state stale_reference}}
 }}
}}
if {{${b}state eq "observed_types_only"}} {{
 if {{[catch {{
  set {b}all_pins [get_obj_pins -of ${b}instance]
  foreach_in_collection {b}pin ${b}all_pins {{lappend {b}all_pin_names [get_property ${b}pin full_name]; lappend {b}all_pin_directions [get_property ${b}pin direction]}}
  set {b}h [get_obj_pins -of ${b}instance -filter {{direction == out}}]
 }}]}} {{set {b}state unresolved}}
}}
'''


def readback(b,test_handle,target):
    # Segment sets preserve real cross-hierarchy relationships; never select a
    # member, change an endpoint or replace the native topology operation.
    return f'''set {b}constant_source_segments {{}}
set {b}constant_target_segments {{}}
foreach_in_collection {b}segment [get_obj_nets -segments -of ${test_handle}h] {{lappend {b}constant_source_segments [get_property ${b}segment full_name]}}
foreach_in_collection {b}segment [get_obj_nets -segments -of {target}] {{lappend {b}constant_target_segments [get_property ${b}segment full_name]}}
set {b}constant_shared_segments {{}}
foreach {b}segment ${b}constant_source_segments {{if {{${b}segment in ${b}constant_target_segments}} {{lappend {b}constant_shared_segments ${b}segment}}}}
if {{[llength ${b}constant_shared_segments] == 0}} {{set {b}state native_operation_failed}}
puts [list ECO_CONSTANT_READBACK ${test_handle}names ${b}constant_shared_segments]
'''
