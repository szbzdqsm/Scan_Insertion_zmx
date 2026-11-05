"""Constrained mode-selected driver splice. Intent is not a proof of repair.

Called only by the production eco_link compiler with fresh native references.
Library truth tables and task modes determine legal pin roles, never names.
"""
import re
from partial_insertion_validation import _boolean

NAME = re.compile(r'^[A-Za-z_][A-Za-z0-9_/.]*$')

def mux_contract(cell, library, spec):
    from eco_structure import requirements
    modes=requirements(spec)['functional_modes']
    shape=library.get(cell,{})
    pins=shape.get('pins',{})
    if not modes or shape.get('ffs') or shape.get('icg'):
        raise ValueError('mode_mux needs actual task functional-mode constraints and a combinational Liberty MUX')
    ins=[p for p,v in pins.items() if v.get('direction')=='input']
    outs=[p for p,v in pins.items() if v.get('direction')=='output']
    matches=[]
    if len(ins)==3 and len(outs)==1:
        out=outs[0]
        for mode,value in modes.items():
            for sel in ins:
                f=_boolean(pins[out].get('function',''),{sel:value})
                t=_boolean(pins[out].get('function',''),{sel:1-value})
                if f and t and len(f[0])==len(t[0])==1 and f[1]==t[1]==(0,1) and f[0]!=t[0]:
                    matches.append(dict(mode=mode,value=value,select=sel,functional=f[0][0],test=t[0][0],output=out))
    if len(matches)!=1: raise ValueError('Mode/MUX library roles ambiguous or unsupported; no guessed pins')
    return matches[0]

def drivers(b, handle):
    """Native, current-state collection. Driver ports/pins stay distinct."""
    return f'''set {b}drivers {{}}
set {b}net [get_obj_nets -of ${handle}]
if {{[sizeof_collection ${b}net] > 0}} {{
 set {b}segments [get_obj_nets -segments -of ${handle}]
 foreach_in_collection {b}p [get_obj_pins -leaf -of ${b}segments -filter {{direction == out}}] {{lappend {b}drivers [get_property ${b}p full_name]}}
 foreach_in_collection {b}p [get_obj_ports -of ${b}segments -filter {{direction == in}}] {{lappend {b}drivers [get_property ${b}p full_name]}}
}}
set {b}drivers [lsort -unique ${b}drivers]
'''

def splice(b, handles, cell, instance, wire, contract, obs, semantic_roles=None, *, constant_source=False, expected_design=None, registry=None):
    """Require explicit selected driver/consumer/test/mode; do not select a sink."""
    if not all(NAME.fullmatch(v) and all(segment not in {'','.','..'} for segment in v.split('/')) for v in [cell,instance,wire]):
        raise ValueError('Unsafe generated object name')
    d,c,t,m=handles
    functional,test,select,out=(contract[k] for k in ['functional','test','select','output'])
    role_by_pin={functional:'functional',test:'test',select:'select',out:'output'}
    pin=lambda p: '${'+b+role_by_pin[p]+'_pin}'
    net=f'${b}created_wire'
    from eco_plan_ownership import preflight,readback as plan_readback,resolve_parent,created
    s=resolve_parent(b,handles,instance,wire,expected_design)
    s+=preflight(b,{'instance':instance,'wire':wire},resolved=True)
    s+=drivers(b,c+'h')
    s+=f'''set {b}driver [get_property ${d}h full_name]
set {b}consumer [get_property ${c}h full_name]
set {b}oldnet [get_property ${b}net full_name]
if {{[get_property ${d}h direction] ne "out" || [get_property ${c}h direction] ne "in" || [sizeof_collection ${b}net] != 1 || ${b}drivers ne [list ${b}driver]}} {{set {b}state driver_mismatch}}
if {{[info exists {b}hierarchy_parent] && [file dirname ${b}oldnet] ne ${b}hierarchy_parent}} {{set {b}state hierarchy_mismatch}}
if {{${m}classes ne "port" || ${m}names ne {{{contract['mode']}}} || [get_property ${m}h direction] ne "in"}} {{set {b}state mode_constraint_missing}}
if {{(${t}classes eq "pin" && [get_property ${t}h direction] ne "out") || (${t}classes eq "port" && [get_property ${t}h direction] ne "in")}} {{set {b}state wrong_type}}

'''
    from eco_plan_semantics import native_clock_guard, native_control_guard
    s+=native_clock_guard(b,handles,semantic_roles or {})
    s+=native_control_guard(b,handles,semantic_roles or {})
    s+=obs
    s+=f'''puts "ECO_PLAN_BEGIN|{b}|driver=${b}driver|consumer=${b}consumer|net=${b}oldnet|functional_mode={contract['mode']}={contract['value']}"
add_net [list ${b}resolved_wire]
lappend {b}creation_steps [list net_created ${b}resolved_wire]
puts "ECO_PLAN_STEP|{b}|${b}creation_steps"
add_inst [list ${b}resolved_instance] {{{cell}}}
lappend {b}creation_steps [list instance_created ${b}resolved_instance]
puts "ECO_PLAN_STEP|{b}|${b}creation_steps"
'''
    s+=created(b,contract,cell,registry)+obs
    s+=f'''disconnect_net ${b}net ${d}h
connect_net {net} ${d}h
connect_net {net} {pin(functional)}
connect_pin -from ${t}h -to {pin(test)} -verbose
connect_pin -from ${m}h -to {pin(select)} -verbose
connect_net [get_obj_nets -exact ${b}oldnet] {pin(out)}
'''
    if constant_source:
        from eco_constant_source import readback
        s+=readback(b,t,pin(test))+obs
    s+=plan_readback(b,handles,instance,wire,contract)
    s+=drivers(b,c+'h')
    s+=f'''if {{[get_property [get_obj_nets -of ${c}h] full_name] ne ${b}oldnet || ${b}drivers ne [list [format {{%s/{out}}} ${b}resolved_instance]]}} {{set {b}state driver_mismatch}}
'''+obs+f'puts "ECO_PLAN_END|{b}|consumers_preserved=structural_only|EQY_required=true"\n'
    return s
