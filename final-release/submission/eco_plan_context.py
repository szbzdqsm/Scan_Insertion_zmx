"""Bounded read-only native inventory for model-selected ECO intent.

Original-state observations are not persistent handles or repair answers.
Every selected operand is queried afresh by the connection compiler.
"""
import hashlib
import json
import re
from pathlib import Path

POLICY = """# Required connection-plan protocol for function-preserving ECO
If changing an existing functional driver/route, use the existing dofile or
dofile_edits fields with eco_ref NAME {NATIVE_READ_ONLY_QUERY} and:
eco_link mode_mux $DRIVER_REF $CONSUMER_REF $TEST_REF $MODE_REF CELL NEW_INSTANCE NEW_FUNCTIONAL_NET
Select operands yourself from actual task/diagnostic/native observations; the
inventory is NOT a preselected repair. DRIVER is the current unique output pin;
CONSUMER is an existing input pin on its original net; TEST is an explicitly
justified input port or output pin; MODE is the task's functional/scan mode port.
Choose a real Liberty mux cell and fresh names in the driver's own scope. The
program derives the cell pins from its truth table and task functional mode,
preserves the original driver on the functional branch and the original
consumer net, and checks current objects before any splice. Issue all four
eco_ref queries AFTER any preceding mutations; mutations invalidate old refs.
Do not disconnect/reconnect an existing functional driver manually or attach
a second driver. Raw legal queries and connections to undriven new objects
remain supported. Unknown/ambiguous operands must be queried, not guessed.
A test branch need not be a direct scan-enable wire: a task-mode-selected
constant is possible if justified. Structural legality never proves functional
equivalence; the original→fixed EQY and all task requirements still apply.
"""


def collect(netlists, libs, spec, original, output, words_for, tool_run, deadline):
    from eco_structure import requirements, source_design
    from eco_connection_plan import drivers, mux_contract
    import time
    req = requirements(spec)
    if not req['required']:
        return None
    root = output / 'eco_inventory' / 'Q1'
    root.mkdir(parents=True, exist_ok=False)
    record = {'kind': 'original_state_read_only_inventory_not_repair', 'status': 'unknown',
              'inputs': {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in [*netlists, *libs]},
              'functional_modes': req['functional_modes'], 'scan_modes': req['scan_modes'],
              'entries': [], 'library_muxes': []}
    try:
        library, design = source_design(netlists, libs, spec, original)
        top = design['top']
        from eco_plan_semantics import clock_contract
        roles=clock_contract(spec,original,words_for,design,library)
        record['task_and_baseline_clock_roles']={k:v for k,v in roles.items() if k!='clock_consumer_pins'}
        record['clock_source_role_note']='Original native objects plus task/baseline declarations, not a repair plan. Recheck current candidate declarations and fresh object references.'
        candidates = []
        for name, cell in sorted(design['cells'].items()):
            shape = library[cell['type']]
            clocks = {v for ff in shape['ffs'] for v in
                      re.findall(r'[A-Za-z_]\w*', ff['properties'].get('clocked_on', ''))}
            for pin, prop in shape['pins'].items():
                if prop.get('direction') == 'input' and (pin in clocks or shape['icg']):
                    candidates.append(('pin', name+'/'+pin))
        candidates += [('port', name) for name, direction in design['modules'][top]['ports'].items()
                       if direction == 'input' and re.fullmatch(r'[A-Za-z_]\w*', name)]
        if len(candidates) > 128:
            raise ValueError('Native inventory bounded at 128 operands; no sampled repair selection')
        for cell in sorted(library):
            try:
                roles = mux_contract(cell, library, spec)
            except (ValueError, RuntimeError):
                continue
            record['library_muxes'].append({'cell': cell, 'roles': roles})
            if len(record['library_muxes']) == 8:
                break
        lines = [*(f'load_lib {{{p}}}' for p in libs),
                 *(f'load_netlist {{{p}}}' for p in netlists), f'present_design {top}']
        for i, (kind, name) in enumerate(candidates):
            if not re.fullmatch(r'[A-Za-z0-9_$/\.\[\]-]+', name):
                continue
            b = f'__inventory_{i}_'
            lines += [f'set {b}h [get_obj_{kind}s -exact {{{name}}}]',
                      f'set {b}n [sizeof_collection ${b}h]',
                      f'puts "ECO_INVENTORY|{i}|count|${b}n"']
            body = f'''if {{${b}n == 1}} {{
set {b}design [get_property [present_design] full_name]
set {b}name [get_property ${b}h full_name]
set {b}class [get_property ${b}h object_class]
set {b}direction [get_property ${b}h direction]
{drivers(b, b+'h')}
foreach {b}field {{design name class direction drivers}} {{
binary scan [encoding convertto utf-8 [set {b}${b}field]] H* {b}hex
puts "ECO_INVENTORY|{i}|${b}field|${b}hex"
}}
}}
'''
            from clock_association_recipe import _chunks
            lines.extend(c.strip().replace('\n', '; ') for c in _chunks(body))
        script = '\n'.join(lines+['exit'])+'\n'
        exe = root/'Q1.dofile'; exe.write_text(script)
        record['script_sha256'] = hashlib.sha256(script.encode()).hexdigest()
        remaining = deadline-time.monotonic()
        if remaining < 3:
            raise ValueError('Insufficient existing case budget for native inventory')
        result = tool_run(script, root, 'Q1', min(20, remaining), exe, abort_on_error=True, allowed_drc=set())
        record['native_status'] = result['status']; record['native_returncode'] = result['returncode']
        log = root/'Q1.log'; text = log.read_text()
        record['log'] = {'path': str(log), 'sha256': hashlib.sha256(log.read_bytes()).hexdigest()}
        parsed = {}
        for n, line in enumerate(text.splitlines(), 1):
            match = re.fullmatch(r'ECO_INVENTORY\|(\d+)\|(\w+)\|([^\r\n]*)', line)
            if not match:
                continue
            key, field, value = match.groups()
            if field != 'count':
                value = bytes.fromhex(value).decode()
            parsed.setdefault(int(key), {}).update({field: value, 'native_line': n})
        for i, entry in sorted(parsed.items()):
            if entry.get('count') == '1' and entry.get('design') == top and entry.get('class') in {'pin', 'port'}:
                record['entries'].append(entry)
        record['status'] = 'observed_original_state' if result['returncode'] == 0 else 'partial_native_failure'
    except (OSError, ValueError, RuntimeError, KeyError) as exc:
        record['unknown_reason'] = str(exc)[:1000]
    (root/'INVENTORY.json').write_text(json.dumps(record, ensure_ascii=False, indent=2))
    return record


def request_context(inventory):
    if inventory is None:
        return ''
    return POLICY + '\n# Real native original-state inventory (re-query before use)\n' + json.dumps(
        inventory, ensure_ascii=False) + '\nCurrent failed-round observations supersede this original-state inventory.\n'
