"""Read-only native argument contracts immediately before selected ECO calls.

Never evaluate Tcl in Python, choose an endpoint, or infer design validity.
Opaque/dynamic expressions are unknown and retain the original native path.
"""
from __future__ import annotations

import hashlib
import json
import re
from clock_association_recipe import _chunks

BEGIN = '# Agent ECO object contract'
END = '# End agent ECO object contract'
MARKER = 'ECO_OBJECT_OBSERVATION'
GETTERS = {'get_obj_nets', 'get_obj_pins', 'get_obj_ports'}


def _getter(expression, words_for):
    if '\n' in expression or '\r' in expression:
        return None
    if not (expression.startswith('[') and expression.endswith(']')):
        return None
    words = words_for(expression[1:-1])
    if not words or words[0] not in GETTERS:
        return None
    # Only native read-only getters with literal or scalar-variable arguments.
    # No nested evaluation, expansion, body execution or command abbreviation.
    for w in words[1:]:
        if re.fullmatch(r'\$[A-Za-z_]\w*|\$\{[A-Za-z_]\w*\}', w):
            continue
        if w.startswith('{') and w.endswith('}'):
            continue
        if re.search(r'[$\[\]\\;\n]', w):
            return None
    return expression


def _known(expression, bindings, words_for):
    direct = _getter(expression, words_for)
    if direct:
        return direct
    variable = re.fullmatch(r'\$(?:([A-Za-z_]\w*)|\{([A-Za-z_]\w*)\})', expression)
    return bindings.get(variable[1] or variable[2]) if variable else None


def _guard(entry, prefix, failure_snapshot):
    """Only collection/property queries, local variables and console writes.

    No literal ERROR token in source echoes (the existing monitor scans logs).
    Exit on a proven bad operand prevents execution of the original connection.
    """
    required = 'net' if entry['required_types'] == ['net'] else 'pin port'
    template = r"""# Agent ECO object contract
set @P@v @EXPR@
set @P@n unknown
set @P@classes {}
set @P@names {}
set @P@state unknown
set @P@design unknown
catch {set @P@design [get_property [present_design] full_name]}
if {![catch {set @P@n [sizeof_collection $@P@v]}]} {
    if {$@P@n == 0} {set @P@state empty}
    if {$@P@n > 0 && $@P@n <= 32} {
        set @P@state observed_types_only
        foreach_in_collection @P@item $@P@v {
            set @P@c [get_property $@P@item object_class]
            lappend @P@classes $@P@c
            lappend @P@names [get_property $@P@item full_name]
            if {$@P@c ni {@REQUIRED@}} {set @P@state wrong_type}
        }
    }
    @MULTIPLE@
}
foreach @P@field {design n classes names state} {
    binary scan [encoding convertto utf-8 [set @P@$@P@field]] H* @P@hex
    puts "ECO_OBJECT_OBSERVATION|@ID@|$@P@field|$@P@hex"
}
if {$@P@state in {empty wrong_type ambiguous_source}} {
    puts OBJECT_FAILURE_BEGIN_@ID@
    dump_netlist -file {@SNAPSHOT@}
    puts OBJECT_FAILURE_END_@ID@
    puts [format {%cERROR%c %cAGENT-ECO-OBJECT%c rejected @ID@} 91 93 91 93]
    flush stdout
    exit
}
# End agent ECO object contract
"""
    multiple = ('if {$@P@n > 1} {set @P@state ambiguous_source}' if entry['single_source'] else
                'if {$@P@n > 1 && $@P@state ne "wrong_type"} {set @P@state unknown_multiple_targets}')
    body = (template.replace('@MULTIPLE@', multiple).replace('@P@', prefix)
        .replace('@EXPR@', entry['expression']).replace('@REQUIRED@', required)
        .replace('@ID@', entry['id']).replace('@SNAPSHOT@', str(failure_snapshot)))
    # The native logger echoes physical lines. Keep every trusted command
    # balanced on one line, so existing strict provenance parsing stays valid.
    return ''.join(chunk if chunk.lstrip().startswith('#') else
                   chunk.strip().replace('\n', '; ') + '\n' for chunk in _chunks(body))



def instrument(script, words_for, *, failure_snapshot):
    """Insert guards at top-level calls only; unknown bodies stay untouched."""
    if re.search(r'[{}\r\n]', str(failure_snapshot)):
        raise ValueError('Unsupported diagnostic snapshot path')
    if BEGIN in script:
        raise ValueError('Object contract must be compiled once from model-owned code')
    # A model redefining queries/commands makes their semantics unknown.
    if re.search(r'(?:^|[\n;{\[])\s*(?:::)?(?:proc|rename|interp|source|eval|uplevel|namespace|trace|apply|exec)\b', script):
        return script, {'checks': [], 'unknown': [{'reason': 'dynamic/redefined command scope'}]}
    prefix = '__agent_obj_' + hashlib.sha256(script.encode()).hexdigest()[:12] + '_'
    if prefix in script:
        raise ValueError('Reserved object-contract variable collision')
    bindings, result, checks, unknown = {}, [], [], []
    position = 0
    for chunk in _chunks(script):
        code = re.sub(r'\\\r?\n\s*', ' ', chunk).strip().rstrip(';').strip()
        line = script[:position].count('\n') + 1
        position += len(chunk)
        w = words_for(code) if code and not code.startswith('#') else []
        if not w:
            result.append(chunk); continue
        name = w[0].removeprefix('::')
        if name in {'present_design', 'load_lib', 'load_netlist', 'load_db'}:
            bindings.clear()
        if name == 'set' and len(w) == 3:
            bindings.pop(w[1], None)
            getter = _getter(w[2], words_for)
            if getter:
                bindings[w[1]] = getter
        elif name not in {'connect_pin', 'disconnect_net', 'connect_net', 'puts', 'set', 'add_net', 'add_inst', 'add_port',
                           'load_lib', 'load_netlist', 'present_design'} and not name.startswith(('set_', 'rpt_', 'dump_', 'examine_')):
            # if/loops/catch/unknown operations may reassign a scalar.
            bindings.clear()
        if name not in {'connect_pin', 'disconnect_net'} and (re.search(r'[$\[]', name) or re.search(r'\b(?:connect_pin|disconnect_net)\b', code)):
            unknown.append({'command': code, 'static_state': 'unknown', 'reason': 'nested/dynamic operation; original tool confirms'})
        operands = []
        if name == 'connect_pin':
            for option in ['-from', '-to']:
                if w.count(option) == 1 and w.index(option) + 1 < len(w):
                    operands.append((option, w[w.index(option) + 1], ['pin', 'port'], option == '-from'))
        elif name == 'disconnect_net' and len(w) == 3:
            operands = [('net', w[1], ['net'], True), ('objects', w[2], ['pin', 'port'], False)]
        blocks = []
        for option, expression, required, single in operands:
            query = _known(expression, bindings, words_for)
            entry = {'id': f'C{len(checks) + 1}', 'command': code, 'original_line': line,
                     'option': option, 'expression': expression, 'query_expression': query,
                     'required_types': required, 'single_source': single,
                     'static_state': 'unknown_until_native_query'}
            if query is None or len(checks) >= 64:
                unknown.append({**entry, 'reason': 'opaque/dynamic expression or bounded scope; original tool confirms'})
                continue
            checks.append(entry); blocks.append(_guard(entry, prefix, failure_snapshot))
        # Preserve the original operation byte-for-byte and on its own line.
        result.append(('\n' + ''.join(blocks)) if blocks else '')
        result.append(chunk)
    return ''.join(result), {'checks': checks, 'unknown': unknown, 'failure_snapshot': str(failure_snapshot),
        'meaning': 'Argument type/count observations only, never ECO effect, object intent or functional proof'}


def observations(script, text, plan):
    """Read only observations emitted by this compiled script's guard blocks."""
    if plan.get('selector_version') == 2:
        return staged_observations(text, plan)
    entries = {e['id']: e for e in plan['checks']}
    fields, refs = {}, {}
    for n, line in enumerate(text.splitlines(), 1):
        match = re.fullmatch(MARKER + r'\|(C\d+)\|(design|n|classes|names|state)\|([0-9a-f]*)', line)
        if not match or match[1] not in entries:
            continue
        key, field = match[1], match[2]
        if field in fields.get(key, {}):
            return [{'state': 'unknown', 'reason': 'repeated observation ID; not a uniquely bound top-level operation'}]
        fields.setdefault(key, {})[field] = bytes.fromhex(match[3]).decode('utf-8')
        refs.setdefault(key, []).append(n)
    references = {}
    for line in text.splitlines():
        m = re.fullmatch(r'ECO_OBJECT_REFERENCE\|(C\d+)\|(token|epoch)\|([0-9a-f_]+)', line)
        if m and m[1] in entries:
            references.setdefault(m[1], {})[m[2]] = bytes.fromhex(m[3]).decode() if m[2] == 'token' else int(m[3])
    return [{**entries[k], **({'object_reference': references[k]} if k in references else {}), 'state': v.get('state', 'unknown'),
             'current_design': v.get('design', 'unknown'), 'actual_count': int(v['n']) if v.get('n', '').isdigit() else None,
             'actual_classes': v.get('classes'), 'actual_full_names': v.get('names'),
             'query_result': v, 'native_log_lines': refs[k], 'meaning': 'not repair/equivalence evidence'}
            for k, v in fields.items() if len(v) == 5]


def staged_observations(text, plan):
    # Each compiler-owned checkpoint is a complete fresh six-field frame;
    # retain all frames rather than overwriting the original type observation.
    from eco_plan_ownership import FIELDS,HIERARCHY_FIELDS
    extra_fields=set((FIELDS+' '+HIERARCHY_FIELDS).split())
    entries={e['id']:e for e in plan['checks']}; frames={}; active=None
    for n,line in enumerate(text.splitlines(),1):
        m=re.fullmatch(r'ECO_OBJECT_OBSERVATION_BEGIN\|(C\d+)',line)
        if m:
            if m[1] not in entries:return [{'state':'unknown','reason':'unbound checkpoint'}]
            active={'fields':{},'lines':[]};frames.setdefault(m[1],[]).append(active)
            if len(frames[m[1]])>4:return [{'state':'unknown','reason':'unexpected repeated checkpoints'}]
            continue
        m=re.fullmatch(MARKER+r'\|(C\d+)\|([a-z_]+)\|([0-9a-f]*)',line)
        if m:
            if m[2] not in {'design','n','classes','names','drivers','state'} | extra_fields:continue
            if active is None or not frames.get(m[1]) or frames[m[1]][-1] is not active or m[2] in active['fields']:
                return [{'state':'unknown','reason':'malformed checkpoint ordering'}]
            active['fields'][m[2]]=bytes.fromhex(m[3]).decode();active['lines'].append(n)
    rows=[]
    for key,history in frames.items():
        if any(not {'design','n','classes','names','drivers','state'}<=set(x['fields']) for x in history):
            rows.append({'state':'unknown','reason':'incomplete native checkpoint','id':key});continue
        f=history[-1]['fields']
        rows.append({**entries[key],'state':f['state'],'current_design':f['design'],
            'actual_count':int(f['n']) if f['n'].isdigit() else None,
            'actual_classes':f['classes'],'actual_full_names':f['names'],'query_result':f,
            'observation_history':history,'native_log_lines':[n for h in history for n in h['lines']],
            'meaning':'bound native diagnostic, not EQY or task success'})
    return rows


def bind_plan(plan, script, run, words_for=None):
    from runtime_events import atomic
    atomic(run / 'eco_object_contract.plan.json', {**plan,
        'script_sha256': hashlib.sha256(script.encode()).hexdigest()})
    if plan.get('selector_version') == 2:
        from plan_provenance import bind
        if words_for is None:
            from scan_agent import literal_tcl_words
            words_for = literal_tcl_words
        try:
            bind({**plan,'script_sha256':hashlib.sha256(script.encode()).hexdigest()}, script, run, words_for)
        except (OSError, ValueError, KeyError, TypeError) as exc:
            atomic(run/'eco_plan_provenance.json',{'status':'unavailable','run_ref':run.name,
                'compiled_script_sha256':hashlib.sha256(script.encode()).hexdigest(),'reason':str(exc),
                'meaning':'No mapping proof issued; existing native object and ECO correctness gates remain required'})


def bound_record(context, text):
    """Diagnostic only; never substitutes for NativeTrace or EQY admission."""
    from eco_plan_ownership import HIERARCHY_FIELDS
    HIERARCHY_EVIDENCE_FIELDS=HIERARCHY_FIELDS.split()
    path = context.run / 'eco_object_contract.plan.json'
    if not path.is_file():
        return [], None
    plan = json.loads(path.read_text())
    if plan.get('script_sha256') != hashlib.sha256(context.script.encode()).hexdigest():
        return [{'state': 'unknown', 'reason': 'Object contract plan/script mismatch'}], None
    records = observations(context.script, text, plan)
    unresolved_queries = {e['id']: e for e in plan.get('unknown', []) if 'id' in e}
    log = context.run / (context.rid + '.log')
    for row in records:
        row['diagnostic'] = ('Existing functional-driver change requires eco_ref/eco_link mode_mux. Select fresh driver, consumer, test and mode references from real queries; retain the original functional branch and consumer net. No mutation was executed.' if row['state'] == 'plan_required' else 'The actual target is already driven: '+str(row.get('query_result',{}).get('drivers'))+'. Select an explicit function-preserving plan; no existing driver was silently removed.' if row['state'] in {'occupied_target','driver_mismatch'} else 'Unresolved or stale reference; no original-command fallback. Refresh a pure native query in this state.' if row['state'] in {'unresolved', 'stale_reference'} else
            'Native full paths place net and pin in different hierarchy scopes; no topology conversion chosen.' if row['state'] == 'hierarchy_mismatch' else
            'Native collection is empty in the observed current design; no hierarchy/leaf fallback was chosen.' if row['state'] == 'empty' else
            'Native object_class is incompatible with the operation argument; a net is not a pin/port.' if row['state'] == 'wrong_type' else
            'A single source is required; no member of this collection was chosen.' if row['state'] == 'ambiguous_source' else
            'Only argument types observed; object intent, connection effect and functional correctness remain unproved.')
        if row.get('state')=='test_clock_mismatch':
            row['diagnostic']='Actual test source is not a task/configured scan clock for the actual clock consumer. '+json.dumps(row.get('plan_semantics',{}),ensure_ascii=False)+'. No splice executed; retain functional driver/consumer net.'
        if row.get('hierarchy_policy'):
            row['hierarchy_evidence']={k:row.get('query_result',{}).get(k,'unknown') for k in HIERARCHY_EVIDENCE_FIELDS}
            row['diagnostic']+=' Native hierarchy, actual creation steps and plan-resource binding: '+json.dumps(row['hierarchy_evidence'],ensure_ascii=False)+'. A partial creation is not a rollback; inspect current objects, do not silently reuse them.'
        unresolved = unresolved_queries.get(row.get('id'))
        if (row.get('state') == 'unresolved' and unresolved and
                unresolved.get('expression') == row.get('expression')):
            # The compiler emitted "state unresolved" instead of evaluating
            # this expression. Do not misreport it as a native empty query.
            row['query_executed'] = False
            row['query_resolution_reason'] = unresolved['reason']
            row['diagnostic'] = ('Object query was not executed: ' + unresolved['reason'] +
                '. Count, type and target remain unknown. Use the existing eco_ref interface '
                'with a pure native getter: brace a literal full path inside the getter or '
                'use a scalar path variable. A raw name list is not an object collection. '
                'No endpoint was selected or rewritten.')
        row['evidence'] = {'source': log.relative_to(context.output).as_posix(),
            'sha256': hashlib.sha256(log.read_bytes()).hexdigest(), 'lines': row.get('native_log_lines', [])}
    target = context.run / 'deliverables/object_contract_failed.v'
    if plan.get('failure_snapshot') != str(target) or not target.is_file() or str(target.absolute()) in context.before_files:
        return records, None
    from canonical_delivery import _real_file
    _real_file(target, context.output)
    for row in records:
        if row.get('state') not in {'empty', 'wrong_type', 'ambiguous_source', 'unresolved', 'stale_reference', 'hierarchy_mismatch', 'driver_mismatch', 'occupied_target', 'mode_constraint_missing', 'preparation_collision', 'native_operation_failed', 'plan_required', 'test_clock_mismatch'}:
            continue
        begin, end = 'OBJECT_FAILURE_BEGIN_' + row['id'], 'OBJECT_FAILURE_END_' + row['id']
        lines = text.splitlines()
        a = [n for n, l in enumerate(lines, 1) if l == begin]
        b = [n for n, l in enumerate(lines, 1) if l == end]
        if len(a) == len(b) == 1 and a[0] < b[0]:
            success = [n for n in range(a[0] + 1, b[0]) if 'VRLG-O-0009' in lines[n-1] and 'Write Netlist successfully.' in lines[n-1]]
            if len(success) == 1:
                return records, {'path': target, 'echo_line': a[0], 'success': success[0],
                    'script_line': row['original_line'], 'pre_scan': True,
                    'authority': 'runtime-owned read-only failure dump, not adopted repair'}
    return records, None
