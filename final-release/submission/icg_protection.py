"""Compile explicit partial-task ICG exclusions from complete source identities.

The source reader establishes the required set; native exact collections verify
that set in the current design immediately before connect_icg_only. No wildcard
fallback, ECO topology change, global exclusion or successful-empty guess.
"""
import hashlib
import json
import re
from pathlib import Path
from dofile_recipe import tcl_chunks
from partial_insertion_validation import (_libraries, _modules, _flatten, _scope_names,
                                         partial_insertion_requirements)

START = '# Agent task-derived ICG protection'
END = '# End agent task-derived ICG protection'
PREFIX = '__agent_icg_protection'


def source_facts(task, spec, netlists, libraries):
    req = partial_insertion_requirements(spec)
    result = {'applicable': task == 'task1' and req['applicable'] and bool(req['icg_excluded_scopes']),
              'status': 'not_applicable', 'objects': [], 'requirements': req,
              'inputs': [], 'problems': []}
    if not result['applicable']:
        return result
    result['status'] = 'unknown'
    try:
        lib, errors = _libraries(libraries)
        modules, issues = _modules(netlists, lib)
        if errors or issues or not req['top'] or req['top'] not in modules:
            raise ValueError('Input/Liberty/top scope is incomplete: ' + '; '.join(errors + issues))
        leaves, _, issues, scopes = _flatten(modules, lib, req['top'])
        selected, missing = _scope_names(req['icg_excluded_scopes'], scopes, req['top'])
        if issues or missing:
            raise ValueError('Required protection hierarchy is unbound: ' + '; '.join(issues + missing))
        objects = [{'path': name, 'cell_type': cell['type']}
                   for name, cell in sorted(leaves.items()) if lib[cell['type']]['icg'] and
                   any(name.startswith(scope + '/') for scope in selected)]
        if len(objects) > 4096:
            raise ValueError('Required exact protection collection exceeds bounded compiler capacity')
        for obj in objects:
            if any(c in obj['path'] + obj['cell_type'] for c in '{}\\\n\r'):
                raise ValueError('Required object needs unsupported literal Tcl quoting: ' + obj['path'])
        result.update(status='complete' if objects else 'proven_empty', objects=objects,
                      design=req['top'], resolved_scopes=selected,
                      inputs=[{'path': str(p.resolve()), 'sha256': hashlib.sha256(p.read_bytes()).hexdigest()}
                              for p in sorted(netlists + libraries)])
    except (OSError, ValueError, KeyError, TypeError) as exc:
        result['problems'] = [str(exc)]
    return result


def _block(facts):
    p = PREFIX
    names = ' '.join('{' + o['path'] + '}' for o in facts['objects'])
    pairs = ' '.join('{' + o['path'] + '} {' + o['cell_type'] + '}' for o in facts['objects'])
    code = [START, f'set {p}_state verified_empty', f'set {p}_design unknown', f'set {p}_expected [list {names}]',
            f'set {p}_actual {{}}', f'set {p}_missing {{}}', f'set {p}_extra {{}}',
            f'set {p}_types [dict create {pairs}]',
            f'if {{[catch {{set {p}_design [get_property [present_design] full_name]}}]}} {{set {p}_state unresolved}}',
            f'if {{![info exists {p}_design] || ${p}_design ne {{{facts["design"]}}}}} {{set {p}_state wrong_design}}']
    ref = ''
    if facts['objects']:
        code += [f'if {{${p}_state eq "verified_empty"}} {{',
                 f'  set {p}_state unresolved',
                 f'  if {{![catch {{set {p}_objects [get_obj_insts -exact [list {names}]]; set {p}_count [sizeof_collection ${p}_objects]}}]}} {{',
                 f'    set {p}_state observed',
                 f'    foreach_in_collection {p}_object ${p}_objects {{',
                 f'      if {{[catch {{set {p}_name [get_property ${p}_object full_name]; set {p}_type [get_property ${p}_object ref_name]; set {p}_icg [get_property ${p}_object is_icg]}}]}} {{set {p}_state unresolved; break}}',
                 f'      lappend {p}_actual ${p}_name',
                 f'      if {{${p}_icg ni {{true 1}} || ![dict exists ${p}_types ${p}_name] || [dict get ${p}_types ${p}_name] ne ${p}_type}} {{set {p}_state wrong_role}}',
                 '    }', '  }',
                 f'  foreach {p}_name ${p}_expected {{if {{${p}_name ni ${p}_actual}} {{lappend {p}_missing ${p}_name}}}}',
                 f'  foreach {p}_name ${p}_actual {{if {{${p}_name ni ${p}_expected}} {{lappend {p}_extra ${p}_name}}}}',
                 f'  if {{${p}_state eq "observed" && ([lsort ${p}_expected] ne [lsort -unique ${p}_actual] || [llength ${p}_actual] != [llength ${p}_expected])}} {{set {p}_state incomplete}}',
                 '}']
        ref = f'set_dft_clock_gating_cfg -exclude_elements ${p}_objects'
    code += [f'puts [list ICG_PROTECTION_OBSERVATION state ${p}_state design ${p}_design expected ${p}_expected actual ${p}_actual missing ${p}_missing extra ${p}_extra]',
             f'if {{${p}_state ni {{observed verified_empty}}}} {{puts [format {{%cERROR%c %cAGENT-ICG-PROTECTION%c required protection unresolved; no connection executed}} 91 93 91 93]; flush stdout; exit}}']
    if ref:
        code.append(ref)
    code += [END]
    return '\n'.join(code) + '\n', ref


def compile_protection(script, facts, words_for, mappings=None):
    if not facts or not facts.get('applicable'):
        return script, {'applicable': False}
    if facts.get('status') not in {'complete', 'proven_empty'}:
        raise ValueError('Required ICG protection scope unknown: ' + '; '.join(facts.get('problems', [])))
    for material in facts['inputs']:
        if hashlib.sha256(Path(material['path']).read_bytes()).hexdigest() != material['sha256']:
            raise ValueError('Required ICG protection input state changed: ' + material['path'])
    script = re.sub(r'(?ms)^' + re.escape(START) + r'\n.*?^' + re.escape(END) + r'(?:\n|$)', '', script)
    if PREFIX in script:
        raise ValueError('Reserved ICG protection compiler namespace present in model script')
    block, reference = _block(facts)
    chunks = tcl_chunks(script); rewritten = []; substitutions = []; connections = 0
    for chunk in chunks:
        text = chunk.strip(); words = words_for(text)
        if words and (words[0] in {'source','eval','exec','uplevel','interp','namespace','load_db','flatten'} or
                re.fullmatch(r'(?:add|delete|connect|disconnect)_(?:inst|net|pin|port)|rewire',words[0])):
            raise ValueError('Task-derived ICG source state is unknown after an unplanned design mutation or dynamic execution')
        if words[:1] == ['set_dft_clock_gating_cfg']:
            if len(words) != 3 or words[1] != '-exclude_elements':
                raise ValueError('Explicit task protection cannot replace unrelated clock-gating settings')
            substitutions.append((text, reference or 'insert_dft_logic -connect_icg_only'))
            rewritten.append('# Task-derived exact exclusion is compiled at the connection boundary.\n')
        elif 'set_dft_clock_gating_cfg' in text and not text.startswith('#'):
            guard = re.fullmatch(r'if\s+\{\[cluster_length\s+(\$[A-Za-z_]\w*)\]\s*>\s*0\}\s*\{\s*set_dft_clock_gating_cfg\s+-exclude_elements\s+\1\s*\}', text)
            if not guard:
                raise ValueError('ICG protection inside an unsupported dynamic scope is unresolved; preserve required objects')
            substitutions.append((text, reference or 'insert_dft_logic -connect_icg_only'))
            rewritten.append('# Conditional exclusion replaced by the task-bound connection check.\n')
        elif words[:1] == ['insert_dft_logic'] and '-connect_icg_only' in words:
            if words != ['insert_dft_logic', '-connect_icg_only']:
                raise ValueError('Ambiguous partial connection operation requires explicit stage scope')
            rewritten.extend([block, chunk]); connections += 1
        else:
            rewritten.append(chunk)
    if connections != 1:
        raise ValueError('Required ICG protection needs one explicit connect_icg_only boundary')
    projected = []
    for item in mappings or []:
        if not isinstance(item, dict) or not isinstance(item.get('dft_config'), str):
            continue
        before = item['dft_config']; parts = tcl_chunks(before); after = []
        for part in parts:
            replacement = next((new for old, new in substitutions if part.strip().rstrip(';') == old.rstrip(';')), None)
            after.append(replacement + '\n' if replacement else part)
        result = ''.join(after).strip()
        if result != before:
            item['dft_config'] = result
            projected.append({'before': before, 'after': result, 'reason': 'same task protection operation compiled to an exact native collection'})
    return ''.join(rewritten), {'applicable': True, 'source_facts': facts,
        'original_script_sha256': hashlib.sha256(script.encode()).hexdigest(),
        'compiled_command': reference, 'replaced_source_commands': [a for a, _ in substitutions],
        'annotation_projection': projected, 'stage': 'immediately_before_connect_icg_only',
        'meaning': 'Required set is task/source-derived; only native exact type/identity/count establishes a usable collection. Structural validation remains mandatory.'}
