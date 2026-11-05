"""Bounded source witnesses for exclusions that cross a literal clock boundary.

Unknown HDL/clock logic falls back to the unchanged real report checks. This
does not elaborate HDL, evaluate Tcl collections, or claim scan eligibility.
"""
from __future__ import annotations

from pathlib import Path
import re

from exclusion_requirements import debug_exclusion_requested, subtree_exclusion_requirements
from scan_exclusion_evidence import _selected, _selectors
from source_hierarchy import _records, _INSTANCE, _SIMPLE_NAMED_CONNECTIONS


_NET = re.compile(r'[A-Za-z_$][\w$]*')
_TAP = re.compile(r'(?:^|[_$.-])tap(?:$|[_$.-])', re.I)


def debug_exclusion_source_facts(paths: list[Path], spec: str, hierarchy: dict, catalog,
                                 *, max_modules: int = 256, max_leaves: int = 1024) -> dict:
    empty = {'applicable': False, 'witnesses': [], 'tap_scopes': []}
    if not debug_exclusion_requested(spec) or not hierarchy.get('complete') or not hasattr(catalog, 'ff_clock_pin'):
        return empty
    modules = {item['name']: item for item in hierarchy['modules']}
    taps = {name for name in modules if _TAP.search(name)}
    edges = hierarchy['module_instances']
    children = {}
    for edge in edges:
        children.setdefault(edge['parent'], set()).add(edge['type'])
    # Generated submodules can carry their parent's role in their type name.
    # Use the outer role scope, not those nested clock-gate implementation types.
    nested = set()
    for name in taps:
        pending = list(children.get(name, ()))
        seen = set()
        while pending and len(seen) <= 4096:
            child = pending.pop()
            if child in seen:
                continue
            seen.add(child)
            if child in taps:
                nested.add(child)
            pending.extend(children.get(child, ()))
        if pending:
            return empty
    taps -= nested
    scope = {edge['parent'] for edge in edges if edge['type'] in taps}
    if not scope:
        return empty
    # Descend from TAP parents, then add only their ancestors, not siblings of
    # those ancestors (which could contain the entire large functional design).
    while True:
        expanded = scope | {edge['type'] for edge in edges if edge['parent'] in scope and edge['parent'] not in taps}
        if len(expanded) > max_modules:
            return empty
        if expanded == scope:
            break
        scope = expanded
    selected = set(scope)
    while True:
        expanded = selected | {edge['parent'] for edge in edges if edge['type'] in selected}
        if len(expanded) > max_modules:
            return empty
        if expanded == selected:
            break
        selected = expanded
    data = {name: {'inputs': set(), 'aliases': {}, 'instances': [], 'complete': False} for name in selected}
    total_leaves = 0
    for path in paths:
        wanted = {name for name in selected if modules[name]['source'] == str(path)}
        if not wanted:
            continue
        current = ''
        for text, number, status in _records(path, 65536, set(catalog)):
            if number > 250000:
                return empty
            if status == 'scope_end':
                if current in wanted:
                    data[current]['complete'] = True
                    wanted.remove(current)
                current = ''
                if not wanted:
                    break
                continue
            if text.startswith('module '):
                match = re.match(r'module\s+([A-Za-z_$][\w$]*)', text)
                current = match[1] if match else ''
            if current not in data:
                continue
            entry = data[current]
            for declaration in re.finditer(r'\binput\b([^;)]*)', text):
                fragment = re.split(r'\b(?:output|inout)\b', declaration[1])[0]
                entry['inputs'].update(word for word in re.findall(r'[A-Za-z_$][\w$]*', fragment)
                                       if word not in {'input', 'wire', 'reg', 'logic', 'signed', 'unsigned'})
            alias = re.fullmatch(r'assign\s+([A-Za-z_$][\w$]*)\s*=\s*([A-Za-z_$][\w$]*)', text)
            if alias:
                if alias[1] in entry['aliases']:
                    return empty
                entry['aliases'][alias[1]] = alias[2]
            instance = _INSTANCE.match(text)
            if not instance or text.startswith('module '):
                continue
            kind, name = instance[1].removeprefix('\\'), instance[2].removeprefix('\\')
            clock_pin = catalog.ff_clock_pin(kind) if current in scope else None
            if kind not in selected and not clock_pin:
                continue
            if '/' in name or not _SIMPLE_NAMED_CONNECTIONS.fullmatch(text[instance.end()-1:]):
                return empty
            pins = {pin: net.strip() for pin, net in re.findall(r'\.([A-Za-z_$][\w$]*)\s*\(([^()]*)\)', text)
                    if _NET.fullmatch(net.strip())}
            entry['instances'].append({'type': kind, 'name': name, 'pins': pins, 'clock_pin': clock_pin,
                                       'source': str(path), 'line': number})
            total_leaves += bool(clock_pin)
            if total_leaves > max_leaves:
                return empty
    if any(not value['complete'] for value in data.values()):
        return empty
    witnesses, tap_scopes = [], []
    visits = 0
    def walk(module, prefix, bindings, root, tap_prefix=''):
        nonlocal visits
        visits += 1
        if visits > 4096:
            return
        entry = data[module]
        def bound(net):
            seen = set()
            while net in entry['aliases'] and net not in seen:
                seen.add(net)
                net = entry['aliases'][net]
            return bindings.get(net) if net not in seen else None
        if module in taps:
            tap_prefix = prefix
        for item in entry['instances']:
            path = prefix + '/' + item['name'] if prefix else item['name']
            pins = {pin: value for pin, net in item['pins'].items() if (value := bound(net)) is not None}
            if item['type'] in data:
                walk(item['type'], path, pins, root, tap_prefix)
            elif item['clock_pin'] in pins:
                row = {'root': root, 'instance': path, 'clock': pins[item['clock_pin']],
                       'clock_pin': item['clock_pin'], 'cell_type': item['type'],
                       'source': item['source'], 'line': item['line'], 'tap_prefix': tap_prefix}
                witnesses.append(row)
                if tap_prefix:
                    tap_scopes.append({'root': root, 'prefix': tap_prefix, 'clock': row['clock']})
    for root in hierarchy['roots']:
        if root in data:
            walk(root, '', {port: port for port in data[root]['inputs']}, root)
    if visits > 4096:
        return empty
    unique = {(item['root'], item['prefix'], item['clock']): item for item in tap_scopes}
    return {'applicable': bool(unique), 'witnesses': witnesses, 'tap_scopes': list(unique.values()),
            'proof_kind': 'literal source input/port/FF clock witnesses, not DRC or scan eligibility'}


def debug_exclusion_preflight_problems(dofile: str, spec: str, facts: dict, words_for) -> list[str]:
    if not facts.get('applicable') or not debug_exclusion_requested(spec):
        return []
    for line in spec.splitlines():
        if (re.search(r'不纳入|不参与|不允许.{0,20}扫描|\bexclude|not.{0,15}scan', line, re.I) and
                not debug_exclusion_requested(line) and not subtree_exclusion_requirements(line)):
            # Another explicitly authorized exception needs its own scope proof.
            return []
    # A later positive command may deliberately restore selected exceptions.
    # Do not infer final state for such a program; use the real report gate.
    if re.search(r'\bset_scan_element\s+(?:true|1|yes|on)\b', dofile, re.I):
        return []
    designs, clocks = set(), set()
    for line in dofile.replace('\\\n', ' ').splitlines():
        words = words_for(line.strip())
        if len(words) == 2 and words[0] == 'present_design' and _NET.fullmatch(words[1].strip('"{}')):
            designs.add(words[1].strip('"{}'))
        if words and words[0] == 'set_scan_signal' and len(words) % 2 == 1:
            options = dict(zip(words[1::2], words[2::2]))
            if options.get('-type', '').strip('"{}') == 'clock':
                clocks.update(port for port in options.get('-port', '').strip('"{}').split() if _NET.fullmatch(port))
    if len(designs) != 1 or not clocks:
        return []
    root = next(iter(designs))
    taps = [row for row in facts['tap_scopes'] if row['root'] == root]
    debug_clocks = {row['clock'] for row in taps}
    functional_clocks = clocks - debug_clocks
    if not taps or not functional_clocks:
        return []
    selectors = _selectors(dofile, words_for)
    permitted = subtree_exclusion_requirements(spec)
    from fnmatch import fnmatchcase
    problems = []
    for row in facts['witnesses']:
        name = row['instance']
        if row['root'] != root or row['tap_prefix'] or row['clock'] not in functional_clocks:
            continue
        if any(name.startswith(rule['prefix']+'/') and not any(fnmatchcase(name, p) for p in rule['exceptions'])
               for rule in permitted):
            continue
        if not any(_selected(candidate, selector) for selector in selectors for candidate in (name, root+'/'+name)):
            continue
        scopes = ', '.join(sorted({item['prefix']+'/*' for item in taps}))
        problems.append(f'Debug/TAP-only exclusion selects functional FF {name}; actual Liberty '
                        f'{row["cell_type"]}.{row["clock_pin"]} traces to declared scan clock {row["clock"]} '
                        f'({row["source"]}:L{row["line"]}). Observed TAP scopes: {scopes}, clocks: '
                        f'{", ".join(sorted(debug_clocks))}. Narrow the selector to the task domain; '
                        'preserve valid reset/control changes from your previous proposal and apply all edits to the same CURRENT base.')
        if len(problems) >= 3:
            break
    return problems
