"""Check explicit subtree exceptions and bounded debug-domain exclusions."""
from __future__ import annotations

from fnmatch import fnmatchcase
import json
from pathlib import Path
import re
from typing import Callable

from report_validation import report_rows
from scan_exclusion_evidence import _selectors, _selected


_PATH = re.compile(r'[A-Za-z_$][\w$./\[\]-]*')


def subtree_exclusion_requirements(spec: str) -> list[dict]:
    result = []
    for line in spec.splitlines():
        paths = re.findall(r'`([^`\n]+)`', line)
        if (len(paths) < 2 or not re.search(r'下.{0,30}(?:所有|全部)|under.{0,30}(?:all|every)', line, re.I)
                or not re.search(r'除了|除外|except', line, re.I)
                or not re.search(r'其余.{0,20}(?:不允许|不得|禁止|不参与)|exclude.{0,40}except', line, re.I)
                or re.search(r'如果|仅在|例如|示例|\b(?:if|when|example)\b', line, re.I)):
            continue
        prefix = paths[0].strip('/')
        exceptions = [path.strip('/') for path in paths[1:] if path.strip('/').startswith(prefix+'/')]
        if _PATH.fullmatch(prefix) and exceptions:
            result.append({'prefix':prefix,'exceptions':exceptions})
    return result


def _designs(dofile: str, words_for: Callable) -> set[str]:
    values = set()
    for line in dofile.splitlines():
        words = words_for(line.strip())
        if len(words) == 2 and words[0] == 'present_design' and _PATH.fullmatch(words[1].strip('"{}')):
            values.add(words[1].strip('"{}'))
    return values


def _relative(name: str, designs: set[str]) -> str:
    name = name.lstrip('/')
    for design in designs:
        if name.startswith(design+'/'):
            return name[len(design)+1:]
    return name


def exclusion_configuration_problems(dofile: str, spec: str, words_for: Callable) -> list[str]:
    """Reject known parent selections; never infer dynamic collection contents."""
    requirements = subtree_exclusion_requirements(spec)
    if not requirements:
        return []
    selectors = _selectors(dofile, words_for)
    if not selectors:
        return []  # Actual reports still have to prove the task scopes.
    designs = _designs(dofile, words_for)
    problems = []
    for requirement in requirements:
        prefix = requirement['prefix']
        names = {prefix,'/'+prefix} | {design+'/'+prefix for design in designs}
        if any(not selector.get('sequential_only') and _selected(name, selector)
               for selector in selectors for name in names):
            problems.append(f'Task exception subtree {prefix}: exclusion selects the hierarchy parent and recursively '
                            'disables its exceptions. Select only sequential descendant leaves and keep the stated exceptions.')
    return problems


def debug_exclusion_requested(spec: str) -> bool:
    return any(re.search(r'JTAG|\bTAP\b', line, re.I) and
               re.search(r'TAP|状态机|state.machine', line, re.I) and
               re.search(r'不纳入|不参与|不允许.{0,20}扫描|exclude|not.{0,15}scan', line, re.I) and
               not re.search(r'如果|仅在|例如|\b(?:if|when|example)\b', line, re.I)
               for line in spec.splitlines())


def debug_domain_source_context(paths: list[Path], spec: str, hints: dict, limit: int = 9000) -> str:
    """Show literal clock bindings of task-relevant debug modules, without inferred roles."""
    if not debug_exclusion_requested(spec):
        return 'No explicit debug-domain exclusion requested'
    module_entries = hints.get('modules', [])
    names = [entry.get('name') if isinstance(entry,dict) else entry for entry in module_entries]
    selected = {name for name in names if isinstance(name,str) and re.search(r'jtag|tap',name,re.I)}
    selected |= {edge['parent'] for edge in hints.get('module_instances',[]) if edge['type'] in selected}
    selected = set(sorted(selected)[:12])
    snippets = []
    consumed = 0
    counts = {}
    module = ''
    for path in paths:
        with path.open(encoding='utf-8',errors='replace') as stream:
            for number,line in enumerate(stream,1):
                found = re.match(r'\s*module\s+([A-Za-z_$][\w$]*)',line) if line.lstrip().startswith('module') else None
                if found:
                    module = found[1]
                if module not in selected:
                    continue
                interesting = found or re.search(r'\binput\b|\.(?:clk|clock|ck|tck)[\w]*\s*\(',line,re.I)
                if interesting and counts.get(module,0) < 24:
                    item = {'module':module,'source':str(path),'line':number,'literal':line.rstrip()[:400]}
                    size = len(json.dumps(item,ensure_ascii=False))
                    if consumed+size > limit:
                        return json.dumps({'source_excerpts':snippets,'display_complete':False,'roles_proved':False},ensure_ascii=False)
                    snippets.append(item);consumed+=size;counts[module]=counts.get(module,0)+1
                if re.match(r'\s*endmodule\b',line):
                    module = ''
    return json.dumps({'source_excerpts':snippets,'display_complete':False,'roles_proved':False},ensure_ascii=False)


def exclusion_report_problems(paths: list[Path], spec: str, dofile: str, words_for: Callable) -> list[str]:
    """Use actual FF state/clock rows; complex unreported eligibility stays unknown."""
    requirements = subtree_exclusion_requirements(spec)
    debug = debug_exclusion_requested(spec)
    if not requirements and not debug:
        return []
    reports = [p for p in paths if 'element' in p.name.lower() and p.suffix.lower() in {'.rpt','.report','.txt'}]
    canonical = [p for p in reports if p.name == 'rpt_scan_element.audit.rpt']
    reports = canonical or reports
    if not reports:
        return ['No actual scan-element state report proves task exclusion scopes']
    designs = _designs(dofile, words_for)
    clocks = set()
    for line in dofile.splitlines():
        words = words_for(line.strip())
        if words and words[0] == 'set_scan_signal' and len(words)%2 == 1:
            options = {k:v.strip('"{}') for k,v in zip(words[1::2],words[2::2])}
            if options.get('-type') == 'clock' and _PATH.fullmatch(options.get('-port','')):
                clocks.add(options['-port'])
    def relevant(line: str) -> bool:
        return ('user_defined_nonscannable' in line if debug else False) or any(
            r['prefix']+'/' in line for r in requirements)
    rows = []
    for path in reports:
        rows.extend(row for row in report_rows(path, {'InstanceName','ObjState','Type'},row_filter=relevant)
                    if row['Type'] in {'dff','sff'} and row['InstanceName'])
    problems = []
    for requirement in requirements:
        prefix = requirement['prefix']
        actual = [(row,_relative(row['InstanceName'],designs)) for row in rows
                  if _relative(row['InstanceName'],designs).startswith(prefix+'/')]
        if not actual:
            problems.append(f'No actual FF state rows prove required exclusion subtree {prefix}')
            continue
        kept = [(row,name) for row,name in actual if any(fnmatchcase(name,pattern) for pattern in requirement['exceptions'])]
        excluded = [(row,name) for row,name in actual if not any(fnmatchcase(name,pattern) for pattern in requirement['exceptions'])]
        if not kept:
            problems.append(f'No actual FF state rows prove the stated exceptions under {prefix}')
        if not excluded:
            problems.append(f'No actual FF state rows prove excluded descendants under {prefix}')
        for row,name in kept:
            if row['ObjState'] == 'user_defined_nonscannable':
                problems.append(f'Task exception {name} was explicitly excluded ({Path(row["source"]).name}:L{row["line"]})')
                break
        for row,name in excluded:
            if row['ObjState'] != 'user_defined_nonscannable':
                problems.append(f'Task excluded descendant {name} lacks explicit exclusion ({Path(row["source"]).name}:L{row["line"]})')
                break
    # For a task with only a debug/TAP-domain exception, a broad parent query
    # must not suppress ordinary FFs on the one declared scan clock. Limit this
    # check to observed TAP paths and a single declared clock; other topologies
    # need source/domain tracing rather than a guessed name-based decision.
    tap_paths = set()
    for row in rows:
        parts = _relative(row['InstanceName'],designs).split('/')
        for index,part in enumerate(parts[:-1]):
            if 'tap' in re.split(r'[_$.-]',part.lower()):
                tap_paths.add('/'.join(parts[:index+1]))
    if debug and len(clocks) == 1 and tap_paths:
        for row in rows:
            name = _relative(row['InstanceName'],designs)
            declared = bool(clocks & set(re.split(r'[,\s]+',row.get('SiSoClocks',''))))
            in_tap = any(name.startswith(prefix+'/') for prefix in tap_paths)
            permitted = any(name.startswith(r['prefix']+'/') and not any(fnmatchcase(name,p) for p in r['exceptions'])
                            for r in requirements)
            if row['ObjState'] == 'user_defined_nonscannable' and declared and not in_tap and not permitted:
                problems.append(f'Debug-only exclusion also disabled clock-controlled functional FF {name} '
                                f'({Path(row["source"]).name}:L{row["line"]}); narrow the source/domain selector')
                if len(problems) >= 12:
                    break
    return problems
