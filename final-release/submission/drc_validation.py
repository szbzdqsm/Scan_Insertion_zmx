"""Read actual DRC result blocks without treating command/configuration names as fails."""
from __future__ import annotations

from pathlib import Path
import re


# Parsed evidence is reused only within one validator invocation. No verdict,
# relation, task result or proof is cached. Every access hashes current bytes.
from contextvars import ContextVar
from functools import wraps
import copy as _copy
import hashlib as _hashlib
import json as _json
_GATE_READS = ContextVar('gate_evidence_reads', default=None)

def scoped_gate_reads(function):
    @wraps(function)
    def run(*args, **kwargs):
        if _GATE_READS.get() is not None:
            return function(*args, **kwargs)
        state = {'values': {}, 'hits': 0, 'misses': 0}
        token = _GATE_READS.set(state)
        try:
            return function(*args, **kwargs)
        finally:
            _GATE_READS.reset(token)
            from runtime_events import emit
            import sys
            from case_deadline import CaseDeadlineExceeded
            if not isinstance(sys.exc_info()[1], CaseDeadlineExceeded):
                emit('gate_parse_scope_end', stage=function.__name__, scope={'parse_hits':state['hits'], 'parse_misses':state['misses'], 'proof_results_cached':False})
    return run

def _gate_read(kind, paths, semantic_key, producer):
    def identity():
        return tuple((str(Path(p).resolve()), _hashlib.sha256(Path(p).read_bytes()).hexdigest()) for p in paths)
    state = _GATE_READS.get()
    if state is None:
        return producer()
    before = identity()
    key = (kind, before, semantic_key)
    if key in state['values']:
        state['hits'] += 1
        return _copy.deepcopy(state['values'][key])
    state['misses'] += 1
    result = producer()
    if identity() != before:
        raise ValueError('Evidence content changed while parsing')
    # Bound memory; exceeding this finite per-call cache simply parses anew.
    if len(state['values']) < 12:
        state['values'][key] = _copy.deepcopy(result)
    return result

def _gate_libraries(paths):
    from partial_insertion_validation import _libraries
    return _gate_read('Liberty', paths, None, lambda: _libraries(paths))

def _gate_design(paths, library, top):
    from eco_structure import read_design
    semantic = (top, _hashlib.sha256(_json.dumps(library,sort_keys=True,separators=(',',':')).encode()).hexdigest())
    return _gate_read('design', paths, semantic, lambda: read_design(paths, library, top))

def _gate_library_definitions(paths):
    from eco_equivalence import _nodes, _cells
    return _gate_read('Liberty_definitions', paths, None,
        lambda: [(path, cell) for path in paths for cell in _cells(_nodes(path.read_text()))])


def rule_codes(text: str) -> set[str]:
    return {re.sub(r"[-_ ]", "", rule).upper()
            for rule in re.findall(r"(?<![A-Za-z0-9_])DFTR[-_ ]?(?:TIE[01]|L[12]|\d+)(?![A-Za-z0-9_])", text, re.I)}


_RULE_PATTERN = r"(?<![A-Za-z0-9_])DFTR[-_ ]?(?:TIE[01]|L[12]|\d+)(?![A-Za-z0-9_])"
_PERMISSION = re.compile(
    r"(?P<ignore>忽略|\bignore\w*\b)|(?P<retain>无需处理|不需要处理|不用处理)|"
    r"(?P<allow>允许|许可|可以|可|\b(?:allow\w*|permit\w*|can|may)\b)", re.I)
_BRIDGE_WORDS = re.compile(
    r"仅|只|以下|下列|这些|上述|该|的|可|可以|允许|许可|保留|剩余|残余|残留|遗留|存在|出现|"
    r"忽略|无需处理|不需要处理|不用处理|违例|违规|规则|检查|标号|编号|为|种|类|固有|特性|"
    r"形式|以|\b(?:the|following|these|above|them|can|may|be|are|is|as|to|"
    r"DRC|rule\w*|violation\w*|warning\w*|residual\w*|remaining|retain\w*|"
    r"remain\w*|exist\w*|allow\w*|permit\w*|inherent|intrinsic|ignored)\b", re.I)
_RESIDUAL_OBJECT = re.compile(
    r"保留|剩余|残余|残留|遗留|存在|出现|违例|违规|规则|无需处理|不需要处理|不用处理|"
    r"\b(?:DRC|rule\w*|violation\w*|warning\w*|residual\w*|remain\w*|retain\w*|exist\w*)\b", re.I)
_NON_DRC_OBJECT = re.compile(r"报告|格式|日志|文件|输出|显示|编码|\b(?:report|format|log|file|output|display|encoding)\w*\b", re.I)
_NEGATIVE_IGNORE = re.compile(
    r"(?:不允许|不得|禁止|不能|不可|不要|不).{0,16}(?:忽略|\bignore\w*)|"
    r"\b(?:must\s+not|do\s+not|cannot|never)\s+ignore\w*|\bnot\s+allowed\b", re.I)
_NEGATIVE_RESIDUAL = re.compile(
    r"修复|消除|清零|必须处理|(?:不允许|不得|禁止|不能|不可).{0,16}(?:保留|残留|存在|出现)|"
    r"\b(?:repair|fix|resolve)\w*|\b(?:must\s+not|do\s+not|cannot|never).{0,16}(?:remain|retain|exist)", re.I)
_CONDITIONAL_PERMISSION = re.compile(r"仅在|只有|如果|范围|指定实例|特定实例|\b(?:if|when|provided|instances?)\b", re.I)
_ACTION_START = (r"忽略|无需处理|不需要处理|不用处理|允许|许可|可以|可保留|不允许|不得|禁止|不能|不可|必须|修复|消除|清零|"
                 r"\b(?:ignore\w*|allow\w*|permit\w*|must|do|never|repair\w*|fix\w*|resolve\w*)\b")
_OTHER_ACTION_START = r"输出|生成|导出|保存|修改|显示|报告|记录|混合|保持|\b(?:keep|generate|dump|write|save|modify|report|display|mix)\w*\b"
_CLAUSE_SPLIT = re.compile(
    r"[，,]|但是|然而|但|\bbut\b|(?:并且|并|且|以及|和|与|及|\band\b)(?=\s*(?:" +
    _ACTION_START + r"|" + _OTHER_ACTION_START + r"|" + _RULE_PATTERN +
    r"[^，,;；。\n]{0,40}(?:" + _ACTION_START + r")))", re.I)


def _clear_drc_bridge(text: str) -> str:
    return re.sub(r"[\s`'\"()（）:：/\[\]_、.\-\d]|\band\b|与|及|和", "", _BRIDGE_WORDS.sub("", text), flags=re.I)


def _permission_sets(spec: str) -> tuple[set[str], set[str]]:
    """Scope each predicate separately, retaining uncertainty as no permission."""
    retained, ignored, denied_residual, denied_ignore = set(), set(), set(), set()
    for sentence in re.split(r"[\n;；。]", spec):
        pending: set[str] = set()
        carry_kind: str | None = None
        for clause in _CLAUSE_SPLIT.split(sentence):
            if not clause.strip():
                continue
            refs = list(re.finditer(_RULE_PATTERN, clause, re.I))
            codes = rule_codes(clause)
            clean = re.sub(r"无需处理|不需要处理|不用处理", "", clause)
            no_ignore = _NEGATIVE_IGNORE.search(clean)
            no_residual = _NEGATIVE_RESIDUAL.search(clean)
            conditional = _CONDITIONAL_PERMISSION.search(clause)
            if no_ignore or no_residual or conditional:
                target = codes
                if not target and pending:
                    stripped = _NEGATIVE_IGNORE.sub("", _NEGATIVE_RESIDUAL.sub("", clean))
                    if not _clear_drc_bridge(stripped):
                        target = pending
                if no_residual or conditional:
                    denied_residual.update(target)
                if no_ignore or no_residual or conditional:
                    denied_ignore.update(target)
                pending, carry_kind = set(), None
                continue
            granted_kind = None
            # A report/log/format permission cannot authorize the DRC condition,
            # even when its identifier immediately follows "allow".
            verbs = list(_PERMISSION.finditer(clause))
            object_start = min([ref.start() for ref in refs] + [verb.start() for verb in verbs], default=0)
            if not _NON_DRC_OBJECT.search(clause[object_start:]):
                for verb in _PERMISSION.finditer(clause):
                    kind = "ignore" if verb.lastgroup == "ignore" else "retain"
                    if kind == "retain" and not _RESIDUAL_OBJECT.search(clause):
                        continue
                    after = next((index for index, ref in enumerate(refs) if ref.start() >= verb.end()), None)
                    before = next((index for index in range(len(refs) - 1, -1, -1) if refs[index].end() <= verb.start()), None)
                    target: set[str] = set()
                    if after is not None and not _clear_drc_bridge(clause[verb.end():refs[after].start()]):
                        last = after
                        while last + 1 < len(refs) and not _clear_drc_bridge(clause[refs[last].end():refs[last + 1].start()]):
                            last += 1
                        # Keep the entire addressed object honest: a dangling
                        # unrelated action after the rule list is not a waiver.
                        if not _clear_drc_bridge(clause[refs[last].end():]):
                            target = set().union(*(rule_codes(ref.group()) for ref in refs[after:last + 1]))
                    elif before is not None and not _clear_drc_bridge(clause[refs[before].end():verb.start()]):
                        first = before
                        while first and not _clear_drc_bridge(clause[refs[first - 1].end():refs[first].start()]):
                            first -= 1
                        if not _clear_drc_bridge(clause[verb.end():]):
                            target = set().union(*(rule_codes(ref.group()) for ref in refs[first:before + 1]))
                    elif not refs and pending and not _clear_drc_bridge(clause[:verb.start()] + clause[verb.end():]):
                        target = pending
                    if target:
                        (ignored if kind == "ignore" else retained).update(target)
                        granted_kind = kind
                # A comma-separated bare list inherits only its own preceding
                # predicate, including the distinction between retain and ignore.
                if codes and carry_kind and not _clear_drc_bridge(re.sub(_RULE_PATTERN, "", clause, flags=re.I)):
                    (ignored if carry_kind == "ignore" else retained).update(codes)
                    granted_kind = carry_kind
            if codes:
                pending, carry_kind = codes, granted_kind
            elif granted_kind:
                carry_kind = granted_kind
            elif (re.search(r"固有特性|设计固有|inherent|intrinsic", clause, re.I) and
                  not re.search(r"允许|许可|allow|permit|时钟|clock|网表|netlist|输出|report", clause, re.I)):
                continue
            else:
                pending, carry_kind = set(), None
    retained -= denied_residual
    ignored -= denied_residual | denied_ignore
    return retained | ignored, ignored


def authorized_rule_codes(spec: str) -> set[str]:
    """Bind residual permission to its DRC object, never to an unrelated action."""
    return _permission_sets(spec)[0]


def authorized_ignored_rule_codes(spec: str) -> set[str]:
    """Only ignore predicates authorize suppression; residual Warning stays visible."""
    return _permission_sets(spec)[1]


def required_ignored_rule_codes(spec: str) -> set[str]:
    """Separate an explicit Ignore instruction from permission to ignore.

    Reuse the existing rule/object/negation scope parser. Optional or conditional
    permission is not a requirement to change the final handling level.
    """
    sentences = []
    for sentence in re.split(r"[\n;；。]", spec):
        clauses = []
        for clause in _CLAUSE_SPLIT.split(sentence):
            if re.search(r"允许|许可|可以|可选择|可(?=忽略)|酌情|不要求|不必|"
                         r"\b(?:allow\w*|permit\w*|may|can|optional\w*)\b", clause, re.I):
                clauses.append("optional handling choice")
            else:
                clauses.append(re.sub(r"(?<!不)(?:必须|应当|应(?=忽略))|"
                                      r"\b(?:must|shall|should)\s+(?!not\b)(?:be\s+)?",
                                      "", clause, flags=re.I))
        sentences.append(",".join(clauses))
    return authorized_ignored_rule_codes("\n".join(sentences))


def required_rule_handling_problems(run_dir: Path, reports: list[Path], dofile: str,
                                    spec: str, words_for) -> list[str]:
    """Check required final levels in same-run, final-state native tables.

    Earlier warnings do not determine final policy. A table from another design,
    run, before insertion or before a later handling update cannot prove it.
    This checks task compliance; it never rewrites Tcl or authorizes suppression.
    """
    required = required_ignored_rule_codes(spec)
    if not required:
        return []
    from operation_audit import operation_trace
    from canonical_delivery import CanonicalDeliveryError, _real_file
    run = run_dir.absolute()
    output = run.parent.parent
    paths = [run / (run.name + ".log"), *(p.absolute() for p in reports)]
    trace = operation_trace(paths, output, dofile, words_for, allow_verbose=True, require_insertion=False)
    tables = []
    if trace:
        # A later native writer replaces an earlier table at the same path.
        # Keep the last writer of any kind, so a different report cannot stand in.
        last_writers = {r['path']: r for r in trace['reports']}
        trace = {**trace, 'reports': list(last_writers.values())}
        last_update = 0
        with paths[0].open(errors="replace") as stream:
            for number, line in enumerate(stream, 1):
                echo = re.search(r"CMD-0034\]\s+@\d+:\s*(.*)", line)
                words = words_for(echo[1]) if echo else []
                if (words and words[0] != 'set' and
                        'set_scan_drc_rule_handling'.startswith(words[0])):
                    last_update = number
        writers = [r for r in trace['reports'] if r['kind'] == 'rpt_scan_drc_rule_handling']
        latest = max((r['log_line'] for r in writers), default=0)
        last_update = max(last_update, (trace['operation'] or {}).get('log_line', 0))
        for path in paths[1:]:
            bindings = [w for w in writers if w['log_line'] == latest and w['log_line'] > last_update and
                        (w['path'] == path or path.parent == run/'reports' and w['path'].name == path.name)]
            if len(bindings) != 1:
                continue
            writer = bindings[0]
            try:
                _real_file(writer['path'], output)
                if writer['path'].read_bytes() != path.read_bytes():
                    continue
                with path.open(errors='replace') as stream:
                    header = ''.join(next(stream, '') for _ in range(5))
                if re.findall(r'(?m)^\s*Design\s*:\s*(\S+)\s*$', header) != [trace['design']]:
                    continue
            except (OSError, CanonicalDeliveryError):
                continue
            rows = []
            with path.open(errors='replace') as stream:
                for line in stream:
                    row = re.fullmatch(r"\s*(DFTR[-\w]+)\s+(Error|Warning|Info|Ignore)\s+"
                                       r"(Error|Warning|Info|Ignore)\s+(\S+)\s*", line)
                    if row and rule_codes(row[1]):
                        rows.append((next(iter(rule_codes(row[1]))), row[3], row[4]))
            tables.append(rows)
    problems = []
    for code in sorted(required):
        if not tables or any(not any(rule == code and level == 'Ignore' and scope == 'all'
                                     for rule, level, scope in rows) or
                             any(rule == code and (level != 'Ignore' or scope != 'all')
                                 for rule, level, scope in rows) for rows in tables):
            problems.append(f"Task requires {code} Ignore for all instances; final same-design "
                            "native rule-handling evidence is missing, stale or has a different level/scope")
    return problems


def diagnostic_residual_claim_problems(issue: dict, permitted: set[str]) -> list[dict]:
    """A repaired DRC condition cannot establish a contradictory waiver claim.

    Only explicit rule-permission statements in the diagnosis/action are checked.
    Requirement citations do not expand the fault. This is not a general causal
    language verifier and never rewrites the model's original diagnosis.
    """
    if not rule_codes(str(issue.get('found', {}).get('excerpt', ''))):
        return []
    diagnosis = issue.get('diagnosis', {})
    attempts = issue.get('attempts') or [{}]
    fields = [('phenomenon', issue.get('phenomenon', '')),
              *((name, diagnosis.get(name, '')) for name in ('summary', 'root_cause')),
              ('fix.action', attempts[-1].get('fix', {}).get('action', ''))]
    problems = []
    for field, text in fields:
        for sentence in re.split(r'[;；。\n]|\.(?![\w$])', str(text)):
            # Keep an explicit permission separate from its proposed explanation.
            # Neither explanation nor final DRC results authorize an extra rule.
            clause = re.split(r'\bbecause\b|\bdue\s+to\b|\bsince\b|因为|由于',
                              sentence, maxsplit=1, flags=re.I)[0]
            if re.search(r'\bno\b.{0,40}\b(?:acceptable|allowed|permitted)\b', clause, re.I):
                continue
            normalized = re.sub(r'\bacceptable\b', 'allowed', clause, flags=re.I)
            asserted = authorized_rule_codes('DRC ' + normalized)
            # A postfix predicate addresses the whole adjacent rule list, not
            # just the last member left by a clause/conjunction split.
            group = _RULE_PATTERN + r'(?:\s*(?:[,，、/]|\band\b|与|及|和)\s*' + _RULE_PATTERN + r')*'
            for match in re.finditer('(' + group + r')\s+(?:(?:is|are)\s+)?'
                                     r'(?:acceptable|allowed|permitted)\b', clause, re.I):
                asserted.update(rule_codes(match[1]))
            contradicted = asserted - permitted
            if contradicted:
                problems.append({'reason': 'residual_permission_contradicts_task', 'field': field,
                                 'original_clause': clause.strip(),
                                 'asserted_residual_rules': sorted(asserted),
                                 'unauthorized_rules': sorted(contradicted),
                                 'task_permitted_rules': sorted(permitted)})
    return problems


def signal_declaration_claim_problems(issue: dict, output_dir: Path, words_for) -> list[dict]:
    """Check explicit declared-role premises against the original native state.

    A DRC message calling an object a clock is not its set_scan_signal type.
    This bounded declaration check does not infer arbitrary causal truth.
    """
    from canonical_delivery import CanonicalDeliveryError, _real_file
    from dofile_recipe import tcl_chunks
    from report_validation import report_rows
    diagnosis = issue.get('diagnosis', {}); claims = []
    for field in ('summary', 'root_cause'):
        for match in re.finditer(
                r'(?P<object>[^;,!?\n]+?)\s+(?:was|is|had\s+been)\s+'
                r'(?:(?:incorrectly|wrongly)\s+)?declared\s+as\s+(?:a\s+)?'
                r'(?P<role>clock|reset|scan_enable|constant)\b', str(diagnosis.get(field, '')), re.I):
            claims.append({'field': field, 'original_clause': match[0],
                           'object': match['object'].strip(), 'claimed_role': match['role'].lower()})
    if not claims:
        return []
    problems = []; root = output_dir.absolute(); found = issue.get('found', {}); rid = str(found.get('run_ref', ''))
    for claim in claims:
        problem = {'reason': 'declared_signal_role_not_established', **claim,
                   'detail': 'Fault elimination does not establish a contradicted or unbound prior declaration type.'}
        try:
            if not re.fullmatch(r'R[1-9]\d*', rid):
                problems.append(problem); continue
            run = root/'runs'/rid; script = run/'deliverables'/(rid+'.dofile'); native = run/(rid+'.log')
            for path in (script, native):_real_file(path, root)
            top = ''; all_declarations = []; line_number = 1; design_count = 0
            for chunk in tcl_chunks(script.read_text()):
                words = words_for(chunk.strip().replace('\\\n', ' '))
                if words[:1] == ['present_design'] and len(words) == 2:
                    top = words[1]; design_count += 1
                if words[:1] == ['set_scan_signal'] and len(words) % 2 == 1:
                    opts = dict(zip(words[1::2], (w.strip('"{}') for w in words[2::2])))
                    if opts.get('-port'):
                        all_declarations.append((line_number, words, opts.get('-type'), opts['-port']))
                line_number += chunk.count('\n')
            # Identity candidates come from this design/run's executed native
            # declarations, not the model's noun or the adopted final netlist.
            # A declaration may name a not-yet-created port; it is not a role
            # effectiveness or physical existence proof.
            executed = []; native_design = None
            with native.open(errors='replace') as stream:
                for number, line in enumerate(stream, 1):
                    m = re.search(r'CMD-0034\]\s+@(\d+):\s*(.*)', line)
                    if m:
                        actual_words = words_for(m[2])
                        if actual_words[:1] == ['present_design']:
                            native_design = actual_words[1] if len(actual_words) == 2 else None
                        for n,w,role,port in all_declarations:
                            if native_design == top and int(m[1]) == n and actual_words == w:
                                executed.append((port, {'source':native.relative_to(root).as_posix(),
                                    'locator':f'L{number}', 'excerpt':line.strip()}))
            subject = re.sub(r'^(?:the|a|an)\s+', '', claim['object'], flags=re.I)
            catalog = {port:None for port,_ in executed} if design_count == 1 and top else {}
            identity = _signal_location(subject, words_for, known_ports=catalog)
            if not identity:
                problem.update(run_ref=rid, identity_status='unresolved',
                    raw_subject=claim['object'], native_identity_candidates=sorted(catalog))
                problems.append(problem); continue
            port = identity['name']
            claim = {**claim, 'object':port}
            problem.update(object=port, identity_binding={
                'raw_subject':subject, 'name':port, 'design':top, 'run_ref':rid,
                'source':'executed native declaration; not physical existence or effective role',
                'parser':'_signal_location', 'kind':identity['kind']})
            declarations = [(n,w,role) for n,w,role,name in all_declarations if name == port]
            echoes = [ref for name,ref in executed if name == port]
            rows = []
            for report in sorted((run/'reports').glob('*signal*.rpt')):
                _real_file(report, root); text = report.read_text()
                if design_count != 1 or re.findall(r'(?m)^\s*Design:\s*(\S+)\s*$', text) != [top]:continue
                lines = text.splitlines()
                for row in report_rows(report, {'Port', 'SignalType', 'OffState'}):
                    if row['Port'] == claim['object']:
                        rows.append({'role': row['SignalType'].split('(')[0],
                                     'source': report.relative_to(root).as_posix(),
                                     'locator': f"L{row['line']}", 'excerpt': lines[row['line']-1]})
            if (len(declarations) != 1 or len(echoes) != 1 or not rows or
                    any(row['role'] != claim['claimed_role'] for row in rows) or
                    declarations[0][2] != claim['claimed_role']):
                problem.update(run_ref=rid, native_commands=echoes, native_rows=rows)
                # This producer checks a prior diagnostic premise, not the
                # adopted final role. Issue scope only when native source,
                # design and the matching declaration itself are unambiguous.
                native_roles = {row['role'] for row in rows}
                contradicted = bool(rows and len(native_roles) == 1 and
                    declarations[0][2] in native_roles and declarations[0][2] != claim['claimed_role']) if len(declarations) == 1 else False
                if (design_count == 1 and top and len(declarations) == len(echoes) == 1 and
                        (declarations[0][2] == claim['claimed_role'] or contradicted)):
                    import hashlib
                    problem['assessment_scope'] = {
                        'kind': 'prior_signal_declaration_premise',
                        'producer': 'signal_declaration_claim_problems',
                        'case_output': str(root), 'run_ref': rid, 'design': top,
                        'object': claim['object'], 'claimed_role': claim['claimed_role'],
                        **({'assessment_status':'contradicted', 'actual_declared_role':declarations[0][2],
                            'actual_native_roles':sorted(native_roles), 'native_role_evidence':rows} if contradicted else {}),
                        'script': script.relative_to(root).as_posix(),
                        'script_sha256': hashlib.sha256(script.read_bytes()).hexdigest(),
                        'native': native.relative_to(root).as_posix(),
                        'native_sha256': hashlib.sha256(native.read_bytes()).hexdigest(),
                        'meaning': 'Prior declaration/effective-role premise unproved; no verdict about final delivery.'}
                problems.append(problem)
        except (OSError, ValueError, TypeError, KeyError, CanonicalDeliveryError):
            problems.append(problem)
    return problems


def signal_fact_claim_problems(issue: dict, output_dir: Path, words_for,
                               input_dir: Path | None = None) -> list[dict]:
    """Check bounded existence and literal leaf-level facts, not arbitrary prose.

    Requirement citations are excluded. No diagnosis is rewritten, and a native
    condition becoming clean cannot establish one of these original facts.
    """
    from canonical_delivery import CanonicalDeliveryError, _real_file
    from report_validation import report_rows, _full_insertion_designs
    text = ' '.join(str(issue.get('diagnosis', {}).get(k, '')) for k in ('summary', 'root_cause'))
    absent = list(re.finditer(r'\bin\s+([A-Za-z_][\w$]*)\s+(?:with\s+)?no\s+scan_enable\b', text, re.I))
    found = issue.get('found', {})
    leaf = re.search(r"Reset input '([^']+)' of 'DFF' '([^']+)'", str(found.get('excerpt', '')))
    inactive = re.search(r'\binactive\s*(?:\(off\)\s*)?(?:state|level)\s+(?:is|=)\s*([01])\b', text, re.I)
    pin_claim = bool(leaf and inactive and re.search(r'\b'+re.escape(leaf[1])+r'\b', text) and
                     re.search(r'\b(?:Liberty|pins?)\b', text))
    if not absent and not pin_claim:
        return []
    problems = []; root = output_dir.absolute(); rid = str(found.get('run_ref', ''))
    try:
        if not re.fullmatch(r'R[1-9]\d*', rid):
            raise ValueError('No original actual run')
        run = root/'runs'/rid; script = run/'deliverables'/(rid+'.dofile')
        _real_file(script, root)
        tops = _full_insertion_designs(script.read_text())
        if len(tops) != 1:
            raise ValueError('Ambiguous original design')
        top = next(iter(tops))
        for claim in absent:
            rows = []
            for path in sorted((run/'reports').glob('*signal*.rpt')):
                _real_file(path, root); lines = path.read_text().splitlines()
                if re.findall(r'(?m)^\s*Design:\s*(\S+)\s*$', '\n'.join(lines)) != [top]:
                    continue
                for row in report_rows(path, {'Port', 'SignalType', 'OwnerPartition'}):
                    if row['SignalType'].split('(')[0] == 'scan_enable' and row['OwnerPartition'] == claim[1]:
                        rows.append({'source': path.relative_to(root).as_posix(), 'locator': f"L{row['line']}",
                                     'excerpt': lines[row['line']-1], 'run_ref': rid})
            if rows:
                problems.append({'status': 'fail', 'reason': 'signal_absence_contradicted',
                    'original_clause': claim[0], 'partition': claim[1], 'native_evidence': rows})
            elif not list((run/'reports').glob('*signal*.rpt')):
                problems.append({'status': 'incomplete', 'reason': 'signal_absence_not_established',
                    'original_clause': claim[0], 'detail': 'The claimed prior partition absence has no native signal report.'})
        if pin_claim:
            proof = _leaf_inactive_fact(input_dir or run/'input', top, leaf[2], leaf[1])
            if not proof:
                problems.append({'status': 'incomplete', 'reason': 'leaf_inactive_fact_not_bound',
                    'original_clause': inactive[0], 'object': leaf[2], 'pin': leaf[1]})
            elif proof['inactive_level'] != int(inactive[1]):
                problems.append({'status': 'fail', 'reason': 'leaf_inactive_fact_contradicted',
                    'original_clause': inactive[0], 'object': leaf[2], 'pin': leaf[1], 'native_fact': proof,
                    'detail': 'The leaf pin and an external control across combinational logic are different objects.'})
    except (OSError, ValueError, TypeError, KeyError, CanonicalDeliveryError) as exc:
        problems.append({'status': 'incomplete', 'reason': 'original_signal_fact_unbound', 'detail': str(exc)})
    return problems


def _library_relation_claims(issue):
    text = ' '.join(str(issue.get('diagnosis', {}).get(k, '')) for k in ('summary', 'root_cause'))
    if not re.search(r'\b(?:statetable|Liberty)\b', text, re.I):
        return []
    return list(re.finditer(r'\b([A-Za-z_]\w*)\s+follows\s+([A-Za-z_]\w*)\s+'
                           r'(?:only\s+when|when)\s+([A-Za-z_]\w*)\s*=\s*([HL01])\b', text))


def _library_context_claims(issue):
    """A named pin/level -> gate-effect assertion is a contextual obligation.

    This finite relation recognizer does not infer a cell truth-table theorem
    or the reachable state of its other enables. Task/action prose is excluded.
    The producer below must resolve the pin against the actual clock driver.
    """
    result=[]
    for field in ('summary','root_cause'):
        text=str(issue.get('diagnosis',{}).get(field,''))
        patterns=[
            r'\b(?P<pin>[A-Za-z_]\w*)\s*(?:测试控制|测试使能|控制|使能)?(?:引脚|端口)?\s*(?:在|为|处于)\s*(?P<level>低|高)电平(?:时)?\s*(?:会|将)?(?P<effect>关闭|阻断|开启|打开)(?:时钟)?(?:门控|门|时钟)',
            r'\b(?P<pin>[A-Za-z_]\w*)\s*(?:pin\s+)?(?:=|is|at)\s*(?P<level>0|1|low|high)\s*(?:level\s*)?(?:causes?\s+|makes?\s+|means?\s+)?(?P<effect>blocks?|closes?|disables?|opens?|enables?)\s+(?:the\s+)?(?:clock\s+)?gat(?:e|ing)'
        ]
        for pattern in patterns:
            for m in re.finditer(pattern,text,re.I):
                result.append({'kind':'conditional_gate_effect','field':field,'clause':m[0],
                    'span':list(m.span()),'control':m['pin'],
                    'level':int(m['level'].lower() in {'1','high','高'}),'effect':m['effect']})
    # Gate-effect context is owned by this verifier, including a later
    # sentence in the same adopted field. Spans are provenance only. Do not
    # treat a sufficient high test input as proof of a low-input gate state.
    for field in ('summary','root_cause'):
        text=str(issue.get('diagnosis',{}).get(field,''))
        gate = r'(?:ICGs?|clock[ -]?gat(?:e|es|ing)|gated\s+clocks?|门控|时钟门|测试引脚)'
        causal = r'\b(?:so|causes?|making|leaving|otherwise|producing|left|remain(?:ed|s)?)\b|导致|否则|无法导通'
        effect = r'\b(?:closed|inactive|uncontrolled|not\s+(?:open|control)|does\s+not\s+open|remain(?:ed|s)?|left)\b|关闭|失效|未连接|无法导通'
        for m in re.finditer(r'[^。;；\n]+', text):
            clause=m[0]
            if not (re.search(gate,clause,re.I) and re.search(causal,clause,re.I) and re.search(effect,clause,re.I)):
                continue
            if any(r['field']==field and m.start()<=r['span'][0] and r['span'][1]<=m.end() for r in result):continue
            pins=set(re.findall(r'\b([A-Za-z_]\w*)\s+(?:is|stays?|remains?)\s+(?:low|high)\b',clause,re.I))
            # No arbitrary pin selection: a single explicit symbol is checked
            # against Liberty. An implicit test role is resolved only AFTER
            # the original FF -> ICG connection and unique role are verified.
            result.append({'kind':'conditional_gate_effect','field':field,
                'clause':clause,'span':list(m.span()),
                'control':next(iter(pins)) if len(pins)==1 else None,
                'control_candidates':sorted(pins),'effect':'contextual_gate_state',
                'binding':'explicit_pin' if len(pins)==1 else 'native_test_role'})
    return result


def _gate_location_binding(issue, native_location, design, trace, words_for):
    location=str(issue.get('diagnosis',{}).get('located_object',''))
    ff,pin=native_location[2],native_location[1]
    if location==ff+'/'+pin or any(location.startswith(ff+'/'+pin+c) for c in ('（','(',' ')):
        return {'kind':'exact_native_FF_pin','object':ff,'pin':pin,
                'design':trace['design'],'found':dict(issue['found']),
                'raw_location':location,'suffix_is_not_a_role_or_causal_proof':True}
    catalog=design['modules'][design['top']]['ports']
    selected=_signal_location(location,words_for,known_ports=catalog)
    words=words_for(location)
    # Existing command/parameter locator form, all tokens must be accounted for.
    if not selected and words[:1]==['set_scan_signal'] and len(words)%2==1:
        opts=dict(zip(words[1::2],(w.strip('{}"') for w in words[2::2])))
        if opts.get('-type')=='scan_enable' and opts.get('-port') in catalog:
            selected={'name':opts['-port'],'kind':'executed_signal_command'}
            if not any(e['words']==words and not e['errors'] for e in trace['signals']):return None
    if not selected and len(words)==3 and words[0] in catalog and words[1:]==['scan_enable','off_state']:
        selected={'name':words[0],'kind':'signal_parameter_locator'}
    if not selected or catalog.get(selected['name'])!='input':return None
    events=[]
    for e in trace['signals']:
        opts=dict(zip(e['words'][1::2],(w.strip('{}"') for w in e['words'][2::2])))
        if opts.get('-port')==selected['name'] and opts.get('-view','spec')=='spec':events.append((e,opts))
    if not events:return None
    event,opts=events[-1]
    if event['errors'] or opts.get('-type')!='scan_enable' or opts.get('-usage') not in {'scan','all','clock_gating'}:return None
    return {'kind':'native_declared_scan_control','object':selected['name'],
        'FF_object':ff,'FF_pin':pin,'design':trace['design'],
        'found':dict(issue['found']),'native_declaration':event,
        'meaning':'Actual declared scan control and diagnostic endpoint; no inference of a prior gate connection or causal state.'}


def _diagnostic_loaded_state(issue, root, input_dir, words_for):
    """Bind the discovered state to native load/writer order, never a file glob.

    The official inventory is separate from successful native loads. Auxiliary
    reads are retained even when their transient contents are no longer saved.
    Missing contents before the diagnostic boundary cannot support a state.
    """
    import hashlib
    from pathlib import PurePosixPath
    from completion_policy import _reference
    from canonical_delivery import _target, _real_file
    from configuration_evidence import _signal_command_trace
    from eco_structure import MUTATIONS, DYNAMIC
    from eco_object_selection import is_context_query
    from scan_agent import get_task_artifacts
    found=issue['found']; rid=found['run_ref']; root=Path(root).absolute()
    _reference(root,found,{rid})
    _,_,nets,libs,_=get_task_artifacts(input_dir)
    official={str(p.resolve()):{'path':str(p),'role':role,'sha256':hashlib.sha256(p.read_bytes()).hexdigest()}
              for role,paths in [('original_netlist',nets),('library',libs)] for p in paths}
    run=root/'runs'/rid; script=run/'deliverables'/(rid+'.dofile'); log=run/(rid+'.log')
    _real_file(script,root); _real_file(log,root)
    physical=script.read_text().splitlines(); trace=_signal_command_trace(root,rid,words_for)
    if not trace:raise ValueError('Native script/design context unbound')
    virtual=None; variables={}; pending=None; active=None; events=[]; reads=[]; exports=[]; writers=[]
    for number,line in enumerate(log.read_text().splitlines(),1):
        origin=re.search(r'\[SOURCE TCL FILE\]\s+(\S+)\s*:',line)
        if origin:
            parts=PurePosixPath(origin[1]).parts
            cuts=[j for j,p in enumerate(parts) if p=='runs' and parts[j+1:j+2]==(rid,)]
            if virtual is not None or len(cuts)!=1:raise ValueError('Multiple native origins')
            virtual=PurePosixPath(*parts[:cuts[0]+2])
        echo=re.search(r'CMD-0034\]\s+@(\d+):\s*(.*)',line)
        if echo:
            # Native versions echo either an entire joined command or each
            # physical continuation line. Both must match the actual source;
            # a continuation is not a new command/design boundary.
            n=int(echo[1]); raw=echo[2].strip()
            if 1<n<=len(physical) and physical[n-2].rstrip().endswith('\\'):
                if raw!=physical[n-1].strip():raise ValueError('Native continuation/script mismatch')
                continue
            if active:active['end_log_line']=number-1
            pending=None; code=echo[2].strip(); n=int(echo[1]); active=None
            if not code or code.startswith('#'):continue
            if not 0<n<=len(physical):raise ValueError('Native source line outside script')
            actual=physical[n-1].strip(); index=n
            while actual.endswith('\\') and index<len(physical):
                actual=actual[:-1]+' '+physical[index].strip(); index+=1
            if code not in {actual,physical[n-1].strip()}:raise ValueError('Native command/script mismatch')
            code=actual
            w=words_for(code)
            if not w and re.match(r'^(?:if|foreach|foreach_in_collection|for|while)\b', code):
                from dofile_recipe import tcl_chunks
                # A nested echo starts inside an outer source group. Parse the
                # smallest complete source prefix, not the unmatched suffix.
                for end in range(n,len(physical)+1):
                    try: chunks=tcl_chunks('\n'.join(physical[n-1:end]))
                    except ValueError: continue
                    if chunks and chunks[0].strip().startswith(code):
                        code=chunks[0].strip();w=words_for(code);break
            if not w and code=='}':
                from dofile_recipe import tcl_chunks
                tcl_chunks('\n'.join(physical))  # exact source was already matched
                continue
            if not w or virtual is None:raise ValueError('Unparsed native command')
            name=w[0]; active={'command':code,'name':name,'line':number,'script_line':n,'design':trace['design']}
            events.append(active)
            if name=='set' and len(w)==3:pending=w[1];variables.pop(w[1],None)
            if name in {'dump_netlist','examine_scan_drc','rpt_scan_drc_violation'} and ('-file' in w or '>' in w):
                flag='-file' if '-file' in w else '>'
                if w.count(flag)!=1 or w.index(flag)+2!=len(w):raise ValueError('Ambiguous artifact writer')
                path=_target(w[-1],variables,virtual,run,words_for,native_generated=True)
                active['path']=str(path)
                if name=='dump_netlist':exports.append(active)
                else:writers.append(active)
        elif pending:
            value=line.strip()
            if value and not value.startswith('[') and not re.search(r'[$\[\]\\;]',value):variables[pending]=value
            pending=None
        match=re.search(r"VRLG-I-0001\]\s+Read Verilog file '([^']+)' successfully\.",line)
        libmatch=re.search(r"LIB-I-0011\]\s+Liberty file '([^']+)' is read successfully\.",line)
        if match or libmatch:
            if not active:raise ValueError('Native read has no operation origin')
            p=Path((match or libmatch)[1]); resolved=p.resolve()
            allowed=resolved.is_relative_to(input_dir.resolve()) or resolved.is_relative_to(root.resolve())
            digest=hashlib.sha256(p.read_bytes()).hexdigest() if allowed and p.is_file() else None
            record={'path':str(p),'log_line':number,'origin':dict(active),'kind':'library' if libmatch else 'netlist',
                    'sha256':digest,'content_status':'available' if digest else 'not_saved_or_outside_bound_roots'}
            if str(resolved) in official:
                record['role']=official[str(resolved)]['role']
                if digest!=official[str(resolved)]['sha256']:raise ValueError('Official loaded content mismatch')
            elif active['name'] in {'load_netlist','load_lib'}:
                prior=[e for e in exports if Path(e['path']).resolve()==resolved and e['line']<number]
                record['role']='generated_export_reload' if len(prior)==1 else 'explicit_dependency_unbound'
                record['producer']=prior[0] if len(prior)==1 else None
            else:record['role']='tool_operation_dependency'
            reads.append(record)
    if active:active['end_log_line']=len(log.read_text().splitlines())
    for exported in exports:
        p=Path(exported['path'])
        exported['sha256']=hashlib.sha256(p.read_bytes()).hexdigest() if p.is_file() else None
        earlier=[e for e in events if e['line']<exported['line']]
        exported['stage']=('after_scan_rewrite' if any(e['name']=='insert_dft_logic' for e in earlier) else
                           'after_ECO_before_scan' if any(e['name'] in MUTATIONS for e in earlier) else
                           'loaded_design_before_mutation')
        exported['meaning']='Native writer/content identity; full freshness, structure and EQY are separately required.'
    source=root/found['source']; boundary=None
    if source==log:
        boundary=int(found['locator'].split('-')[0].removeprefix('L'))
    else:
        digest=hashlib.sha256(source.read_bytes()).hexdigest()
        matched=[w for w in writers if Path(w['path']).is_file() and
                 hashlib.sha256(Path(w['path']).read_bytes()).hexdigest()==digest]
        if len(matched)!=1:raise ValueError('Diagnostic report writer is missing or ambiguous')
        boundary=matched[0]['line']
    prior=[r for r in reads if r['log_line']<boundary]
    if {str(Path(r['path']).resolve()) for r in prior if r['role']=='original_netlist'}!={str(p.resolve()) for p in nets}:
        raise ValueError('Diagnostic state did not load the official input family')
    if {str(Path(r['path']).resolve()) for r in prior if r['kind']=='library'}!={str(p.resolve()) for p in libs}:
        raise ValueError('Diagnostic library family mismatch')
    mutations=[]
    for e in events:
        if e['line']>=boundary:continue
        name=e['name']
        if (name in MUTATIONS|DYNAMIC|{'insert_dft_logic','connect_icg','connect_icg_only','replace_scan_cell'} or
                name.startswith('$') or name in {'if','for','foreach','while','proc'} and
                not is_context_query(e['command']) and re.search(r'\b(?:'+ '|'.join(sorted(MUTATIONS|DYNAMIC))+r')\b',e['command'])):
            mutations.append(e)
    inventory={'official_inputs':list(official.values()),'native_reads':reads,'native_exports':exports,
               'diagnostic_boundary_log_line':boundary,'prior_mutations':mutations,
               'script_sha256':hashlib.sha256(script.read_bytes()).hexdigest(),'log_sha256':hashlib.sha256(log.read_bytes()).hexdigest(),
               'run_ref':rid,'design':trace['design'],'found':dict(found)}
    # A pre-diagnostic auxiliary dependency or reload requires a separately
    # verified design snapshot; do not silently drop it from the design.
    unavailable=[r for r in prior if r['role'] not in {'original_netlist','library'}]
    inventory['state_status']='original_input_bound' if not mutations and not unavailable else 'changed_or_dependent_state_unproved'
    return trace,nets,libs,inventory


def gate_diagnosis_requirement(issue, root, words_for, input_dir):
    """Require a diagnostic verdict from the native fault/ICG identity, not prose.

    This is deliberately limited to a reported FF clock fault driven by one
    ICG. It does not certify causality, and failure to bind is not N/A.
    """
    import hashlib, json
    from configuration_evidence import _signal_command_trace
    from completion_policy import _reference
    from partial_insertion_validation import _libraries
    from eco_structure import read_design
    from canonical_delivery import CanonicalDeliveryError
    from netlist_repair import RepairRejected
    found = issue.get('found', {})
    location = re.search(r"Clock input '([^']+)' of 'DFF' '([^']+)'", found.get('excerpt', ''))
    if not location:
        return {'status':'not_applicable', 'required':False, 'basis':'not a native FF clock diagnostic'}
    result = {'status':'incomplete', 'required':True, 'basis':'native FF clock diagnostic; driver binding pending',
              'adopted_diagnosis_sha256':hashlib.sha256(json.dumps(issue.get('diagnosis',{}),sort_keys=True).encode()).hexdigest()}
    try:
        rid=found['run_ref']; root=Path(root).absolute()
        if input_dir is None or not re.fullmatch(r'R[1-9]\d*',rid):raise ValueError('Missing original input/run')
        _reference(root,found,{rid})
        trace,nets,libs,inventory=_diagnostic_loaded_state(issue,root,input_dir,words_for)
        result['source_state']=inventory
        if inventory['state_status']!='original_input_bound':
            raise ValueError('Discovery state changed before its report; an exact prior snapshot is required')
        script=root/'runs'/rid/'deliverables'/(rid+'.dofile')
        controls=[row for row in trace['signals'] if not row['errors'] and
                  int(row['locator'][1:]) < inventory['diagnostic_boundary_log_line'] and
                  dict(zip(row['words'][1::2],row['words'][2::2])).get('-type')=='scan_enable']
        if not controls:
            return {'status':'not_applicable','required':False,
                    'basis':'no executed scan_enable declaration at discovered state; separate clock-declaration checks apply',
                    'source_state':inventory,'design':trace['design'],'run_ref':rid}
        library,unknown=_gate_libraries(libs)
        if unknown:raise ValueError('Ambiguous library')
        design=_gate_design(nets,library,trace['design'])
        ff=design['cells'].get(location[2])
        if not ff or not library[ff['type']]['ffs'] or location[1] not in ff['pins']:raise ValueError('FF pin unbound')
        driver=design['graph'].resolve(ff['pins'][location[1]])
        if driver is None:raise ValueError('Original clock driver unresolved')
        gates=[(name,c) for name,c in design['cells'].items() for p,v in library[c['type']]['pins'].items()
               if v.get('clock_gate_out_pin')=='true' and driver==design['graph'].resolve(c['pins'].get(p))]
        if not gates:
            return {'status':'not_applicable','required':False,'basis':'resolved clock driver is not an ICG output',
                    'native_found':dict(found),'driver':list(driver),'design':trace['design'],'run_ref':rid,'source_state':inventory}
        if len(gates)!=1 or driver[1]:raise ValueError('Ambiguous/inverted ICG driver')
        name,gate=gates[0]
        binding=_gate_location_binding(issue,location,design,trace,words_for)
        if not binding:raise ValueError('Diagnostic object differs from native endpoint')
        result.update(status='bound',basis='actual FF clock pin -> unique uninverted ICG output',
            binding={'location':binding,'design':trace['design'],'run_ref':rid,'FF_object':location[2],
                     'FF_pin':location[1],'ICG_instance':name,'cell_type':gate['type'],
                     'script_sha256':hashlib.sha256(script.read_bytes()).hexdigest(),
                     'input_sha256':{str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in nets+libs}})
    except (OSError,ValueError,TypeError,KeyError,IndexError,TimeoutError,RepairRejected,CanonicalDeliveryError) as error:
        result['detail']=str(error)
    return result


def _complete_gate_relation(issue):
    """Only the existing explicit cell relation has a complete semantic form.

    Extra clauses are unverified, not stripped or certified by text coverage.
    This check selects the finite proof language, never the need for a proof.
    """
    fields=[str(issue.get('diagnosis',{}).get(k,'')).strip() for k in ('summary','root_cause')]
    grammar=(r'(?:Liberty(?:\s+statetable)?\s*[:：]?\s*)?'
             r'[A-Za-z_]\w*\s+follows\s+[A-Za-z_]\w*\s+'
             r'(?:only\s+when|when)\s+[A-Za-z_]\w*\s*=\s*[HL01]\s*[.]?')
    return bool(any(fields) and any(re.search(r'\bLiberty\b',s,re.I) for s in fields) and
                all(not s or re.fullmatch(grammar,s,re.I) for s in fields))


def _effective_gate_claims(issue, root, words_for, input_dir, requirement=None):
    claims=_library_relation_claims(issue)+_library_context_claims(issue)
    requirement=requirement or gate_diagnosis_requirement(issue,root,words_for,input_dir)
    if requirement['required'] and not _complete_gate_relation(issue):
        # Preserve recognized refutations as well as the uncovered full adopted
        # diagnosis; neither a partial receipt nor a repair proves this context.
        clause='\n'.join(str(issue.get('diagnosis',{}).get(k,'')) for k in ('summary','root_cause')).strip()
        claims.append({'kind':'bound_gate_diagnosis_unverified','field':'adopted_diagnosis',
                       'clause':clause,'control':None,'control_candidates':[],
                       'effect':'unverified_original_gate_context','binding':'native_FF_ICG_requirement'})
    return claims


def gate_diagnosis_result(requirement, assessment):
    """Independent consumer guard: action success cannot fill a missing result."""
    if not requirement.get('required'):
        return {'status':'not_applicable','requirement':requirement}
    coverage=assessment.get('coverage',{}) if isinstance(assessment,dict) else {}
    obligations=coverage.get('obligations',[])
    bound=(requirement.get('status')=='bound' and coverage.get('native_requirement')==requirement)
    complete=(bound and isinstance(assessment,dict) and assessment.get('applicable') is True and
              assessment.get('status')=='pass' and coverage.get('complete_semantic_form') is True and
              bool(obligations) and all(o.get('status')=='pass' and o.get('positive_receipts') for o in obligations))
    return {'status':'pass' if complete else 'fail' if bound and assessment.get('status')=='fail' else 'incomplete',
            'requirement':requirement,'coverage':coverage,
            'detail':'Bound native diagnostic obligation needs actual complete relation receipts; signal/action evidence is separate.'}


def library_relation_claim_assessment(issue, output_dir, words_for, input_dir=None, *, requirement=None):
    """Expose applicability separately from exhaustive native relation checks.

    The existing verifier returns incomplete for missing object/library/state
    bindings. Its applicable empty result means the bound finite relation was
    exhaustively checked, not that an unrecognized sentence was proved.
    """
    requirement = requirement or gate_diagnosis_requirement(issue, output_dir, words_for, input_dir)
    all_claims = _effective_gate_claims(issue, output_dir, words_for, input_dir, requirement)
    claims = [c for c in all_claims if not isinstance(c,dict)]
    contextual = [c for c in all_claims if isinstance(c,dict)]
    receipts=[]
    problems = library_relation_claim_problems(issue, output_dir, words_for, input_dir, _receipts=receipts)
    status = ('not_applicable' if not (claims or contextual) else
              'fail' if any(p.get('status') == 'fail' for p in problems) else
              'incomplete' if problems else 'pass')
    represented=[{'clause': m[0], 'output': m[1], 'clock': m[2],
                  'control': m[3], 'required_level': m[4]} for m in claims] + contextual
    obligations=[]
    for claim in represented:
        checked=[p for p in problems if p['original_clause']==claim['clause']]
        obligations.append({'claim':claim,'status':('fail' if any(p['status']=='fail' for p in checked)
            else 'incomplete' if checked else 'pass' if any(r['original_clause']==claim['clause'] for r in receipts) else 'incomplete'),
            'native_checks':checked, 'positive_receipts':[r for r in receipts if r['original_clause']==claim['clause']]})
    if status=='pass' and any(o['status']!='pass' for o in obligations):
        status='incomplete'
        problems.append({'status':'incomplete','reason':'library_relation_not_bound','detail':'Finite relation checked without an actual native receipt'})
    return {'applicable': bool(claims or contextual), 'status': status,
            'claims': represented, 'problems': problems,
            'coverage': {'capability':'bound_ICG_relation', 'obligations':obligations,
                'native_requirement':requirement,'complete_semantic_form':_complete_gate_relation(issue),
                'meaning':'Native checks retain their source identities and missing context. No certificate is synthesized from a success boolean; no other prose is certified.'}}


def library_relation_claim_problems(issue: dict, output_dir: Path, words_for,
                                    input_dir: Path | None = None, *, _receipts=None) -> list[dict]:
    """Check a literal three-pin necessity assertion against its bound ICG.

    This finite grammar represents the explicit symbolic relation O follows C
    only when T=level. It is not a keyword permission or a general causal
    interpreter. Task citations/actions are not library assertions. A failed
    relation says nothing about the effectiveness of the recorded repair.
    """
    claims = _effective_gate_claims(issue, output_dir, words_for, input_dir)
    if not claims:
        return []
    from itertools import product
    from configuration_evidence import _signal_command_trace
    from canonical_delivery import CanonicalDeliveryError
    from partial_insertion_validation import _libraries, _boolean
    from eco_structure import read_design
    from eco_equivalence import _nodes, _cells, _arguments, _state_table
    from netlist_repair import RepairRejected
    root = output_dir.absolute(); found = issue.get('found', {}); rid = str(found.get('run_ref', ''))
    problems = []
    for claim in claims:
        problem = {'status': 'incomplete', 'reason': 'library_relation_not_bound',
                   'original_clause': claim['clause'] if isinstance(claim,dict) else claim[0],
                   'detail': 'Original library relation/object/state is not proved.'}
        try:
            if input_dir is None or not re.fullmatch(r'R[1-9]\d*', rid):
                raise ValueError('Missing original input or run')
            location = re.search(r"Clock input '([^']+)' of 'DFF' '([^']+)'", found.get('excerpt', ''))
            if not location:
                raise ValueError('No original native FF clock diagnostic')
            from completion_policy import _reference
            _reference(root, found, {rid})
            trace,nets,libs,inventory=_diagnostic_loaded_state(issue,root,input_dir,words_for)
            if inventory['state_status']!='original_input_bound':
                raise ValueError('Discovery state changed before its report; prior snapshot unproved')
            script=root/'runs'/rid/'deliverables'/(rid+'.dofile')
            library, unknown = _gate_libraries(libs)
            if unknown:
                raise ValueError('Ambiguous actual library')
            design = _gate_design(nets, library, trace['design'])
            location_binding = _gate_location_binding(issue, location, design, trace, words_for)
            if not location_binding:raise ValueError('Located object is not bound to the native FF or a declared gate control role')
            ff = design['cells'].get(location[2]); ffshape = library.get(ff['type']) if ff else None
            if not ffshape or not ffshape['ffs'] or location[1] not in ff['pins']:
                raise ValueError('Original FF clock endpoint not uniquely resolved')
            driver = design['graph'].resolve(ff['pins'][location[1]])
            gates = [(name, cell) for name, cell in design['cells'].items()
                     for pin, prop in library[cell['type']]['pins'].items()
                     if prop.get('clock_gate_out_pin') == 'true' and driver is not None and
                     driver == design['graph'].resolve(cell['pins'].get(pin))]
            if len(gates) != 1 or driver[1] != 0:
                raise ValueError('Actual clock driver is not one uninverted ICG output')
            name, gate = gates[0]
            roles = library[gate['type']]['pins']
            if isinstance(claim,dict):
                outputs=[p for p,v in roles.items() if v.get('clock_gate_out_pin')=='true']
                clocks=[p for p,v in roles.items() if v.get('clock_gate_clock_pin')=='true']
                if len(outputs)!=1 or len(clocks)!=1:raise ValueError('Ambiguous ICG roles')
                tests=[p for p,v in roles.items() if v.get('clock_gate_test_pin')=='true']
                if len(tests)!=1 or len(claim.get('control_candidates',[]))>1:raise ValueError('Ambiguous gate control role')
                output,clock,control=outputs[0],clocks[0],claim['control'] or tests[0]
            else:output, clock, control = claim.group(1, 2, 3)
            if any(roles.get(pin, {}).get(attr) != 'true' for pin, attr in
                   [(output, 'clock_gate_out_pin'), (clock, 'clock_gate_clock_pin'), (control, 'clock_gate_test_pin')]):
                raise ValueError('Asserted pin symbols differ from actual library roles')
            definitions = [(path, cell) for path, cell in _gate_library_definitions(libs)
                           if _arguments(cell['args']) == [gate['type']]]
            if len(definitions) != 1:
                raise ValueError('Actual ICG library definition is not unique')
            libpath, cell = definitions[0]
            states = [n for n in cell['children'] if n['name'] == 'statetable']
            pins = {_arguments(n['args'])[0]: n for n in cell['children'] if n['name'] == 'pin'}
            if len(states) != 1 or output not in pins:
                raise ValueError('Unsupported state semantics')
            inputs = [pin for pin, n in pins.items() if n['props'].get('direction') == 'input']
            _, _, semantic = _state_table(states[0], inputs)
            factor = semantic.get('transparent_enable_factorization')
            expression = pins[output]['props'].get('state_function', '')
            if not factor or factor['enable_pin'] != clock or factor['enable_value'] != 0:
                raise ValueError('Relation requires the exact supported low-transparent clock table')
            if isinstance(claim,dict):
                import hashlib
                # Physical and library identities are established; the alleged
                # historical GATE assignment/reachable context is not. Do not
                # turn a missing causal proof into a library counterexample.
                problem.update(reason='library_relation_not_bound',
                    detail='The named gate/level effect requires the original functional-enable state and causal scope; neither repair success nor the cell table alone proves that context.',
                    native_fact={'kind':'bound_conditional_gate_context','source_state':inventory,'location_binding':location_binding,'design':trace['design'],
                        'run_ref':rid,'FF_object':location[2],'FF_pin':location[1],
                        'ICG_instance':name,'cell_type':gate['type'],
                        'claim_symbols':{'output':output,'clock':clock,'control':control},
                        'context_claim':claim,'functional_enable_drivers':{
                            p:list(design['graph'].resolve(gate['pins'].get(p))) if design['graph'].resolve(gate['pins'].get(p)) is not None else None for p,v in roles.items()
                            if v.get('clock_gate_enable_pin')=='true'},
                        'state_semantics':semantic,'output_expression':expression,
                        'library_source':str(libpath),'library_sha256':hashlib.sha256(libpath.read_bytes()).hexdigest(),
                        'statetable':states[0],'script_sha256':hashlib.sha256(script.read_bytes()).hexdigest(),
                        'netlist_fingerprints':{str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in nets}})
                problems.append(problem);continue
            required = int(claim[4] in {'H', '1'}); other = [p for p in semantic['inputs'] if p != clock]
            necessity = bool(re.search(r'\bonly\s+when\b', claim[0]))
            counterexample = None
            checked_assignments = []
            for values in product((0, 1), repeat=len(other)):
                assignment = dict(zip(other, values))
                if (assignment[control] == required) == necessity:
                    continue
                before = {**assignment, clock: 0}; after = {**assignment, clock: 1}
                low = semantic['truth'][''.join(str(before[p]) for p in semantic['inputs'])]
                high = semantic['truth'][''.join(str(after[p]) for p in semantic['inputs'])]
                if low not in {'L', 'H'} or high != 'N':
                    raise ValueError('Unsupported output/hold interval')
                bit = int(low == 'H')
                observed = [_boolean(expression, {**a, semantic['state']: bit}) for a in (before, after)]
                if any(v is None or v[0] for v in observed):
                    raise ValueError('Unsupported output expression')
                values_observed = [int(v[1][0]) for v in observed]
                checked_assignments.append({'low_phase':before,'high_phase':after,'state':{semantic['state']:bit},'outputs':values_observed})
                if (values_observed == [0, 1]) == necessity:
                    counterexample = {'low_phase': before, 'high_phase': after,
                                      'state': {semantic['state']: bit}, 'output_values': values_observed}
                    break
            if counterexample is None:
                if _receipts is not None:
                    import hashlib
                    _receipts.append({'original_clause':claim[0], 'kind':'exhaustive_bound_cell_necessity' if necessity else 'exhaustive_bound_cell_sufficiency',
                        'checked_assignments':checked_assignments,
                        'design':trace['design'], 'run_ref':rid, 'location_binding':location_binding,
                        'FF_object':location[2], 'FF_pin':location[1], 'ICG_instance':name, 'cell_type':gate['type'],
                        'claim_symbols':{'output':output,'clock':clock,'control':control,'required_level':required},
                        'state_semantics':semantic,'output_expression':expression,'statetable':states[0],
                        'library_source':str(libpath),'library_sha256':hashlib.sha256(libpath.read_bytes()).hexdigest(),
                        'script_sha256':hashlib.sha256(script.read_bytes()).hexdigest(),
                        'netlist_fingerprints':{str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in nets}})
                continue  # Only this exact fully enumerated relation; no whole-cause certificate.

            import hashlib
            if not necessity:
                problem['detail']='Bound cell does not support the asserted sufficient relation'
                problems.append(problem); continue
            problem.update(status='fail', reason='library_relation_contradicted',
                detail='Actual bound cell permits this clock cycle without the asserted necessary control level; the repair fact is independent.',
                native_fact={'design': trace['design'], 'run_ref': rid, 'FF_object': location[2],
                    'FF_pin': location[1], 'ICG_instance': name, 'cell_type': gate['type'],
                    'claim_symbols': {'output': output, 'clock': clock, 'control': control, 'required_level': required},
                    'counterexample': counterexample, 'state_semantics': semantic,
                    'output_expression': expression, 'library_source': str(libpath),
                    'library_sha256': hashlib.sha256(libpath.read_bytes()).hexdigest(),
                    'statetable': states[0], 'script_sha256': hashlib.sha256(script.read_bytes()).hexdigest(),
                    'netlist_fingerprints': {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in nets}})
            problems.append(problem)
        except (OSError, ValueError, TypeError, KeyError, IndexError, RepairRejected, CanonicalDeliveryError) as error:
            problem['detail'] = str(error); problems.append(problem)
    return problems


def library_relation_scope(conflicts):
    """Typed counterevidence shape, never sufficient delivery authorization.

    The issuer below must recompute these facts from actual input/native state;
    the consumer additionally requires the existing opaque delivery proof.
    """
    if not isinstance(conflicts, list) or not conflicts:
        return False
    for p in conflicts:
        if not isinstance(p, dict) or not isinstance(p.get('native_fact'), dict):return False
        fact = p['native_fact']
        if not isinstance(fact.get('claim_symbols'), dict):return False
        if fact.get('kind') == 'bound_conditional_gate_context':
            if (p.get('status') != 'incomplete' or not p.get('original_clause') or
                    not all(fact.get(k) for k in ['design','run_ref','FF_object','FF_pin','ICG_instance',
                        'cell_type','context_claim','functional_enable_drivers','state_semantics','output_expression',
                        'library_source','library_sha256','statetable','script_sha256','netlist_fingerprints']) or
                    any(v is None for v in fact['functional_enable_drivers'].values()) or
                    fact['context_claim'].get('clause') != p['original_clause'] or
                    fact['context_claim'].get('control') not in {None, fact['claim_symbols'].get('control')}):return False
            continue
        if not isinstance(fact.get('counterexample'),dict):return False
        symbols = fact['claim_symbols']
        witness = fact.get('counterexample', {})
        low, high, state = (witness.get(k, {}) for k in ['low_phase', 'high_phase', 'state'])
        if not all(isinstance(v, dict) for v in [low, high, state]):return False
        if type(symbols.get('required_level')) is not int:return False
        clock, control = symbols.get('clock'), symbols.get('control')
        if (p.get('status') != 'fail' or p.get('reason') != 'library_relation_contradicted' or
                not p.get('original_clause') or symbols.get('required_level') not in {0, 1} or
                not all(fact.get(k) for k in ['design','run_ref','FF_object','FF_pin','ICG_instance',
                    'cell_type','output_expression','library_source','library_sha256','script_sha256',
                    'netlist_fingerprints','state_semantics','statetable']) or
                not re.fullmatch(r'R[1-9]\d*', fact['run_ref']) or
                not all(re.fullmatch(r'[A-Za-z_]\w*', str(symbols.get(k,'')))
                        for k in ['output','clock','control']) or
                not low or set(low) != set(high) or clock not in low or control not in low or
                low[clock] != 0 or high[clock] != 1 or low[control] != high[control] or
                low[control] == symbols['required_level'] or
                any(high[k] != v for k,v in low.items() if k != clock) or
                any(v not in {0,1} for v in [*low.values(),*high.values(),*state.values()]) or
                witness.get('output_values') != [0,1] or not state):
            return False
    return True


def eco_gate_diagnostic_scope(conflicts):
    """A bound original gate diagnosis, optionally mixed with a bound action gap.

    Shape selects a producer, not permission to complete. The issuer replays
    both assessments; the opaque delivery proof still checks task/EQY/coverage.
    """
    if not isinstance(conflicts,list) or not conflicts:return False
    library=[p for p in conflicts if isinstance(p,dict) and p.get('native_fact')]
    actions=[p for p in conflicts if isinstance(p,dict) and p.get('assessment_scope',{}).get('kind')=='native_connection_action']
    return (len(library)+len(actions)==len(conflicts) and bool(library) and
            library_relation_scope(library) and all(p['assessment_scope'].get('producer')=='connection_action_assessment'
            and p['assessment_scope'].get('context',{}).get('found') and p['assessment_scope'].get('citations') for p in actions))


def eco_gate_delivery_condition(issue, conflicts, changes, root, rid, words_for, input_dir, trace, validation):
    """Recheck final physical identity without backdating new controls/ports."""
    import hashlib,json
    from operation_audit import connection_action_assessment, connection_action_delivery_condition
    from eco_structure import read_design
    import eco_evidence as ee
    from netlist_repair import RepairRejected
    from canonical_delivery import CanonicalDeliveryError
    try:
        if not eco_gate_diagnostic_scope(conflicts) or trace is None or not validation or validation.get('status')!='pass':return None
        ee.assert_trace(trace)
        library_conflicts=[p for p in conflicts if p.get('native_fact')]
        actions=[p for p in conflicts if p.get('assessment_scope')]
        if library_relation_claim_problems(issue,root,words_for,input_dir)!=library_conflicts:return None
        current=connection_action_assessment(issue,changes,root,rid,words_for,input_dir)
        if current['problems']!=actions:return None
        facts=[p['native_fact'] for p in library_conflicts]
        identities={(f['design'],f['run_ref'],f['FF_object'],f['FF_pin'],f['ICG_instance'],f['cell_type']) for f in facts}
        if len(identities)!=1:return None
        design,prior,ff,pin,gate,kind=next(iter(identities))
        if prior!=issue['found']['run_ref'] or not int(prior[1:])<int(rid[1:]) or trace.context.rid!=rid or trace.data['design']!=design:return None
        if validation['native']!=trace.data or validation['binding']['native_fingerprints']!=trace.fingerprints:return None
        library,before=ee.source_design(trace.context.originals,trace.context.libs,trace.context.spec,trace.context.original)
        fixed=read_design([Path(trace.data['fixed_export']['path'])],library,design)
        original_gate=before['cells'].get(gate);new_gate=fixed['cells'].get(gate)
        if not original_gate or not new_gate or original_gate['type']!=kind or new_gate['type']!=kind:return None
        if ff not in validation['coverage']['object_mapping'] or ff not in fixed['cells']:return None
        roles=library[kind]['pins'];outputs=[p for p,v in roles.items() if v.get('clock_gate_out_pin')=='true']
        tests=[p for p,v in roles.items() if v.get('clock_gate_test_pin')=='true']
        functional=[p for p,v in roles.items() if v.get('clock_gate_enable_pin')=='true']
        if len(outputs)!=1 or len(tests)!=1 or not functional:return None
        clock=fixed['graph'].resolve(fixed['cells'][ff]['pins'].get(pin))
        if clock is None or clock!=fixed['graph'].resolve(new_gate['pins'].get(outputs[0])):return None
        if any(before['graph'].resolve(original_gate['pins'].get(p)) is None or
               before['graph'].resolve(original_gate['pins'].get(p))!=fixed['graph'].resolve(new_gate['pins'].get(p)) for p in functional):return None
        # Route and mode semantics are task-derived and independently rebuilt
        # by delivery_proof_paths after this condition is collected.
        routes=[r for r in validation['structure']['changed_routes'] if r['consumer']==gate+'/'+tests[0]]
        if len(routes)!=1:return None
        paths=[Path(trace.data['fixed_export']['path']),root/issue['found']['source'],
               root/'runs'/prior/'deliverables'/(prior+'.dofile'),root/'runs'/prior/(prior+'.log'),*trace.context.originals,*trace.context.libs]
        action_condition=None
        if actions:
            bound=connection_action_delivery_condition(issue,actions,changes,root,rid,words_for,input_dir,trace,validation)
            if bound is None:return None
            action_condition,extra=bound;paths+=extra
        return ({'kind':'native_ECO_library_diagnostic','prior_checks':conflicts,'original_run_ref':prior,
            'design':design,'run_ref':rid,'located_object':issue['diagnosis']['located_object'],
            'object_binding':{'FF_object':ff,'FF_pin':pin,'ICG_instance':gate,'cell_type':kind,
                'original_identity':facts,'final_FF_mapping':validation['coverage']['object_mapping'][ff],
                'final_task_routes':routes,'functional_enable_driver_preserved':True},
            'final_export_sha256':hashlib.sha256(paths[0].read_bytes()).hexdigest(),
            'action_condition':action_condition,'diagnosis_remains_unproved':True,
            'meaning':'Original diagnosis and action evidence remain separate from current proven ECO object/task delivery.'},paths)
    except (OSError,ValueError,KeyError,TypeError,IndexError,RepairRejected,CanonicalDeliveryError):return None


def library_relation_delivery_condition(issue, conflicts, root, run_ref, spec,
                                        files, dofile, words_for, input_dir):
    """Recompute library counterevidence; independently bind the final endpoint.

    A library witness refutes the diagnostic, not task delivery. The unchanged
    caller checks every task/artifact/EQY gate before sealing the full proof.
    This producer additionally proves the actual final control and object state.
    """
    import hashlib, json
    from itertools import product
    from canonical_delivery import _native_sources, CanonicalDeliveryError
    from configuration_evidence import _signal_command_trace
    from operation_audit import operation_trace, post_operation_report
    from dft_signal_requirements import explicit_signal_role_requirements, _covers
    from report_validation import report_rows
    from partial_insertion_validation import _libraries, _boolean
    from eco_structure import read_design
    from netlist_repair import RepairRejected
    try:
        if (not library_relation_scope(conflicts) or
                json.dumps(library_relation_claim_problems(issue, root, words_for, input_dir),sort_keys=True) != json.dumps(conflicts,sort_keys=True) or
                issue['attempts'][-1]['verify'].get('resolved') is not False or
                issue['attempts'][-1]['verify'].get('run_ref') != run_ref):
            return None
        facts = [p['native_fact'] for p in conflicts]
        identities = {(f['design'],f['run_ref'],f['FF_object'],f['FF_pin'],f['ICG_instance'],f['cell_type']) for f in facts}
        if len(identities) != 1:
            return None
        design, prior, ffname, ffpin, gatename, kind = next(iter(identities))
        if (prior != issue['found']['run_ref'] or not int(prior[1:]) < int(run_ref[1:])):
            return None
        libs = sorted((input_dir/'lib').glob('*.lib')); nets = sorted((input_dir/'netlist').glob('*.v'))
        library, unknown = _gate_libraries(libs)
        if unknown:return None
        export, _, actual_design = _native_sources(root, run_ref, words_for)
        if actual_design != design:return None
        before = _gate_design(nets,library,design); final = _gate_design([export['source']],library,design)
        prior_trace=_signal_command_trace(root,prior,words_for)
        native_location=re.search(r"Clock input '([^']+)' of 'DFF' '([^']+)'",issue['found']['excerpt'])
        if not native_location or not prior_trace or not _gate_location_binding(issue,native_location,before,prior_trace,words_for):return None
        ff = final['cells'].get(ffname); gate = final['cells'].get(gatename)
        if not ff or not gate or gate['type'] != kind or not library[ff['type']]['ffs']:
            return None
        roles = library[kind]['pins']; testpins = [p for p,v in roles.items() if v.get('clock_gate_test_pin')=='true']
        if len(testpins)!=1:return None
        test = testpins[0]; outputpins = {f['claim_symbols']['output'] for f in facts}
        if len(outputpins)!=1 or any(f['claim_symbols']['control'] != test for f in facts):return None
        output = next(iter(outputpins)); driver = final['graph'].resolve(ff['pins'].get(ffpin))
        if driver is None or driver != final['graph'].resolve(gate['pins'].get(output)) or driver[1]:return None
        # The library witness is a legal low-transparent/hold transition. An
        # actually tied pin must not contradict that witness on this instance.
        witness_drivers = {}
        old_gate = before['cells'][gatename]
        for pin,value in facts[0].get('counterexample',{}).get('low_phase',{}).items():
            source = before['graph'].resolve(old_gate['pins'].get(pin))
            if source is None or source[0] in {'$0','$1'} and int(source[0][1]) != value:return None
            witness_drivers[pin] = source
        # Preserve the functional enable driver; a final DRC0 alone is not this check.
        functional = [p for p,v in roles.items() if v.get('clock_gate_enable_pin')=='true']
        if not functional or any(before['graph'].resolve(before['cells'][gatename]['pins'].get(p)) is None or
                before['graph'].resolve(before['cells'][gatename]['pins'].get(p)) !=
                final['graph'].resolve(gate['pins'].get(p)) for p in functional):return None
        control = final['graph'].resolve(gate['pins'].get(test))
        if not control or control[1] or not control[0].startswith(design+'::'):return None
        port = control[0][len(design)+2:]
        if final['modules'][design]['ports'].get(port) != 'input':return None
        bound_location=_gate_location_binding(issue,native_location,before,prior_trace,words_for)
        if bound_location['kind']=='native_declared_scan_control' and bound_location['object']!=port:return None
        requirements = [r for r in explicit_signal_role_requirements(spec) if r.port==port]
        if len(requirements)!=1 or not {'scan','clock_gating'}<=requirements[0].roles:return None
        trace = operation_trace(files,root,dofile,words_for,allow_verbose=True)
        commands = _signal_command_trace(root,run_ref,words_for)
        if not trace or trace['design']!=design or not commands or commands['design']!=design:return None
        writers = [w for w in trace['reports'] if w['kind']=='rpt_scan_signal' and w['design']==design]
        if not writers:return None
        report = max(writers,key=lambda w:w['log_line'])['path']
        writer = post_operation_report(report,'rpt_scan_signal',trace,root)
        if not writer or any(int(e['locator'][1:])>=writer['log_line'] for e in commands['signals']):return None
        events=[]
        for e in commands['signals']:
            opts=dict(zip(e['words'][1::2],(w.strip('"{}') for w in e['words'][2::2])))
            if opts.get('-port')==port and opts.get('-view','spec')=='spec':events.append((e,opts))
        if not events:return None
        event,opts=events[-1]
        rows=[r for r in report_rows(report,{'Port','SignalType','Usage','OffState','OwnerPartition'})
              if r['Port']==port and r['SignalType']=='scan_enable(spec)']
        if (len(rows)!=1 or event['errors'] or opts.get('-type')!='scan_enable'):return None
        row=rows[0]
        if (not _covers(row['Usage'],requirements[0].roles) or row['OffState'] not in {'0','1'} or
                row['OwnerPartition']!=event['partition'] or
                any(opts.get('-'+k,v)!=v for k,v in [('usage',row['Usage']),('off_state',row['OffState'])]) or
                requirements[0].off_state is not None and row['OffState']!=requirements[0].off_state):return None
        # Derive the force-on value from the exact retained table; no pin/polarity names.
        force=[];f=facts[0];semantic=f['state_semantics'];clock=f['claim_symbols']['clock']
        other=[p for p in semantic['inputs'] if p not in {clock,test}]
        for value in [0,1]:
            follows=True
            for values in product((0,1),repeat=len(other)):
                base=dict(zip(other,values));lo={**base,test:value,clock:0};hi={**base,test:value,clock:1}
                state=semantic['truth'][''.join(str(lo[p]) for p in semantic['inputs'])]
                if state not in {'L','H'} or semantic['truth'][''.join(str(hi[p]) for p in semantic['inputs'])]!='N':return None
                observed=[_boolean(f['output_expression'],{**x,semantic['state']:int(state=='H')}) for x in [lo,hi]]
                if any(v is None or v[0] for v in observed):return None
                follows &= [int(v[1][0]) for v in observed]==[0,1]
            if follows:force.append(value)
        if len(force)!=1 or 1-int(row['OffState'])!=force[0]:return None
        evidence={'run_ref':run_ref,'source':report.relative_to(root).as_posix(),
                  'locator':'L'+str(row['line']),'excerpt':report.read_text().splitlines()[row['line']-1]}
        paths=[export['source'],report,root/event['source'],root/'runs'/run_ref/'deliverables'/(run_ref+'.dofile')]+nets+libs
        for f in facts:paths += [root/'runs'/f['run_ref']/(f['run_ref']+'.log'),root/'runs'/f['run_ref']/'deliverables'/(f['run_ref']+'.dofile')]
        paths.append(root/issue['found']['source'])
        return ({'kind':'native_library_premise_and_delivery','design':design,'run_ref':run_ref,
            'located_object':issue['diagnosis']['located_object'],'prior_checks':conflicts,
            'original_run_ref':prior,'object_binding':{'FF_object':ffname,'FF_pin':ffpin,'ICG_instance':gatename,
                'cell_type':kind,'output_pin':output,'test_pin':test,'control_port':port,
                'functional_enable_driver_preserved':True,'original_witness_drivers':witness_drivers},'task_requirement':{'port':port,'roles':sorted(requirements[0].roles)},
            'final_condition':evidence,'native_command':{k:event[k] for k in ['run_ref','source','locator','excerpt','design','partition']},
            'native_writer':writer,'force_on_level':force[0],'final_export_sha256':hashlib.sha256(export['source'].read_bytes()).hexdigest(),
            'meaning':'Historical library premise verdicts are retained individually (refuted or incomplete); final task control and full delivery are independent, and the diagnosis remains false.'},paths)
    except (OSError,ValueError,TypeError,KeyError,IndexError,CanonicalDeliveryError,RepairRejected):
        return None


def _leaf_inactive_fact(input_dir: Path, top: str, target: str, pin: str) -> dict | None:
    """Resolve the complete actual instance path, then its simple Liberty fact.

    This does not infer a root-port off_state or match an unrelated leaf suffix.
    Unsupported hierarchy or reset expressions remain unknown.
    """
    from source_hierarchy import _records, _INSTANCE, _MODULE, _name
    parts = target.split('/')
    if parts[:1] == [top]:
        parts = parts[1:]
    if not parts or any(not x for x in parts):
        return None
    wanted = set(parts); index = {}; definitions = {}; leaf_ref = None
    for path in sorted((input_dir/'netlist').glob('*.v')):
        module = ''
        for text, line, status in _records(path, 65536):
            if status == 'scope_end':
                module = ''
            elif (header := _MODULE.match(text)):
                module = _name(header[1]); definitions[module] = definitions.get(module, 0)+1
            elif module and (instance := _INSTANCE.match(text)) and _name(instance[2]) in wanted:
                key = (module, _name(instance[2]))
                if key in index:
                    return None
                index[key] = (_name(instance[1]), {'source': str(path), 'locator': f'L{line}', 'excerpt': text})
    module = top
    for part in parts:
        if definitions.get(module) != 1 or (module, part) not in index:
            return None
        module, leaf_ref = index[module, part]
    facts = []
    for path in sorted((input_dir/'lib').glob('*.lib')):
        kind = ''
        with path.open(errors='replace') as stream:
            for number, line in enumerate(stream, 1):
                cell = re.match(r'\s*cell\s*\(\s*"?([^"\s)]+)', line)
                if cell:
                    kind = cell[1]
                expr = re.match(r'\s*(?:clear|preset)\s*:\s*"([^"\n]+)"', line)
                if kind == module and expr:
                    expression = re.sub(r'[()\s]', '', expr[1])
                    match = re.fullmatch(r'(!?)'+re.escape(pin), expression)
                    if match:
                        facts.append({'inactive_level': int(bool(match[1])), 'cell_type': module,
                            'instance': target, 'pin': pin, 'instance_evidence': leaf_ref,
                            'source': str(path), 'locator': f'L{number}', 'excerpt': line.strip()})
    return facts[0] if len(facts) == 1 else None


def _prior_exclusion_claims(issue):
    """Finite prior scan-exclusion state assertions, not arbitrary causal prose.

    A typed native DRC object and an explicit adopted exclusion state are the
    scope. Missing/future exclusions are actions/requirements, not assertions
    that exclusion was already active at discovery.
    """
    diagnosis = issue.get('diagnosis', {}); claims = []
    if not rule_codes(str(issue.get('found', {}).get('excerpt',''))):return claims
    for field in ('summary','root_cause'):
        for clause in re.split(r'[.;；。\n]',str(diagnosis.get(field,''))):
            if re.search(r'\b(?:missing|lack\w*|without|absent|no|not|never|must|should|will|need\w*)\b|缺少|未排除|应当|需要|须排除',clause,re.I):continue
            state = re.search(r'\b(?:is|was|were|are|has\s+been|have\s+been)\s+(?:explicitly\s+)?excluded\s+from\s+scan\b|已(?:被)?排除.{0,15}扫描',clause,re.I)
            relation = re.search(r'\bexclusion\b.{0,32}\b(?:causes?|caused|results?|leads?)\b',clause,re.I)
            if state or relation:claims.append({'field':field,'original_clause':clause.strip(),'kind':'prior_scan_exclusion_state'})
    return claims


def prior_exclusion_claim_assessment(issue, output_dir, words_for):
    """Producer-owned applicability AND verdict; [] is never an unknown PASS."""
    claims=_prior_exclusion_claims(issue)
    if not claims:return {'applicable':False,'status':'not_applicable','claims':[],'problems':[]}
    problems=_prior_exclusion_evidence(issue,output_dir,words_for,claims)
    status='incomplete' if problems else 'pass'
    counterexample=_prior_exclusion_inclusion_counterexample(issue,output_dir,words_for) if problems else None
    if counterexample:
        status='fail'
        for problem in problems:problem.update(status='fail',counterevidence=counterexample)
    # Scope is issued only from authenticated original native context/object.
    # An unbound problem remains conservative, without a delivery escape.
    if problems:
        from configuration_evidence import _signal_command_trace
        from completion_policy import _reference
        from canonical_delivery import CanonicalDeliveryError
        import hashlib
        try:
            root=output_dir.absolute();rid=issue['found']['run_ref'];_reference(root,issue['found'],{rid})
            objects=re.findall(r"'(?:DFF|SFF|FF|LATCH)'\s+'([^']+)'",issue['found']['excerpt'],re.I)
            trace=_signal_command_trace(root,rid,words_for)
            if len(objects)!=1 or issue['diagnosis']['located_object']!=objects[0] or not trace:
                raise ValueError('Prior exclusion diagnostic object/native context not unique')
            script=root/'runs'/rid/'deliverables'/(rid+'.dofile');native=root/'runs'/rid/(rid+'.log')
            scope={'kind':'prior_scan_exclusion_premise','producer':'prior_exclusion_claim_assessment','case_output':str(root.resolve()),
                'run_ref':rid,'design':trace['design'],'object':objects[0],'assessment_status':'contradicted' if status=='fail' else status,
                'script':script.relative_to(root).as_posix(),'script_sha256':hashlib.sha256(script.read_bytes()).hexdigest(),
                'native':native.relative_to(root).as_posix(),'native_sha256':hashlib.sha256(native.read_bytes()).hexdigest(),
                'loaded_inputs':trace['loaded_input_netlists'],'meaning':'Unproved diagnostic antecedent only; no final exclusion/task verdict.'}
            for problem in problems:problem.update(status=status,assessment_scope=scope)
        except (OSError,ValueError,KeyError,TypeError,IndexError,CanonicalDeliveryError):
            for problem in problems:problem['status']='incomplete'
    return {'applicable':True,'status':status,'claims':claims,'problems':problems}


def _prior_exclusion_inclusion_counterexample(issue, root, words_for):
    """Only explicit authenticated native enable-before-fault contradicts state.

    Absence of an exclusion command, missing reports or defaults are not a
    counterexample. This never infers arbitrary cause from the true setting.
    """
    try:
        from completion_policy import _reference
        from configuration_evidence import _signal_command_trace
        rid=issue['found']['run_ref'];_reference(root,issue['found'],{rid})
        objects=re.findall(r"'(?:DFF|SFF|FF|LATCH)'\s+'([^']+)'",issue['found']['excerpt'],re.I)
        trace=_signal_command_trace(root,rid,words_for)
        if len(objects)!=1 or not trace or issue['diagnosis']['located_object']!=objects[0]:return None
        script=(root/'runs'/rid/'deliverables'/(rid+'.dofile')).read_text().splitlines()
        log=root/'runs'/rid/(rid+'.log');lines=log.read_text().splitlines();operations=[];checks=[]
        for n,line in enumerate(lines,1):
            m=re.search(r'CMD-0034\]\s+@(\d+):\s*(.*)',line)
            if not m:continue
            w=words_for(m[2].strip())
            if w[:1]==['examine_scan_drc']:checks.append(n)
            if w[:1]!=['set_scan_element']:continue
            if len(w)!=3 or w[1]!='true' or w[2].strip('{}"')!=objects[0]:return None
            if not 0<int(m[1])<=len(script) or script[int(m[1])-1].strip()!=m[2].strip():return None
            result=[]
            for later in lines[n:]:
                if 'CMD-0034]' in later:break
                result.append(later)
            if any('[ERROR]' in l or '[FATAL]' in l for l in result) or '1' not in [l.strip() for l in result]:return None
            operations.append({'run_ref':rid,'source':log.relative_to(root).as_posix(),'locator':'L'+str(n),'excerpt':line})
        if len(operations)==len(checks)==1 and int(operations[0]['locator'][1:])<checks[0]:return operations[0]
    except (OSError,ValueError,KeyError,IndexError,TypeError):pass
    return None


def prior_exclusion_claim_problems(issue, output_dir, words_for):
    """Compatibility adapter; production aggregation consumes the full result."""
    return prior_exclusion_claim_assessment(issue,output_dir,words_for)['problems']


def _prior_exclusion_evidence(issue, output_dir, words_for, claims):
    found = issue.get('found', {})
    problem = {'reason': 'prior_exclusion_not_established', 'claims': claims,
               'found': dict(found), 'detail': 'DRC elimination does not establish that exclusion of this object caused the original fault.'}
    from canonical_delivery import CanonicalDeliveryError, _real_file
    from operation_audit import operation_trace
    from scan_exclusion_evidence import _selectors, _selected
    try:
        output = output_dir.absolute(); rid = str(found.get('run_ref', ''))
        if not re.fullmatch(r'R[1-9]\d*', rid):
            return [problem]
        run = output/'runs'/rid; script = run/'deliverables'/(rid+'.dofile'); native = run/(rid+'.log')
        source = output/str(found.get('source', ''))
        for path in (script, native, source):
            _real_file(path, output)
            if not path.is_relative_to(run):
                return [problem]
        locator = re.fullmatch(r'L([1-9]\d*)(?:-L([1-9]\d*))?', str(found.get('locator', '')))
        objects = re.findall(r"'(?:DFF|SFF|FF|LATCH)'\s+'([^']+)'", str(found.get('excerpt', '')), re.I)
        if not locator or len(objects) != 1:
            return [problem]
        first, last = int(locator[1]), int(locator[2] or locator[1])
        fragment = []
        with source.open(errors='replace') as stream:
            for number, line in enumerate(stream, 1):
                if number > last:
                    break
                if number >= first:
                    fragment.append(line.rstrip('\r\n'))
        if last < first or len(fragment) != last-first+1 or found['excerpt'] not in '\n'.join(fragment):
            return [problem]
        text = script.read_text(); checks = []; exclusions = []; observed = None
        with native.open(errors='replace') as stream:
            for number, line in enumerate(stream, 1):
                echo = re.search(r'CMD-0034\]\s+@(\d+):\s*(.*)', line)
                words = words_for(echo[2]) if echo else []
                if words and words[0] == 'examine_scan_drc':
                    checks.append((number, int(echo[1])))
                if words[:2] == ['set_scan_element', 'false']:
                    exclusions.append((number, int(echo[1]), echo[2].strip()))
                if found['excerpt'] in line:
                    observed = number
        scopes = _selectors(text, words_for)
        if len(checks) == len(exclusions) == len(scopes) == 1:
            event, script_line, command = exclusions[0]
            if (observed and event < checks[0][0] < observed and
                    text.splitlines()[script_line-1].strip() == command and
                    _selected(objects[0], scopes[0]) and
                    operation_trace([native, source], output, text, words_for, allow_verbose=True)):
                return []
        problem['prior_script'] = {'source': script.relative_to(output).as_posix(),
                                   'recognized_exclusion_scopes': len(scopes)}
    except (OSError, ValueError, KeyError, TypeError, IndexError, CanonicalDeliveryError):
        pass
    return [problem]


def redirected_drc_codes(run_dir: Path, cache: dict) -> set[str]:
    """Preview growing actual reports so redirection does not hide blocking DRC from the monitor."""
    observed = set()
    for path in run_dir.rglob("*"):
        if path.suffix.lower() not in {".rpt", ".report", ".txt"} or path.name.startswith("llm_") or not path.is_file():
            continue
        try:
            info = path.stat()
            stamp = (info.st_mtime_ns, info.st_size)
            old = cache.get(path)
            if old and old[0] == stamp:
                observed.update(old[1])
                continue
            with path.open(encoding="utf-8", errors="replace") as stream:
                head = stream.read(8192)
                if "DRC Report" not in head or not re.search(r"(?m)^\s*Total violations:\s*[1-9]\d*\s*$", head):
                    codes = set()
                else:
                    stream.seek(max(0, info.st_size - 8192))
                    text = head + "\n" + stream.read(8192)
                    codes = set()
                    for line in text.splitlines():
                        if ("CMD-0034" not in line and
                                (re.search(r"\[(?:WARNING|INFO)\].*\[\s*DFTDRC-", line) or
                                 re.search(r"\[INFO\]\s+There were \d+ DRC rule '.+' fails", line))):
                            codes.update(rule_codes(line))
        except OSError:
            # The tool may rotate an output between directory enumeration and reading.
            continue
        cache[path] = (stamp, codes)
        observed.update(codes)
    return observed


def preceding_drc_observation(run_dir: Path, permitted: set[str], *, eco_stage=None, eco_required=False) -> dict:
    """Bind repair context to the last actual native summary and real reports.

    Early-aborted tools may never create reports. This supplies existing repair
    feedback/preflight with native failures, not an acceptance/success result.
    Incomplete or conflicting native counts stay unknown rather than invented.
    """
    reported = redirected_drc_codes(run_dir, {})
    result = {'run_ref': run_dir.name, 'redirected_report_codes': sorted(reported),
              'native_summary_status': 'missing_or_unbound', 'native_summary': None}
    native = run_dir / (run_dir.name + '.log')
    native_codes = set()
    if re.fullmatch(r'R[1-9]\d*', run_dir.name) and native.is_file() and not native.is_symlink():
        summaries = drc_summaries(native)
        if summaries:
            summary = summaries[-1]
            counts = summary['counts']
            valid = (not summary.get('invalid_counts') and
                     sum(counts.values()) == summary['total'] and
                     (bool(counts) or summary['total'] == 0))
            result['native_summary_status'] = 'complete_counts' if valid else 'incomplete_or_conflicting_counts'
            result['native_summary'] = {'source': f'runs/{run_dir.name}/{native.name}', **summary}
            if valid:
                native_codes = {code for code, count in counts.items() if count > 0}
    result['native_positive_codes'] = sorted(native_codes)
    result['permitted_codes'] = sorted(permitted)
    result['blocking_codes'] = sorted((reported | native_codes) - permitted)
    if eco_required:
        # A genuine early report is still historical evidence, not a claim
        # that the design after ECO has the same violations.
        result['historical_report_codes'] = sorted(reported)
        result['redirected_report_codes'] = []
        result['native_positive_codes'] = []
        result['blocking_codes'] = []
        result['native_summary_status'] = 'current_ECO_state_unverified'
        result['native_summary'] = None
        try:
            from eco_evidence import native_drc_snapshot
            if eco_stage is None or eco_stage.context.run != run_dir.resolve():
                raise ValueError('No same-round runtime native ECO binding')
            snapshot = native_drc_snapshot(eco_stage)
            result['current_native_drc'] = snapshot
            result['native_summary_status'] = 'stage_bound_' + snapshot['status']
            result['native_summary'] = snapshot['summaries'][-1] if snapshot['summaries'] else None
            if snapshot['status'] in {'clean', 'nonzero'}:
                current = {c for s in snapshot['summaries'] for c,n in s['counts'].items() if n > 0}
                result['native_positive_codes'] = sorted(current)
                result['blocking_codes'] = sorted(current - permitted)
        except (OSError,ValueError,KeyError,RuntimeError) as exc:
            result['current_state_unverified_reason'] = str(exc)
        result['phase_instruction'] = ('Historical/pre-repair DRC remains available for diagnosis. '
            'Missing current proof does not establish current violations or successful repair; '
            'only the bound current_native_drc may describe the adopted ECO state.')
    return result


def drc_summaries(path: Path) -> list[dict]:
    """Collect each total and its tool-generated per-rule fail counts, streaming the file."""
    summaries = []
    current = None
    span = []
    with path.open(encoding="utf-8", errors="replace") as stream:
        for number, line in enumerate(stream, 1):
            total = re.fullmatch(r"\s*Total violations:\s*(\d+)\s*", line)
            if total:
                current = {"total": int(total.group(1)), "counts": {}, "line": number,
                           "end_line": number, "excerpt": line.strip()}
                span = [line.rstrip("\r\n")]
                summaries.append(current)
            elif current:
                if "CMD-0034" in line:
                    current = None
                    span = []
                    continue
                span.append(line.rstrip("\r\n"))
                counted = re.search(r"\[INFO\]\s+(?:\[DFTDRC-7001\]\s+)?There were (\d+) DRC rule '([^']+)' fails", line)
                if counted:
                    codes = rule_codes(counted.group(2))
                    if len(codes) == 1:
                        code, count = next(iter(codes)), int(counted.group(1))
                        if code in current["counts"] and current["counts"][code] != count:
                            current["invalid_counts"] = True
                        current["counts"][code] = count
                    else:
                        current["invalid_counts"] = True
                    current.update(end_line=number, excerpt="\n".join(span))
    return summaries


def summary_permitted(summary: dict, permitted: set[str]) -> bool:
    if summary.get("invalid_counts"):
        return False
    counts = summary["counts"]
    if summary["total"] == 0:
        return all(count == 0 for count in counts.values())
    return bool(counts and sum(counts.values()) == summary["total"] and
                set(counts) <= permitted)


def excluded_scan_cells(paths: list[Path]) -> list[str]:
    """Keep real tool evidence of explicit scan-cell exclusions, regardless of total."""
    evidence = []
    for path in paths:
        with path.open(encoding="utf-8", errors="replace") as stream:
            for number, line in enumerate(stream, 1):
                if "DFTDRC-7006" in line and "set_scan_element" in line:
                    evidence.append(f"{path.name}:L{number}: {line.strip()}")
    return evidence


def residual_positive_evidence(files: list[Path], output_dir: Path, permitted: set[str],
                               repaired: set[str]) -> dict[str, str] | None:
    """Prove repair only when every related actual result agrees; retain visible residual counts."""
    if repaired & permitted:
        return None
    results = []
    for path in files:
        if (path.suffix.lower() != ".log" and
                (path.suffix.lower() not in {".rpt", ".report", ".txt"} or
                 not re.search(r"drc|violation", path.name, re.I))):
            continue
        results.extend((path, summary) for summary in drc_summaries(path))
    if not results or any(not summary_permitted(summary, permitted) for _, summary in results):
        return None
    if any(summary["total"] > 0 and not repaired for _, summary in results):
        # An unspecified violation cannot be called repaired while violations remain.
        return None
    if any(repaired & {code for code, count in summary["counts"].items() if count > 0}
           for _, summary in results):
        return None
    # Prefer an actual report block that displays the permitted residual and its counts.
    candidates = [(path, summary) for path, summary in results if summary["total"] > 0] or results
    reports = [(path, summary) for path, summary in candidates if path.suffix.lower() != ".log"]
    path, summary = (reports or candidates)[-1]
    first, last = summary["line"], summary["end_line"]
    return {"source": path.relative_to(output_dir).as_posix(),
            "locator": f"L{first}" if first == last else f"L{first}-L{last}",
            "excerpt": summary["excerpt"]}


def prior_signal_scope(problems):
    """Internal applicability, never an allow-list or a delivery proof."""
    return bool(problems) and all(isinstance(p.get('assessment_scope'), dict) and
        p['assessment_scope'].get('kind') == 'prior_signal_declaration_premise' and
        p['assessment_scope'].get('producer') == 'signal_declaration_claim_problems'
        for p in problems)


def _aggregate_drc_claim(issue):
    """Explicit rule-group scope only; a task citation is never a fault list."""
    diagnosis = issue.get('diagnosis', {})
    fields = {'phenomenon': str(issue.get('phenomenon', '')),
              **{k: str(diagnosis.get(k, '')) for k in ('summary', 'root_cause')}}
    codes = set().union(*(rule_codes(v) for v in fields.values()))
    return fields, codes


def _aggregate_native_scope(issue, root, words_for):
    """Authenticate the original report and retain each native endpoint role.

    Summarized 'other cells' are not an enumerated object set. We retain that
    uncertainty instead of shrinking an aggregate to its quoted representative.
    """
    import hashlib
    from canonical_delivery import _real_file, CanonicalDeliveryError
    from completion_policy import _reference
    from configuration_evidence import _signal_command_trace
    rid = str(issue.get('found', {}).get('run_ref', ''))
    if not re.fullmatch(r'R[1-9]\d*', rid):
        raise ValueError('Original aggregate run is unbound')
    _reference(root, issue['found'], {rid})
    run = root/'runs'/rid
    source = root/issue['found']['source']
    script, native = run/'deliverables'/(rid+'.dofile'), run/(rid+'.log')
    for path in (source, script, native):
        _real_file(path, root)
        if not path.is_relative_to(run):
            raise ValueError('Original aggregate source is outside its run')
    text = source.read_text(errors='replace')
    if 'DRC Report' not in text:
        raise ValueError('Aggregate discovery is not a native DRC report')
    blocks = drc_summaries(source)
    if len(blocks) != 1 or blocks[0].get('invalid_counts') or sum(blocks[0]['counts'].values()) != blocks[0]['total']:
        raise ValueError('Original aggregate counts are incomplete or conflicting')
    trace = _signal_command_trace(root, rid, words_for)
    if not trace or not trace.get('design'):
        raise ValueError('Original aggregate script/native design is unbound')
    # Bind the report to a real same-run DRC writer and its actual content.
    echoes = []
    for number, line in enumerate(native.read_text(errors='replace').splitlines(), 1):
        match = re.search(r'CMD-0034\]\s+@(\d+):\s*(.*)', line)
        words = words_for(match[2]) if match else []
        if words[:1] == ['examine_scan_drc'] and '-file' in words:
            echoes.append({'run_ref': rid, 'source': native.relative_to(root).as_posix(),
                           'locator': 'L'+str(number), 'excerpt': line,
                           'script_line': int(match[1]), 'command': match[2]})
    # Native input material is bound by the existing authenticated trace. A
    # unique DRC writer and identical complete native block prevent borrowing
    # an arbitrary zero/nonzero report from another operation.
    if len(echoes) != 1:
        raise ValueError('Original aggregate DRC writer is not unique')
    physical = script.read_text().splitlines(); echo = echoes[0]
    if not 0 < echo['script_line'] <= len(physical) or physical[echo['script_line']-1].strip() != echo['command'].strip():
        raise ValueError('Original DRC writer differs from executed script')
    # Tool redirection may omit report text from stdout. The collected report
    # must exactly equal the actual writer artifact, not merely share a name.
    from pathlib import PurePosixPath
    from canonical_delivery import _target
    variables = {}; pending = ''; virtual = None; matches = []; signal_writers = []
    for native_number,line in enumerate(native.read_text(errors='replace').splitlines(),1):
        origin = re.search(r'\[SOURCE TCL FILE\]\s+(\S+)\s*:', line)
        if origin:
            p = PurePosixPath(origin[1]); indexes = [i for i,v in enumerate(p.parts)
                if v == 'runs' and p.parts[i+1:i+2] == (rid,)]
            if virtual is not None or len(indexes) != 1 or '..' in p.parts:
                raise ValueError('Original DRC source origin is ambiguous')
            cut = indexes[0]+2; virtual = PurePosixPath(*p.parts[:cut])
            actual = run.joinpath(*p.parts[cut:]); _real_file(actual, root)
            if actual.read_bytes() != script.read_bytes():raise ValueError('Executed original DRC script differs')
        echo_match = re.search(r'CMD-0034\]\s+@(\d+):\s*(.*)', line)
        if echo_match:
            words = words_for(echo_match[2]); pending = ''
            if words[:1] == ['set'] and len(words) == 3:
                pending = words[1]; variables.pop(pending, None)
            elif words[:1] == ['examine_scan_drc'] and len(words) == 3 and words[1] == '-file':
                if virtual is None:raise ValueError('DRC writer origin unavailable')
                path = _target(words[2], variables, virtual, run, words_for)
                _real_file(path, root)
                if path.read_bytes() == source.read_bytes():matches.append({'path': path})
            elif words[:1] == ['rpt_scan_signal'] and len(words) == 3 and words[1] in {'-file','>'}:
                # A report role is meaningful only at its authenticated writer
                # state. Do not derive a scan-signal role from the DRC's generic
                # 'Clock ... capture' wording.
                try:
                    n = int(echo_match[1])
                    if virtual is None or not 0 < n <= len(physical) or physical[n-1].strip() != echo_match[2].strip():
                        raise ValueError('Original signal report writer/script differs')
                    path = _target(words[2], variables, virtual, run, words_for); _real_file(path, root)
                    signal_writers.append({'path':path,'run_ref':rid,'design':trace['design'],
                        'source':native.relative_to(root).as_posix(),'locator':'L'+str(native_number),
                        'script_line':n,'command':echo_match[2]})
                except (OSError,ValueError,TypeError,KeyError,CanonicalDeliveryError):pass
            continue
        if pending:
            value = line.strip()
            if value and not value.startswith('[') and not re.search(r'[$\[\]\\;]', value):variables[pending] = value
            pending = ''
    if len(matches) != 1:
        raise ValueError('Original DRC collected report has no unique native writer')
    rows = []; role_paths = []
    from report_validation import report_rows
    def signal_role(name):
        before = [event for event in trace['signals'] if int(event['locator'][1:]) < int(echo['locator'][1:]) and
                  dict(zip(event['words'][1::2],event['words'][2::2])).get('-port','').strip('"{}') == name]
        if not before:return None
        event = before[-1]
        opts = {k:v.strip('"{}') for k,v in zip(event['words'][1::2],event['words'][2::2])}
        if event['errors'] or opts.get('-type') not in {'clock','reset','scan_enable','constant'}:return None
        found = []
        for writer in signal_writers:
            # A later report can establish the earlier role only when no
            # relevant declaration intervened; a prior report is handled with
            # the corresponding no-update interval too.
            writer_line = int(writer['locator'][1:]); declaration_line = int(event['locator'][1:]); drc_line = int(echo['locator'][1:])
            if writer_line <= declaration_line:continue
            frame = []
            for native_line in native.read_text(errors='replace').splitlines()[writer_line:]:
                if 'CMD-0034]' in native_line:break
                frame.append(native_line)
            if not any(line.strip()=='1' for line in frame) or any(re.search(r'\[(?:ERROR|FATAL)\]',line) for line in frame):continue
            end = max(writer_line,drc_line)
            if any(declaration_line < int(e['locator'][1:]) < end and
                   dict(zip(e['words'][1::2],e['words'][2::2])).get('-port','').strip('"{}') == name for e in trace['signals']):continue
            path = writer['path']; content = path.read_text(errors='replace')
            if re.findall(r'(?m)^\s*Design\s*:\s*(\S+)\s*$',content) != [trace['design']]:continue
            selected = [r for r in report_rows(path,{'Port','SignalType','OffState','OwnerPartition'}) if r['Port']==name]
            if len(selected)!=1:return None
            row = selected[0]; role = row['SignalType'].split('(')[0]
            if role != opts['-type'] or ('-off_state' in opts and row['OffState']!=opts['-off_state']):return None
            if row['OwnerPartition'] not in {event['partition'],'' if event['partition']=='Default_Partition' else event['partition']}:return None
            copies = [path]; collector = run/'reports'/path.name
            if collector.exists():
                _real_file(collector,root)
                if collector.read_bytes()!=path.read_bytes():return None
                copies.append(collector)
            found.append({'role':role,'native_command':{k:event[k] for k in ('run_ref','source','locator','excerpt','design','partition')},
                'native_report':{'run_ref':rid,'source':path.relative_to(root).as_posix(),'locator':'L'+str(row['line']),
                    'excerpt':content.splitlines()[row['line']-1]},
                'native_writer':{k:v for k,v in writer.items() if k!='path'},'_paths':copies})
        if not found or len({r['role'] for r in found})!=1:return None
        # Repeated identical reports are retained as evidence, not additional
        # role candidates. Conflicting/unknown reports cannot select a role.
        for value in found:role_paths.extend(value.pop('_paths'))
        return {'role':found[0]['role'],'evidence':found}
    for number, line in enumerate(text.splitlines(), 1):
        codes = rule_codes(line)
        endpoint = re.search(r"(Clock|Set|Reset) input '([^']+)' of '(DFF|SFF|FF|LATCH)' '([^']+)'", line)
        clock = re.search(r"Clock '([^']+)' is unable to capture", line)
        if len(codes) != 1 or not (endpoint or clock):continue
        binding = signal_role(clock[1]) if clock and not endpoint else None
        rows.append({'rule': next(iter(codes)), 'role': endpoint[1].lower() if endpoint else binding['role'] if binding else 'unknown',
                     'native_role_word':endpoint[1].lower() if endpoint else 'clock',
                     **({'role_binding':binding} if binding else {}),
                     'object': endpoint[4] if endpoint else clock[1],
                     'pin': endpoint[2] if endpoint else None,
                     'object_class': endpoint[3] if endpoint else 'signal',
                     'source': source.relative_to(root).as_posix(), 'locator': 'L'+str(number),
                     'excerpt': line, 'count': blocks[0]['counts'].get(next(iter(codes)))})
    paths = [source, script, native, matches[0]['path'],*role_paths]
    scope = {'kind': 'prior_heterogeneous_drc_scope', 'producer': 'aggregate_drc_scope_assessment',
             'case_output': str(root.resolve()), 'run_ref': rid, 'design': trace['design'],
             'native_rows': rows, 'native_counts': blocks[0]['counts'], 'native_writer': echo,
             'native_report': matches[0]['path'].relative_to(root).as_posix(),
             'script': script.relative_to(root).as_posix(), 'native': native.relative_to(root).as_posix(),
             'source': source.relative_to(root).as_posix(),
             'fingerprints': {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest() for p in paths},
             'loaded_inputs': trace['loaded_input_netlists'],
             'meaning': 'Original diagnostic scope only; no verdict about final delivery or arbitrary causality.'}
    return scope


def _universal_endpoint_claims(fields):
    """Quantified native endpoint sets; never infer them from task citations."""
    result=[]
    for field,text in fields.items():
        for m in re.finditer(r'\b(?:all|every|each)\s+(?:the\s+)?(?:DFF|FF|flip-flop)s?\s+(?P<role>reset|set|clock)\s+(?:pins?|inputs?)\b|(?:所有|全部|每个)(?:的)?(?:DFF|FF|触发器)(?:的)?(?P<cn>复位|置位|时钟)(?:引脚|输入)',text,re.I):
            role=m['role'].lower() if m['role'] else {'复位':'reset','置位':'set','时钟':'clock'}[m['cn']]
            result.append({'field':field,'clause':m[0],'span':list(m.span()),'quantifier':'all','role':role})
    return result


def aggregate_drc_scope_assessment(issue, output_dir, words_for, input_dir=None):
    """Finite heterogeneous endpoint-scope guard, with explicit four states.

    Homogeneous clock groups remain with their existing clock/control verifier;
    this producer does not certify their full causal/object scope. Unknown
    native scope stays applicable/incomplete, never N/A or an empty-list PASS.
    """
    from canonical_delivery import CanonicalDeliveryError
    fields, codes = _aggregate_drc_claim(issue)
    found_excerpt = str(issue.get('found', {}).get('excerpt', ''))
    if re.search(r'\[(?:ERROR|FATAL)\]', found_excerpt):
        from command_error_evidence import failed_command
        try:
            command = failed_command(issue['found'], Path(output_dir).absolute())
            words = words_for(command) if command else []
        except (OSError,ValueError,TypeError,KeyError,IndexError,CanonicalDeliveryError):words = []
        if words[:1] == ['set_scan_drc_rule_handling']:
            return {'applicable': False, 'status': 'not_applicable', 'claims': [], 'problems': [],
                    'coverage_limit': 'Authenticated native rule-handling command failure is handled by command/parameter validators; rule-ID operands are not a grouped native DRC-condition scope.'}
    universal = _universal_endpoint_claims(fields)
    # A single rule can quantify many objects. Rule diversity is not the same
    # thing as object-set completeness.
    if universal:codes |= rule_codes(found_excerpt)
    claims = [{'fields': fields, 'claimed_rules': sorted(codes), 'universal':universal}] if len(codes) > 1 or universal else []
    base = {'applicable': bool(claims), 'status': 'not_applicable', 'claims': claims, 'problems': []}
    if not claims:return base
    root = Path(output_dir).absolute(); scope = None
    try:
        scope = _aggregate_native_scope(issue, root, words_for)
        rows = [row for row in scope['native_rows'] if row['rule'] in codes]
        observed = {row['rule'] for row in rows}
        if observed != codes or any(not row.get('count') for row in rows):
            raise ValueError('Not every claimed native rule has bound endpoint/count evidence')
        roles = {row['role'] for row in rows}
        if 'unknown' in roles:
            raise ValueError('Signal-level DRC role has no bound original native declaration/report state')
        if len(roles) == 1 and not universal:
            return {**base, 'applicable': False, 'claims':[], 'scope': scope,
                    'coverage_limit': 'Homogeneous native endpoint group; existing dedicated relation checks still apply. No full-scope proof is issued here.'}
        # A declared reset repair is not a clock-control/capture repair. Set and
        # reset roles may share a root port, but require physical evidence too.
        # Do not infer that relationship from a task citation or DRC cleanup.
        from configuration_evidence import signal_operations
        operations = signal_operations(issue)
        scope.update(claimed_rules=sorted(codes), endpoint_roles=sorted(roles),
                     declared_signal_operations=operations, assessment_status='incomplete')
        if universal:
            location=str(issue.get('diagnosis',{}).get('located_object',''))
            if not any(location in {r['object'],r['object']+'/'+str(r['pin'])} for r in rows):
                raise ValueError('The quantified claim representative does not match its actual native object')
            # No shrinking an all-object statement to one reported example.
            # The native report can summarize unnamed members; that proves a
            # count, not the identities or all causal subclaims.
            if {c['role'] for c in universal} != roles:
                raise ValueError('Quantified endpoint roles differ from the authenticated native fault')
            scope.update(universal_claims=universal,
                scope_obligation='Complete original endpoint identities and each asserted condition/cause',
                unproved_object_counts={code:scope['native_counts'][code]-len({(r['object'],r['pin']) for r in rows if r['rule']==code}) for code in sorted(codes)},
                unproved_scope=rows)
            problem={'status':'incomplete','reason':'aggregate_drc_scope_not_established',
                'claimed_rules':sorted(codes),'assessment_scope':scope,
                'detail':'A quantified original fault set is not established by representative rows, summary counts or a later successful repair.'}
            return {**base,'status':'incomplete','scope':scope,'problems':[problem]}

        # The contract is deliberately the *uncovered heterogeneous role*
        # check, not an attempt to prove every aggregate cause. Record real
        # reset/set root relationships separately from unsupported clock scope.
        supported = []; missing = []
        from partial_insertion_validation import _libraries
        from eco_structure import read_design
        from netlist_repair import RepairRejected
        physical = None
        if input_dir is not None:
            try:
                import hashlib
                nets = sorted((Path(input_dir)/'netlist').glob('*.v'))
                libs = sorted((Path(input_dir)/'lib').glob('*.lib'))
                library, unknown = _libraries(libs)
                # Use the caller's controlled case-input root. Do not use a
                # stale run/input symlink left by container export or guess a
                # file from its leaf name. The known /input mount preserves
                # exact family-relative identity across host replay.
                loaded = scope['loaded_inputs']
                actual_inputs = [Path(input_dir)/Path(p).relative_to('/input') if Path(p).parts[:2] == ('/','input') else Path(p) for p in loaded]
                if nets and libs and not unknown and sorted(p.resolve() for p in actual_inputs) == sorted(p.resolve() for p in nets):
                    physical = read_design(nets,library,scope['design'])
                    scope['physical_input_fingerprints'] = {str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in nets+libs}
            except (OSError,ValueError,TypeError,KeyError,RepairRejected):pass
        for row in rows:
            matches = []
            if physical is not None and row['object_class'] == 'signal' and row.get('role_binding'):
                for operation in operations:
                    if (operation.get('port') == row['object'] and operation.get('type') == row['role'] and
                            physical['modules'][scope['design']]['ports'].get(row['object']) == 'input'):
                        matches.append({'signal':row['object'],'declared_role':row['role'],'native_role':row['role'],
                            'object':row['object'],'pin':None,'actual_signal_role':row['role_binding'],
                            'meaning':'Exact original input identity and effective native scan-signal role; not a physical clock-role assertion or whole-cause proof.'})
            elif physical is not None and row['role'] in {'reset','set'} and row['object_class'] != 'signal':
                cell = physical['cells'].get(row['object'])
                driver = physical['graph'].resolve(cell['pins'].get(row['pin'])) if cell else None
                for operation in operations:
                    if operation.get('type') == 'reset' and operation.get('port') and driver and driver[0] == scope['design']+'::'+operation['port']:
                        matches.append({'signal':operation['port'],'declared_role':'reset',
                                        'native_role':row['role'],'physical_driver':list(driver),
                                        'cell_type':cell['type'],'object':row['object'],'pin':row['pin'],
                                        'meaning':'Physical control relation only; cited action/delta and polarity are independently validated.'})
            elif physical is not None and row['role'] == 'clock':
                cell = physical['cells'].get(row['object']) if row['object_class'] != 'signal' else None
                driver = physical['graph'].resolve(cell['pins'].get(row['pin'])) if cell else None
                for operation in operations:
                    port = operation.get('port')
                    identity = (row['object_class'] == 'signal' and row['object'] == port and
                                physical['modules'][scope['design']]['ports'].get(port) == 'input')
                    if operation.get('type') == 'clock' and port and (identity or driver and driver == (scope['design']+'::'+port,0)):
                        matches.append({'signal':port,'declared_role':'clock','native_role':'clock',
                            'physical_driver':list(driver) if driver is not None else None,'object':row['object'],'pin':row['pin'],
                            'meaning':'Exact clock identity/driver relation only; actual action and original cause remain independently checked.'})
            if len(matches) == 1:supported.append({**row,'support':matches[0]})
            else:missing.append({**row,'support':'not_established'})
        scope['covered_native_relations'] = supported
        scope['unproved_scope'] = missing
        scope['unsupported_roles'] = sorted({row['role'] for row in missing})
        scope['unproved_object_counts'] = {code:scope['native_counts'][code] - len({(r['object'],r['pin']) for r in rows if r['rule']==code})
            for code in sorted(codes) if scope['native_counts'][code] > len({(r['object'],r['pin']) for r in rows if r['rule']==code})}
        if not missing and not scope['unproved_object_counts']:
            return {**base,'applicable':False,'claims':[],'scope':scope,
                'coverage_limit':'All explicit heterogeneous native representatives have physical typed-action relations; existing action, polarity, object and positive-evidence validators still decide closure. No aggregate causal PASS issued here.'}
        detail = ('The aggregate names heterogeneous native endpoint roles. The selected signal configuration '
                  'and its repair evidence do not independently establish every original group/object relation; '
                  'the original scope is retained, not reduced to the repaired signal.')
    except (OSError, ValueError, TypeError, KeyError, IndexError, CanonicalDeliveryError) as exc:
        detail = str(exc)
    problem = {'status': 'incomplete', 'reason': 'aggregate_drc_scope_not_established',
               'claimed_rules': sorted(codes), 'detail': detail}
    if scope:problem['assessment_scope'] = scope
    return {**base, 'status': 'incomplete', 'scope': scope, 'problems': [problem]}


def aggregate_drc_scope(conflicts):
    """Recognize producer-owned scope, never authorize delivery on a code."""
    return bool(conflicts) and all(isinstance(p, dict) and p.get('status') == 'incomplete' and
        isinstance(p.get('assessment_scope'), dict) and
        p['assessment_scope'].get('kind') == 'prior_heterogeneous_drc_scope' and
        p['assessment_scope'].get('producer') == 'aggregate_drc_scope_assessment' and
        (len(p['assessment_scope'].get('endpoint_roles', [])) > 1 or
         bool(p['assessment_scope'].get('universal_claims')) and
         {c.get('role') for c in p['assessment_scope']['universal_claims']} == set(p['assessment_scope'].get('endpoint_roles',[]))) and
        set(p.get('claimed_rules', [])) == set(p['assessment_scope'].get('claimed_rules', [])) and
        set(p['assessment_scope'].get('native_counts', {})) >= set(p.get('claimed_rules', []))
        for p in conflicts)


def _aggregate_task_roles(spec, port):
    """Finite explicit task roles, including the existing partition table."""
    from report_validation import partition_requirements
    clean = spec.replace('`', '').replace('**', '')
    roles = _task_native_roles(clean, port)
    for line in clean.splitlines():
        if re.search(r'例如|示例|不要|不作为|\b(?:not|example)\b', line, re.I):continue
        if re.search(r'(?<![\w$])'+re.escape(port)+r'(?![\w$])\s+配置为(?:异步)?复位(?:信号)?',line):roles.add('reset')
    for row in partition_requirements(spec).values():
        if any(re.search(r'clocks',key,re.I) and value.strip('` ') == port for key,value in row.items()):roles.add('clock')
    return roles


def _universal_drc_delivery_condition(issue, conflicts, root, run_ref, spec, files,
                                      dofile, words_for, input_dir, permitted_rules):
    """Independent non-ECO task scope for a quantified historical DRC claim.

    Authenticate source FF identities against the *entire* final native object
    inventory, actual signal setters/reports and same-state DRC. These facts
    prove current task coverage, not historical membership or causality. The
    existing caller still checks task constraints, canonical outputs and EQY.
    """
    import hashlib, json
    from configuration_evidence import _signal_command_trace, signal_operations, _signal_check
    from canonical_delivery import _native_sources, _real_file, CanonicalDeliveryError
    from operation_audit import operation_trace, post_operation_report
    from partial_insertion_validation import _libraries, _modules
    from report_validation import report_rows
    try:
        scope=conflicts[0]['assessment_scope'];prior=issue['found']['run_ref']
        if (len(conflicts)!=1 or not scope.get('universal_claims') or
                scope['case_output']!=str(root.resolve()) or scope['run_ref']!=prior or
                not int(prior[1:])<int(run_ref[1:])):return None
        old=_signal_command_trace(root,prior,words_for);current=_signal_command_trace(root,run_ref,words_for)
        trace=operation_trace(files,root,dofile,words_for,allow_verbose=True)
        if (not old or not current or not trace or
                old['design']!=current['design'] or current['design']!=scope['design'] or
                trace['design']!=scope['design'] or old['loaded_input_netlists']!=current['loaded_input_netlists']):return None
        from eco_structure import MUTATIONS, DYNAMIC
        mutation=r'\b(?:'+'|'.join(re.escape(c) for c in sorted(MUTATIONS | DYNAMIC | {'eco_link'}))+r')\b'
        for rid in (prior,run_ref):
            if re.search(mutation,(root/'runs'/rid/'deliverables'/(rid+'.dofile')).read_text()):return None
        nets=sorted((input_dir/'netlist').glob('*.v'));libs=sorted((input_dir/'lib').glob('*.lib'))
        if not nets or not libs:return None
        for rid in (prior,run_ref):
            native=(root/'runs'/rid/(rid+'.log')).read_text()
            for family,pattern in [(nets,r"Read Verilog file '([^']+)' successfully"),
                                   (libs,r"Liberty file '([^']+)' is read successfully")]:
                loaded=re.findall(pattern,native)
                expected={str(p.resolve()) for p in family}
                actual=[input_dir/Path(p).relative_to('/input') if Path(p).parts[:2]==('/','input') else Path(p) for p in loaded]
                if len(actual)!=len(expected) or {str(p.resolve()) for p in actual}!=expected:return None
        roles=scope['endpoint_roles']
        if len(roles)!=1 or roles[0] not in {'clock','reset','set'}:return None
        role='clock' if roles[0]=='clock' else 'reset'
        # Current task evidence uses actual same-state declarations, not the
        # subset of signal names the model happened to place in its action.
        operations=[]
        for e in current['signals']:
            opts=dict(zip(e['words'][1::2],(w.strip('{}\"') for w in e['words'][2::2])))
            if opts.get('-type')==role and not e['errors']:operations.append(opts)
        ports=sorted({o.get('-port') for o in operations if o.get('-port')})
        if not ports:return None
        signal_reports=[]
        signal_writers=[w for w in trace['reports'] if w['kind']=='rpt_scan_signal']
        if not signal_writers:return None
        last_signal_writer=max(w['log_line'] for w in signal_writers)
        for report in files:
            if report.suffix!='.rpt':continue
            writer=post_operation_report(report,'rpt_scan_signal',trace,root)
            if not writer or writer['log_line']!=last_signal_writer or any(int(e['locator'][1:])>=writer['log_line'] for e in current['signals']):continue
            observed=[r for r in report_rows(report,{'Port','SignalType','OffState','OwnerPartition'}) if r['Port'] in ports]
            if len(observed)!=len(ports) or {r['Port'] for r in observed}!=set(ports):continue
            if any(r['SignalType'].split('(')[0]!=role or r['OffState'] not in {'0','1'} or
                   (r['OwnerPartition'] or 'Default_Partition')!='Default_Partition' for r in observed):continue
            if any(o.get('-off_state',r['OffState'])!=r['OffState'] for o in operations for r in observed if o['-port']==r['Port']):continue
            first,last=min(r['line'] for r in observed),max(r['line'] for r in observed)
            signal_reports.append((report,{'source':report.relative_to(root).as_posix(),
                'locator':f'L{first}-L{last}','excerpt':'\n'.join(report.read_text().splitlines()[first-1:last])}))
        if not signal_reports:return None
        # Multiple collected aliases must be content-identical for these rows.
        if len({json.dumps(ref,sort_keys=True) for _,ref in signal_reports})!=1:return None
        signal_path,selected=signal_reports[0]
        # Identity enumeration reuses the existing source parser. No graph
        # expansion, invented causal relation or raising a parser size limit.
        library,unknown=_libraries(libs);modules,unknown_modules=_modules(nets,library)
        if unknown or unknown_modules or scope['design'] not in modules:return None
        if any(modules[scope['design']]['ports'].get(port)!='input' for port in ports):return None
        original=set();reset=set();visited=set()
        def walk(kind,prefix,ancestors):
            if kind in ancestors or modules[kind]['unknown']:raise ValueError('Incomplete original hierarchy')
            seen=set();visited.add(kind)
            for cell in modules[kind]['cells']:
                name=cell['instance'];typ=cell['type'];full=prefix+name
                if name in seen:raise ValueError('Ambiguous original instance')
                seen.add(name)
                if typ in modules:walk(typ,full+'/',ancestors|{kind})
                elif typ not in library:raise ValueError('Unknown original cell')
                elif library[typ]['ffs']:
                    if len(library[typ]['ffs'])!=1:raise ValueError('Unmapped multi-state cell')
                    original.add(full)
                    if 'clear' in library[typ]['ffs'][0]['properties']:reset.add(full)
        walk(scope['design'],'',set())
        if not original or roles[0]=='reset' and not reset:return None
        for fault in scope['native_rows']:
            if fault['rule'] in scope['claimed_rules'] and fault['object'] not in (reset if roles[0]=='reset' else original):return None
        reports=[]
        for path in files:
            if path.suffix!='.rpt':continue
            writer=post_operation_report(path,'rpt_scan_element',trace,root)
            if writer:reports.append((path,writer))
        if len(reports)!=1:return None
        path,writer=reports[0]
        rows=[r for r in report_rows(path,{'Type','Length','InstanceName','ObjState'}) if r['InstanceName']]
        names=[r['InstanceName'] for r in rows]
        if (len(names)!=len(set(names)) or set(names)!=original or
                any(r['Type'] not in {'dff','sff'} or r['Length']!='1' or
                    r['ObjState'] not in {'scannable','user_defined_nonscannable'} for r in rows)):return None
        # Current final DRC must be native, complete, after the last relevant
        # state change; a zero in an arbitrary log is never selected.
        permitted=set(permitted_rules or ());clean=[]
        for report in files:
            if report.suffix not in {'.rpt','.report','.txt'}:continue
            blocks=drc_summaries(report)
            if len(blocks)!=1 or blocks[0].get('invalid_counts'):continue
            block=blocks[0]
            if sum(block['counts'].values())!=block['total'] or {c for c,n in block['counts'].items() if n}-permitted:continue
            ref={'run_ref':run_ref,'source':report.relative_to(root).as_posix(),
                 'locator':'L'+str(block['line']),'excerpt':'Total violations: '+str(block['total'])}
            try:bound=_aggregate_native_scope({'found':ref},root,words_for)
            except (OSError,ValueError,KeyError,CanonicalDeliveryError):continue
            line=int(bound['native_writer']['locator'][1:]);later=[]
            for text in (root/'runs'/run_ref/(run_ref+'.log')).read_text().splitlines()[line:]:
                echo=re.search(r'CMD-0034\]\s+@\d+:\s*(.*)',text);w=words_for(echo[1]) if echo else []
                if w and (w[0].startswith('set_scan_') or re.match(mutation,w[0]) or w[0] in {'present_design','load_netlist','set_current_scan_partition'}):later.append(w)
            if not later:clean.append((report,ref,bound))
        identities={json.dumps(e[2]['native_writer'],sort_keys=True) for e in clean}
        if len(identities)!=1:return None
        if len({hashlib.sha256(e[0].read_bytes()).hexdigest() for e in clean})!=1:return None
        export,_,design=_native_sources(root,run_ref,words_for)
        if design!=scope['design']:return None
        events=[]
        for event in current['signals']:
            opts=dict(zip(event['words'][1::2],(w.strip('{}"') for w in event['words'][2::2])))
            if opts.get('-port') in ports and opts.get('-type')==role and not event['errors']:events.append(event)
        if {dict(zip(e['words'][1::2],e['words'][2::2])).get('-port') for e in events}!=set(ports):return None
        event=events[-1]
        paths=[*nets,*libs,path,export['source'],root/selected['source'],root/issue['found']['source']]
        paths += [e[0] for e in clean]
        for rid in (prior,run_ref):paths += [root/'runs'/rid/(rid+'.log'),root/'runs'/rid/'deliverables'/(rid+'.dofile')]
        return ({'kind':'native_task_drc_scope','design':design,'run_ref':run_ref,'original_run_ref':prior,
            'located_object':issue['diagnosis']['located_object'],'prior_checks':conflicts,
            'condition_scope':'complete_task_native_role_and_object_set',
            'object_binding':{'original_FF_count':len(original),'original_reset_FF_count':len(reset),
                'original_FF_identity_sha256':hashlib.sha256('\n'.join(sorted(original)).encode()).hexdigest(),
                'same_final_native_object_set':True,'native_element_writer':writer,
                'task_signal_objects':ports,'scope':'Full original FF identity vs final native inventory; not original fault membership/causality.'},
            'final_export_sha256':hashlib.sha256(export['source'].read_bytes()).hexdigest(),
            'final_condition':{'run_ref':run_ref,**selected},
            'native_command':{k:event[k] for k in ('run_ref','source','locator','excerpt','design','partition')},
            'same_state_drc':clean[0][1],'native_drc_writer':clean[0][2]['native_writer'],
            'permitted_residual_rules':sorted(permitted)},paths)
    except (OSError,ValueError,TypeError,KeyError,IndexError,CanonicalDeliveryError):return None


def aggregate_drc_delivery_condition(issue, conflicts, root, run_ref, spec,
                                     files, dofile, words_for, input_dir, *, permitted_rules=None):
    """Separate actual final task roles/object coverage from unknown old cause.

    This bounded non-ECO signal condition is not a complete delivery verdict.
    The caller must additionally revalidate every task/artifact/EQY gate and
    seal the existing opaque proof. Unknown/mixed scopes cannot issue it.
    """
    import hashlib, json
    from canonical_delivery import _real_file, _native_sources, CanonicalDeliveryError
    from configuration_evidence import _signal_command_trace, signal_operations
    from operation_audit import operation_trace, post_operation_report
    from report_validation import report_rows
    from partial_insertion_validation import _libraries, _boolean
    from eco_structure import read_design
    from netlist_repair import RepairRejected
    try:
        root = Path(root).absolute(); input_dir = Path(input_dir)
        if (not aggregate_drc_scope(conflicts) or
                json.dumps(aggregate_drc_scope_assessment(issue, root, words_for, input_dir)['problems'],sort_keys=True,ensure_ascii=False,separators=(',',':')) !=
                json.dumps(conflicts,sort_keys=True,ensure_ascii=False,separators=(',',':')) or
                issue['attempts'][-1]['verify'].get('run_ref') != run_ref or
                issue['attempts'][-1]['verify'].get('resolved') is not False):return None
        if len(conflicts)==1 and conflicts[0]['assessment_scope'].get('universal_claims'):
            return _universal_drc_delivery_condition(issue,conflicts,root,run_ref,spec,files,dofile,words_for,input_dir,permitted_rules)
        prior = issue['found']['run_ref']; scopes = [p['assessment_scope'] for p in conflicts]
        if len(scopes) != 1 or not int(prior[1:]) < int(run_ref[1:]):return None
        scope = scopes[0]
        if scope['case_output'] != str(root.resolve()) or scope['run_ref'] != prior:return None
        trace = _signal_command_trace(root, run_ref, words_for)
        native_trace = operation_trace(files, root, dofile, words_for, allow_verbose=True)
        if not trace or not native_trace or trace['design'] != scope['design'] or native_trace['design'] != scope['design']:return None
        top = scope['design']; operations = signal_operations(issue)
        # Only an explicitly located literal reset command is supported here.
        # No signal is inferred from diagnostic prose or a sole candidate.
        wanted = {(o.get('port'), o.get('type')) for o in operations}
        if len(wanted) != 1:return None
        port, role = next(iter(wanted))
        if role != 'reset' or _aggregate_task_roles(spec, port) != {'reset'}:return None
        export, _, design = _native_sources(root, run_ref, words_for)
        if design != top:return None
        nets = sorted((input_dir/'netlist').glob('*.v')); libs = sorted((input_dir/'lib').glob('*.lib'))
        if not nets or not libs:return None
        paths = [export['source'], *nets, *libs]
        # The actual original and adopted native loads must be the same source
        # family. Copied paths differ across runs, so compare unique file names
        # and content, never basename alone or an untrusted serialized flag.
        for rid in (prior, run_ref):
            native = root/'runs'/rid/(rid+'.log'); _real_file(native, root)
            raw = native.read_text(errors='replace')
            for family, pattern in [(nets, r"Read Verilog file '([^']+)' successfully"),
                                    (libs, r"Liberty file '([^']+)' is read successfully")]:
                loaded = re.findall(pattern, raw)
                if len(loaded) != len(family):return None
                for original in family:
                    matching = [Path(p) for p in loaded if Path(p).name == original.name]
                    if len(matching) != 1:return None
                    actual = matching[0]
                    if actual.parts[:2] == ('/','input'):
                        actual = input_dir/actual.relative_to('/input')
                    if actual.resolve() != original.resolve():return None
                    _real_file(actual, input_dir.absolute())
                    if actual.read_bytes() != original.read_bytes():return None
                    paths.append(actual)
            paths += [native, root/'runs'/rid/'deliverables'/(rid+'.dofile')]
        # No in-memory ECO can be discharged by this non-ECO condition.
        mutation = r'\b(?:eco_link|add_inst|delete_inst|add_net|connect_pin|connect_net|disconnect_net|rewire|load_db)\b'
        if any(re.search(mutation, (root/'runs'/r/'deliverables'/(r+'.dofile')).read_text()) for r in (prior,run_ref)):return None
        library, unknown = _libraries(libs)
        if unknown:return None
        before = read_design(nets, library, top); final = read_design([export['source']], library, top)
        if before['modules'][top]['ports'].get(port) != 'input' or final['modules'][top]['ports'].get(port) != 'input':return None
        events = []
        for event in trace['signals']:
            opts = {k:v.strip('"{}') for k,v in zip(event['words'][1::2],event['words'][2::2])}
            if opts.get('-port') == port:events.append((event,opts))
        if len(events) != 1:return None
        event, opts = events[0]
        if event['errors'] or opts.get('-type') != role or opts.get('-off_state') not in {'0','1'}:return None
        candidates = []
        for report in files:
            if report.suffix not in {'.rpt','.report','.txt'}:continue
            writer = post_operation_report(report, 'rpt_scan_signal', native_trace, root)
            if not writer or writer['log_line'] <= int(event['locator'][1:]):continue
            rows = [r for r in report_rows(report, {'Port','SignalType','OffState','OwnerPartition'}) if r['Port'] == port]
            if len(rows) == 1 and rows[0]['SignalType'].split('(')[0] == role and rows[0]['OffState'] == opts['-off_state']:
                candidates.append((writer, report, rows[0]))
        if not candidates:return None
        writer, report, row = max(candidates, key=lambda x:x[0]['log_line'])
        if row['OwnerPartition'] not in {event['partition'], '' if event['partition']=='Default_Partition' else event['partition']}:return None
        # Each *enumerated* native FF survives with the same full identity and
        # functional clock/reset/set driver. Summary-only other objects are
        # never manufactured; full task/chain coverage is checked by caller.
        bound = []
        for fault in scope['native_rows']:
            if fault['rule'] not in scope['claimed_rules']:continue
            name, pin = fault['object'], fault['pin']
            if fault['object_class'] == 'signal':
                if before['modules'][top]['ports'].get(name) != 'input' or final['modules'][top]['ports'].get(name) != 'input':return None
                bound.append({'rule':fault['rule'],'object':name,'kind':'input_port','identity_preserved':True});continue
            old, new = before['cells'].get(name), final['cells'].get(name)
            if not old or not new or not library[old['type']]['ffs'] or not library[new['type']]['ffs']:return None
            if pin not in old['pins'] or pin not in new['pins']:return None
            driver = before['graph'].resolve(old['pins'][pin]); adopted = final['graph'].resolve(new['pins'][pin])
            if driver is None or driver != adopted:return None
            if fault['role'] in {'reset','set'}:
                if driver[0] != top+'::'+port:return None
                property_name = 'clear' if fault['role']=='reset' else 'preset'
                expressions = [f['properties'][property_name] for f in library[new['type']]['ffs'] if property_name in f['properties']]
                if len(expressions) != 1:return None
                inactive = int(opts['-off_state']) ^ driver[1]
                fact = _boolean(expressions[0], {pin:inactive})
                if fact is None or fact[0] or list(fact[1]) != [0]:return None
            elif fault['role'] == 'clock':
                if driver[1] or not driver[0].startswith(top+'::'):return None
                clock = driver[0][len(top)+2:]
                if _aggregate_task_roles(spec,clock) != {'clock'}:return None
                clocks = [e for e in trace['signals'] if not e['errors'] and
                          dict(zip(e['words'][1::2], e['words'][2::2])).get('-port') == clock and
                          dict(zip(e['words'][1::2], e['words'][2::2])).get('-type') == 'clock']
                if len(clocks) != 1:return None
            bound.append({'rule':fault['rule'],'object':name,'pin':pin,'role':fault['role'],
                          'original_cell':old['type'],'final_cell':new['type'],'preserved_driver':driver})
        # Find and authenticate the task-permitted same-state report. A later
        # setting or design mutation invalidates it; no arbitrary log zero is
        # selected. This does not waive the caller's native final DRC checks.
        permitted = set(permitted_rules) if permitted_rules is not None else authorized_rule_codes(spec)
        clean = []
        for path in files:
            if path.suffix not in {'.rpt','.report','.txt'}:continue
            blocks = drc_summaries(path)
            if (len(blocks) != 1 or blocks[0].get('invalid_counts') or
                    sum(blocks[0]['counts'].values()) != blocks[0]['total'] or
                    {c for c,n in blocks[0]['counts'].items() if n>0} - permitted):continue
            evidence = {'run_ref':run_ref,'source':path.relative_to(root).as_posix(),
                        'locator':'L'+str(blocks[0]['line']),'excerpt':'Total violations: '+str(blocks[0]['total'])}
            try:actual = _aggregate_native_scope({'found':evidence},root,words_for)
            except (OSError,ValueError,TypeError,KeyError,CanonicalDeliveryError):continue
            line = int(actual['native_writer']['locator'][1:]); later=[]
            for text in (root/'runs'/run_ref/(run_ref+'.log')).read_text().splitlines()[line:]:
                echo=re.search(r'CMD-0034\]\s+@\d+:\s*(.*)',text)
                w=words_for(echo[1]) if echo else []
                if w and (w[0].startswith('set_scan_') or re.match(mutation,w[0]) or w[0] in {'present_design','load_netlist','set_current_scan_partition'}):later.append(w)
            if not later:clean.append((path,evidence,actual))
        # The report collector retains a content-identical copy of the actual
        # writer artifact. Two paths are not two independent proofs. Join only
        # by the complete authenticated writer identity AND content hash.
        groups = {}
        for path,evidence,actual in clean:
            native_writer = actual['native_writer']
            identity = tuple(native_writer.get(k) for k in ('run_ref','source','locator','script_line','command'))
            groups.setdefault(identity,[]).append((path,evidence,actual))
        if len(groups) != 1:return None
        aliases = next(iter(groups.values()))
        native_paths = {root/a['native_report'] for _,_,a in aliases}
        if len(native_paths) != 1:return None
        cleanpath = next(iter(native_paths)); _real_file(cleanpath,root)
        digest = hashlib.sha256(cleanpath.read_bytes()).hexdigest()
        if any(hashlib.sha256(p.read_bytes()).hexdigest() != digest for p,_,_ in aliases):return None
        # Any collector copy for this exact writer must agree, including one
        # whose malformed/nonpermitted content failed the earlier selection.
        collector = root/'runs'/run_ref/'reports'/cleanpath.name
        checked_copies = {cleanpath,*(p for p,_,_ in aliases)}
        if collector in files:
            _real_file(collector,root); checked_copies.add(collector)
            if hashlib.sha256(collector.read_bytes()).hexdigest() != digest:return None
        cleanactual = aliases[0][2]
        block = drc_summaries(cleanpath)[0]
        cleanref = {'run_ref':run_ref,'source':cleanpath.relative_to(root).as_posix(),
                    'locator':'L'+str(block['line']),'excerpt':'Total violations: '+str(block['total'])}
        ref = {'run_ref':run_ref,'source':report.relative_to(root).as_posix(),'locator':'L'+str(row['line']),
               'excerpt':report.read_text().splitlines()[row['line']-1]}
        paths += [report,*sorted(checked_copies),root/issue['found']['source'],
                  *(root/p for p in scope['fingerprints'])]
        return ({'kind':'native_task_drc_scope','design':top,'run_ref':run_ref,
            'original_run_ref':prior,'located_object':issue['diagnosis']['located_object'],
            'prior_checks':conflicts,'object_binding':{'task_signal':port,'task_role':role,
                'native_diagnostic_representatives':bound,'aggregate_other_object_scope':'Caller independently verifies full task and scan object coverage; not original causality.'},
            'final_export_sha256':hashlib.sha256(export['source'].read_bytes()).hexdigest(),
            'final_condition':ref,'native_command':{k:event[k] for k in ('run_ref','source','locator','excerpt','design','partition')},
            'same_state_drc':cleanref,'native_drc_writer':cleanactual['native_writer'],
            'same_state_drc_copies':[{'source':p.relative_to(root).as_posix(),'sha256':digest} for p in sorted(checked_copies)],
            'same_state_drc_counts':cleanactual['native_counts'],'permitted_residual_rules':sorted(permitted),
            'permission_source':'Existing runtime task and organizer-clarification permission; no diagnostic permission inferred.',
            'meaning':'Independent current task role/representative identity and same-state task-permitted DRC. Original heterogeneous diagnostic cause remains unproved.'}, paths)
    except (OSError,ValueError,TypeError,KeyError,IndexError,CanonicalDeliveryError,RepairRejected):
        return None


def _signal_location(location, words_for, *, known_ports=None):
    """Resolve a finite identity expression, never evaluate it or infer a role.

    Bare names and the existing exact getter retain their contract. Descriptive
    labels require a catalog from the actual design, and match the COMPLETE
    name with a bounded type/direction label and balanced quotation. A word in
    an object name is never removed. No leaf-name, substring or sole-candidate
    fallback is used; existence and signal roles have separate native proofs.
    """
    from eco_plan_semantics import reference_selection
    text = str(location).strip()
    if re.fullmatch(r'[A-Za-z_][\w$]*', text) and known_ports is None:
        return {'kind': 'literal_port', 'name': text}
    words = words_for(text)
    if words[:1] == ['eco_ref']:
        selected = reference_selection(text, words_for)
    else:
        query = text[1:-1] if text.startswith('[') and text.endswith(']') else text
        selected = reference_selection('eco_ref location {' + query + '}', words_for)
    if selected and selected['kind'] == 'port' and (known_ports is None or selected['name'] in known_ports):
        return {'kind': 'exact_port_query', 'name': selected['name']}
    if known_ports is None:
        return None
    matches = set()
    labels = [('ports?', None), ('signals?', None), ('端口', None), ('信号', None),
              ('top[- ]level\\s+ports?', None), ('顶层端口', None),
              ('input\\s+ports?', 'input'), ('output\\s+ports?', 'output'),
              ('输入端口', 'input'), ('输出端口', 'output')]
    quotes = [('', ''), ('`', '`'), ('"', '"'), ("'", "'"), ('“', '”'), ('‘', '’'), ('{', '}')]
    for name, direction in known_ports.items():
        if not name or any(c in name for c in '\n\r\x00'):
            continue
        atom = '(?:' + '|'.join(re.escape(a+name+b) for a,b in quotes) + ')'
        if re.fullmatch(atom, text):
            matches.add(name)
        for label, required_direction in labels:
            if required_direction is not None and direction != required_direction:
                continue
            # English labels must be separated; Chinese labels may be adjacent.
            sep = r'\s*[:：]\s*|\s+' if label.isascii() else r'\s*[:：]?\s*'
            typed = '(?i:'+label+')'
            if (re.fullmatch(typed+'(?:'+sep+')'+atom, text) or
                    re.fullmatch(atom+'(?:'+sep+')'+typed, text)):
                matches.add(name)
    if len(matches) == 1:
        return {'kind': 'literal_port', 'name': next(iter(matches))}
    return None


def _signal_query_binding(root, rid, port, design, spec, words_for, *, found=None):
    """Read the existing production compiler ledger and real getter frames.

    A failed discovery may prove a unique exact query returned no object. It
    never proves an effective role or that the missing object already existed.
    The adopted query must instead return the actual unique port. No query or
    model/tool execution occurs here, including on unresolved expressions.
    """
    import hashlib, json
    from canonical_delivery import _real_file
    from completion_policy import _reference
    from eco_object_contract import staged_observations
    from eco_plan_semantics import reference_selection
    from plan_provenance import build
    run = root/'runs'/rid
    paths = [run/'deliverables'/(rid+'.dofile'), run/(rid+'.log'),
             run/'eco_object_contract.plan.json', run/'eco_plan_provenance.json',
             run/'eco_plan.source.dofile']
    for path in paths: _real_file(path, root)
    script = paths[0].read_text(); text = paths[1].read_text(errors='replace')
    plan = json.loads(paths[2].read_text()); ledger = json.loads(paths[3].read_text())
    if (ledger != build(plan, script, run, words_for) or
            plan.get('task_spec_sha256') != hashlib.sha256(spec.encode()).hexdigest()):
        raise ValueError('Signal query compiler/input/task binding differs')
    # Bind even failed queries to the actual native source file/version. Error
    # messages after their observation are retained, not treated as success.
    origins = re.findall(r'\[SOURCE TCL FILE\]\s+(\S+)\s*:', text)
    if len(origins) != 1:
        raise ValueError('Signal query native source ambiguous')
    origin = Path(origins[0]); _real_file(origin, root)
    if not origin.is_relative_to(run) or origin.read_bytes() != paths[0].read_bytes():
        raise ValueError('Signal query executed a different script')
    wanted_id = None
    if found is not None:
        _reference(root, found, {rid})
        match = re.search(r'\[AGENT-ECO-OBJECT\]\s+(C[1-9]\d*)\s+(?:empty|unresolved)\b', found['excerpt'])
        if not match or found['source'] != paths[1].relative_to(root).as_posix():
            raise ValueError('Discovery does not bind a native query checkpoint')
        wanted_id = match[1]
    rows = staged_observations(text, plan); selected = []
    unknown = {r.get('id') for r in plan.get('unknown', [])}
    physical = script.splitlines()
    for row in rows:
        if row.get('option') != 'query' or (wanted_id and row.get('id') != wanted_id): continue
        query = row.get('query_expression', '')
        identity = reference_selection('eco_ref location {'+query[1:-1]+'}', words_for) if query.startswith('[') and query.endswith(']') else None
        if identity != {'kind': 'port', 'name': port}: continue
        if row['id'] in unknown or row.get('current_design') != design:
            raise ValueError('Unresolved/different-design signal query')
        result = row['query_result']; count = row.get('actual_count')
        if found is not None:
            if (count == 0 and (row['state'] != 'empty' or result['classes'] or result['names'])):
                raise ValueError('Invalid empty query frame')
            if count not in {0, 1}: raise ValueError('Ambiguous discovery query')
        if count == 1:
            if (row['state'] != 'observed_types_only' or result['classes'] != 'port' or result['names'] != port):
                raise ValueError('Signal query identity/type mismatch')
        elif found is None:
            raise ValueError('Adopted signal query is not a unique port')
        ops = [op for op in ledger['operations'] if row['id'] in op['check_ids'] and op['design'] == design]
        if len(ops) != 1: raise ValueError('Signal query source operation ambiguous')
        op = ops[0]; echoes = []
        for number, line in enumerate(text.splitlines(), 1):
            echo = re.search(r'CMD-0034\]\s+@(\d+):\s*(.*)', line)
            if not echo: continue
            n = int(echo[1])
            if op['compiled_first'] <= n <= op['compiled_last'] and query in echo[2]:
                if not 1 <= n <= len(physical) or physical[n-1].strip() != echo[2].strip():
                    raise ValueError('Signal getter echo/script mismatch')
                echoes.append(number)
        if len(echoes) != 1 or not row['native_log_lines'] or echoes[0] >= min(row['native_log_lines']):
            raise ValueError('Signal getter not uniquely executed before its result')
        selected.append({'run_ref': rid, 'design': design, 'object': port,
                         'object_class': result['classes'] or None, 'actual_count': count,
                         'state': row['state'], 'check_id': row['id'],
                         'source_operation': op['source_command'], 'operation_id': op['operation_id'],
                         'native_source': paths[1].relative_to(root).as_posix(),
                         'getter_log_line': echoes[0], 'observation_lines': row['native_log_lines'],
                         'meaning': 'identity/existence only; no signal-role verdict'})
    if not selected or wanted_id and len(selected) != 1:
        raise ValueError('Signal query identity has no unique native binding')
    return selected, paths + [origin]


def _task_native_roles(spec, port):
    """Only explicit task role assignments, never model requirements or names."""
    roles = set()
    for line in spec.splitlines():
        if not re.search(r'(?<![\w$])'+re.escape(port)+r'(?![\w$])', line):
            continue
        if re.search(r'例如|示例|不作为|不要|not\s+(?:a|as)|example', line, re.I):
            continue
        for role, pattern in [('reset', r'配置为(?:异步)?复位信号|configured?\s+as\s+(?:a\s+)?reset(?:\s+signal)?'),
                              ('clock', r'配置为(?:扫描)?时钟信号|configured?\s+as\s+(?:a\s+)?clock(?:\s+signal)?')]:
            if re.search(pattern, line, re.I):roles.add(role)
    return roles


def _contradicted_role_delivery(issue, conflicts, root, run_ref, spec, files, dofile,
                                words_for, source_netlists, source_libraries):
    """Non-ECO prior-role counterevidence AND actual independent task role.

    All other delivery/EQY/canonical guards remain in the caller. Missing or
    inconsistent current native state cannot be discharged by a prior error.
    """
    from configuration_evidence import _signal_command_trace
    from operation_audit import operation_trace, post_operation_report
    from canonical_delivery import _native_sources, CanonicalDeliveryError
    from eco_structure import source_design, read_design
    from netlist_repair import RepairRejected
    from report_validation import report_rows
    try:
        if not source_netlists or not source_libraries or not conflicts or any(
                p['assessment_scope'].get('assessment_status') != 'contradicted' for p in conflicts):
            return None
        objects = {(p['object'],p['claimed_role']) for p in conflicts}
        if len(objects) != 1:return None
        port, claimed = next(iter(objects)); scopes = [p['assessment_scope'] for p in conflicts]
        trace = operation_trace(files, root, dofile, words_for, allow_verbose=True)
        if not trace:return None
        design = trace['design']; export, _, native_design = _native_sources(root, run_ref, words_for)
        if native_design != design:return None
        original_script = (root/'runs'/issue['found']['run_ref']/'deliverables'/(issue['found']['run_ref']+'.dofile')).read_text()
        library,before = source_design(source_netlists,source_libraries,spec,original_script)
        after = read_design([export['source']],library,design)
        if before['top'] != design:return None
        catalog = {n:d for n,d in before['modules'][design]['ports'].items()
                   if after['modules'][design]['ports'].get(n) == d}
        location = _signal_location(issue['diagnosis']['located_object'], words_for, known_ports=catalog)
        expected = _task_native_roles(spec, port)
        if not location or location != {'kind':'literal_port','name':port} or len(expected) != 1:
            return None
        role = next(iter(expected))
        if role == claimed or any(p['case_output'] != str(root.resolve()) or
                p['object'] != port or p.get('actual_declared_role') != role or
                int(p['run_ref'][1:]) >= int(run_ref[1:]) for p in scopes):
            return None
        commands = _signal_command_trace(root, run_ref, words_for)
        if not trace or not commands or commands['design'] != trace['design'] or any(p['design'] != trace['design'] for p in scopes):
            return None
        declarations = []
        for e in commands['signals']:
            opts = {k:v.strip('"{}') for k,v in zip(e['words'][1::2],e['words'][2::2])}
            if opts.get('-port') == port:declarations.append((e,opts))
        if len(declarations) != 1:return None
        event, opts = declarations[0]
        if event['errors'] or opts.get('-type') != role or opts.get('-off_state') not in {'0','1'}:
            return None
        candidates = []
        for report in files:
            if report.suffix not in {'.rpt','.report','.txt'}:continue
            writer = post_operation_report(report, 'rpt_scan_signal', trace, root)
            if not writer or writer['log_line'] <= int(event['locator'][1:]):continue
            rows = [r for r in report_rows(report, {'Port','SignalType','OffState','OwnerPartition'}) if r['Port']==port]
            if len(rows) != 1:continue
            row = rows[0]
            if row['SignalType'].split('(')[0] != role or row['OffState'] != opts['-off_state']:
                continue
            if row['OwnerPartition'] != event['partition'] and not (event['partition']=='Default_Partition' and not row['OwnerPartition']):
                continue
            candidates.append((writer,report,row))
        if not candidates:return None
        writer,report,row = max(candidates,key=lambda x:x[0]['log_line'])
        originals = sorted(str(p.resolve()) for p in source_netlists)
        if sorted(str(__import__('pathlib').Path(p).resolve()) for p in commands['loaded_netlists']) != originals:
            return None
        if before['top'] != design or any(net['modules'][design]['ports'].get(port) != 'input' for net in [before,after]):
            return None
        evidence = {'run_ref':run_ref,'source':report.relative_to(root).as_posix(),
                    'locator':'L'+str(row['line']),'excerpt':report.read_text().splitlines()[row['line']-1]}
        paths = [report,root/event['source'],export['source'],*source_netlists,*source_libraries]
        for scope in scopes:paths += [root/scope['script'],root/scope['native']]
        return ({'kind':'native_task_signal_role','design':design,'run_ref':run_ref,
            'located_object':issue['diagnosis']['located_object'],'object_binding':{'kind':'literal_port','object':port,'prior_claimed_role':claimed},
            'role':role,'task_requirement':{'port':port,'role':role},'signal_condition':evidence,
            'native_command':{k:event[k] for k in ['run_ref','source','locator','excerpt','design','partition']},
            'native_writer':writer,'prior_diagnostic_scopes':scopes,
            'meaning':'Prior declaration contradicted by actual native records; independently proved current task role.'},paths)
    except (OSError,ValueError,TypeError,KeyError,IndexError,RepairRejected,CanonicalDeliveryError):
        return None


def signal_scope_delivery_condition(issue, conflicts, root, run_ref, spec, files,
                                    dofile, words_for, eco_trace, eco_validation, *,
                                    source_netlists=None, source_libraries=None):
    """Recompute prior scope and prove the separate, task-required final role.

    Only actual task scan-enable roles supported by the existing requirement
    parser are covered. Other/ambiguous roles abstain, as do mixed diagnostics.
    Native stage, consumer/FF coverage and complete EQY are independently checked
    by the caller's unchanged production delivery entry, never by this reason.
    """
    import hashlib
    from configuration_evidence import _signal_command_trace
    from operation_audit import operation_trace, post_operation_report
    from dft_signal_requirements import explicit_signal_role_requirements, _covers
    from report_validation import report_rows
    try:
        if (not prior_signal_scope(conflicts) or
                signal_declaration_claim_problems(issue, root, words_for) != conflicts):
            return None
        if eco_trace is None:
            return _contradicted_role_delivery(issue, conflicts, root, run_ref, spec, files,
                dofile, words_for, source_netlists, source_libraries)
        if not eco_validation or eco_validation.get('status') != 'pass':
            return None
        data = eco_trace.data
        if (data['run_ref'] != run_ref or data['output_root'] != str(root.resolve()) or
                eco_trace.context.rid != run_ref):
            return None
        design = data['design']; scopes = [p['assessment_scope'] for p in conflicts]
        objects = {(p['object'], p['claimed_role']) for p in conflicts}
        if len(objects) != 1:
            return None
        port, prior_role = next(iter(objects))
        from eco_structure import read_design
        from partial_insertion_validation import _libraries
        library, problems = _libraries(eco_trace.context.libs)
        if problems:return None
        fixed = read_design([Path(data['fixed_export']['path'])], library, design)
        post = read_design([Path(data['post_export']['path'])], library, design)
        # Catalog membership proves a physical identity at this adopted state,
        # not its task role or the historical diagnostic premise.
        # The diagnostic may precede physical creation by scan insertion.
        # Identity uses the bound adopted export; pre-scan and post-scan
        # existence are recorded separately and never inferred backwards.
        catalog = dict(post['modules'][design]['ports'])
        fixed_role = fixed['modules'][design]['ports'].get(port)
        created_by_scan = fixed_role is None
        if fixed_role is not None and catalog.get(port) != fixed_role:
            return None
        location = _signal_location(issue['diagnosis']['located_object'], words_for, known_ports=catalog)
        if (not location or location['name'] != port or
                any(p['case_output'] != str(root.resolve()) or p['design'] != design or
                    not re.fullmatch(r'R[1-9]\d*', p['run_ref']) or
                    int(p['run_ref'][1:]) >= int(run_ref[1:]) for p in scopes)):
            return None
        requirements = [r for r in explicit_signal_role_requirements(spec) if r.port == port]
        if len(requirements) != 1:
            return None
        requirement = requirements[0]
        # This existing parser proves final task scan-enable requirements.
        # The old diagnostic's claimed role is a different, unproved premise.
        role = 'scan_enable'
        location_evidence = {'raw_location': issue['diagnosis']['located_object'],
                             'object': port, 'kind': location['kind'],
                             'prior_claimed_role': prior_role,
                             'actual_direction': catalog[port], 'design': design, 'run_ref': run_ref,
                             'identity_sources': [data['fixed_export']['path'], data['post_export']['path']],
                             'meaning': 'Exact physical identity only; final role and original diagnostic are independently checked.'}
        location_paths = []
        query_discovery = bool(re.search(r'\[AGENT-ECO-OBJECT\]\s+C[1-9]\d*\s+(?:empty|unresolved)\b',
                                        issue['found'].get('excerpt','')))
        if location['kind'] == 'exact_port_query' or query_discovery:
            prior_query, prior_paths = _signal_query_binding(root, issue['found']['run_ref'],
                port, design, spec, words_for, found=issue['found'])
            location_evidence['prior_queries'] = prior_query
            location_paths += prior_paths
            if not created_by_scan:
                final_query, final_paths = _signal_query_binding(root, run_ref,
                    port, design, spec, words_for)
                location_evidence['final_queries'] = final_query
                location_paths += final_paths
            else:
                # No synthetic final getter: the actual insertion/export and
                # every FF enable connection must provide the final proof.
                location_evidence['final_query'] = 'not performed; scan creation proof required'
        trace = operation_trace(files, root, dofile, words_for, allow_verbose=True)
        commands = _signal_command_trace(root, run_ref, words_for)
        report = Path(data['reports']['rpt_scan_signal']['path'])
        writer = post_operation_report(report, 'rpt_scan_signal', trace, root)
        if not writer or not commands or commands['design'] != design or trace['design'] != design:
            return None
        events = []
        for event in commands['signals']:
            words = event['words']; opts = dict(zip(words[1::2], (w.strip('"{}') for w in words[2::2])))
            if opts.get('-port') == port:events.append((event, opts))
        if (len(events) != 1 or events[0][0]['errors'] or events[0][1].get('-type') != role or
                not _covers(events[0][1].get('-usage', ''), requirement.roles) or
                writer['log_line'] <= int(events[0][0]['locator'][1:])):
            return None
        rows = [r for r in report_rows(report, {'Port','SignalType','Usage','OffState','OwnerPartition'})
                if r['Port'] == port]
        if len(rows) != 1:
            return None
        row = rows[0]; event, opts = events[0]
        if (row['SignalType'].split('(')[0] != role or not _covers(row['Usage'], requirement.roles) or
                row['Usage'] != opts.get('-usage') or row['OffState'] != opts.get('-off_state') or
                requirement.off_state is not None and row['OffState'] != requirement.off_state or
                row['OwnerPartition'] != event['partition']):
            return None
        if catalog.get(port) != 'input' or fixed_role not in {None, 'input'}:
            return None
        if created_by_scan:
            scan = data.get('scan', {})
            if not (scan.get('design') == design and
                    int(events[0][0]['locator'][1:]) < scan['log_line'] and
                    data['fixed_export']['end_log_line'] < scan['log_line'] <
                    scan['end_log_line'] < data['post_export']['log_line'] < writer['log_line']):
                return None
            members = eco_validation.get('coverage', {}).get('object_mapping', {})
            if not members or len(members) != scan.get('replacement_count'):
                return None
            enables = {name:m.get('scan_enable_binding', {}) for name,m in members.items()}
            if any(b.get('port') != port or b.get('source') != str(report) or
                   not b.get('actual_driver') or b.get('actual_driver') != b.get('port_driver') or
                   str(b.get('native_off_state')) != row['OffState'] for b in enables.values()):
                return None
            location_evidence['creation_binding'] = {
                'stage':'scan insertion after fixed export', 'run_ref':run_ref, 'design':design,
                'fixed_exists':False, 'post_direction':catalog[port],
                'scan_event':scan, 'post_export':data['post_export'],
                'member_enable_bindings':enables,
                'meaning':'Final physical input and complete actual scan-enable connections; not prior diagnostic proof'}
        else:
            location_evidence['creation_binding'] = {'fixed_exists':True, 'post_direction':catalog[port]}

        evidence = {'run_ref': run_ref, 'source': report.relative_to(root).as_posix(),
                    'locator': 'L'+str(row['line']), 'excerpt': report.read_text().splitlines()[row['line']-1]}
        paths = [report, root/event['source'], Path(data['fixed_export']['path']), Path(data['post_export']['path'])] + location_paths
        for scope in scopes:paths += [root/scope['script'], root/scope['native']]
        return ({'kind': 'native_task_signal_role', 'design': design, 'run_ref': run_ref,
                 'located_object': issue['diagnosis']['located_object'], 'object_binding': location_evidence,
                 'role': role, 'task_requirement': {
                     'port': port, 'roles': sorted(requirement.roles), 'off_state': requirement.off_state},
                 'signal_condition': evidence, 'native_command': {k:event[k] for k in
                     ['run_ref','source','locator','excerpt','design','partition']},
                 'native_writer': writer, 'prior_diagnostic_scopes': scopes,
                 'meaning': 'Final task role independently established; prior diagnosis remains unresolved.'}, paths)
    except (OSError, ValueError, TypeError, KeyError, IndexError):
        return None


def prior_exclusion_scope(problems):
    return bool(problems) and all(isinstance(p.get('assessment_scope'),dict) and
        p['assessment_scope'].get('kind')=='prior_scan_exclusion_premise' and
        p['assessment_scope'].get('producer')=='prior_exclusion_claim_assessment' and
        p['assessment_scope'].get('assessment_status') in {'incomplete','contradicted'}
        for p in problems)


def prior_exclusion_delivery_condition(issue, conflicts, root, run_ref, spec, files, dofile, words_for):
    """Separate native final task exclusion from unproved historical causality.

    The caller still reruns every task/canonical/input/EQY hard check and issues
    the opaque proof. This helper proves only this exact final object/operation.
    """
    from configuration_evidence import _signal_command_trace
    from operation_audit import operation_trace,post_operation_report
    from scan_exclusion_evidence import _selectors,_selected
    from exclusion_requirements import debug_exclusion_requested,subtree_exclusion_requirements,exclusion_report_problems
    from completion_policy import _reference
    from canonical_delivery import CanonicalDeliveryError,_real_file,_native_sources
    from report_validation import report_rows
    try:
        if not prior_exclusion_scope(conflicts) or prior_exclusion_claim_assessment(issue,root,words_for)['problems']!=conflicts:return None
        object=issue['diagnosis']['located_object'];scopes=[p['assessment_scope'] for p in conflicts]
        if any(s['case_output']!=str(root.resolve()) or s['object']!=object or int(s['run_ref'][1:])>=int(run_ref[1:]) for s in scopes):return None
        if not (debug_exclusion_requested(spec) or any(object.startswith(r['prefix']+'/') for r in subtree_exclusion_requirements(spec))):return None
        trace=operation_trace(files,root,dofile,words_for,allow_verbose=True);native=_signal_command_trace(root,run_ref,words_for)
        if not trace or not native or any(s['design']!=trace['design'] or s['loaded_inputs']!=native['loaded_input_netlists'] for s in scopes):return None
        if trace['design']!=native['design'] or not native['loaded_input_netlists']:return None
        export,_,design=_native_sources(root,run_ref,words_for)
        if design!=trace['design'] or exclusion_report_problems(files,spec,dofile,words_for):return None
        selectors=_selectors(dofile,words_for)
        if sum(_selected(object,s) for s in selectors)!=1:return None
        # Authentication and order of the actual final operation are explicit.
        events=[];lines=(root/'runs'/run_ref/(run_ref+'.log')).read_text().splitlines();script=dofile.splitlines()
        for n,line in enumerate(lines,1):
            m=re.search(r'CMD-0034\]\s+@(\d+):\s*(.*)',line)
            if not m:continue
            w=words_for(m[2].strip())
            if w[:2]==['set_scan_element','false']:
                if not 0<int(m[1])<=len(script) or script[int(m[1])-1].strip()!=m[2].strip():return None
                result=[]
                for later in lines[n:]:
                    echo=re.search(r'CMD-0034\]\s+@\d+:\s*(.*)',later)
                    if echo:
                        if re.fullmatch(r'\}+(?:\s*;)?',echo[1].strip()):continue
                        break
                    result.append(later)
                if any('[ERROR]' in l or '[FATAL]' in l for l in result) or '1' not in [l.strip() for l in result]:return None
                events.append({'run_ref':run_ref,'source':f'runs/{run_ref}/{run_ref}.log','locator':'L'+str(n),'excerpt':line})
        if len(events)!=1:return None
        reports=[]
        for path in files:
            if path.name!='rpt_scan_element.audit.rpt':continue
            writer=post_operation_report(path,'rpt_scan_element',trace,root)
            if not writer or writer['log_line']<=int(events[0]['locator'][1:]):continue
            rows=[r for r in report_rows(path,{'InstanceName','ObjState','Type'},row_filter=lambda l:object in l) if r['InstanceName']==object]
            if len(rows)!=1 or rows[0]['Type'] not in {'dff','sff'} or rows[0]['ObjState']!='user_defined_nonscannable':continue
            row=rows[0];reports.append((path,writer,{'run_ref':run_ref,'source':path.relative_to(root).as_posix(),'locator':'L'+str(row['line']),'excerpt':path.read_text().splitlines()[row['line']-1]}))
        if len(reports)!=1:return None
        path,writer,evidence=reports[0];paths=[path,root/events[0]['source'],export['source']]
        for scope in scopes:paths.extend([root/scope['script'],root/scope['native']])
        return ({'kind':'native_task_exclusion_condition','design':design,'run_ref':run_ref,'located_object':object,
            'prior_checks':conflicts,'object_binding':{'object':object,'native_type':rows[0]['Type'],'final_state':'user_defined_nonscannable'},
            'final_condition':evidence,'native_command':events[0],'native_writer':writer,
            'meaning':'Actual final task exclusion only; original diagnostic antecedent remains unresolved.'},paths)
    except (OSError,ValueError,KeyError,IndexError,TypeError,CanonicalDeliveryError):return None

def task_scope_diagnostic_basis(issue, conflicts, root, run_ref, changes, words_for, input_dir):
    """Reproduce a finite prior-evidence gap; never prove its diagnosis.

    This selects a delivery proof obligation, not an audit success. Complete
    native task scope is required independently by the caller.
    """
    import json, hashlib
    from completion_policy import _reference
    from command_error_evidence import command_parameter_claim_assessment
    from operation_audit import fix_action_reference_problems
    try:
        if not conflicts or issue['attempts'][-1]['verify']['resolved'] is not False:return None
        # Preserve the existing native-fact producer and its independently
        # bound delivery scope; this fallback only serves uncovered scopes.
        if library_relation_scope(conflicts):return None
        prior=issue['found']['run_ref']
        if not re.fullmatch(r'R[1-9]\d*',prior) or not int(prior[1:])<int(run_ref[1:]):return None
        _reference(root,issue['found'],{prior})
        location=issue['diagnosis']['located_object'];basis=None;objects=[]
        if aggregate_drc_scope(conflicts):
            assessment=aggregate_drc_scope_assessment(issue,root,words_for,input_dir)
            if assessment['problems']!=conflicts:return None
            rows=conflicts[0]['assessment_scope']['native_rows']
            if not any(location in {r['object'],r['object']+'/'+r['pin']} for r in rows):return None
            objects=[r['object'] for r in rows];basis='native_prior_aggregate'
        elif prior_exclusion_scope(conflicts):
            if prior_exclusion_claim_problems(issue,root,words_for)!=conflicts:return None
            # The existing prior producer must bind the native endpoint.
            objects=[p['assessment_scope']['object'] for p in conflicts]
            basis='native_prior_exclusion'
        else:
            from operation_audit import connection_action_assessment
            relation=library_relation_claim_assessment(issue,root,words_for,input_dir)
            action=connection_action_assessment(issue,changes,root,run_ref,words_for,input_dir)
            produced=action.get('problems',[])+relation.get('problems',[])
            if (relation.get('applicable') and produced==conflicts and
                    relation.get('status') in {'incomplete','fail'}):
                trace,_,_,inventory=_diagnostic_loaded_state(issue,root,input_dir,words_for)
                native=re.search(r"Clock input '([^']+)' of 'DFF' '([^']+)'",issue['found']['excerpt'])
                if (inventory['state_status']=='original_input_bound' and native and
                        location in {native[2],native[2]+'/'+native[1]}):
                    return {'kind':'native_prior_relation_and_action','status':'diagnostic_incomplete',
                        'objects':[native[2]],'prior_run':prior,'located_object':location,
                        'conflicts':conflicts,'native_evidence':[dict(issue['found'])],
                        'source_state':inventory,'relation_assessment':relation,
                        'action_assessment':action}
            gate=gate_diagnosis_requirement(issue,root,words_for,input_dir)
            if gate.get('required') and gate.get('source_state',{}).get('state_status')=='original_input_bound':
                assessment=library_relation_claim_assessment(issue,root,words_for,input_dir,requirement=gate)
                if assessment.get('problems')!=conflicts:return None
                native=re.search(r"Clock input '([^']+)' of 'DFF' '([^']+)'",issue['found']['excerpt'])
                if not native:return None
                # Bind the real primary endpoint, retaining the whole unresolved
                # aggregate suffix. No inferred membership or causal proof.
                primary=native[2]
                if not any(location==v or location.startswith(v+' ') for v in [primary,primary+'/'+native[1]]):return None
                objects=[primary];basis='native_prior_gate'
            else:
                assessment=command_parameter_claim_assessment(issue,root,words_for)
                if (assessment.get('coverage',{}).get('capability')=='native_failed_option_coverage' and
                        assessment.get('problems')==conflicts and assessment.get('discovery_binding')):
                    b=assessment['discovery_binding'];words=words_for(b['command'])
                    opts=dict(zip(words[1::2],words[2::2]))
                    objects=[opts['-port'].strip('{}"')];basis='native_prior_parameter_omission'
                elif fix_action_reference_problems(issue,changes,root,words_for)==conflicts:
                    missing={n for p in conflicts for n in p.get('missing_commands',[])}
                    if (not missing or any(p.get('missing_options') or p.get('missing_literal_operations') for p in conflicts)):
                        return None
                    receipts=[]
                    for name in sorted(missing):
                        for rid in (prior,run_ref):
                            script=(root/'runs'/rid/'deliverables'/(rid+'.dofile')).read_text().splitlines()
                            hits=[]
                            for number,line in enumerate((root/'runs'/rid/(rid+'.log')).read_text().splitlines(),1):
                                echo=re.search(r'CMD-0034\]\s+@(\d+):\s*(.*)',line)
                                if not echo:continue
                                words=words_for(echo[2]);idx=int(echo[1])-1
                                if words and words[0]==name and 0<=idx<len(script) and script[idx].strip()==echo[2].strip():
                                    hits.append({'run_ref':rid,'source':f'runs/{rid}/{rid}.log','locator':f'L{number}','excerpt':line})
                            if len(hits)!=1:return None
                            receipts+=hits
                    basis='retained_native_command_not_added';objects=[]
                    return {'kind':basis,'status':'contradicted_action','objects':objects,'native_evidence':receipts,
                        'prior_run':prior,'located_object':location,'conflicts':conflicts}
        if not basis:return None
        return {'kind':basis,'status':'diagnostic_incomplete','objects':objects,
            'prior_run':prior,'located_object':location,'conflicts':conflicts,
            'native_evidence':[dict(issue['found'])]}
    except (OSError,ValueError,KeyError,TypeError,IndexError):return None


def task_native_delivery_scope(root,input_dir,run_ref,spec,netlists,libraries,files,dofile,words_for,*,deadline=None):
    """Independent final roles, full FF identities, exclusion and chain set.

    Only unmodified, single-design native full insertion is covered. No model
    names, audit prose or saved success flags determine the required object set.
    The caller still rechecks all task/configuration/canonical/EQY gates.
    """
    import hashlib,json,time
    from configuration_evidence import _signal_command_trace
    from operation_audit import operation_trace,post_operation_report
    from canonical_delivery import _native_sources,_real_file,CanonicalDeliveryError
    from partial_insertion_validation import _modules
    from report_validation import report_rows
    from exclusion_requirements import debug_exclusion_requested,subtree_exclusion_requirements
    from eco_structure import MUTATIONS,DYNAMIC
    from case_deadline import CaseDeadlineExceeded
    def check():
        if deadline is not None and time.monotonic()>=deadline:
            raise CaseDeadlineExceeded('Native task proof deadline reached; failure reserve retained')
    def digest(names):return hashlib.sha256('\n'.join(sorted(names)).encode()).hexdigest()
    check();trace=operation_trace(files,root,dofile,words_for,allow_verbose=True)
    current=_signal_command_trace(root,run_ref,words_for)
    if not trace or not current or trace['design']!=current['design']:raise ValueError('Final native design/operation absent')
    design=trace['design'];export,_,export_design=_native_sources(root,run_ref,words_for)
    if export_design!=design:raise ValueError('Export design mismatch')
    mutation=r'\b(?:'+'|'.join(map(re.escape,sorted(MUTATIONS|DYNAMIC|{'eco_link'})))+r')\b'
    if re.search(mutation,dofile):raise ValueError('Native full-scope proof does not cover ECO/dynamic design mutations')
    native=(root/'runs'/run_ref/(run_ref+'.log')).read_text()
    paths=list(netlists)+list(libraries)+[export['source'],root/'runs'/run_ref/(run_ref+'.log'),root/'runs'/run_ref/'deliverables'/(run_ref+'.dofile')]
    for family,pattern in [(netlists,r"Read Verilog file '([^']+)' successfully"),(libraries,r"Liberty file '([^']+)' is read successfully")]:
        observed=re.findall(pattern,native);resolved=[]
        for name in observed:
            p=Path(name);p=input_dir/p.relative_to('/input') if p.parts[:2]==('/','input') else p
            resolved.append(str(p.resolve(strict=True)))
        if len(resolved)!=len(family) or set(resolved)!={str(p.resolve(strict=True)) for p in family}:
            raise ValueError('Loaded input inventory differs from actual task inputs')
    check();library,unknown=_gate_libraries(libraries)
    semantic=hashlib.sha256(json.dumps(library,sort_keys=True).encode()).hexdigest()
    modules,bad=_gate_read('task_original_modules',netlists,semantic,lambda:_modules(netlists,library))
    if unknown or bad or design not in modules:raise ValueError('Original hierarchy/Liberty is incomplete')
    original=set()
    def walk(kind,prefix,parents):
        check()
        if kind in parents or modules[kind]['unknown']:raise ValueError('Incomplete/recursive original hierarchy')
        seen=set()
        for c in modules[kind]['cells']:
            full=prefix+c['instance'];typ=c['type']
            if c['instance'] in seen:raise ValueError('Ambiguous original instance')
            seen.add(c['instance'])
            if typ in modules:walk(typ,full+'/',parents|{kind})
            elif typ not in library:raise ValueError('Unknown source cell')
            elif library[typ]['ffs']:
                if len(library[typ]['ffs'])!=1 or full in original:raise ValueError('Unmapped sequential state')
                original.add(full)
    walk(design,'',set())
    if not original:raise ValueError('No complete original FF set')
    # All effective native roles are bound separately, including multi-role
    # ports and one enable shared by several partitions.
    expected={}
    for e in current['signals']:
        if e['errors']:raise ValueError('Failed final signal declaration')
        opts=dict(zip(e['words'][1::2],(v.strip('{}"') for v in e['words'][2::2])))
        role=opts.get('-type');port=opts.get('-port')
        if role not in {'clock','reset','scan_enable','constant'}:raise ValueError('Unsupported task role declaration')
        if not port:raise ValueError('Unbound signal port')
        # Literal Tcl list supplied to -port is a collection, not one name.
        for member in port.split():
            key=(member,role,opts.get('-view','spec'),e['partition']);expected[key]=(e,opts)
    if not expected:raise ValueError('Missing native task roles')
    signal_candidates=[]
    for p in files:
        if p.suffix not in {'.rpt','.txt','.report'}:continue
        writer=post_operation_report(p,'rpt_scan_signal',trace,root)
        if writer:signal_candidates.append((writer,p))
    if not signal_candidates:raise ValueError('Missing final signal report')
    writer,signal_path=max(signal_candidates,key=lambda x:x[0]['log_line'])
    if any(int(e['locator'][1:])>=writer['log_line'] for e in current['signals']):raise ValueError('Signal report predates effective role')
    rows=list(report_rows(signal_path,{'Port','SignalType','OffState','Usage','OwnerPartition','ConstantValue'}));receipts=[]
    for (port,role,view,partition),(event,opts) in expected.items():
        actual=[r for r in rows if r['Port']==port and r['SignalType'].split('(')[0]==role and
                (role!='scan_enable' or r['SignalType']==role+'('+view+')') and
                partition in [x.strip() for x in (r['OwnerPartition'] or 'Default_Partition').split(',')]]
        if len(actual)!=1:raise ValueError('Native role/object/partition is not unique: '+str((port,role,partition)))
        r=actual[0]
        if role=='constant':
            if r['ConstantValue']!=opts.get('-constant_value','X'):raise ValueError('Constant role value mismatch')
        elif r['OffState']!=opts.get('-off_state','0'):raise ValueError('Role polarity mismatch')
        if role=='scan_enable' and r['Usage']!=opts.get('-usage','all'):raise ValueError('Role usage mismatch')
        if port in modules[design]['ports'] and modules[design]['ports'][port]!='input':raise ValueError('Task role source direction mismatch')
        if port not in modules[design]['ports'] and (role!='scan_enable' or r.get('PortProperty')!='tool_created'):
            raise ValueError('Role not in original input or native-created enable')
        receipts.append({'port':port,'role':role,'partition':partition,'view':view,'command':event,'row':r})
    paths.append(signal_path);check()
    excluded=set();exclusion_basis=[]
    if subtree_exclusion_requirements(spec):raise ValueError('Subtree exceptions require their existing specialized scope proof')
    if debug_exclusion_requested(spec):
        from source_hierarchy import source_hierarchy_hints
        from debug_exclusion_preflight import debug_exclusion_source_facts
        from library_cell_catalog import LibraryCellCatalog
        from scan_agent import liberty_summary
        # Reuse the normal source-analysis catalog, including native Liberty
        # clock attributes omitted by the separate structural parser.
        catalog=LibraryCellCatalog();catalog.capture_clock_pins=True
        for lib in libraries:liberty_summary(lib,cell_names=catalog)
        hierarchy=source_hierarchy_hints(netlists,catalog)
        facts=debug_exclusion_source_facts(netlists,spec,hierarchy,catalog)
        scopes=[s for s in facts['tap_scopes'] if s['root']==design]
        if not facts.get('applicable') or not scopes:raise ValueError('Task TAP role not established from actual source')
        excluded={n for n in original if any(n.startswith(s['prefix']+'/') for s in scopes)}
        if not excluded:raise ValueError('Task exclusion scope unexpectedly empty')
        exclusion_basis=scopes
    element=[];chains=[]
    for p in files:
        if p.suffix not in {'.rpt','.txt','.report'}:continue
        w=post_operation_report(p,'rpt_scan_element',trace,root)
        if w:element.append((w,p))
        w=post_operation_report(p,'rpt_scan_chain_cell',trace,root)
        if w:chains.append((w,p))
    if element:
        w,p=max(element,key=lambda x:x[0]['log_line']);states={};seen=[]
        for row in report_rows(p,{'InstanceName','Type','Length','ObjState'}):
            if row['Type'] not in {'dff','sff'}:continue
            name=row['InstanceName'];seen.append(name);states[name]=row['ObjState']
            if row['Length']!='1':raise ValueError('Unknown sequential bit length')
        if len(seen)!=len(states) or set(states)!=original:raise ValueError('Final FF set differs from original protected universe')
        if any(st not in {'scannable','user_defined_nonscannable'} for st in states.values()):raise ValueError('Unknown final element state')
        if {n for n,st in states.items() if st=='user_defined_nonscannable'}!=excluded:raise ValueError('Actual exclusion differs from required exclusion/kept sets')
        paths.append(p)
    elif excluded:raise ValueError('Missing actual exclusion-state report')
    members=[];chain_source=None;chain_writer=None
    if chains:
        chain_writer,chain_source=max(chains,key=lambda x:x[0]['log_line'])
        members=[r['InstanceName'] for r in report_rows(chain_source,{'InstanceName','CellNo','RefName'}) if r['InstanceName']]
    else:
        defs=[e for e in trace['outputs'] if e['kind']=='dump_def' and e.get('completion') and
              e['design']==design and e['run_ref']==run_ref and
              e['log_line']>trace['operation']['replacement']['log_line']]
        if not defs:raise ValueError('Missing native chain-member report or completed SCANDEF')
        chain_writer=max(defs,key=lambda e:e['log_line']);chain_source=chain_writer['path'];_real_file(chain_source,root)
        count=None;starts=ends=0;inside=False;done=False;design_headers=0;end_design=False
        for n,line in enumerate(chain_source.open(),1):
            if n%4096==0:check()
            text=line.strip()
            if text.startswith('DESIGN '):
                design_headers+=1
                if text!=f'DESIGN {design} ;':raise ValueError('SCANDEF design mismatch')
            if text=='END DESIGN':end_design=True
            if done:
                if text and text!='END DESIGN':raise ValueError('Unexpected data after SCANDEF chains')
                continue
            match=re.fullmatch(r'SCANCHAINS (\d+) ;',text)
            if match:
                if count is not None:raise ValueError('Duplicate SCANDEF chain section')
                count=int(match[1]);inside=True;continue
            if not inside:continue
            if text=='END SCANCHAINS':done=True;continue
            if text.startswith('- '):starts+=1
            elif text==';':ends+=1
            elif '( BITS' in text:
                m=re.fullmatch(r'(\S+)\s+\( IN \S+ \)\s+\( OUT \S+ \)\s+\( BITS 1 \)',text)
                if not m:raise ValueError('Unsupported SCANDEF member')
                members.append(re.sub(r'\\(.)',r'\1',m[1]))
            elif text and not text.startswith(('+ PARTITION ','+ START ','+ STOP ','+ FLOATING','+ ORDERED')):
                raise ValueError('Unparsed SCANDEF member/section')
        if not done or not end_design or design_headers!=1 or count!=starts or starts!=ends:raise ValueError('Truncated SCANDEF chain set')
    if len(members)!=len(set(members)) or set(members)!=original-excluded:
        raise ValueError('Chain membership omits protected FFs or includes excluded/extra objects')
    paths.append(chain_source)
    last_setting=max([0]+[i for i,l in enumerate(native.splitlines(),1) if
        (m:=re.search(r'CMD-0034\]\s+@\d+:\s*(.*)',l)) and
        (w:=words_for(m[1])) and w[0].startswith('set_scan_')])
    if last_setting>=min(writer['log_line'],chain_writer['log_line']):
        raise ValueError('Role or chain evidence precedes a relevant final setting')
    check()
    return ({'kind':'complete_native_task_scope','design':design,'run_ref':run_ref,
        'input_fingerprints':{str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in [*netlists,*libraries]},
        'task_sha256':hashlib.sha256(spec.encode()).hexdigest(),'final_export_sha256':hashlib.sha256(export['source'].read_bytes()).hexdigest(),
        'roles':receipts,'signal_writer':writer,'original_FF_count':len(original),'original_FF_sha256':digest(original),
        'excluded_count':len(excluded),'excluded_sha256':digest(excluded),'exclusion_basis':exclusion_basis,
        'kept_count':len(original-excluded),'kept_sha256':digest(original-excluded),'chain_counted_members':len(members),
        'chain_source':str(chain_source.relative_to(root)),
        'chain_source_sha256':hashlib.sha256(chain_source.read_bytes()).hexdigest(),
        'chain_writer':{k:str(v) if isinstance(v,Path) else v for k,v in chain_writer.items()},
        'meaning':'Current task scope only; no historical action or diagnostic causality is inferred.'},paths,original)
