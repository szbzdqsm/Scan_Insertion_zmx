"""Bind command-error repairs to actual command targets and native state rows."""
from pathlib import Path, PurePosixPath
from eco_object_selection import is_context_query
import re
import json
import hashlib

from dofile_recipe import tcl_chunks
from report_validation import report_rows, _full_insertion_designs
from source_hierarchy import _records
from partial_insertion_validation import _libraries, _compatible
from drc_validation import rule_codes


def _level_legality_premises(text):
    """Extract an explicit tool-enum premise, not task-level adequacy.

    Bind the predicate to the actual parameter/value in either subject or
    modifier position. Rule-ID errors and a task requiring a different *legal*
    value are separate predicates. This is limited to this command's enum
    contract; unrelated explanatory prose is not a new proof obligation.
    """
    v = r'(?<![\w])(?P<value>[A-Za-z_]\w*)(?![\w])'
    parameter = r'(?:(?:rule|DRC|handling|severity|processing)\s+){0,3}(?:level|value)'
    invalid = r'(?:invalid|unsupported|not\s+(?:a\s+)?(?:legal|valid|supported))'
    patterns = [
        v + r'\s*(?:不是|并非|不属于)\s*(?:合法|有效)(?:的)?(?:规则|处理|参数|\s)*(?:级别|取值|值)',
        v + r'\s+(?:is|was)\s+(?:an?\s+)?' + invalid + r'\s+(?:an?\s+)?' + parameter + r'\b',
        r'\b' + invalid + r'\s+' + parameter + r'\s*[:=]?\s*[`\'\"]?' + v,
        r'\b' + invalid + r'\s+' + v + r'\s+' + parameter + r'\b',
        r'\b' + parameter + r'\s*[`\'\"]?' + v + r'[`\'\"]?\s+(?:is|was)\s+' + invalid + r'\b',
        r'\b(?:tool|command)\s+(?:does\s+not|doesn\'t)\s+support\s+[`\'\"]?' + v,
    ]
    candidates = []
    for form, pattern in enumerate(patterns):
        for match in re.finditer(pattern, text, re.I):
            candidates.append((form, match.span(), match.span('value'),
                               {'clause': match[0], 'value': match['value']}))
    matches = {}
    for form, clause, value, fact in candidates:
        # A subject-form assertion already owns its adjectival complement.
        # Do not reinterpret words inside that complement as another value,
        # including a following conjunction after "... invalid handling level".
        if form in {2, 3} and any(other_form not in {2, 3} and
                outer[0] <= clause[0] < outer[1]
                for other_form, outer, _, _ in candidates):
            continue
        matches.setdefault(value, fact)
    return [matches[span] for span in sorted(matches)]


def _parameter_order_premises(diagnosis, *, command_words=None):
    """Finite native-parameter position claims, separate from command order.

    The relative endpoints are formal roles (or this command's literal values),
    not arbitrary nearby words. Important but unbound parameter-position claims
    remain unknown. Neutral summary descriptions add no proof obligation.
    """
    operator = r'(?:(?:argument|parameter)s?\s+(?:order(?:ing)?|positions?)|order(?:ing)?\s+of\s+(?:the\s+)?(?:arguments|parameters)|参数(?:排列|顺序|位置))'
    negative = r'\b(?:invalid|incorrect(?:ly)?|illegal(?:ly)?|wrong(?:ly)?|reversed|improper(?:ly)?|erroneous(?:ly)?)\b|\bnot\s+(?:correct|legal|valid|proper)(?:ly)?\b|错误|颠倒|不(?:合法|正确)'
    positive = r'\b(?:correct|legal|valid|proper)(?:ly)?\b|合法|正确'
    relation = r'\b(after|before|follows?|precedes?)\b|(?:放|置|位)?于[^。；;\n]{0,55}?(之后|之前|后面|前面|后|前)|(?:放|置|位)?在[^。；;\n]{0,55}?(之后|之前|后面|前面|后|前)'
    roles = {
        'level': r'\blevel\b|\bseverity\b|级别|处理等级',
        'drc_rule_id': r'\bdrc_rule_id\b|\b(?:DRC\s+)?(?:rule\s+)?IDs?\b|\brule\s+list\b|规则(?:\s*ID(?:列表)?|编号(?:列表)?|列表)',
    }
    # Values are aliases only inside this already identified command. They are
    # never interpreted as Tcl or as proof of the operand's validity.
    if command_words and len(command_words) >= 3:
        for name, value in [('drc_rule_id',command_words[1]),('level',command_words[2])]:
            value = value.strip('{}\"')
            if value and not re.search(r'[$\[\];\n]', value):
                roles[name] += r'|(?<![\w])'+re.escape(value)+r'(?![\w])'
    def predicate(text):
        bad = list(re.finditer(negative,text,re.I))
        good = [m for m in re.finditer(positive,text,re.I)
                if not any(a.start() <= m.start() and m.end() <= a.end() for a in bad)]
        return 'unknown' if bad and good else 'defect' if bad else 'valid' if good else 'unknown'
    def mentions(text):
        return [(m.start(),m.end(),role) for role,pattern in roles.items()
                for m in re.finditer(pattern,text,re.I)]
    claims = []
    for field in ('root_cause','summary'):
        text = str(diagnosis.get(field,''))
        # Keep the historical abstract contract. A root explicitly adopts this
        # cause; a summary requires an explicit local legality assertion.
        for abstract in re.finditer(operator,text,re.I):
            before,after = text[:abstract.start()],text[abstract.end():]
            bad_near = (re.search('(?:'+negative+r')\s*$',before,re.I) or
                        re.match(r'\s*(?:(?:is|was|are|were)\s+)?(?:'+negative+')',after,re.I))
            good_near = (re.search('(?:'+positive+r')\s*$',before,re.I) or
                         re.match(r'\s+(?:(?:is|was|are|were)\s+)?(?:'+positive+')',after,re.I))
            # Explicit qualifiers belong to THIS operator, not another
            # parameter's validity elsewhere in the same compound field.
            pred = 'defect' if bad_near else 'valid' if good_near else predicate(text)
            if field == 'root_cause' or pred != 'unknown':
                claims.append({'kind':'argument_position','field':field,
                               'clause':text,'predicate':pred,
                               'binding':'formal_parameter_order'})
        for clause in re.split(r'[;；。\n]|,\s*(?:and|but)\s+|\s+but\s+',text,flags=re.I):
            rels = list(re.finditer(relation,clause,re.I))
            pred = predicate(clause)
            if not rels:
                # A parameter-position topic with an adopted legality claim
                # still needs a result when its relation cannot be parsed.
                positional = re.search(r'\b(?:positions?|positioned|placement|placed|order(?:ing)?|first|second)\b|排列|顺序|位置|前置|后置|放置',clause,re.I)
                if (positional and mentions(clause) and not re.search(operator,clause,re.I) and
                        (field=='root_cause' or pred!='unknown' or re.search(r'\b(?:unproved|restriction|constraint)\b|限制|约束',clause,re.I))):
                    claims.append({'kind':'argument_position','field':field,'clause':clause.strip(),
                                   'predicate':'unknown','binding':'unresolved_parameter_relation'})
                continue
            if field == 'summary' and pred == 'unknown':continue
            for rel in rels:
                # The English form has two literal endpoints around the
                # relation; Chinese forms put the object between 在/于 and 前/后.
                if rel.group(1):
                    left,right = clause[:rel.start()],clause[rel.end():]
                    relname = rel.group(1).lower()
                    relname = 'after' if relname.startswith(('after','follow')) else 'before'
                else:
                    left = clause[:rel.start()]
                    mid = re.sub(r'^(?:放|置|位)?[于在]','',rel.group(0))
                    tail = rel.group(2) or rel.group(3)
                    right = mid[:-len(tail)]
                    relname = 'after' if tail.startswith('后') or tail=='之后' else 'before'
                l,r = mentions(left),mentions(right)
                lroles = {role for a,b,role in l if b == max((z[1] for z in l),default=-1)}
                rroles = {role for a,b,role in r if a == min((z[0] for z in r),default=-1)}
                bound = len(lroles)==len(rroles)==1 and lroles != rroles
                # A command/call endpoint is an execution dependency, not an
                # unbound positional parameter. Its existing verifier owns it.
                command_endpoint = re.search(r'\b(?:load|insert|examine|set|dump|rpt|add)_[a-z_]+\b',left+' '+right)
                explicit_parameter = re.search(r'\b(?:arguments?|parameters?)\b|参数',clause,re.I)
                if not bound and command_endpoint and not explicit_parameter:continue
                if not bound and not explicit_parameter and not (l and r):continue
                claims.append({'kind':'argument_position','field':field,'clause':clause.strip(),
                    'predicate':pred if bound else 'unknown','relation':relname,
                    'subject_role':next(iter(lroles)) if len(lroles)==1 else None,
                    'relative_role':next(iter(rroles)) if len(rroles)==1 else None,
                    'binding':'formal_parameter_roles' if bound else 'unresolved_parameter_relation'})
    return claims


def _parameter_role_premises(diagnosis, command_words):
    """Finite literal-operand -> formal-role relations, not general prose proof.

    Values are taken from the actual call. A role mention alone or a task
    requiring a different value is not an assertion about argument identity.
    Retain each original field/span so one supported part cannot erase another.
    """
    roles = {'drc_rule_id': r'(?:DRC\s+)?(?:rule\s+)?IDs?|规则\s*(?:ID|编号)|drc_rule_id',
             'level': r'(?:specified\s+|handling\s+|severity\s+)?level|级别|处理等级'}
    result = []
    for field in ('summary', 'root_cause'):
        text = str(diagnosis.get(field, ''))
        for value in dict.fromkeys(w.strip('{}"') for w in command_words[1:3]):
            if not value or re.search(r'[$\[\];\n]',value):continue
            literal = r'(?<![\w])' + re.escape(value) + r'(?![\w])'
            for role, pattern in roles.items():
                forms = [literal+r'[`\'"]?\s*(?:作为|当作|被当作|是|充当)\s*(?:'+pattern+r')',
                         literal+r'[`\'"]?\s+(?:(?:is|was)\s+)?(?:passed|used|treated|interpreted)\s+as\s+(?:the\s+|a\s+)?(?:'+pattern+r')',
                         r'(?:'+pattern+r')\s*(?:为|是|[:=])\s*[`\'"]?'+literal]
                forms.append(r'\b(?:uses?|used|passes?|passed|treats?|treated|interprets?|interpreted)\s+[\x60\x27\x22]?'+literal+r'[\x60\x27\x22]?\s+as\s+(?:the\s+|a\s+)?(?:'+pattern+r')')
                for pattern in forms:
                    for m in re.finditer(pattern,text,re.I):
                        row={'kind':'argument_role','field':field,'clause':m[0],
                             'span':list(m.span()),'value':value,'claimed_role':role}
                        if row not in result:result.append(row)
    return result


def _argument_position_status(claim, parameter_positions):
    """Compare a bound proposition against this command's real help schema."""
    if claim['predicate']=='unknown':return 'incomplete'
    if 'relation' not in claim:
        # Existing abstract premise refers to the executed ID-then-level form.
        return {'defect':'fail','valid':'pass'}[claim['predicate']]
    positions = {p['role']:p['position'] for p in parameter_positions}
    first,second = positions.get(claim.get('subject_role')),positions.get(claim.get('relative_role'))
    if first is None or second is None or first==second:return 'incomplete'
    relation_holds = first > second if claim['relation']=='after' else first < second
    if not relation_holds:
        return 'fail'  # The alleged placement did not occur in this native call.
    return 'fail' if claim['predicate']=='defect' else 'pass'


def _signal_error_parameter_coverage(issue, output_dir, words_for, command, words):
    """A native option error supports that option, not other named premises.

    This finite dispatch uses the actual failed command, native error parameter
    and explicit option identities already present in the adopted diagnosis.
    It does not infer missing-option causality from a successful later command,
    nor interpret an optional schema field as meeting a task-specific role.
    """
    result = {'applicable': False, 'status': 'not_applicable', 'claims': [], 'problems': []}
    found = issue.get('found', {}); diagnosis = issue.get('diagnosis', {})
    error = re.search(r"Unknown option\s+['\"]?(-[a-z_]+)", str(found.get('excerpt', '')), re.I)
    if not error or words[:1] != ['set_scan_signal']:
        return result
    from configuration_evidence import _signal_fault_binding
    # Reuse the existing typed omission claims. A valid replacement mentioned
    # alongside the invalid option is not another alleged original defect.
    # The producer proves omission as a syntax fact; that alone never proves
    # omission caused the native failure.
    rid = str(found.get('run_ref', ''))
    if not re.fullmatch(r'R[1-9]\d*', rid):
        return result  # The ordinary reference validator rejects this identity.
    opts = dict(zip(words[1::2], (v.strip('{}"') for v in words[2::2])))
    binding = _signal_fault_binding(issue, opts.get('-port', '').split(), output_dir,
        output_dir/'runs'/rid/'deliverables'/(rid+'.dofile'), words_for)
    omitted = [c for c in binding.get('claims', []) if c.get('kind') == 'omitted_option']
    extra = sorted({c['option'] for c in omitted} - set(words) - {error[1]})
    if not extra:
        return result
    result.update(applicable=True, status='incomplete')
    from configuration_evidence import _signal_command_trace
    try:
        history = _signal_command_trace(output_dir, found['run_ref'], words_for)
        events = [e for e in (history or {}).get('signals', []) if e['words'] == words and
                  any(x['text'] == found['excerpt'] for x in e['errors'])]
        if len(events) != 1 or words_for(str(diagnosis.get('located_object', ''))) != words:
            raise ValueError('Native failed command/object is not uniquely bound')
        event = events[0]; help_path = Path(__file__).with_name('tool_help.json')
        help_text = json.loads(help_path.read_text())[words[0]]
        evidence = {'command': command, 'design': event['design'], 'partition': event['partition'],
            'run_ref': found['run_ref'], 'loaded_netlists': history['loaded_netlists'],
            'native_error_parameter': error[1],
            'native_evidence': [{k: found[k] for k in ('run_ref','source','locator','excerpt')},
                                {k: event[k] for k in ('run_ref','source','locator','excerpt')}],
            'help_evidence': {'path': str(help_path), 'sha256': hashlib.sha256(help_path.read_bytes()).hexdigest(),
                              'command': words[0], 'text': help_text}}
        result['discovery_binding'] = evidence
        result['prior_syntax_binding'] = binding
        result['claims'] = [{'kind': 'native_error_parameter', 'parameter': error[1], 'status': 'pass'}]
        for option in extra:
            schema = [line.strip() for line in help_text.splitlines()
                      if re.match(r'\s*\[?' + re.escape(option) + r'(?:\s|\])', line)]
            claim = {'kind': 'additional_parameter_premise', 'parameter': option, 'status': 'incomplete',
                     'schema': schema, 'adopted_fields': {k: diagnosis.get(k, '') for k in ('summary','root_cause')}}
            result['claims'].append(claim)
            result['problems'].append({'reason': 'native_parameter_premise_unbound', 'status': 'incomplete',
                'claim_kind': claim['kind'], 'parameter': option, **evidence,
                'detail': 'The actual native error verifies a different parameter. An additional named premise needs its own evidence; later action/configuration success is not that proof.'})
        result['coverage'] = {'capability': 'native_failed_option_coverage', 'obligations': result['claims']}
    except (OSError, ValueError, TypeError, KeyError):
        result['problems'] = [{'reason': 'native_parameter_premise_unbound', 'status': 'incomplete',
            'command': command, 'parameters': extra, 'detail': 'Native command/option coverage could not be uniquely bound.'}]
    return result


def command_parameter_claim_assessment(issue, output_dir, words_for):
    """Explicit applicability and status for a bound native command contract.

    Identity/error, adopted diagnostic premise, and later repair evidence are
    different obligations. A legal parameter position says nothing about the
    ordering of commands with execution dependencies.
    """
    found = issue.get('found', {}); diagnosis = issue.get('diagnosis', {})
    located = words_for(str(diagnosis.get('located_object', '')))
    command = failed_command(found, output_dir); words = words_for(command or '')
    signal = _signal_error_parameter_coverage(issue, output_dir, words_for, command, words)
    if signal['applicable']:
        return signal
    subject = words if words and words[0] == 'set_scan_drc_rule_handling' else located
    result = {'applicable': False, 'status': 'not_applicable', 'claims': [], 'problems': []}
    if len(subject) < 3 or subject[0] != 'set_scan_drc_rule_handling':
        return result
    text = ' '.join(str(diagnosis.get(k, '')) for k in ['summary', 'root_cause'])
    claims = [dict(a, kind='enum_legality', predicate='invalid') for a in _level_legality_premises(text)]
    claims += _parameter_order_premises(diagnosis, command_words=subject)
    claims += _parameter_role_premises(diagnosis, subject)
    for field in ('summary', 'root_cause'):
        for m in re.finditer(r'[^。;；\n]*\b(?:value|parameter|argument)\b[^。;；\n]*\b(?:causes?|results?\s+in)\b[^。;；\n]*', str(diagnosis.get(field,'')), re.I):
            claims.append({'kind':'parameter_causal_scope','field':field,
                'clause':m[0], 'span':list(m.span()), 'predicate':'unknown'})
    error = re.fullmatch(r"\[ERROR\]\s+\[DFTDRC-\d+\]\s+Invalid DRC ID for '([^']+)' level\. Set a valid DRC ID for the 'set_scan_drc_rule_handling' command\.", str(found.get('excerpt', '')))
    if not claims and not error:
        return result
    result.update(applicable=True, status='incomplete', claims=claims)
    original = '; '.join(a['clause'] for a in claims) or str(found.get('excerpt', ''))
    def unknown(detail):
        result['problems'] = [{'status': 'incomplete', 'reason': 'native_parameter_premise_unbound',
            'original_clause': original, 'command': command, 'detail': detail}]
        return result
    if located != words or len(words) < 3:
        return unknown('The diagnosed command and actual native execution are not identical.')
    help_path = Path(__file__).with_name('tool_help.json')
    from configuration_evidence import _signal_command_trace
    try:
        help_text = json.loads(help_path.read_text()).get(words[0], '')
        enums = re.findall(r'(?m)^\s*([A-Za-z_]\w*(?:\s*\|\s*[A-Za-z_]\w*)+)\s+\(specified level\)', help_text)
        # Read the actual help schema; positional proof requires both fields,
        # not just an enum found somewhere in a document.
        parameter_lines = [line.strip() for line in help_text.splitlines() if line[:1].isspace() and line.strip()]
        if (len(enums) != 1 or len(parameter_lines) < 2 or
                not re.match(r'drc_rule_id\s+\(', parameter_lines[0]) or
                not re.search(r'\(specified level\)', parameter_lines[1])):
            return unknown('The native command parameter schema is missing or ambiguous.')
        allowed = [v.strip() for v in enums[0].split('|')]
        trace = _signal_command_trace(output_dir, found['run_ref'], words_for, include_rule_commands=True)
        events = [e for e in (trace or {}).get('rule_commands', []) if e['words'] == words and
                  any(x['text'] == found['excerpt'] for x in e['errors'])]
        if len(events) != 1 or not error or error[1] != words[2]:
            return unknown('Native command, failed parameter, design/round or error source is not uniquely bound.')
        event = events[0]
        scope = {'kind': 'prior_command_parameter_premise', 'producer': 'command_parameter_claim_problems',
                 'case_output': str(output_dir.absolute()), 'run_ref': found['run_ref'],
                 'design': event['design'], 'partition': event['partition'],
                 'loaded_netlists': trace['loaded_netlists'], 'command_words': words}
        facts = {'assessment_scope': scope, 'allowed_values': allowed,
                 'parameter_positions': [{'position': 1, 'role': 'drc_rule_id'}, {'position': 2, 'role': 'level'}],
                 'native_error_parameter': 'rule_ids',
                 'native_evidence': [{k: found[k] for k in ['run_ref','source','locator','excerpt']},
                    {k: event[k] for k in ['run_ref','source','locator','excerpt']}],
                 'help_evidence': {'path': str(help_path), 'sha256': hashlib.sha256(help_path.read_bytes()).hexdigest(),
                                  'command': words[0], 'text': help_text}}
        result['discovery_binding'] = facts
        # A native call/schema can be fully identified while the adopted
        # diagnostic predicate is not understood. Keep those two facts
        # separate; never turn an unparsed predicate into a refutation.
        order_property = {'kind': 'native_formal_parameter_order',
            'assessment_scope': scope, 'parameter_positions': facts['parameter_positions'],
            'help_sha256': facts['help_evidence']['sha256']}
        # The actual observed rule-ID error is an explicitly checked native
        # fact, not an empty-list claim that every diagnostic premise passed.
        assessments = [{'kind':'native_error_parameter','field':'found',
            'clause':found['excerpt'],'parameter':'rule_ids','status':'pass'}]
        for claim in claims:
            if claim['kind'] == 'enum_legality':
                status = ('incomplete' if claim['value'].casefold() != words[2].casefold() else
                          'fail' if words[2] in allowed else 'pass')
            elif claim['kind'] == 'argument_role':
                matches = [p['role'] for p in facts['parameter_positions']
                           if words[p['position']].strip('{}\"') == claim['value']]
                status = ('incomplete' if len(matches) != 1 else
                          'pass' if matches[0] == claim['claimed_role'] else 'fail')
            elif claim['kind'] == 'parameter_causal_scope':
                status = 'incomplete'
            else:
                # The actual native error identifies words[2] as level, while
                # help specifies rule-ID then level: position, not value validity.
                status = _argument_position_status(claim, facts['parameter_positions'])
            premise_binding = None
            if (len(words) == 3 and claim['kind'] == 'argument_position' and
                    claim.get('binding') == 'formal_parameter_order' and
                    'relation' not in claim and
                    # A sentence-final period is punctuation, not part of a
                    # command/file name. Preserve the original clause itself.
                    _command_subjects(re.sub(r'\.(?=\s|$)', ' ', claim['clause'])) <= {words[0]}):
                premise_binding = {'kind': 'bound_diagnostic_parameter_order',
                    'property': order_property, 'field': claim['field'],
                    'predicate': claim['predicate'],
                    'unknown_components': ['predicate'] if status == 'incomplete' else []}
            assessments.append({**claim, 'status': status,
                **({'premise_binding': premise_binding} if premise_binding else {})})
            if status == 'pass':
                continue
            problem = {'status': status,
                'reason': 'native_parameter_premise_contradicted' if status == 'fail' else 'native_parameter_premise_unbound',
                'claim_kind': claim['kind'], 'original_clause': claim['clause'], 'command': command,
                'detail': 'The actual native parameter contract contradicts this adopted premise; actual task policy and repair remain separate.' if status == 'fail' else 'The adopted material parameter premise has no unique supported interpretation/binding.'}
            if status == 'fail':
                problem.update(facts)
            if premise_binding:
                # This is diagnostic interpretation scope, not a delivery
                # verdict. Missing native/help/object binding returns above
                # and can never acquire this typed scope.
                problem.update(facts, premise_binding=premise_binding)
            result['problems'].append(problem)
        # Semantic obligations and actual evidence, not literal character coverage.
        # Unadapted validators keep their own contracts; this is not a receipt
        # certifying every natural-language sentence in the issue.
        result['coverage'] = {'capability':'native_command_parameter_contract',
            'scope':facts, 'obligations':assessments,
            'meaning':'Only the represented parameter/position propositions are checked; unresolved propositions retain their status.'}
        result['claims'] = assessments
        result['status'] = ('fail' if any(a['status'] == 'fail' for a in assessments) else
                            'incomplete' if any(a['status'] == 'incomplete' for a in assessments) else 'pass')
        return result
    except (OSError, ValueError, TypeError, KeyError):
        return unknown('The native command or diagnostic premise evidence could not be read and bound.')


def command_parameter_claim_problems(issue, output_dir, words_for):
    """Compatibility API: failure-only projection of the full assessment."""
    return command_parameter_claim_assessment(issue, output_dir, words_for)['problems']


def command_parameter_scope(problems):
    """Bound prior diagnoses; unknown predicates are not presumed refuted.

    The limited mixed case requires an independently refuted representation
    of the SAME native two-role order property. Unknown roles, relations,
    other commands/parameters, missing evidence and all-unknown sets do not
    qualify. Actual task delivery still requires a fresh runtime proof.
    """
    if not problems or not all(p.get('status') in {'fail', 'incomplete'} and
        p.get('assessment_scope', {}).get('kind') == 'prior_command_parameter_premise' and
        p['assessment_scope'].get('producer') == 'command_parameter_claim_problems'
        for p in problems):
        return False
    refuted = [p for p in problems if p['status'] == 'fail']
    if not refuted:
        return False
    def bound_order(problem):
        binding = problem.get('premise_binding', {})
        prop = binding.get('property', {})
        scope = problem.get('assessment_scope', {})
        if (problem.get('claim_kind') != 'argument_position' or
                binding.get('kind') != 'bound_diagnostic_parameter_order' or
                binding.get('field') not in {'root_cause', 'summary'} or
                prop.get('kind') != 'native_formal_parameter_order' or
                prop.get('assessment_scope') != scope or
                prop.get('parameter_positions') != problem.get('parameter_positions') or
                prop.get('parameter_positions') != [
                    {'position': 1, 'role': 'drc_rule_id'}, {'position': 2, 'role': 'level'}] or
                not problem.get('native_evidence') or not problem.get('help_evidence') or
                prop.get('help_sha256') != problem['help_evidence'].get('sha256') or
                any(e.get('run_ref') != scope.get('run_ref') for e in problem['native_evidence'])):
            return None
        return binding
    for problem in problems:
        if problem['status'] == 'fail':
            continue
        binding = bound_order(problem)
        if not binding:
            return False
        prop = binding['property']
        if (
                binding.get('predicate') != 'unknown' or
                binding.get('unknown_components') != ['predicate'] or
                not any(bound_order(p) is not None and
                    p['premise_binding'].get('property') == prop and
                    p['premise_binding'].get('unknown_components') == [] and
                    p['premise_binding'].get('field') != binding['field'] and
                    p.get('native_evidence') == problem['native_evidence'] and
                    p.get('help_evidence') == problem['help_evidence'] for p in refuted)):
            return False
    return True


def command_parameter_delivery_condition(issue, conflicts, root, rid, spec, files, dofile, words_for):
    """Recompute the prior fact and separately bind actual final task policy."""
    from configuration_evidence import _signal_command_trace
    from drc_validation import required_ignored_rule_codes, required_rule_handling_problems
    from operation_audit import operation_trace
    if (not command_parameter_scope(conflicts) or
            command_parameter_claim_problems(issue, root, words_for) != conflicts or
            not required_ignored_rule_codes(spec) or
            required_rule_handling_problems(root/'runs'/rid, [p for p in files if p.suffix == '.rpt'], dofile, spec, words_for)):
        return None
    current = _signal_command_trace(root, rid, words_for, include_rule_commands=True)
    if (not current or any(p['assessment_scope']['design'] != current['design'] or
            p['assessment_scope']['loaded_netlists'] != current['loaded_netlists'] or
            p['assessment_scope']['case_output'] != str(root.absolute()) or
            int(p['assessment_scope']['run_ref'][1:]) >= int(rid[1:]) for p in conflicts)):
        return None
    phase = operation_trace(files, root, dofile, words_for, allow_verbose=True)
    if not phase or phase['design'] != current['design']:
        return None
    writers = [w for w in phase['reports'] if w['kind'] == 'rpt_scan_drc_rule_handling']
    if not writers:
        return None
    writer = max(writers, key=lambda w: w['log_line'])
    path = writer['path']; lines = path.read_text().splitlines()
    ref = {'run_ref': rid, 'source': path.relative_to(root).as_posix(),
           'locator': 'L1-L'+str(min(len(lines), 8)), 'excerpt': '\n'.join(lines[:8])}
    paths = [path, root/'runs'/rid/(rid+'.log'), Path(__file__).with_name('tool_help.json')]
    for p in conflicts:
        paths += [root/e['source'] for e in p['native_evidence']]
        fr = p['assessment_scope']['run_ref']
        paths.append(root/'runs'/fr/'deliverables'/(fr+'.dofile'))
    return {'kind': 'native_task_command_parameter', 'run_ref': rid, 'design': current['design'],
            'located_object': issue['diagnosis']['located_object'], 'prior_checks': conflicts,
            'final_condition': ref, 'required_ignored_rules': sorted(required_ignored_rule_codes(spec))}, paths


def _output_command(name: str) -> bool:
    return name.startswith(('rpt_', 'dump_', 'write_'))


def _command_subjects(text: str) -> set[str]:
    return set(re.findall(
        r'(?<![\w/$.])(?:(?:load|set|dump|write|rpt|examine|insert|add)_[a-z_0-9]+|present_design)'
        r'(?![\w./])', text))


def _compatible_command_subject(issue: dict, allowed: set[str]) -> bool:
    """An explicit different command cannot be proved by this command's success.

    Natural input descriptions need not contain a command. The real failed
    command/file/line remains the proof anchor, not an arbitrary model phrase.
    """
    located = str(issue.get('diagnosis', {}).get('located_object', ''))
    commands = _command_subjects(located)
    return not commands - allowed


def report_operation_binding_problem(issue: dict) -> dict | None:
    """A DRC condition cannot discover or prove a different tool operation.

    Select by literal tool commands, not issue IDs or prose labels. A concrete
    diagnosed command is primary; an otherwise unnamed object can select output
    operations when its entire stated fix consists of output commands. Control
    fixes for real DRC objects keep their existing rule-specific proof.
    """
    found = issue.get('found', {})
    excerpt = str(found.get('excerpt', ''))
    drc_observation = (rule_codes(excerpt) and re.search(
        r'DFTDRC-\d+\]|\bDRC rule [\'"]|\(\s*DFTR[-\w]+\s*\)', excerpt))
    if not (drc_observation or re.search(r'Total violations:\s*[1-9]\d*', excerpt)):
        return None
    declared = _command_subjects(str(issue.get('diagnosis', {}).get('located_object', '')))
    if not declared:
        attempts = issue.get('attempts') or [{}]
        fixes = _command_subjects(str(attempts[-1].get('fix', {}).get('action', '')))
        outputs = {command for command in fixes if _output_command(command)}
        if outputs and not fixes - outputs - {'insert_dft_logic'}:
            # Insertion may be an ordering prerequisite of an output repair.
            # Its mention cannot disable the output-operation binding.
            declared = outputs
    operations = {command for command in declared if _output_command(command) or
                  command in {'insert_dft_logic', 'replace_unscan', 'set_scan_cell_mapping'}}
    if not operations:
        return None
    return {'reason': 'drc_condition_does_not_prove_operation', 'found': dict(found),
            'declared_operation_commands': sorted(operations),
            'conclusion': 'DRC evidence supports a DRC condition only; operation discovery and native execution evidence are required.'}


def command_proof_kind(issue: dict, output_dir: Path, words_for) -> str | None:
    """Select strict typed proofs before generic positive-report fallbacks."""
    failed = words_for(failed_command(issue.get('found', {}), output_dir) or '')
    declared = _command_subjects(str(issue.get('diagnosis', {}).get('located_object', '')))
    if 'set_scan_cell_mapping' in declared or failed and failed[0] == 'set_scan_cell_mapping':
        return 'mapping'
    if 'dump_netlist' in declared or failed and failed[0] == 'dump_netlist':
        return 'netlist_export'
    return None


def _same_file_bytes(left: Path, right: Path) -> bool:
    """Compare all collected bytes with bounded memory, including large HDL."""
    if left.stat().st_size != right.stat().st_size:
        return False
    with left.open('rb') as a, right.open('rb') as b:
        while True:
            chunk = a.read(1024 * 1024)
            if chunk != b.read(1024 * 1024):
                return False
            if not chunk:
                return True


def command_binding_problem(issue: dict, output_dir: Path, words_for) -> dict | None:
    """Detect a concrete execution-error citation about other named commands.

    This rejects an unsupported binding, not the underlying task requirement or
    an untested causal hypothesis. Native messages naming both commands can
    discover real ordering failures. Input initialization is one grouped proof.
    Reports, DRC conditions and natural object descriptions keep their existing
    semantic verifiers. Unknown binding never supplies positive evidence.
    """
    found = issue.get('found', {})
    excerpt = str(found.get('excerpt', ''))
    if not re.search(r'\[ERROR\]\s+\[\s*(?:CMD|COM|SCAN)-\d+\]', excerpt):
        return None
    named = _command_subjects(str(issue.get('diagnosis', {}).get('located_object', '')))
    failed = words_for(failed_command(found, output_dir) or '')
    if not named or not failed:
        return None
    allowed = {failed[0]} | _command_subjects(excerpt)
    initialization = {'load_lib', 'load_netlist', 'present_design'}
    if failed[0] in initialization:
        allowed |= initialization
    if named <= allowed:
        return None
    return {'reason': 'unsupported_native_command_binding',
            'found': dict(found), 'actual_failed_command': failed_command(found, output_dir),
            'declared_commands': sorted(named), 'supported_commands': sorted(allowed),
            'conclusion': 'Citation does not establish this diagnosis; no repair or resolution claimed.'}


def load_input_evidence(issue: dict, files: list[Path], output_dir: Path,
                        dofile: str, words_for) -> dict | None:
    """Prove library/netlist/design initialization in one real later tool run.

    Literal load paths only. The caller still freezes the actual input tree and
    requires all output checks. A library message alone or a DRC summary cannot
    establish this grouped requirement. Unknown/dynamic Tcl remains unresolved.
    """
    failed = words_for(failed_command(issue.get('found', {}), output_dir) or '')
    if (not failed or failed[0] not in {'load_lib', 'load_netlist'} or
            not _compatible_command_subject(issue, {'load_lib', 'load_netlist', 'present_design'})):
        return None
    found_run = str(issue.get('found', {}).get('run_ref', ''))
    if not re.fullmatch(r'R[1-9]\d*', found_run):
        return None
    declarations, tops = {}, []
    try:
        chunks = tcl_chunks(dofile)
    except ValueError:
        return None
    for chunk in chunks:
        text = chunk.strip()
        if not text or text.startswith('#'):
            continue
        words = words_for(text)
        if not words or words[0] in {'source', 'eval', 'proc', 'uplevel', 'interp',
                                     'namespace', 'rename', 'trace', 'exec'}:
            return None
        if words[0] in {'load_lib', 'load_netlist'}:
            if len(words) != 2:
                return None
            value = words[1]
            if value[:1] in {'"', '{'}:
                value = value[1:-1]
            path = PurePosixPath(value)
            if (not path.is_absolute() or '..' in path.parts or
                    re.search(r'[$\[\]\\;\r\n]', value) or
                    path.name in {'golden.dofile', 'preset_issues.json', '.env'} or
                    path.name.startswith('.env.') or 'answers' in path.parts):
                return None
            key = (words[0], value)
            if key in declarations:
                return None
            declarations[key] = text
        elif words[0] == 'present_design':
            if len(words) != 2 or not re.fullmatch(r'[A-Za-z_$][\w$]*', words[1]):
                return None
            tops.append((words[1], text))
        elif not is_context_query(text) and re.search(r'\b(?:load_lib|load_netlist|present_design)\b', text):
            return None
    if ({key[0] for key in declarations} != {'load_lib', 'load_netlist'} or len(tops) != 1):
        return None
    source_lines = dofile.splitlines()
    expected_top, top_command = tops[0]
    for log in files:
        run = log.parent
        if (not re.fullmatch(r'R[1-9]\d*', run.name) or log.name != run.name + '.log' or
                int(run.name[1:]) <= int(found_run[1:]) or log.is_symlink() or
                not log.resolve().is_relative_to((output_dir / 'runs' / run.name).resolve())):
            continue
        delivered = run / 'deliverables' / (run.name + '.dofile')
        if not delivered.is_file() or delivered.is_symlink() or delivered.read_text() != dofile:
            continue
        # These links are staged by the runtime from the current frozen input
        # (or the EQY-proven candidate). Do not infer an input from its basename.
        roots = {}
        for command, directory in [('load_lib', 'lib'), ('load_netlist', 'netlist')]:
            binding = run / 'input' / directory
            if not binding.is_symlink():
                break
            target = PurePosixPath(str(binding.readlink()))
            if not target.is_absolute() or '..' in target.parts:
                break
            roots[command] = target
        if (len(roots) != 2 or any(not PurePosixPath(path).is_relative_to(roots[command])
                                   for command, path in declarations)):
            continue
        bound, active, seen, first, complete = False, None, set(), None, None
        captured = []
        invalid = False
        with log.open(errors='replace') as stream:
            for number, line in enumerate(stream, 1):
                if re.search(r'\[(?:ERROR|FATAL)\]', line):
                    invalid = True
                    break
                origin = re.search(r'\[SOURCE TCL FILE\]\s+(\S+)\s*:', line)
                if origin:
                    path = PurePosixPath(origin[1])
                    indexes = [i for i, part in enumerate(path.parts)
                               if part == 'runs' and path.parts[i + 1:i + 2] == (run.name,)]
                    if bound or '..' in path.parts or len(indexes) != 1:
                        invalid = True
                        break
                    executed = run.joinpath(*path.parts[indexes[0] + 2:])
                    if (not executed.is_file() or executed.is_symlink() or
                            not executed.resolve().is_relative_to(run.resolve()) or
                            executed.read_bytes() != delivered.read_bytes()):
                        invalid = True
                        break
                    bound = True
                echo = re.search(r'CMD-0034\]\s+@(\d+):\s*(.*)', line)
                if echo:
                    active = None
                    command = echo[2].strip()
                    words = words_for(command)
                    if words and words[0] in {'load_lib', 'load_netlist', 'present_design'}:
                        index = int(echo[1])
                        if not bound or not 0 < index <= len(source_lines) or source_lines[index - 1].strip() != command:
                            invalid = True
                            break
                        if words[0] == 'present_design':
                            if command != top_command or seen != set(declarations):
                                invalid = True
                                break
                            active = ('present_design', expected_top)
                        else:
                            active = next((key for key, text in declarations.items() if text == command), None)
                            if active is None or active in seen or complete is not None:
                                invalid = True
                                break
                        if first is None:
                            first = number
                if first is not None and complete is None:
                    captured.append(line.rstrip('\r\n'))
                library = re.fullmatch(r"\[INFO\]\s+\[\s*LIB-I-0011\]\s+Liberty file '([^'\n]+)' is read successfully\.\s*", line.strip())
                netlist = re.fullmatch(r"\[INFO\]\s+\[VRLG-I-0001\]\s+Read Verilog file '([^'\n]+)' successfully\.\s*", line.strip())
                design = re.fullmatch(r"\[INFO\]\s+\[\s*CMD-1300\]\s+Present design is '([^'\n]+)'\.\s*", line.strip())
                if library and active == ('load_lib', library[1]):
                    seen.add(active)
                elif netlist and active == ('load_netlist', netlist[1]):
                    seen.add(active)
                elif design and active == ('present_design', design[1]) and design[1] == expected_top:
                    complete = number
        if bound and complete is not None and not invalid and seen == set(declarations):
            return {'source': log.relative_to(output_dir).as_posix(),
                    'locator': f'L{first}-L{complete}', 'excerpt': '\n'.join(captured)}
    return None


def netlist_export_evidence(issue: dict, files: list[Path], output_dir: Path,
                            dofile: str, words_for) -> dict | None:
    """Bind a failed export to a later native write and its actual HDL target.

    This proves export, not scan correctness or equivalence. The caller still
    requires all native/report/coverage checks and freezes inputs and artifacts.
    Unknown Tcl, ambiguous writes, absent/incomplete HDL or mismatched collected
    bytes cannot close the issue. No Tcl or model-provided commands are executed.
    """
    failed = words_for(failed_command(issue.get('found', {}), output_dir) or '')
    if (not failed or failed[0] != 'dump_netlist' or
            not _compatible_command_subject(issue, {'dump_netlist'})):
        return None
    named = words_for(str(issue.get('diagnosis', {}).get('located_object', '')).strip())
    if named and named[0] == 'dump_netlist' and len(named) > 1:
        # A concrete wrong old target cannot be repaired by an unrelated export.
        # Natural descriptions and the bare command bind to the actual failure.
        if ([word.strip('"{}') for word in named] !=
                [word.strip('"{}') for word in failed[:len(named)]]):
            return None
    try:
        commands = [chunk.strip() for chunk in tcl_chunks(dofile) if chunk.strip() and
                    not chunk.lstrip().startswith('#')]
    except ValueError:
        return None
    tops, exports = [], []
    for text in commands:
        words = words_for(text)
        if not words or words[0] in {'source', 'eval', 'proc', 'uplevel', 'interp', 'namespace'}:
            return None
        if words[0] == 'present_design' and len(words) == 2 and re.fullmatch(r'[A-Za-z_$][\w$]*', words[1]):
            tops.append(words[1])
        elif words[0] == 'dump_netlist' and len(words) == 3 and words[1] == '-file':
            exports.append(text)
        elif not is_context_query(text) and re.search(r'\b(?:present_design|dump_netlist)\b', text):
            return None
    if len(tops) != 1 or len(exports) != 1:
        return None
    for path in files:
        run = path.parent
        if (path.name != run.name + '.log' or not re.fullmatch(r'R[1-9]\d*', run.name) or
                run.name == issue.get('found', {}).get('run_ref') or path.is_symlink() or
                not path.resolve().is_relative_to((output_dir / 'runs' / run.name).resolve())):
            continue
        found_run = str(issue.get('found', {}).get('run_ref', ''))
        if not re.fullmatch(r'R[1-9]\d*', found_run) or int(run.name[1:]) <= int(found_run[1:]):
            continue
        script = run / 'deliverables' / (run.name + '.dofile')
        if not script.is_file() or script.is_symlink() or script.read_text() != dofile:
            continue
        variables, virtual_run, target, completed = {}, None, None, None
        pending_set = ''
        writing = False
        began = False
        with path.open(errors='replace') as stream:
            for number, line in enumerate(stream, 1):
                if re.search(r'\[(?:ERROR|FATAL)\]', line):
                    return None
                origin = re.search(r'\[SOURCE TCL FILE\]\s+(\S+)\s*:', line)
                if origin:
                    origin_path = PurePosixPath(origin[1])
                    if '..' in origin_path.parts:
                        return None
                    matches = [i for i, part in enumerate(origin_path.parts)
                               if part == 'runs' and origin_path.parts[i + 1:i + 2] == (run.name,)]
                    if virtual_run is not None or len(matches) != 1:
                        return None
                    offset = matches[0] + 2
                    virtual_run = PurePosixPath(*origin_path.parts[:offset])
                    executed = run.joinpath(*origin_path.parts[offset:])
                    if (not executed.is_file() or executed.is_symlink() or
                            not executed.resolve().is_relative_to(run.resolve()) or
                            executed.read_bytes() != script.read_bytes()):
                        return None
                echo = re.search(r'CMD-0034\]\s+@(\d+):\s*(.*)', line)
                if echo:
                    pending_set = ''
                    writing = False
                    words = words_for(echo[2])
                    if len(words) == 3 and words[0] == 'set' and re.fullmatch(r'[A-Za-z_]\w*', words[1]):
                        pending_set = words[1]
                        variables.pop(pending_set, None)
                    if words and words[0] == 'dump_netlist':
                        if completed or target or virtual_run is None or echo[2].strip() != exports[0]:
                            return None
                        source_lines = dofile.splitlines()
                        if int(echo[1]) > len(source_lines) or source_lines[int(echo[1]) - 1].strip() != exports[0]:
                            return None
                        value = words[2]
                        literal = value.startswith('{') and value.endswith('}')
                        value = value[1:-1] if value[:1] in {'"', '{'} else value
                        if not literal:
                            value = re.sub(r'\$(?:\{([A-Za-z_]\w*)\}|([A-Za-z_]\w*))',
                                           lambda m: variables.get(m[1] or m[2], '$UNKNOWN'), value)
                        if re.search(r'[$\[\]\\;\r\n]', value):
                            return None
                        native_target = PurePosixPath(value)
                        if not native_target.is_absolute():
                            native_target = virtual_run / native_target
                        if '..' in native_target.parts or not native_target.is_relative_to(virtual_run):
                            return None
                        relative = native_target.relative_to(virtual_run)
                        if not relative.parts or relative.parts[0] == 'input':
                            return None
                        target = run.joinpath(*relative.parts)
                        writing = True
                        began = False
                    continue
                if pending_set:
                    # Tcl's native `set` result is the executed value, not a
                    # guessed evaluation of arbitrary bracket expressions.
                    value = line.strip()
                    if value and not value.startswith('[') and not re.search(r'[$\[\]\\;]', value):
                        variables[pending_set] = value
                    pending_set = ''
                if writing and re.fullmatch(r'\[INFO\]\s+\[VRLG-O-0008\]\s+Begin to write Netlist\.\s*', line.strip()):
                    began = True
                if writing and began and re.fullmatch(r'\[INFO\]\s+\[VRLG-O-0009\]\s+Write Netlist successfully\.\s*', line.strip()):
                    completed = (number, line.strip())
        if not completed or target is None or not target.is_file() or target.suffix.lower() not in {'.v', '.vg'}:
            continue
        if (target.is_symlink() or
                not target.resolve().is_relative_to(run.resolve()) or
                any(parent.is_symlink() for parent in target.parents if parent != run and parent.is_relative_to(run))):
            continue
        collected = run / 'deliverables' / target.name
        if collected.exists() and (collected.is_symlink() or not _same_file_bytes(collected, target)):
            continue
        modules, current, statements = [], '', 0
        for text, _, status in _records(target, 65536):
            if status not in {'statement', 'scope_end'}:
                break
            if text.startswith('module '):
                match = re.match(r'module\s+([A-Za-z_$][\w$]*)\s*\(', text)
                if current or not match:
                    break
                current = match[1]
                modules.append(current)
            elif status == 'scope_end':
                if not current:
                    break
                current = ''
            elif current and re.search(r'\w', text) and not re.match(r'(?:input|output|inout|wire|tri)\b', text):
                statements += 1
        else:
            if current or tops[0] not in modules or not statements:
                continue
            return {'source': path.relative_to(output_dir).as_posix(),
                    'locator': f'L{completed[0]}', 'excerpt': completed[1]}
    return None


def failed_command(found: dict, output_dir: Path) -> str | None:
    relative = Path(str(found.get('source', '')))
    run = str(found.get('run_ref', ''))
    locator = re.fullmatch(r'L(\d+)(?:-L(\d+))?', str(found.get('locator', '')))
    if relative.is_absolute() or '..' in relative.parts or not locator or relative.suffix != '.log':
        return None
    path = output_dir / relative
    if not path.is_file() or path.is_symlink() or not re.fullmatch(r'R\d+', run):
        return None
    if not path.resolve().is_relative_to((output_dir / 'runs' / run).resolve()):
        return None
    first, last = int(locator[1]), int(locator[2] or locator[1])
    command, fragment = '', []
    with path.open(errors='replace') as stream:
        for number, line in enumerate(stream, 1):
            if number > last:
                break
            if number <= first:
                echo = re.search(r'CMD-0034\]\s+@\d+:\s*(.*)', line)
                if echo:
                    command = echo[1].strip()
            if number >= first:
                fragment.append(line)
    excerpt = str(found.get('excerpt', ''))
    return command if excerpt and excerpt in ''.join(fragment) and '[ERROR]' in excerpt else None


def mismatched_signal_target(item: dict, found: dict, output_dir: Path, words_for) -> bool:
    command = failed_command(found, output_dir)
    words = words_for(command or '')
    located = str(item.get('located_object', ''))
    if not words or words[0] != 'set_scan_signal' or '-port' not in words:
        return False
    index = words.index('-port')
    if index + 1 >= len(words):
        return False
    ports = words[index + 1].strip('"{}').split()
    if not ports or any(not re.fullmatch(r'[A-Za-z_][\w$]*', port) for port in ports):
        return False
    role_target = re.fullmatch(
        r'(?:scan[_ ]enable|clock|reset|test[_ ]mode)\s+[`\'"{]?[A-Za-z_][\w$]*[`\'"}]?',
        located.strip(), re.I)
    explicit = bool(role_target or re.search(r'\bports?\s+\w+', located, re.I) or
                    re.fullmatch(r'[A-Za-z_][\w$]*', located) and located != 'set_scan_signal')
    return explicit and not any(re.search(r'(?<![\w$])' + re.escape(port) + r'(?![\w$])', located)
                                for port in ports)


def bare_configuration_evidence(issue: dict, files: list[Path], output_dir: Path,
                                dofile: str, words_for) -> dict | None:
    command = failed_command(issue.get('found', {}), output_dir)
    if command not in {'set_scan_cfg', 'set_wrapper_cfg'}:
        return None
    fix = str(issue.get('attempts', [{}])[-1].get('fix', {}).get('action', ''))
    if not re.search(r'remove|delet|correct|fix|移除|删除|修', fix, re.I):
        return None
    if any(words_for(line.strip()) == [command] for line in dofile.splitlines()):
        return None
    report_name = 'scan_cfg' if command == 'set_scan_cfg' else 'wrapper_cfg'
    header = 'ScanConfigurationParameter' if command == 'set_scan_cfg' else 'WrapperConfigurationParameter'
    for path in files:
        if report_name not in path.name or path.suffix != '.rpt':
            continue
        lines = path.read_text(errors='replace').splitlines()
        starts = [i for i, line in enumerate(lines) if header in line and 'Value' in line]
        for first in starts:
            end = next((i for i in range(first + 2, len(lines)) if lines[i].startswith('---')), None)
            if end is not None and any(re.match(r'\s*max_length\s+\d+\s*$', line)
                                       for line in lines[first:end]):
                return {'source': path.relative_to(output_dir).as_posix(),
                        'locator': f'L{first + 1}-L{end + 1}', 'excerpt': '\n'.join(lines[first:end + 1])}
    return None


def grouped_signal_evidence(issue: dict, files: list[Path], output_dir: Path,
                            dofile: str, words_for, *, allow_reset: bool = False,
                            allow_constant: bool = False) -> dict | None:
    located = str(issue.get('diagnosis', {}).get('located_object', ''))
    match = re.search(r'\bports\s+(.+)', located, re.I)
    if not match:
        return None
    targets = set(re.findall(r'[A-Za-z_][\w$]*', match[1]))
    if not targets:
        return None
    try:
        chunks = tcl_chunks(dofile)
    except ValueError:
        return None
    # Scope only unconditional, literal commands. Dynamic evaluation may change
    # either the selected design or partition without an observable declaration.
    scoped = {'present_design', 'set_current_scan_partition', 'set_scan_signal'}
    selected_design = ''
    designs = []
    partition = 'Default_Partition'
    declarations = {}
    for chunk in chunks:
        line = chunk.strip().replace('\\\n', ' ')
        if not line or line.startswith('#'):
            continue
        words = words_for(line)
        if not words:
            return None
        command = words[0]
        if command in {'source', 'eval', 'uplevel', 'interp', 'namespace'}:
            return None
        if command not in scoped:
            if is_context_query(line):continue
            if re.search(r'\b(?:present_design|set_current_scan_partition|set_scan_signal)\b', line):
                return None
            continue
        if ';' in line:
            return None
        if command in {'present_design', 'set_current_scan_partition'}:
            if len(words) != 2 or not re.fullmatch(r'[A-Za-z_]\w*', words[1].strip('"{}')):
                return None
            name = words[1].strip('"{}')
            if command == 'present_design':
                selected_design = name
                designs.append(name)
            else:
                partition = name
            continue
        if len(words) % 2 != 1:
            return None
        if len(set(words[1::2])) != len(words[1::2]):
            return None
        options = {key: value.strip('"{}') for key, value in zip(words[1::2], words[2::2])}
        port = options.get('-port')
        if port in targets:
            role = options.get('-type')
            if (not re.fullmatch(r'[A-Za-z_]\w*', port) or not selected_design or port in declarations or
                    role not in ({'constant'} if allow_constant else
                                 {'reset', 'clock', 'scan_enable'} if allow_reset else {'scan_enable'}) or
                    (options.get('-constant_value') not in {'0', '1'} if role == 'constant' else
                     options.get('-off_state') not in {'0', '1'}) or
                    role == 'scan_enable' and options.get('-usage') not in {'all', 'scan', 'clock_gating'} or
                    role in {'reset', 'clock', 'constant'} and '-usage' in options):
                return None
            declarations[port] = {**options, 'partition': partition, 'design': selected_design}
        elif port is None or re.search(r'[$\[\\]', port):
            # A computed declaration may create one of the target ports.
            return None
    if len(designs) != 1 or set(declarations) != targets:
        return None
    for path in files:
        if ('signal' not in path.name or path.suffix != '.rpt' or path.is_symlink() or
                not path.is_file() or not path.resolve().is_relative_to(output_dir.resolve())):
            continue
        lines = path.read_text(errors='replace').splitlines()
        reported_designs = [m[1] for line in lines if (m := re.fullmatch(r'\s*Design:\s*(\S+)\s*', line))]
        if reported_designs != designs:
            continue
        required = {'Port', 'SignalType', 'OffState', 'Usage', 'OwnerPartition'}
        if allow_constant:
            required.add('ConstantValue')
        selected = [row for row in report_rows(path, required)
                    if row['Port'] in targets]
        if len(selected) != len(targets) or {row['Port'] for row in selected} != targets:
            continue
        # Reset is a design control, whose native default partition column is
        # empty. Scan-enable ownership/usage remain mandatory and explicit.
        if any(row['SignalType'].split('(')[0] != declarations[row['Port']]['-type'] or
               (row.get('ConstantValue') != declarations[row['Port']]['-constant_value'] if allow_constant else
                row['OffState'] != declarations[row['Port']]['-off_state']) or
               (row['SignalType'].split('(')[0] == 'scan_enable' and
                (row['Usage'] != declarations[row['Port']]['-usage'] or
                 row['OwnerPartition'] != declarations[row['Port']]['partition'])) or
               (row['SignalType'] in {'reset', 'clock', 'constant'} and
                (row['Usage'] or (row['OwnerPartition'] or 'Default_Partition') !=
                 declarations[row['Port']]['partition']))
               for row in selected):
            continue
        first, last = min(row['line'] for row in selected), max(row['line'] for row in selected)
        return {'source': path.relative_to(output_dir).as_posix(), 'locator': f'L{first}-L{last}',
                'excerpt': '\n'.join(lines[first - 1:last])}
    return None


def _mapping_library_repair(issue: dict, run: Path, log: Path, dofile: str,
                            command: str, source: str, target: str, words_for) -> bool:
    """A missing-library repair may keep a correct mapping's target unchanged.

    This is a dependency proof, not an unchanged-target exemption. Only actual
    input libraries loaded successfully before the mapping can supply the FF
    definitions; unknown or incompatible cell functions cannot close the issue.
    The caller still binds the executed script, replacement and typed cell row.
    """
    if not re.fullmatch(r"\[ERROR\]\s+\[\s*COM-3008\]\s+Nothing matched for liberty\.\s*",
                        str(issue.get('found', {}).get('excerpt', '')).strip()):
        return False
    binding = run / 'input/lib'
    if not binding.is_symlink():
        return False
    root = Path(binding.readlink())
    if not root.is_absolute() or '..' in root.parts:
        return False
    declarations = {}
    mappings = 0
    before_mapping = True
    for chunk in tcl_chunks(dofile):
        text = chunk.strip()
        if not text or text.startswith('#'):
            continue
        words = words_for(text)
        if not words:
            return False
        if words[0] == 'exit':
            break
        if words[0] in {'proc', 'rename', 'trace', 'exec', 'apply', 'load_ctl'}:
            return False
        if words[0] == 'set_scan_cell_mapping':
            mappings += 1
            before_mapping = False
        if words[0] == 'load_lib':
            if not before_mapping or len(words) != 2:
                return False
            value = words[1].strip('"{}')
            path = Path(value)
            if (not path.is_absolute() or '..' in path.parts or
                    re.search(r'[$\[\]\\;\s{}"]', value) or path.suffix != '.lib' or
                    not path.is_relative_to(root) or not path.resolve().is_relative_to(root.resolve()) or
                    path.is_symlink() or not path.is_file() or value in declarations):
                return False
            declarations[value] = text
        elif re.search(r'\bload_lib\b', text):
            return False
    if not declarations or mappings != 1:
        return False
    active = None
    loaded = set()
    mapped = False
    lines = dofile.splitlines()
    for line in log.read_text(errors='replace').splitlines():
        echo = re.search(r'CMD-0034\]\s+@(\d+):\s*(.*)', line)
        if echo:
            active = None
            text = echo[2].strip()
            if text in declarations.values() or text == command:
                index = int(echo[1])
                if not 0 < index <= len(lines) or lines[index-1].strip() != text:
                    return False
                if text == command:
                    if loaded != set(declarations) or mapped:
                        return False
                    mapped = True
                else:
                    if mapped:
                        return False
                    active = next(name for name, value in declarations.items() if value == text)
        success = re.fullmatch(r"\[INFO\]\s+\[\s*LIB-I-0011\]\s+Liberty file '([^'\n]+)' is read successfully\.\s*", line)
        if success and active == success[1]:
            loaded.add(active)
    if not mapped:
        return False
    try:
        library, unknown = _libraries([Path(name) for name in declarations])
    except OSError:
        return False
    return (not unknown and source in library and target in library and
            _compatible(library[source], library[target]) is True)


def mapping_command_evidence(issue: dict, files: list[Path], output_dir: Path,
                             dofile: str, words_for) -> dict | None:
    """Bind a failed DFF mapping to a later executed mapping and native SFF row.

    The source cell comes from the real failed command, not a model's abbreviated
    replacement phrase. This proves the observed mapping/configuration only;
    all scan, task, structure and equivalence requirements still apply.
    """
    from operation_audit import operation_trace, post_operation_report

    phase = operation_trace(files, output_dir, dofile, words_for)
    if phase is None:
        return None
    old = words_for(failed_command(issue.get('found', {}), output_dir) or '')
    located = words_for(str(issue.get('diagnosis', {}).get('located_object', '')))
    if (len(old) != 3 or old[0] != 'set_scan_cell_mapping' or
            not 1 <= len(located) <= 3 or located != old[:len(located)] or
            any(not re.fullmatch(r'[A-Za-z_]\w*', value) for value in old[1:])):
        return None
    designs = _full_insertion_designs(dofile)
    if len(designs) != 1:
        return None
    selected = []
    for chunk in tcl_chunks(dofile):
        text = chunk.strip().replace('\\\n', ' ')
        if not text or text.startswith('#'):
            continue
        words = words_for(text)
        if words and words[0] == 'exit':
            break
        if words and words[0] in {'source', 'eval', 'uplevel', 'interp', 'namespace'}:
            return None
        if words and words[0] == 'set_scan_cell_mapping':
            if len(words) != 3 or any(not re.fullmatch(r'[A-Za-z_]\w*', value) for value in words[1:]):
                return None
            if words[1] == old[1]:
                selected.append((text, words[2]))
        elif re.search(r'\bset_scan_cell_mapping\b', text):
            return None
    if len(selected) != 1:
        return None
    command, target = selected[0]
    same_target = target == old[2]
    old_run = str(issue.get('found', {}).get('run_ref', ''))
    for log in files:
        run = log.parent
        if log.name != run.name+'.log' or not re.fullmatch(r'R[1-9]\d*', run.name):
            continue
        if (not re.fullmatch(r'R[1-9]\d*', old_run) or int(run.name[1:]) <= int(old_run[1:]) or
                log.is_symlink() or not log.resolve().is_relative_to((output_dir/'runs'/run.name).resolve())):
            continue
        script = run/'deliverables'/(run.name+'.dofile')
        if not script.is_file() or script.is_symlink() or script.read_text() != dofile:
            continue
        echoed = source_bound = replaced = False
        with log.open(errors='replace') as stream:
            for line in stream:
                if re.search(r'\[(?:ERROR|FATAL)\]', line):
                    return None
                origin = re.search(r'\[SOURCE TCL FILE\]\s+(\S+)\s*:', line)
                if origin:
                    path = PurePosixPath(origin[1]);parts = path.parts
                    indexes = [i for i, part in enumerate(parts) if part == 'runs' and parts[i+1:i+2] == (run.name,)]
                    if source_bound or '..' in parts or len(indexes) != 1:
                        return None
                    actual = run.joinpath(*parts[indexes[0]+2:])
                    if (not actual.is_file() or actual.is_symlink() or not actual.resolve().is_relative_to(run.resolve()) or
                            actual.read_bytes() != script.read_bytes()):
                        return None
                    source_bound = True
                echo = re.search(r'CMD-0034\]\s+@(\d+):\s*(.*)', line)
                if echo and echo[2].strip() == command:
                    number = int(echo[1]);lines = dofile.splitlines()
                    echoed = bool(source_bound and 0 < number <= len(lines) and lines[number-1].strip() == command)
                match = re.search(r"SCAN-7600\]\s+There were (\d+) 'D' flip-flops that have been replaced\.", line)
                if match and int(match[1]) > 0 and echoed:
                    replaced = True
        if not source_bound or not echoed or not replaced:
            continue
        if same_target and not _mapping_library_repair(issue, run, log, dofile, command, old[1], target, words_for):
            continue
        for path in files:
            if (not any(name in path.name.lower() for name in ('cell', 'element')) or
                    path.suffix != '.rpt' or path.is_symlink() or
                    not path.resolve().is_relative_to(run.resolve())):
                continue
            stage = post_operation_report(path, 'rpt_scan_chain_cell', phase, output_dir)
            if stage is None:
                continue
            with path.open(errors='replace') as stream:
                header = ''.join(next(stream, '') for _ in range(5))
            if re.findall(r'(?m)^\s*Design\s*:\s*(\S+)\s*$', header) != list(designs):
                continue
            for row in report_rows(path, {'RefName', 'InstanceName', 'Clocks'}):
                if row['RefName'] == target and row['InstanceName'] and row['Clocks']:
                    with path.open(errors='replace') as stream:
                        line = next(text for number, text in enumerate(stream, 1) if number == row['line'])
                    return {'source': path.relative_to(output_dir).as_posix(),
                            'locator': f"L{row['line']}", 'excerpt': line.strip(),
                            'operation_evidence': [phase['operation'], stage]}
    return None
