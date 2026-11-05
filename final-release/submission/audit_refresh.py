"""Read-only selection of existing evidence for an existing issue's audit plan.

This module neither calls a model nor declares a repair successful. The caller
must freeze inputs/proofs/artifacts and run the existing semantic verifier again.
"""
from __future__ import annotations

import json
import copy
import hashlib
from pathlib import Path, PurePosixPath
import re
from typing import Any


def _eligible(issues: list[dict], runs: list[dict], current_run: str) -> dict[str, dict]:
    ids = [run.get("run_id", run.get("tool_call_id")) for run in runs]
    if (not ids or any(not isinstance(identity, str) or not re.fullmatch(r"R[1-9]\d*", identity) for identity in ids) or
            len(set(ids)) != len(ids) or ids[-1] != current_run):
        raise ValueError("Audit refresh requires the latest actual tool run")
    current = runs[-1]
    if current.get("status", current.get("exit_status")) != "completed" or current.get("returncode") != 0:
        raise ValueError("Audit refresh requires an actually completed successful tool process")
    result = {}
    seen = set()
    for issue in issues:
        identity = issue.get("issue_id")
        if not isinstance(identity, str) or identity in seen:
            raise ValueError("Existing issue identifiers must be unique strings")
        seen.add(identity)
        found = issue.get("found", {})
        attempts = issue.get("attempts", [])
        if (found.get("verified") is True and found.get("run_ref") in ids[:-1] and attempts and
                attempts[-1].get("fix", {}).get("artifact_ref") and
                not attempts[-1].get("verify", {}).get("resolved")):
            result[identity] = issue
    return result


def _catalog_entry(entry: Any, current_run: str) -> dict[str, str]:
    if not isinstance(entry, dict):
        raise ValueError("Evidence must be a catalog object")
    source, locator, excerpt = (entry.get(key) for key in ("source", "locator", "excerpt"))
    if not all(isinstance(value, str) and value for value in (source, locator, excerpt)):
        raise ValueError("Evidence needs an exact source, line locator and excerpt")
    path = PurePosixPath(source)
    if (path.is_absolute() or ".." in path.parts or path.parts[:2] != ("runs", current_run) or
            path.suffix.lower() not in {".log", ".rpt", ".report", ".txt"}):
        raise ValueError("Evidence must come from the current actual run's tool log/report")
    match = re.fullmatch(r"L([1-9]\d*)(?:-L([1-9]\d*))?", locator)
    if not match or int(match.group(2) or match.group(1)) < int(match.group(1)):
        raise ValueError("Invalid evidence line locator")
    return {"source": source, "locator": locator, "excerpt": excerpt}


def current_evidence_catalog(output_dir: Path, current_run: str, *, maximum: int = 32,
                             byte_budget: int = 16000) -> dict[str, dict[str, str]]:
    """Offer bounded real report lines/windows, without labelling them successful.

    The semantic verifier decides whether a selected candidate proves that issue.
    Full small reports allow aggregate/partition evidence without invented text.
    """
    root = output_dir / "runs" / current_run
    if not re.fullmatch(r"R[1-9]\d*", current_run):
        raise ValueError("Invalid current tool run identifier")
    if maximum <= 0 or byte_budget <= 0:
        return {}
    paths = sorted(path for path in (root / "reports").rglob("*") if path.is_file() and
                   path.suffix.lower() in {".rpt", ".report", ".txt"})
    paths += [root / f"{current_run}.log"]
    catalog = {}
    consumed = 0
    for path in paths:
        if not path.is_file() or not path.resolve().is_relative_to(root.resolve()):
            continue
        small = path.stat().st_size <= min(3000, byte_budget - consumed)
        with path.open(encoding="utf-8", errors="replace") as stream:
            if small:
                text = stream.read()
                exact = text.rstrip("\r\n")
                candidates = [(1, len(exact.splitlines()), exact)] if text.strip() else []
            else:
                candidates = []
                inspected = 0
                for number, line in enumerate(stream, 1):
                    inspected += len(line.encode("utf-8"))
                    if inspected > 131072:
                        break
                    text = line.rstrip("\r\n")
                    if len(text.encode("utf-8")) <= 1000 and re.search(
                            r"Total violations:|Design:|SignalType|ScanConfigurationParameter|"
                            r"WrapperConfigurationParameter|^\s*[IW]\s+\S+\s+\d+|"
                            r"\[INFO\].*(?:completed|successfully|passed)", text, re.I):
                        candidates.append((number, number, text))
                    if len(candidates) >= 8:
                        break
        for first, last, text in candidates:
            length = len(text.encode("utf-8"))
            if consumed + length > byte_budget or len(catalog) >= maximum:
                return catalog
            consumed += length
            catalog[f"V{len(catalog) + 1}"] = {
                "source": path.relative_to(output_dir).as_posix(),
                "locator": f"L{first}" if first == last else f"L{first}-L{last}", "excerpt": text}
    return catalog


def build_audit_refresh_request(issues: list[dict], run_records: list[dict], current_run: str,
                                catalog: dict[str, dict[str, str]]) -> list[dict[str, str]]:
    eligible = _eligible(issues, run_records, current_run)
    checked_catalog = {key: _catalog_entry(value, current_run) for key, value in catalog.items()}
    system = (
        "Select verification evidence for existing unresolved audit issues only. No tool will run. "
        "The listed current run already executed; only its actual catalog text may be selected. "
        "Return exactly one JSON object: {\"verification_updates\":[{\"issue_id\":\"I1\",\"evidence_id\":\"V1\"}]}. "
        "Return {\"verification_updates\":[]} if the supplied evidence cannot prove an issue's existing fix. "
        "Output only the JSON object, without markdown fences or other text. "
        "Do not change diagnoses, discoveries, fixes, Dofiles, netlists or run identifiers; do not "
        "withdraw issues or claim success/resolved. A runtime semantic verifier decides closure. "
        "Absence of an old diagnostic is not positive evidence."
    )
    return [{"role": "system", "content": system}, {"role": "user", "content": json.dumps(
        {"current_actual_run": current_run, "issues": list(eligible.values()),
         "current_actual_evidence_catalog": checked_catalog}, ensure_ascii=False)}]


def validate_audit_refresh(response: Any, issues: list[dict], run_records: list[dict], current_run: str,
                           catalog: dict[str, dict[str, str]]) -> dict[str, dict[str, str]]:
    """Return new verification plans; leave issues/found/fixes/run records intact."""
    eligible = _eligible(issues, run_records, current_run)
    if not isinstance(response, dict) or set(response) != {"verification_updates"}:
        raise ValueError("Only verification_updates are permitted in audit refresh")
    updates = response["verification_updates"]
    if not isinstance(updates, list) or len(updates) > len(eligible):
        raise ValueError("Invalid audit verification update list")
    plans = {}
    for update in updates:
        if not isinstance(update, dict) or set(update) != {"issue_id", "evidence_id"}:
            raise ValueError("An audit update may select only issue_id and evidence_id")
        identity, evidence_id = update["issue_id"], update["evidence_id"]
        if not isinstance(identity, str) or identity not in eligible or identity in plans:
            raise ValueError("Unknown, duplicate or ineligible existing issue_id")
        if not isinstance(evidence_id, str) or evidence_id not in catalog:
            raise ValueError("Unknown current actual evidence_id")
        evidence = _catalog_entry(catalog[evidence_id], current_run)
        plans[identity] = {"source": evidence["source"], "locator": evidence["locator"],
                           "expected_excerpt": evidence["excerpt"]}
    return plans


def issue_digest(issue: dict) -> str:
    return hashlib.sha256(json.dumps(issue, ensure_ascii=False, sort_keys=True,
                                    separators=(',', ':')).encode()).hexdigest()


def record_verification_projection(root, original, verified, current):
    """Immutable native-verifier history; never a model-authored revision.

    This sidecar preserves old booleans/attempts before a production caller
    adopts a rechecked view. It supplies no proof or permission to close it.
    Read-only independent validators do not enable this explicit journal.
    """
    if original == verified:
        return None
    import os
    from artifact_operations import assert_output_directories
    if not re.fullmatch(r'R[1-9]\d*', current):
        raise ValueError('Verification projection requires an actual round')
    folder = root/'audit_verification'/current
    folder.parent.mkdir(exist_ok=True)
    assert_output_directories(root, ['audit_verification'])
    folder.mkdir(exist_ok=True)
    assert_output_directories(root, ['audit_verification/'+current])
    record = {'kind': 'native_verification_projection_not_model_revision',
              'run_ref': current, 'original_issue': copy.deepcopy(original),
              'original_issue_hash': issue_digest(original),
              'verified_issue': copy.deepcopy(verified),
              'verified_issue_hash': issue_digest(verified),
              'new_tool_execution': False}
    data = json.dumps(record, ensure_ascii=False, sort_keys=True, indent=2)
    path = folder/(hashlib.sha256(data.encode()).hexdigest()+'.json')
    if path.exists():
        if path.is_symlink() or not path.is_file() or path.read_text() != data:
            raise ValueError('Verification projection history changed')
    else:
        with path.open('x', encoding='utf-8') as stream:
            stream.write(data); stream.flush(); os.fsync(stream.fileno())
    return path.relative_to(root).as_posix()


def _fact_file(root: Path, source: str) -> Path:
    path = PurePosixPath(source)
    if (path.is_absolute() or '..' in path.parts or not path.parts or
            path.parts[0] not in {'runs', 'diffs'} or path.suffix not in {'.log', '.rpt', '.dofile', '.diff'}):
        raise ValueError('Correction facts must be registered scripts/diffs/native reports')
    p = root / source
    if p.resolve() != p.absolute() or not p.is_file() or p.stat().st_size > 8 * 1024 * 1024:
        raise ValueError('Correction fact absent, linked or outside bounded size')
    return p


def _fact_ref(root: Path, source: str, first: int, last: int) -> dict:
    path = _fact_file(root, source)
    raw = path.read_bytes(); lines = raw.decode('utf-8', errors='replace').splitlines()
    if not 1 <= first <= last <= len(lines):
        raise ValueError('Invalid actual fact line range')
    return {'source': source, 'locator': f'L{first}' if first == last else f'L{first}-L{last}',
            'excerpt': '\n'.join(lines[first-1:last]), 'sha256': hashlib.sha256(raw).hexdigest()}


def _literal_action_correction_context(issues, runs, current, changes, root, words_for):
    """Correct a reference to a proven add_port/add_net, never invent an edit.

    This reuses the existing one-selection transaction and immutable final
    projection. Only an exact named object, byte-verified introducing delta,
    native command echo and its own success record can produce an option.
    General diagnostic causes and the old discovery remain unproved.
    """
    import difflib
    from collections import Counter
    from operation_audit import fix_action_reference_problems
    for issue in _eligible(issues, runs, current).values():
        try:
            failures = fix_action_reference_problems(issue, changes, root, words_for)
            if len(failures) != 1:
                continue
            commands = failures[0].get('required_commands', [])
            if len(commands) != 1 or commands[0] not in {'add_port', 'add_net'}:
                continue
            target = issue['diagnosis']['located_object']
            if not re.fullmatch(r'[A-Za-z_][\w/.$]*(?:\[\d+\])?', target):
                continue
            current_script = _fact_file(root, f'runs/{current}/deliverables/{current}.dofile').read_text()
            candidates = []
            for change in changes:
                if change.get('type') != 'dofile':
                    continue
                delta = _fact_file(root, change['diff_path']).read_text()
                header = re.match(r'--- (R[1-9]\d*)\n\+\+\+ (R[1-9]\d*)\n', delta)
                if not header:
                    continue
                old, new = header.groups()
                if not int(issue['found']['run_ref'][1:]) <= int(old[1:]) < int(new[1:]) <= int(current[1:]):
                    continue
                if change['path'] != f'runs/{new}/deliverables/{new}.dofile':
                    continue
                before = _fact_file(root, f'runs/{old}/deliverables/{old}.dofile').read_text()
                after = _fact_file(root, change['path']).read_text()
                expected = ''.join(difflib.unified_diff(before.splitlines(True), after.splitlines(True), fromfile=old, tofile=new))
                if delta != expected:
                    continue
                rows = [(n, line, words_for(line)) for n, line in enumerate(after.splitlines(), 1)]
                prior = Counter(tuple(words_for(line)) for line in before.splitlines())
                for number, line, words in rows:
                    if (len(words) < 2 or words[0] != commands[0] or words[1] != target or
                            any(re.search(r'[$\[\]{};]', x) for x in words) or
                            prior[tuple(words)] or sum(w == words for _, _, w in rows) != 1 or
                            sum(words_for(s) == words for s in current_script.splitlines()) != 1):
                        continue
                    logsource = f'runs/{new}/{new}.log'
                    log = _fact_file(root, logsource).read_text().splitlines()
                    echoes = [i for i, text in enumerate(log) if re.search(
                        r'CMD-0034\]\s+@'+str(number)+r':\s*'+re.escape(line.strip())+r'\s*$', text)]
                    if len(echoes) != 1:
                        continue
                    index = echoes[0]
                    code, noun = ('1004', 'port') if words[0] == 'add_port' else ('1003', 'net')
                    if (index+2 >= len(log) or log[index+2].strip() != '1' or
                            not re.search(r'\[INFO\].*CMD-'+code+r'\].*Successfully added '+noun+r" '"+re.escape(target)+r"'", log[index+1])):
                        continue
                    designs = re.findall(r'CMD-0034\]\s+@\d+:\s*present_design\s+(\w+)\s*$', '\n'.join(log[:index]), re.M)
                    current_designs = re.findall(r'^\s*present_design\s+(\w+)\s*$', current_script, re.M)
                    if len(designs) != 1 or current_designs != designs:
                        continue
                    refs = [_fact_ref(root, change['path'], number, number),
                            _fact_ref(root, logsource, index+1, index+3)]
                    added = [n for n, text in enumerate(delta.splitlines(), 1) if text == '+'+line]
                    if len(added) != 1:
                        continue
                    refs.append(_fact_ref(root, change['diff_path'], added[0], added[0]))
                    found = issue['found']; locator = re.fullmatch(r'L(\d+)(?:-L(\d+))?', found['locator'])
                    if not locator:
                        continue
                    fact = _fact_ref(root, found['source'], int(locator[1]), int(locator[2] or locator[1]))
                    if found['excerpt'] not in fact['excerpt']:
                        continue
                    refs.append(fact)
                    action = 'Executed the recorded command '+line.strip()+' in '+new+'.'
                    candidates.append({'issue_id': issue['issue_id'], 'base_issue_hash': issue_digest(issue),
                        'attempt_index': len(issue['attempts'])-1, 'current_actual_run': current,
                        'proposal_id': 'P1', 'kind': 'native_literal_action_reference',
                        'field_updates': {'diagnosis.summary': issue['diagnosis']['summary'],
                            'diagnosis.root_cause': issue['diagnosis']['root_cause'],
                            'attempt.fix.action': action, 'attempt.fix.artifact_ref': [change['change_id']]},
                        'facts': {f'C{i+1}': r for i, r in enumerate(refs)}, 'scope_complete': False,
                        'operation_proof': {'status': 'native_command_recorded', 'design': designs[0],
                            'object': target, 'command': line.strip(), 'actual_run': new},
                        'base_run_change_hash': issue_digest({'runs': runs, 'changes': changes})})
            if len(candidates) == 1:
                return candidates[0]
        except (OSError, ValueError, TypeError, KeyError, IndexError):
            continue
    return None


def correction_context(issues: list[dict], runs: list[dict], current: str, changes: list[dict],
                       root: Path, words_for) -> dict | None:
    """A deliberately finite capability: proven literal missing-port corrections.

    Reuse the strict existing correction verifier to derive facts, not to close
    the original diagnosis. Aggregate DRC observations keep an incomplete scope.
    No case/object names or saved answers are used. Unknown Tcl/scope abstains.
    """
    from configuration_evidence import _signal_command_trace, _signal_port_correction, claim_parameters
    for issue in _eligible(issues, runs, current).values():
        try:
            old = issue['found']['run_ref']
            location = words_for(issue['diagnosis']['located_object'])
            if location[:1] != ['set_scan_signal'] or '-port' not in location:
                continue
            target_port = location[location.index('-port')+1]
            prior = _signal_command_trace(root, old, words_for)
            after = _signal_command_trace(root, current, words_for)
            if not prior or not after:
                continue
            candidates = []
            for event in prior['signals']:
                for error in event['errors']:
                    match = re.search(r"Port '([A-Za-z_]\w*)' does not exist in the design\.", error['text'])
                    if not match:
                        continue
                    before_words = event['words']
                    for fixed in after['signals']:
                        now = fixed['words']
                        if len(now) != len(before_words) or '-port' not in now:
                            continue
                        index = now.index('-port')+1
                        if (target_port not in {before_words[index], now[index]} or
                                before_words[index] == now[index] or
                                before_words[:index]+before_words[index+1:] != now[:index]+now[index+1:]):
                            continue
                        found = {'run_ref': old, 'source': event['source'],
                                 'locator': f"L{error['line']}", 'excerpt': error['text'], 'verified': True}
                        for change in changes:
                            # A removed command elsewhere plus another added
                            # command is not a rename/correction mapping. This
                            # finite path accepts only an isolated -/+ pair in
                            # the byte-checked actual diff, never similarity.
                            delta = _fact_file(root, change['diff_path']).read_text().splitlines()
                            paired = any(
                                line.startswith('-') and not line.startswith('---') and
                                delta[n+1].startswith('+') and not delta[n+1].startswith('+++') and
                                words_for(line[1:]) == before_words and words_for(delta[n+1][1:]) == now and
                                (n == 0 or not delta[n-1].startswith('-')) and
                                (n+2 == len(delta) or not delta[n+2].startswith('+'))
                                for n, line in enumerate(delta[:-1]))
                            if not paired:
                                continue
                            # A synthetic query proves only the actual command
                            # operation; it never replaces the issue's discovery.
                            probe = copy.deepcopy(issue)
                            probe['found'] = found
                            probe['diagnosis']['located_object'] = ' '.join(before_words)
                            action = f'Changed -port {before_words[index]} to -port {now[index]}.'
                            probe['attempts'][-1]['fix'] = {'action': action, 'artifact_ref': [change['change_id']]}
                            native_files = sorted((root/'runs'/current/'reports').glob('*.rpt')) + [root/'runs'/current/(current+'.log')]
                            proof = _signal_port_correction(probe, native_files, root,
                                (root/'runs'/current/'deliverables'/(current+'.dofile')).read_text(), words_for, changes)
                            if proof['status'] == 'pass':
                                candidates.append((event, fixed, error, found, action, change, proof))
            if len(candidates) != 1:
                continue
            event, fixed, error, fact_found, action, change, proof = candidates[0]
            refs = [
                _fact_ref(root, event['source'], error['line'], error['line']),
                _fact_ref(root, f'runs/{old}/deliverables/{old}.dofile', event['script_line'], event['script_line']),
                _fact_ref(root, change['path'], fixed['script_line'], fixed['script_line']),
                _fact_ref(root, fixed['source'], int(fixed['locator'][1:]), int(fixed['locator'][1:])),
            ]
            diff_path = _fact_file(root, change['diff_path'])
            if diff_path.stat().st_size > 16000:
                continue
            refs.append(_fact_ref(root, change['diff_path'], 1, len(diff_path.read_text().splitlines())))
            positive = proof['evidence']; m = re.fullmatch(r'L(\d+)(?:-L(\d+))?', positive['locator'])
            refs.append(_fact_ref(root, positive['source'], int(m[1]), int(m[2] or m[1])))
            original_found = issue['found']
            loc = re.fullmatch(r'L(\d+)(?:-L(\d+))?', original_found['locator'])
            if not loc:
                continue
            discovery = _fact_ref(root, original_found['source'], int(loc[1]), int(loc[2] or loc[1]))
            if original_found['excerpt'] not in discovery['excerpt']:
                continue
            refs.append(discovery)
            # A claim about a previously absent configuration may be corrected
            # only if its actual old declaration/native execution is retained.
            preserved = []
            old_script = (root/'runs'/old/'deliverables'/(old+'.dofile')).read_text()
            new_script = (root/'runs'/current/'deliverables'/(current+'.dofile')).read_text()
            old_log = _fact_file(root, f'runs/{old}/{old}.log').read_text().splitlines()
            for parameter in sorted(claim_parameters(issue)):
                lines = [(n, line) for n, line in enumerate(old_script.splitlines(), 1)
                         if (words_for(line) or [''])[0] == 'set_scan_cfg' and '-'+parameter in words_for(line)]
                if len(lines) != 1 or new_script.splitlines().count(lines[0][1]) != 1:
                    raise ValueError('An original configuration premise is not safely refuted')
                n, text = lines[0]
                matches = [i for i, line in enumerate(old_log) if re.search(
                    r'CMD-0034\]\s+@'+str(n)+r':\s*'+re.escape(text.strip())+r'\s*$', line)]
                if len(matches) != 1 or matches[0]+1 >= len(old_log) or old_log[matches[0]+1].strip() != '1':
                    raise ValueError('Old configuration execution is not positively recorded')
                refs += [_fact_ref(root, f'runs/{old}/deliverables/{old}.dofile', n, n),
                         _fact_ref(root, f'runs/{old}/{old}.log', matches[0]+1, matches[0]+2)]
                preserved.append(text.strip())
            complete_scope = (original_found['source'] == fact_found['source'] and
                              original_found['locator'] == fact_found['locator'] and
                              original_found['excerpt'].strip() == fact_found['excerpt'].strip())
            summary = (f"Native execution in {old} rejected the command target {proof['old_port']}; "
                       f"the recorded {change['change_id']} correction targets the existing port {proof['new_port']} "
                       f"in design {proof['design']} and partition {event['partition']}.")
            if preserved:
                summary += ' Previously executed configuration was retained, not added: ' + ' ; '.join(preserved) + '.'
            root_cause = f"The command target {proof['old_port']} did not exist; {proof['new_port']} is the native pre-existing port."
            if not complete_scope:
                root_cause += ' This establishes the command error, but the cause of the complete original diagnostic scope remains unproven.'
            update = {'diagnosis.summary': summary, 'diagnosis.root_cause': root_cause,
                      'attempt.fix.action': action, 'attempt.fix.artifact_ref': [change['change_id']]}
            if (issue['diagnosis']['summary'] == summary and issue['diagnosis']['root_cause'] == root_cause and
                    issue['attempts'][-1]['fix'] == {'action': action, 'artifact_ref': [change['change_id']]}):
                continue
            catalog = {f'C{i+1}': r for i, r in enumerate(refs)}
            if len(catalog) > 16 or sum(len(r['excerpt'].encode()) for r in refs) > 12000:
                continue
            return {'issue_id': issue['issue_id'], 'base_issue_hash': issue_digest(issue),
                    'attempt_index': len(issue['attempts'])-1, 'current_actual_run': current,
                    'proposal_id': 'P1', 'field_updates': update, 'facts': catalog,
                    'scope_complete': complete_scope, 'operation_proof': proof,
                    'base_run_change_hash': issue_digest({'runs': runs, 'changes': changes})}
        except (OSError, ValueError, TypeError, KeyError, IndexError):
            continue
    return _literal_action_correction_context(issues, runs, current, changes, root, words_for)


def correction_messages(context: dict, issue: dict) -> list[dict]:
    compact = {k: issue[k] for k in ['issue_id', 'phenomenon', 'found', 'diagnosis']}
    compact['attempts'] = [{'fix': a['fix'], 'verify': {k: a['verify'].get(k) for k in
                           ['run_ref', 'source', 'resolved', 'locator', 'excerpt']}} for a in issue['attempts']]
    prompt = (
        'One read-only record correction opportunity; no tool or script will execute. '
        'The immutable original is not an effective corrected record. You may select the supplied '
        'fact-grounded patch for this one existing issue/attempt, or decline it. No free-form edits, '
        'withdrawals, new runs, objects, attempts, Dofiles/netlists or success flags are permitted. '
        'The selected patch only corrects descriptions of the actual command operation. It does not '
        'prove the entire original diagnostic or repair. Runtime revalidates every reference and scope. '
        'Return exactly JSON {"claim_corrections":[{"issue_id":"...","base_issue_hash":"...",'
        '"proposal_id":"P1","evidence_ids":["C1", "..."]}],"verification_updates":[]}. '
        'Cite all supplied correction fact IDs or decline with {"claim_corrections":[],"verification_updates":[]}. '
        'Do not change any fields in the supplied patch or claim resolved. No markdown.'
    )
    payload = {k: context[k] for k in ['issue_id', 'base_issue_hash', 'attempt_index', 'current_actual_run',
                                     'proposal_id', 'field_updates', 'facts', 'scope_complete']}
    return [{'role': 'system', 'content': prompt}, {'role': 'user', 'content': json.dumps(
        {'immutable_original': compact, 'record_patch_option': payload}, ensure_ascii=False)}]


def apply_claim_correction(response, context, issues, runs, current, changes, root, words_for):
    """Validate the whole record-only transaction; return a separate view."""
    if not isinstance(response, dict) or set(response) != {'claim_corrections', 'verification_updates'}:
        raise ValueError('Correction response contains unauthorized fields')
    if response['verification_updates'] != [] or not isinstance(response['claim_corrections'], list):
        raise ValueError('This finite correction transaction cannot mix unrelated changes')
    entries = response['claim_corrections']
    if entries == []:
        return None
    if len(entries) != 1 or not isinstance(entries[0], dict) or set(entries[0]) != {
            'issue_id', 'base_issue_hash', 'proposal_id', 'evidence_ids'}:
        raise ValueError('One exact record correction selection is required')
    entry = entries[0]
    if any(entry[k] != context[k] for k in ['issue_id', 'base_issue_hash', 'proposal_id']):
        raise ValueError('Unknown object/proposal or stale issue version')
    if (not isinstance(entry['evidence_ids'], list) or len(entry['evidence_ids']) != len(context['facts']) or
            set(entry['evidence_ids']) != set(context['facts'])):
        raise ValueError('Every required original-operation fact must be cited exactly once')
    fresh = correction_context(issues, runs, current, changes, root, words_for)
    if fresh != context:
        raise ValueError('Original issue, run, design, input binding or native evidence changed')
    issue = next(i for i in issues if i['issue_id'] == context['issue_id'])
    view = copy.deepcopy(issue)
    patch = context['field_updates']
    view['diagnosis']['summary'] = patch['diagnosis.summary']
    view['diagnosis']['root_cause'] = patch['diagnosis.root_cause']
    view['attempts'][context['attempt_index']]['fix'] = {
        'action': patch['attempt.fix.action'], 'artifact_ref': patch['attempt.fix.artifact_ref'][:]}
    # Discovery, located object, requirements, previous attempts and execution
    # IDs are immutable. No model-supplied verify state is accepted.
    return view


def effective_issue_views(issues, views, current, root=None):
    result = copy.deepcopy(issues)
    for index, issue in enumerate(result):
        entry = views.get(issue['issue_id'])
        intact = True
        if entry and root is not None:
            try:
                intact = all(hashlib.sha256(_fact_file(root, r['source']).read_bytes()).hexdigest() == r['sha256']
                             for r in entry['facts'].values())
                for source, digest in entry['journal'].items():
                    p = root/source
                    if (not p.is_relative_to(root/'audit_reviews') or p.resolve() != p.absolute() or
                            not p.is_file() or hashlib.sha256(p.read_bytes()).hexdigest() != digest):
                        intact = False
            except (OSError, ValueError):
                intact = False
        if entry and intact and entry['run_ref'] == current and entry['base_issue_hash'] == issue_digest(issue):
            result[index] = copy.deepcopy(entry['issue'])
    return result


def official_issue_projection(issue):
    """Existing appendix fields only; detailed checks stay in audit sidecars."""
    return {'issue_id': issue['issue_id'], 'phenomenon': issue['phenomenon'],
            'found': {k: issue['found'][k] for k in ['run_ref', 'source', 'locator', 'excerpt']},
            'diagnosis': {k: issue['diagnosis'].get(k, '') for k in
                          ['summary', 'located_object', 'root_cause', 'violated_requirement']},
            'attempts': [{'fix': copy.deepcopy(a['fix']),
                          'verify': {k: a['verify'][k] for k in
                                     ['run_ref', 'source', 'resolved', 'locator', 'excerpt']}}
                         for a in issue['attempts']]}
