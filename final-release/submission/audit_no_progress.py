"""Fail bounded audit stalls; never infer Tcl equivalence or task success."""
from pathlib import Path
import json
import re
import stat

from dofile_recipe import tcl_chunks
from model_script_view import model_owned_script


def audit_artifacts_unchanged(run_dir: Path, previous: tuple | None,
                              current: tuple | None) -> bool:
    """Retry guard only: ignore directory timestamps outside the actual run.

    Creating a sibling proposal changes its parents, not the previous native
    outputs. Preserve ancestor identity/mode/link bindings and every field for
    the run, its files, links and recorded external targets. Unknown snapshots
    never authorize the guard. This does not change the validation cache.
    """
    if not previous or not current:
        return False
    ancestors = {str(path) for path in run_dir.absolute().parents}

    def scoped(snapshot):
        result = []
        for row in snapshot:
            if len(row) != 8:
                return None
            if row[0] in ancestors and stat.S_ISDIR(row[3]):
                # path/dev/inode/mode and link target stay bound; an unrelated
                # sibling can legitimately change directory size/mtime/ctime.
                row = (*row[:4], row[7])
            result.append(row)
        return tuple(result)

    before, after = scoped(previous), scoped(current)
    return before is not None and after is not None and before == after


def save_stop_diagnostic(output_dir: Path, *, event: dict, issues: list,
                         plans: dict, tool_runs: list, changes: list) -> None:
    """Persist actual audit state before final artifact copies, never as success."""
    target = output_dir / 'audit_no_progress.json'
    temporary = target.with_suffix('.tmp')
    temporary.write_text(json.dumps({'status': 'failed_audit_no_progress',
        'scope': 'Diagnostic snapshot, not a final success result.', 'event': event,
        'issue_resolutions': issues, 'verification_plans': plans,
        'tool_runs': tool_runs, 'file_changes': changes}, ensure_ascii=False, indent=2))
    temporary.replace(target)


def execution_request(script: str) -> tuple[str, ...] | None:
    """Compare literal command requests, preserving quoted/braced contents.

    Only runtime-owned recipes and outside-command blank/comment chunks are
    omitted. This is a retry-budget signal, not a Tcl equivalence check.
    """
    if ';' in script or re.search(r'(?m)^\s*#.*\\\s*$', script):
        return None
    try:
        return tuple(text for chunk in tcl_chunks(model_owned_script(script))
                     if (text := chunk.strip()) and not text.startswith('#')) or None
    except ValueError:
        return None


def repeated_audit_request(previous: str, proposed: str, *, outputs_passed: bool,
                           audit_unclosed: bool, inputs_unchanged: bool,
                           artifacts_unchanged: bool, netlist_changes: bool) -> bool:
    if (not outputs_passed or not audit_unclosed or not inputs_unchanged or
            not artifacts_unchanged or netlist_changes):
        return False
    before, after = execution_request(previous), execution_request(proposed)
    return before is not None and after is not None and before == after


class AuditProgress:
    """Two output-valid rounds without new verified closure end in failure.

    Actual tool errors and input repairs remain separate. Model wording and
    another verification of the same issue do not count as new progress.
    """
    def __init__(self):
        self.stalled_rounds = 0
        self.resolved = set()
        self.input_signature = None

    def observe(self, issues: list[dict], *, outputs_passed: bool,
                audit_problems: list[str], input_signature: object,
                netlist_changes: bool = False) -> bool:
        resolved = set()
        for issue in issues:
            attempts = issue.get('attempts', [])
            verify = attempts[-1].get('verify', {}) if attempts else {}
            found = issue.get('found', {})
            if (found.get('verified') is True and verify.get('resolved') is True and
                    verify.get('source') and verify.get('locator') and verify.get('excerpt')):
                resolved.add((found.get('run_ref'), found.get('source'),
                              found.get('locator'), found.get('excerpt')))
        if not outputs_passed or not audit_problems:
            self.stalled_rounds = 0
            self.resolved = resolved
            self.input_signature = input_signature
            return False
        changed_inputs = input_signature != self.input_signature or netlist_changes
        progressed = bool(resolved - self.resolved)
        self.stalled_rounds = (1 if changed_inputs or progressed or not self.stalled_rounds
                               else self.stalled_rounds + 1)
        self.resolved = resolved if changed_inputs else self.resolved | resolved
        self.input_signature = input_signature
        return self.stalled_rounds >= 2


def audit_gap_details(issues: list[dict], plans: dict, output_dir: Path,
                      current_run: str, problems: list[str]) -> dict:
    """Inspect only bounded plan text in real current-run evidence, read-only.

    Finding a string is diagnostic, never positive semantic verification.
    Invalid, secret, answer, symlink and other-run references are not read.
    """
    gaps = []
    run = output_dir / 'runs' / current_run
    for issue in issues:
        attempts = issue.get('attempts', [])
        if attempts and attempts[-1].get('verify', {}).get('resolved') is True:
            continue
        plan = plans.get(issue.get('issue_id'), {})
        source = str(plan.get('source', ''))
        wanted = str(plan.get('expected_excerpt', ''))
        relative = Path(source)
        item = {'issue_id': issue.get('issue_id'), 'found': issue.get('found'),
                'requirement': issue.get('diagnosis', {}).get('violated_requirement', ''),
                'planned_source': source, 'expected_excerpt': wanted[:2000],
                'actual_run': current_run, 'reference_status': 'invalid_or_other_run'}
        if attempts and attempts[-1].get('verify', {}).get('operation_check'):
            item['operation_check'] = attempts[-1]['verify']['operation_check']
        if attempts and attempts[-1].get('verify', {}).get('configuration_check'):
            item['configuration_check'] = attempts[-1]['verify']['configuration_check']
        if attempts and attempts[-1].get('verify', {}).get('evidence_selection'):
            item['evidence_selection'] = attempts[-1]['verify']['evidence_selection']
        parts = relative.parts
        if (source and not relative.is_absolute() and '..' not in parts and
                not any(p in {'golden.dofile', 'preset_issues.json', 'answers', '.env'} or
                        p.startswith('.env.') for p in parts)):
            target = output_dir / relative if parts[:1] == ('runs',) else run / relative
            if target.is_symlink():
                item['reference_status'] = 'symlink_not_read'
            elif not target.resolve().is_relative_to(run.resolve()):
                item['reference_status'] = 'other_run_not_read'
            elif not target.is_file():
                item['reference_status'] = 'missing_file'
            elif not wanted or len(wanted) > 4000 or '\n' in wanted:
                item['reference_status'] = 'missing_or_unsupported_excerpt'
            else:
                present, scanned, exhausted = False, 0, False
                with target.open(errors='replace') as stream:
                    for line in stream:
                        scanned += len(line)
                        if wanted in line:
                            present = True
                            break
                        if scanned >= 1048576:
                            exhausted = True
                            break
                item['reference_status'] = ('text_exists_semantic_proof_still_missing' if present else
                                             'not_seen_in_bounded_scan' if exhausted else 'expected_text_absent')
        gaps.append(item)
    return {'actual_run': current_run, 'problems': problems, 'unresolved': gaps,
            'instruction': 'Inspect existing native evidence and bind each required object. '
                           'A successful output check or another identical insertion cannot close this audit. '
                           'Only propose a different execution when an actual required operation is missing. '
                           'This diagnostic is not semantic proof, Tcl equivalence, or task success.'}
