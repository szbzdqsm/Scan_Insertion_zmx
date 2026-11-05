"""Formal marker-gated startup, retaining the historical module path.

Input contents are checked only after case_upload_marker is observed. Waiting
does not consume the case budget; the business receives that observation time.
"""
from __future__ import annotations

import json
import math
import os
from pathlib import Path
import re
import stat
import sys
import time

import model_config
from case_deadline import CaseDeadline, CaseDeadlineExceeded
from platform_protocol import (arguments, wait_input, activate_marker_ready, publish_completion,
                               prepare_case_output, OutputDirectoryError)
from runtime_limits import effective_case_seconds

VERSION = '1104-marker-v1'


class StartupError(ValueError):
    pass


def log(stage, **facts):
    print('[startup] ' + json.dumps({'version': VERSION, 'mode': 'marker',
                                   'stage': stage, **facts}, ensure_ascii=False), flush=True)


def readable_file(path):
    try:
        # Opening only one byte tests readability without parsing design content.
        if not stat.S_ISREG(path.stat().st_mode):
            return False
        with path.open('rb') as stream:
            return bool(stream.read(1))
    except (OSError, ValueError):
        return False


def input_check(root):
    if not root.is_dir():
        raise StartupError('Input directory missing or not a directory: ' + str(root))
    case = root / 'input' if not (root / 'task_spec.md').is_file() and (root / 'input/task_spec.md').is_file() else root
    missing = [str(case / name) for name in ('task_spec.md', 'limitations.md') if not readable_file(case / name)]
    if missing:
        raise StartupError('Missing, empty, or unreadable required input: ' + ', '.join(missing))
    return case


def check_design_files(case):
    required = []
    missing = []
    for folder, suffix in [('netlist', '.v'), ('lib', '.lib')]:
        files = sorted((case / folder).rglob('*' + suffix)) if (case / folder).is_dir() else []
        if not files:
            missing.append(str(case / folder / ('*' + suffix)))
        required.extend(files)
    # Honor explicit input paths, including auxiliary CTL, without reading
    # reference answers or attempting to infer a case ID from folder names.
    with (case / 'task_spec.md').open() as stream:
        spec = stream.read(60000)
    for match in re.finditer(r'`(?:input/)?((?:netlist|lib|ctl)/[^`\r\n]+)`', spec):
        relative = Path(match.group(1))
        if '..' in relative.parts or relative.is_absolute():
            raise StartupError('Invalid relative input path in task specification')
        required.append(case / relative)
    original = case / 'original.dofile'
    if original.exists() or 'original.dofile' in spec:
        required.append(original)
    missing += [str(p) for p in dict.fromkeys(required) if not readable_file(p)]
    if missing:
        raise StartupError('Missing, empty, or unreadable required input: ' + ', '.join(missing))
    return {'case_input': str(case), 'required_files_checked': len(set(required)) + 2,
            'netlists': sum(p.suffix == '.v' for p in set(required)),
            'libraries': sum(p.suffix == '.lib' for p in set(required))}


def startup_failure(output, clock, error):
    # Never overwrite previous results or claim an interrupted business run was
    # finalized. A platform capture log can coexist with this case's failure.
    if output is None:
        return
    try:
        prepare_case_output(output)
        with (output / 'startup_failure.json').open('x') as stream:
            json.dump({'version': VERSION, 'mode': 'marker', 'error': error,
                       'entry_clock': clock, 'business_entered': False}, stream, indent=2)
            stream.flush()
            os.fsync(stream.fileno())
        publish_completion(output, 2, clock)
    except (OSError, OutputDirectoryError):
        print('[startup] failed to persist startup failure in output', file=sys.stderr, flush=True)


def run(started, utc_started):
    clock = {'entry_monotonic_seconds': started, 'entry_utc_seconds': utc_started,
             'event': 'local_entry_started', 'startup_mode': 'marker',
             'clock_basis': 'local observation of case_upload_marker; not platform t1',
             'input_ready_observed': False}
    output = None
    guard = None
    business_entered = False
    try:
        args = arguments()
        root, output = Path(args.input).resolve(), Path(os.path.abspath(args.output))
        # Do not write into the input mount or consume prior output as results.
        if output.resolve() == root or root in output.resolve().parents:
            output = None
            raise StartupError('Output must be outside the input directory')
        log('checking_output', input_root=str(root), output_root=str(output))
        try:
            output_facts = prepare_case_output(output)
        except OutputDirectoryError:
            output = None
            raise
        clock['output_initialization'] = output_facts
        log('output_validated', **output_facts)
        log('waiting_for_input_marker', marker=str(root / 'case_upload_marker'),
            business_budget_started=False)
        ready = wait_input(root)
        clock.update(ready, input_ready_observed=True,
                     input_wait_seconds=ready['monotonic_seconds'] - started)
        started = ready['monotonic_seconds']
        log('input_marker_observed', **clock)
        log('checking_input', input_root=str(root), output_root=str(output))
        case = input_check(root)
        with (case / 'limitations.md').open() as stream:
            limits = stream.read(1024 * 1024)
        limit = effective_case_seconds(limits, os.environ.get('AGENT_CASE_TIMEOUT'))
        supplied = os.environ.get('AGENT_CONTROLLER_REMAINING_SECONDS', '').strip()
        if supplied:
            remaining = float(supplied)
            if not math.isfinite(remaining) or remaining <= 0:
                raise StartupError('Invalid controller remaining duration')
            limit = min(limit, remaining)
        # One observed-ready start covers validation, imports, work and closing.
        guard = CaseDeadline(started + limit)
        guard.arm()
        clock.update(deadline_monotonic=started + limit, limit_seconds=limit)
        facts = check_design_files(case)
        log('input_validated', **facts, deadline_monotonic=started + limit,
            remaining_seconds=max(0, started + limit - time.monotonic()))
        try:
            selected_model, _, _ = model_config.settings()
        except ValueError as exc:
            raise StartupError(str(exc)) from None
        if not os.environ.get('SCANINSERTION_LICENSE_SERVER', '').strip():
            raise StartupError('SCANINSERTION_LICENSE_SERVER must be injected at runtime')
        log('configuration_validated', model=selected_model)
        clock.update(event='marker_input_validated', input_check_passed=True,
                     input_root=str(root), input_check=facts)
        activate_marker_ready(clock)
        log('importing_business')
        from scan_agent import main
        log('entering_business', remaining_seconds=max(0, started + limit - time.monotonic()))
        business_entered = True
        return main(started_at=started, entry_clock=clock)
    except (Exception, CaseDeadlineExceeded) as exc:
        # Known validation errors never contain configuration values. For an
        # unexpected import/business error report the class, not arbitrary data.
        error = str(exc) if isinstance(exc, (StartupError, CaseDeadlineExceeded, OutputDirectoryError)) else type(exc).__name__
        log('failed', error=error, business_entered=business_entered)
        print('[startup] ' + error, file=sys.stderr, flush=True)
        if not business_entered:
            startup_failure(output, clock, error)
        return 2
    finally:
        if guard is not None:
            guard.close()
