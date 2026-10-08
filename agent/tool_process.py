"""Run the actual tool, retaining process state and cleaning its whole group."""
from __future__ import annotations

import os
from pathlib import Path
import re
import signal
import subprocess
import time

from case_deadline import CaseDeadlineExceeded
from drc_validation import redirected_drc_codes, rule_codes


def stop_group(process: subprocess.Popen) -> bool:
    alive = process.poll() is None
    # The leader can finish while same-group background writers still exist.
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    process.wait()
    return alive


def run_tool_process(command: list[str], run_dir: Path, run_id: str, timeout: float,
                     log_path: Path, *, abort_on_error: bool = True,
                     allowed_drc: set[str] | None = None) -> dict:
    started = time.monotonic()
    error = None
    killed = False
    with log_path.open('w', encoding='utf-8') as log:
        process = subprocess.Popen(command, cwd=run_dir, stdout=log, stderr=subprocess.STDOUT,
                                   start_new_session=True)
        try:
            suffix = ''
            drc_count = 0
            observed: set[str] = set()
            report_cache = {}
            with log_path.open(encoding='utf-8', errors='replace') as monitor:
                while process.poll() is None:
                    chunk = monitor.read(262144)
                    for line in (suffix + chunk).splitlines():
                        if 'CMD-0034' in line:
                            continue
                        if re.search(r'\[(?:WARNING|INFO)\].*\[\s*DFTDRC-', line):
                            observed.update(rule_codes(line))
                        total = re.fullmatch(r'\s*Total violations:\s*(\d+)\s*', line)
                        if total:
                            drc_count = int(total[1])
                    if abort_on_error and re.search(r'\[(?:ERROR|FATAL)\]', suffix + chunk):
                        error = 'early_tool_error'
                    elif (abort_on_error and allowed_drc is not None and
                          (redirected_drc_codes(run_dir, report_cache) - allowed_drc or
                           drc_count > 0 and observed - allowed_drc)):
                        error = 'unallowed_drc'
                    elif time.monotonic() - started >= max(0.001, timeout):
                        error = 'timeout'
                    if error:
                        killed = stop_group(process)
                        log.write(f'\n[agent] process ended after {error}; remaining commands were not executed\n')
                        break
                    suffix = (suffix + chunk)[-100:]
                    time.sleep(0.1)
            code = process.wait()
            stop_group(process)
        except BaseException as exc:
            killed = stop_group(process)
            code = process.returncode
            log.write('\n[agent] tool process group terminated during case interruption\n')
            if isinstance(exc, CaseDeadlineExceeded):
                exc.tool_record = {'run_id': run_id, 'status': 'aborted' if killed else 'completed' if code == 0 else 'error',
                                   'returncode': code, 'error': 'case_deadline', 'log_path': log_path,
                                   'elapsed_seconds': round(time.monotonic() - started, 3),
                                   'collection_seconds': 0, 'artifacts': []}
            raise
    status = 'aborted' if killed else 'error' if error or code != 0 else 'completed'
    return {'run_id': run_id, 'status': status, 'returncode': code, 'error': error,
            'termination_reason': error if killed else None, 'log_path': log_path,
            'elapsed_seconds': round(time.monotonic() - started, 3), 'collection_seconds': 0, 'artifacts': []}
