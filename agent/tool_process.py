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


_POLL_INTERVAL = 0.1
_READ_CHUNK = 262144
_COMMAND_ECHO = re.compile(r"^\s*\[INFO\]\s*\[\s*CMD-0034\]\s*@(?P<script_line>\d+):\s*(?P<command>[A-Za-z_][A-Za-z0-9_:]*)\b")


def _command_stage(name: str) -> str:
    if name.startswith("load_") or name == "present_design":
        return "load"
    if name == "examine_scan_drc":
        return "drc"
    if name == "examine_scan_chain":
        return "chain_analysis"
    if name == "insert_dft_logic":
        return "insertion"
    if name.startswith("rpt_"):
        return "report"
    if name.startswith("dump_"):
        return "deliverable"
    if name == "set" or name.startswith(("set_", "add_", "remove_")):
        return "config"
    return "unknown"


class CommandTimingObservations:
    """Bounded arrival observations, never CPU or exact command execution time."""
    def __init__(self, started: float, maximum: int = 1024):
        self.started = started
        self.maximum = min(1024, max(0, int(maximum)))
        self.records: list[dict] = []
        self.current: dict | None = None
        self.stage_totals: dict[str, float] = {}
        self.stage_counts: dict[str, int] = {}
        self.echo_count = 0
        self.overflow_count = 0
        self.first_offset: float | None = None
        self.pending = ""
        self.line_number = 1

    def _end_current(self, observed_at: float, reason: str) -> None:
        if self.current is None:
            return
        end = max(self.current["observed_start_seconds"], observed_at - self.started)
        duration = end - self.current["observed_start_seconds"]
        self.current.update(observed_end_seconds=round(end, 6), observed_duration_seconds=round(duration, 6),
                            end_observation=reason)
        stage = self.current["stage"]
        self.stage_totals[stage] = self.stage_totals.get(stage, 0.0) + duration
        self.current = None

    def _line(self, line: str, observed_at: float) -> None:
        if "CMD-0034" not in line:
            return
        match = _COMMAND_ECHO.match(line)
        if not match:
            return
        self._end_current(observed_at, "next_stdout_echo_arrival")
        offset = max(0.0, observed_at - self.started)
        if self.first_offset is None:
            self.first_offset = offset
        stage = _command_stage(match["command"])
        self.echo_count += 1
        self.stage_counts[stage] = self.stage_counts.get(stage, 0) + 1
        self.current = {"command_name": match["command"], "source_line": self.line_number,
                        "script_line": int(match["script_line"]), "stage": stage,
                        "observed_start_seconds": round(offset, 6)}
        if len(self.records) < self.maximum:
            self.records.append(self.current)
        else:
            self.overflow_count += 1

    def feed(self, chunk: str, observed_at: float) -> None:
        if not chunk:
            return
        text = self.pending + chunk
        # Report bodies usually contain no command echoes: avoid per-row dicts
        # and regex calls. The bounded prefix holds only an unfinished line.
        if "CMD-0034" not in text:
            self.line_number += text.count("\n")
            self.pending = text.rsplit("\n", 1)[-1][:4096]
            return
        parts = text.split("\n")
        for line in parts[:-1]:
            self._line(line, observed_at)
            self.line_number += 1
        self.pending = parts[-1][:4096]

    def finish(self, observed_at: float, reason: str) -> dict:
        if self.pending:
            self._line(self.pending, observed_at)
            self.pending = ""
        self._end_current(observed_at, reason)
        return {"source": "stdout_echo", "clock": "monotonic_arrival", "poll_interval_seconds": _POLL_INTERVAL,
                "timing_kind": "observed_duration", "maximum_records": self.maximum,
                "observed_echo_count": self.echo_count, "overflow_count": self.overflow_count,
                "records": self.records, "stage_observed_seconds": {key: round(value, 6) for key, value in self.stage_totals.items()},
                "stage_echo_counts": self.stage_counts,
                "unattributed_before_first_echo_seconds": round(self.first_offset, 6) if self.first_offset is not None else None,
                "unattributed_without_echo_seconds": round(max(0.0, observed_at - self.started), 6) if not self.echo_count else None,
                "last_interval_includes_unknown_end_gap": bool(self.echo_count),
                "quality": "Echo arrival can be delayed or batched by buffering and polling; durations are not CPU or exact command execution times."}


def _observed_diagnostics(window: str, observed: set[str], drc_count: int) -> int:
    for line in window.splitlines():
        if 'CMD-0034' in line:
            continue
        if 'DFTDRC-' in line and re.search(r'\[(?:WARNING|INFO)\].*\[\s*DFTDRC-', line):
            observed.update(rule_codes(line))
        if 'Total violations:' in line:
            total = re.fullmatch(r'\s*Total violations:\s*(\d+)\s*', line)
            if total:
                drc_count = int(total[1])
    return drc_count


def _drain_observations(monitor, observations: CommandTimingObservations) -> None:
    while chunk := monitor.read(_READ_CHUNK):
        observations.feed(chunk, time.monotonic())


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
    observations = CommandTimingObservations(started)
    command_timing = None
    with log_path.open('w', encoding='utf-8') as log:
        process = subprocess.Popen(command, cwd=run_dir, stdout=log, stderr=subprocess.STDOUT,
                                   start_new_session=True)
        monitor = None
        try:
            monitor = log_path.open(encoding='utf-8', errors='replace')
            suffix = ''
            drc_count = 0
            observed: set[str] = set()
            report_cache = {}
            while process.poll() is None:
                chunk = monitor.read(_READ_CHUNK)
                observations.feed(chunk, time.monotonic())
                drc_count = _observed_diagnostics(suffix + chunk, observed, drc_count)
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
                time.sleep(_POLL_INTERVAL)
            code = process.wait()
            stop_group(process)
            log.flush()
            if monitor is not None:
                _drain_observations(monitor, observations)
            command_timing = observations.finish(time.monotonic(), error or "process_end_observed")
        except BaseException as exc:
            killed = stop_group(process)
            code = process.returncode
            log.write('\n[agent] tool process group terminated during case interruption\n')
            log.flush()
            if monitor is not None:
                _drain_observations(monitor, observations)
            command_timing = observations.finish(time.monotonic(), "case_interruption_observed")
            if isinstance(exc, CaseDeadlineExceeded):
                exc.tool_record = {'run_id': run_id, 'status': 'aborted' if killed else 'completed' if code == 0 else 'error',
                                   'returncode': code, 'error': 'case_deadline', 'log_path': log_path,
                                   'elapsed_seconds': round(time.monotonic() - started, 3),
                                   'collection_seconds': 0, 'artifacts': [], 'command_timing': command_timing}
            raise
        finally:
            if monitor is not None:
                monitor.close()
    status = 'aborted' if killed else 'error' if error or code != 0 else 'completed'
    return {'run_id': run_id, 'status': status, 'returncode': code, 'error': error,
            'termination_reason': error if killed else None, 'log_path': log_path,
            'elapsed_seconds': round(time.monotonic() - started, 3), 'collection_seconds': 0, 'artifacts': [],
            'command_timing': command_timing}
