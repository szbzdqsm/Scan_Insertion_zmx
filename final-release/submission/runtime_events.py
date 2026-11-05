"""Durable, bounded machine events; no credentials, prompts or invented outcomes.

All budgets use local CLOCK_MONOTONIC and an absolute case deadline. UTC and
BOOTTIME are correlation observations only, never extra case allowance.
"""
from __future__ import annotations

from contextvars import ContextVar
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import time
import uuid

_ACTIVE = ContextVar('runtime_event_journal', default=None)
_SECRET = re.compile(r'sk-[A-Za-z0-9_.-]{16,}|ghp_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,}')
_FIELDS = {'run_ref', 'stage', 'status', 'error_type', 'request_id', 'model', 'response_model',
           'response_id', 'usage', 'elapsed_seconds', 'returncode', 'termination_reason',
           'remaining_seconds', 'allocated_seconds', 'deadline_monotonic', 'sdk_retries',
           'request_kind', 'proposal_index', 'tool_record', 'checks_passed', 'problem_count',
           'reason', 'source', 'trace_id', 'entry_clock', 'controller_remaining_seconds',
           'controller_clock_domain', 'limit_seconds', 'exit_code', 'scope', 'feedback_ref'}

def clock_sample():
    wall = time.time()
    return {'UTC': datetime.fromtimestamp(wall, timezone.utc).isoformat(),
            'realtime_seconds': wall, 'monotonic_seconds': time.monotonic(),
            'boottime_seconds': time.clock_gettime(time.CLOCK_BOOTTIME) if hasattr(time, 'CLOCK_BOOTTIME') else None,
            'budget_clock': time.get_clock_info('monotonic').implementation,
            'clock_domain': 'local_process_kernel', 'pid': os.getpid()}

def _clean(value):
    if isinstance(value, dict):
        return {str(k): _clean(v) for k, v in value.items()
                if not re.search(r'^(?:.*_)?api_key$|^secret$|^authorization$|^prompt$|^content$|^environment$', str(k), re.I)}
    if isinstance(value, (list, tuple)):
        return [_clean(v) for v in value[:1024]]
    if isinstance(value, (str, Path)):
        return _SECRET.sub('[REDACTED]', str(value))[:4000]
    if value is None or isinstance(value, (int, float, bool)):
        return value
    return type(value).__name__

def atomic(path, value):
    if path.is_symlink():
        raise ValueError('Indirect event state refused')
    temp = path.with_suffix(path.suffix + '.tmp')
    if temp.is_symlink():
        raise ValueError('Indirect event temporary refused')
    with temp.open('w') as stream:
        json.dump(_clean(value), stream, ensure_ascii=False, indent=2)
        stream.write('\n'); stream.flush(); os.fsync(stream.fileno())
    temp.replace(path)

def model_record(path, value):
    """Dedicated full request/response record; no headers or credential fields.

    Machine event cleaning intentionally removes prompts. This separate writer
    preserves message text without the event writer's 4000-character truncation.
    Only redaction changes the actual SDK body; it never edits parsed candidates.
    """
    secrets = [os.environ.get(k, '') for k in ('LLM_API_KEY', 'DEV_DS_API_KEY')]
    def redact(item):
        if isinstance(item, dict):
            return {str(k): redact(v) for k,v in item.items()
                    if not re.search(r'api_key|authorization|^secret$|^headers$|^environment$', str(k), re.I)}
        if isinstance(item, (tuple, list)):
            return [redact(v) for v in item]
        if isinstance(item, str):
            for secret in secrets:
                if secret: item = item.replace(secret, '[REDACTED]')
            return _SECRET.sub('[REDACTED]', item)
        return item
    if path.is_symlink(): raise ValueError('Indirect model record refused')
    temp = path.with_suffix(path.suffix + '.tmp')
    if temp.is_symlink(): raise ValueError('Indirect model temporary refused')
    with temp.open('w') as stream:
        json.dump(redact(value), stream, ensure_ascii=False, indent=2)
        stream.write('\n'); stream.flush(); os.fsync(stream.fileno())
    temp.replace(path)


def recover(path):
    """A partial last line is not a completed event. Never infer success."""
    events = []
    with path.open('rb') as stream:
        for raw in stream:
            if not raw.endswith(b'\n'):
                break
            try:
                row = json.loads(raw)
            except ValueError:
                break
            if row.get('seq') != len(events) + 1:
                break
            events.append(row)
    trace = events[0].get('trace_id') if events else None
    tools = []
    for file in sorted(path.parent.glob('R*.tool.json')):
        if file.is_symlink(): continue
        try:
            row = json.loads(file.read_text())
            if trace and row.get('trace_id') == trace and row.get('kind') == 'finished_native_tool_record':
                tools.append(row)
        except (OSError, ValueError):
            continue
    return {'events': events, 'last_seq': len(events), 'finished_tool_records':tools,
            'last_event': events[-1] if events else None,
            'state': 'finished_with_recorded_exit' if events and events[-1]['event'] == 'case_end' and
                     events[-1].get('exit_code') is not None else 'incomplete_or_interrupted',
            'not_a_success_verdict': True}

class Journal:
    def __init__(self, output: Path, started: float, entry_clock=None):
        self.root = Path(output) / 'runtime_events'
        if self.root.exists() or self.root.is_symlink():
            raise ValueError('Existing event directory must not be inherited by a new case')
        self.root.mkdir(parents=True)
        self.path = self.root / 'events.jsonl'
        self.started, self.deadline, self.seq = started, None, 0
        self.run_ref, self.requests = '', 0
        supplied = os.environ.get('AGENT_TRACE_RUN_ID', '')
        self.trace_id = supplied if re.fullmatch(r'[A-Za-z0-9_-]{1,80}', supplied) else uuid.uuid4().hex
        self.token = _ACTIVE.set(self)
        self.event('case_entry', entry_clock=entry_clock, trace_id=self.trace_id)

    def event(self, event, **data):
        if not re.fullmatch(r'[a-z_]{1,64}', event) or set(data) - _FIELDS:
            raise ValueError('Unknown machine event schema')
        clock = clock_sample()
        row = {'seq': self.seq + 1, 'event': event, 'trace_id': self.trace_id,
               'clock': clock, 'case_elapsed_monotonic_seconds': clock['monotonic_seconds'] - self.started,
               'remaining_monotonic_seconds': max(0, self.deadline - clock['monotonic_seconds']) if self.deadline else None,
               'run_ref': self.run_ref, **_clean(data)}
        with self.path.open('a') as stream:
            stream.write(json.dumps(row, ensure_ascii=False) + '\n'); stream.flush(); os.fsync(stream.fileno())
        self.seq += 1
        atomic(self.root / 'latest.json', row)
        return row

    def round(self, rid):
        self.run_ref = rid
        self.event('round_start')

    def request(self, request_log, model, allocated_seconds=None):
        cap = os.environ.get('AGENT_MAX_MODEL_REQUESTS', '').strip()
        if cap:
            if not cap.isdecimal() or int(cap) < 1:
                raise ValueError('Invalid development model request limit')
            if self.requests >= int(cap):
                self.event('model_request_budget_exhausted', request_id=self.requests,
                           status='incomplete', reason='development actual-request ceiling reached')
                raise RuntimeError('Development actual model-request budget exhausted; no new request sent')
        self.requests += 1
        retry = request_log is not None and 'retry' in request_log.name
        self.event('model_request_start', request_id=self.requests, model=model,
                   request_kind='candidate_retry' if retry else 'request', sdk_retries=0,
                   allocated_seconds=allocated_seconds)
        return self.requests

    def tool(self, record):
        # Persist completed native round BEFORE validation or next model request.
        clean = {k: v for k, v in record.items() if k in {
            'run_id','status','returncode','error','termination_reason','elapsed_seconds',
            'collection_seconds','command_timing','artifacts'}}
        payload = {'trace_id':self.trace_id, 'run_ref':self.run_ref,'kind':'finished_native_tool_record',**clean}
        atomic(self.root / (self.run_ref + '.tool.json'), payload)
        self.event('tool_end', tool_record=payload)

    def close(self, exit_code=None):
        self.event('case_end', exit_code=exit_code, status='finished' if exit_code is not None else 'interrupted_or_error')
        _ACTIVE.reset(self.token)

def active(): return _ACTIVE.get()

def emit(event, **data):
    current = active()
    if current is not None:
        return current.event(event, **data)
    return None

def usage_fields(usage):
    if usage is None:
        return {}
    value = usage.model_dump() if hasattr(usage, 'model_dump') else usage
    if not isinstance(value, dict): return {}
    return {key: value[key] for key in ['prompt_tokens','completion_tokens','total_tokens','prompt_tokens_details'] if key in value}
