"""10.22 file handshake. Completion means finished, never task correctness."""
from __future__ import annotations

import argparse
import functools
import json
import os
from pathlib import Path
import stat
import tempfile
import time

INPUT_MARKER = 'case_upload_marker'
OUTPUT_MARKER = '.case_complete_marker'
_validated_marker_ready = None


class OutputDirectoryError(ValueError):
    """Existing output is unsafe for a fresh case; never remove its contents."""


def prepare_case_output(output: Path):
    """Allow only the observed platform capture file, never prior case data.

    This is a name/type contract, not a suffix rule or a claim about log
    contents. The caller must not open, truncate or consume this log as input.
    Re-run at the business boundary so newly appearing conflicts also fail.
    """
    try:
        if output.is_symlink():
            raise OutputDirectoryError('Output directory must not be a symbolic link: ' + str(output))
        if output.exists():
            if not stat.S_ISDIR(output.lstat().st_mode):
                raise OutputDirectoryError('Output path is not a directory: ' + str(output))
        else:
            output.mkdir(parents=True, exist_ok=False)
        mode = output.lstat().st_mode
        if not mode & 0o222 or not mode & 0o111 or not os.access(output, os.W_OK | os.X_OK):
            raise OutputDirectoryError('Output directory is not writable/searchable: ' + str(output))
        allowed = []
        conflicts = []
        for entry in sorted(output.iterdir(), key=lambda item: item.name):
            info = entry.lstat()  # Do not follow links, including dangling ones.
            kind = ('symlink' if stat.S_ISLNK(info.st_mode) else
                    'directory' if stat.S_ISDIR(info.st_mode) else
                    'regular_file' if stat.S_ISREG(info.st_mode) else 'special_file')
            if entry.name == 'container.log' and kind == 'regular_file' and info.st_nlink == 1:
                allowed.append({'name': entry.name, 'type': kind, 'ownership': 'external_capture'})
            else:
                reason = 'multiple hard links' if info.st_nlink > 1 and kind == 'regular_file' else 'not an allowed platform log'
                conflicts.append(entry.name + ' (' + kind + '; ' + reason + ')')
        if conflicts:
            raise OutputDirectoryError('Output artifact conflict in ' + str(output) + ': ' + ', '.join(conflicts))
        return {'output_root': str(output), 'allowed_existing': allowed,
                'policy': 'only exact single-link regular container.log; all other existing entries conflict'}
    except OutputDirectoryError:
        raise
    except OSError as exc:
        raise OutputDirectoryError('Cannot initialize output directory ' + str(output) + ': ' + exc.strerror) from None


def activate_marker_ready(ready):
    """Carry the real marker observation across entry validation and business."""
    global _validated_marker_ready
    if _validated_marker_ready is not None:
        raise RuntimeError('Marker entry may only be activated once')
    if (ready.get('event') != 'marker_input_validated'
            or not ready.get('input_check_passed')
            or not ready.get('input_ready_observed')
            or ready.get('startup_mode') != 'marker'
            or ready.get('marker') != str(Path(ready['input_root']) / INPUT_MARKER)):
        raise ValueError('Marker readiness requires observation and a completed entry check')
    _validated_marker_ready = dict(ready)


def publish_completion(output: Path, rc: int, ready):
    """All caller-owned files must be closed before this final publication."""
    with (output / 'platform_completion.json').open('x') as stream:
        json.dump({'exit_code': rc, 'input_ready_observation': ready,
                   'completion_is_not_a_success_verdict': True,
                   'completed_monotonic_seconds': time.monotonic(),
                   'completed_utc_seconds': time.time()}, stream, indent=2)
        stream.flush()
        os.fsync(stream.fileno())
    fd = os.open(output / OUTPUT_MARKER, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
    os.fsync(fd)
    os.close(fd)


def arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument('-input', '--input', required=True)
    parser.add_argument('-output', '--output', required=True)
    return parser.parse_args()


def wait_input(root: Path):
    if _validated_marker_ready is not None:
        if str(root.resolve()) != _validated_marker_ready['input_root']:
            raise ValueError('Input root differs from the marker-validated root')
        return dict(_validated_marker_ready)
    # Stat only the marker, never list/read partial uploads. No pre-upload case
    # deadline: t1 belongs to the evaluator that atomically publishes the marker.
    marker = root / INPUT_MARKER
    while True:
        try:
            mode = marker.lstat().st_mode
            if not stat.S_ISREG(mode):
                raise ValueError('Input ready marker must be a regular file')
            return {'monotonic_seconds': time.monotonic(), 'utc_seconds': time.time(),
                    'event': 'input_marker_observed', 'marker': str(marker)}
        except FileNotFoundError:
            time.sleep(0.02)


def completed_main(function):
    @functools.wraps(function)
    def run(started_at=None, entry_clock=None):
        args = arguments()
        root, output = Path(args.input).absolute(), Path(args.output).absolute()
        ready = wait_input(root)
        start = ready['monotonic_seconds'] if started_at is None else started_at
        if ready.get('startup_mode') == 'marker':
            prepare_case_output(output)
        else:
            if output.exists() and any(output.iterdir()):
                raise ValueError('A new case requires an empty output directory')
            output.mkdir(parents=True, exist_ok=True)
        if ready.get('startup_mode') == 'marker':
            with (output / 'startup_protocol.json').open('x') as stream:
                json.dump(ready, stream, indent=2)
        # Native tool and library temporary files must also stay on output.
        temp = output / '.tmp'
        temp.mkdir()
        os.environ['TMPDIR'] = str(temp)
        tempfile.tempdir = str(temp)
        old_cwd = Path.cwd()
        os.chdir(output)
        rc = None
        try:
            rc = function(started_at=start, entry_clock=entry_clock or ready)
            return rc
        finally:
            os.chdir(old_cwd)
            # An unhandled exception/kill is incomplete; do not publish a marker.
            # A returned failure is finalized with its real status, not success.
            if isinstance(rc, int):
                # This is the final output write, after main's finally/Journal.
                publish_completion(output, rc, ready)
    return run
