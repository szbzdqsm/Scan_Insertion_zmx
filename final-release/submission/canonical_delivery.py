"""Publish guide §8.2 names from an already validated final native run.

This module runs no Tcl, model or EDA. It preserves all original artifacts and
selects exports by actual executed commands, never by a guessed file basename.
"""
from __future__ import annotations

import hashlib
from pathlib import Path, PurePosixPath
import re

from artifact_operations import assert_output_directories, independent_copy


class CanonicalDeliveryError(RuntimeError):
    pass


def _real_file(path: Path, root: Path) -> None:
    if (not path.is_file() or path.stat().st_size == 0 or not path.is_relative_to(root) or
            any(p.is_symlink() for p in [path, *path.parents] if p.is_relative_to(root))):
        raise CanonicalDeliveryError('Missing, empty or unbound native artifact: ' + str(path))


def _sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1048576), b''):
            digest.update(block)
    return digest.hexdigest()


def _target(value: str, variables: dict, virtual: PurePosixPath, run: Path, words_for, *, native_generated=False) -> Path:
    """Resolve literal paths and observed set results, without evaluating Tcl."""
    if value.startswith('[file join ') and value.endswith(']'):
        parts = words_for(value[1:-1])
        if parts[:2] != ['file', 'join'] or len(parts) < 3:
            raise CanonicalDeliveryError('Unsupported native output path')
        resolved = [_target(p, variables, virtual, run, words_for, native_generated=native_generated) for p in parts[2:3]]
        # The remaining join components must be relative literal names.
        path = resolved[0]
        for part in parts[3:]:
            part = part.strip('"{}')
            if not part or re.search(r'[$\[\]\\;\r\n]', part) or PurePosixPath(part).is_absolute() or '..' in PurePosixPath(part).parts:
                raise CanonicalDeliveryError('Ambiguous file join output path')
            path = path / part
        return path
    literal = value.startswith('{') and value.endswith('}')
    if value[:1] in {'"', '{'}:
        value = value[1:-1]
    if not literal:
        value = re.sub(r'\$(?:\{([A-Za-z_]\w*)\}|([A-Za-z_]\w*))',
                       lambda m: variables.get(m[1] or m[2], '$UNKNOWN'), value)
    if not value or re.search(r'[$\[\]\\;\r\n]', value):
        raise CanonicalDeliveryError('Unresolved native output path')
    native = PurePosixPath(value)
    if not native.is_absolute():
        native = virtual / native
    if not native.is_relative_to(virtual):
        raise CanonicalDeliveryError('Output path is outside the selected run')
    relative = native.relative_to(virtual)
    parts = []
    for part in relative.parts:
        if part == '..':
            if not parts:
                raise CanonicalDeliveryError('Output path escapes the selected run')
            parts.pop()
        else:
            parts.append(part)
            if run.joinpath(*parts).is_symlink():
                raise CanonicalDeliveryError('Output path traverses a symlink')
    if not parts or parts[0] == 'input' and not native_generated:
        raise CanonicalDeliveryError('Input cannot be a final native output')
    return run.joinpath(*parts)


def _native_sources(output: Path, rid: str, words_for, *, eco_trace=None) -> tuple[dict, dict, str]:
    allowed = set()
    if eco_trace is not None:
        from eco_evidence import assert_trace
        assert_trace(eco_trace)
        if eco_trace.context.output != output or eco_trace.context.rid != rid or eco_trace.data.get('phase') == 'pre_scan':
            raise CanonicalDeliveryError('Canonical ECO source belongs to another scope/stage')
        allowed = {e['path'] for e in eco_trace.data['events'] if 'path' in e}
    run = output / 'runs' / rid
    log, script = run / (rid + '.log'), run / 'deliverables' / (rid + '.dofile')
    _real_file(log, output)
    _real_file(script, output)
    source_lines = script.read_text().splitlines()
    virtual, top, pending_set, active = None, '', '', None
    variables, exports, configs = {}, [], []
    completed, begun = False, False
    with log.open(errors='replace') as stream:
        for number, line in enumerate(stream, 1):
            if re.search(r'\[(?:ERROR|FATAL)\]', line):
                raise CanonicalDeliveryError('Selected native run contains an error')
            origin = re.search(r'\[SOURCE TCL FILE\]\s+(\S+)\s*:', line)
            if origin:
                native = PurePosixPath(origin[1])
                matches = [i for i, p in enumerate(native.parts) if p == 'runs' and native.parts[i + 1:i + 2] == (rid,)]
                if virtual is not None or len(matches) != 1 or '..' in native.parts:
                    raise CanonicalDeliveryError('Ambiguous executed script origin')
                cut = matches[0] + 2
                virtual = PurePosixPath(*native.parts[:cut])
                executed = run.joinpath(*native.parts[cut:])
                _real_file(executed, output)
                if executed.read_bytes() != script.read_bytes():
                    raise CanonicalDeliveryError('Executed script differs from retained final run')
            echo = re.search(r'CMD-0034\]\s+@(\d+):\s*(.*)', line)
            if echo:
                text, lineno = echo[2].strip(), int(echo[1])
                active, pending_set, begun = None, '', False
                words = words_for(text)
                if words and words[0] in {'dump_netlist', 'rpt_scan_cfg', 'present_design', 'set'}:
                    if lineno < 1 or lineno > len(source_lines) or source_lines[lineno - 1].strip() != text:
                        raise CanonicalDeliveryError('Native command/script line mismatch')
                if len(words) == 3 and words[0] == 'set':
                    pending_set = words[1]
                    variables.pop(pending_set, None)
                elif words and words[0] == 'present_design':
                    if top or len(words) != 2 or not re.fullmatch(r'[A-Za-z_$][\w$]*', words[1]):
                        raise CanonicalDeliveryError('Multiple or unknown present designs')
                    active = {'kind': 'design', 'requested': words[1]}
                elif words and words[0] in {'dump_netlist', 'rpt_scan_cfg'}:
                    if virtual is None or not top or len(words) != 3:
                        raise CanonicalDeliveryError('Unbound export/config command')
                    option = words[1]
                    if option != '-file' and not (words[0] == 'rpt_scan_cfg' and option == '>'):
                        raise CanonicalDeliveryError('Unsupported export/config target')
                    target = _target(words[2], variables, virtual, run, words_for, native_generated=eco_trace is not None)
                    if target.is_relative_to(run / 'input') and str(target) not in allowed:
                        raise CanonicalDeliveryError('Input subtree export lacks fresh native ECO binding')
                    active = {'kind': words[0], 'source': target, 'script_line': lineno,
                              'command': text, 'command_log_line': number, 'design': top}
                    if words[0] == 'dump_netlist':
                        exports.append(active)
                    else:
                        configs.append(active)
                continue
            if pending_set:
                value = line.strip()
                if value and not value.startswith('[') and not re.search(r'[$\[\]\\;]', value):
                    variables[pending_set] = value
                pending_set = ''
            if active and active['kind'] == 'design':
                match = re.search(r"CMD-1300\]\s+Present design is '([^']+)'", line)
                if match:
                    if match[1] != active['requested']:
                        raise CanonicalDeliveryError('Native design differs from command')
                    top = match[1]
            elif active and active['kind'] == 'dump_netlist':
                if re.search(r'VRLG-O-0008\]\s+Begin to write Netlist\.', line):
                    begun = True
                if begun and re.search(r'VRLG-O-0009\]\s+Write Netlist successfully\.', line):
                    active['success_log_line'] = number
            if 'CMD-0042' in line and 'Thank you' in line:
                completed = True
    if not completed or not exports or not configs or any('success_log_line' not in x for x in exports):
        raise CanonicalDeliveryError('Native final export or config evidence is missing')
    # Different explicit export operations are ordered by real native execution.
    # This handles partial flows: the last completed dump is the final state,
    # not an arbitrary same-suffix intermediate file.
    export, config = exports[-1], configs[-1]
    if any(x['source'] == export['source'] for x in configs):
        raise CanonicalDeliveryError('One path is claimed as both netlist and config')
    return export, config, top


def publish_canonical_artifacts(output_dir: Path, final_run: str, run_record: dict,
                                *, words_for, eco_trace=None) -> dict:
    """Called only after unchanged task/audit/integrity checks have passed."""
    output = Path(output_dir).absolute()
    if (not re.fullmatch(r'R[1-9]\d*', final_run) or run_record.get('returncode') != 0 or
            run_record.get('run_id', run_record.get('tool_call_id')) != final_run or
            run_record.get('exit_status', run_record.get('status')) != 'completed'):
        raise CanonicalDeliveryError('Canonical publication requires a completed adopted run')
    assert_output_directories(output, ['runs/' + final_run, 'final_results/deliverables', 'final_results/reports'])
    export, config, top = _native_sources(output, final_run, words_for, eco_trace=eco_trace)
    _real_file(export['source'], output)
    _real_file(config['source'], output)
    # Existing native validation proves scan semantics. These format guards only
    # prevent copying an empty/wrong-kind/wrong-design file as the required type.
    modules, ends = [], 0
    with export['source'].open(errors='replace') as stream:
        for line in stream:
            if match := re.match(r'\s*module\s+([A-Za-z_$][\w$]*)\s*(?:\(|;)', line):
                modules.append(match[1])
            if re.match(r'\s*endmodule\b', line):
                ends += 1
    if top not in modules or len(modules) != ends:
        raise CanonicalDeliveryError('Final native export is not complete HDL for the current design')
    with config['source'].open(errors='replace') as stream:
        text = stream.read(1048577)
    if (len(text) > 1048576 or 'ScanConfigurationParameter' not in text or
            not re.search(r'(?m)^Scan partition:\s*\S+', text) or
            not re.search(r'(?m)^max_length\s+(?:\d+|--)\s*$', text) or
            not re.search(r'(?m)^chain_count\s+(?:\d+|--)\s*$', text)):
        raise CanonicalDeliveryError('Selected native report is not a complete scan configuration report')
    plans = [(export, output / 'final_results/deliverables/post_scan.v'),
             (config, output / 'final_results/reports/scan_configuration.rpt')]
    prepared = []
    for native, target in plans:
        source = native['source']
        digest = _sha(source)
        if target.exists() or target.is_symlink():
            _real_file(target, output)
            if _sha(target) != digest:
                raise CanonicalDeliveryError('Conflicting canonical deliverable: ' + str(target))
        prepared.append((native, target, digest))
    bindings = []
    for native, target, digest in prepared:
        source = native['source']
        existed = target.exists()
        if not existed:
            independent_copy(source, target)
        if _sha(source) != digest or _sha(target) != digest:
            raise CanonicalDeliveryError('Native/canonical bytes changed during publication')
        bindings.append({'source': source.relative_to(output).as_posix(),
                         'target': target.relative_to(output).as_posix(), 'sha256': digest,
                         'bytes': target.stat().st_size, 'already_present': existed,
                         'script': f'runs/{final_run}/deliverables/{final_run}.dofile',
                         **{k: v for k, v in native.items() if k not in {'source', 'kind'}}})
    return {'status': 'published', 'run_ref': final_run, 'design': top,
            'scope': 'Canonical copies only; original names and references retained.',
            'bindings': bindings}
