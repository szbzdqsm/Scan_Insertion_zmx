"""Bind command-error repairs to actual command targets and native state rows."""
from pathlib import Path
import re

from dofile_recipe import tcl_chunks
from report_validation import report_rows


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
    explicit = bool(re.search(r'\bports?\s+\w+', located, re.I) or
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
                            dofile: str, words_for) -> dict | None:
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
            if (not re.fullmatch(r'[A-Za-z_]\w*', port) or not selected_design or port in declarations or
                    options.get('-type') != 'scan_enable' or options.get('-off_state') not in {'0', '1'} or
                    options.get('-usage') not in {'all', 'scan', 'clock_gating'}):
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
        selected = [row for row in report_rows(path, {'Port', 'SignalType', 'OffState', 'Usage', 'OwnerPartition'})
                    if row['Port'] in targets]
        if len(selected) != len(targets) or {row['Port'] for row in selected} != targets:
            continue
        if any(row['SignalType'].split('(')[0] != 'scan_enable' or
               row['OffState'] != declarations[row['Port']]['-off_state'] or
               row['Usage'] != declarations[row['Port']]['-usage'] or
               row['OwnerPartition'] != declarations[row['Port']]['partition']
               for row in selected):
            continue
        first, last = min(row['line'] for row in selected), max(row['line'] for row in selected)
        return {'source': path.relative_to(output_dir).as_posix(), 'locator': f'L{first}-L{last}',
                'excerpt': '\n'.join(lines[first - 1:last])}
    return None
