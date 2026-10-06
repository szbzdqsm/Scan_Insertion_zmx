"""Read actual fixed-column ScanInsertion reports without prefix truncation."""
from __future__ import annotations

from collections import defaultdict
from pathlib import Path
import re
from typing import Any, Iterator


def report_rows(path: Path, required: set[str]) -> Iterator[dict[str, Any]]:
    columns = []
    with path.open(encoding="utf-8", errors="replace") as stream:
        for number, line in enumerate(stream, 1):
            names = [(match.group(), match.start()) for match in re.finditer(r"\S+", line)]
            if required <= {name for name, _ in names}:
                columns = names
                continue
            if not columns or not line.strip() or line.lstrip().startswith(("-", "Design:")):
                continue
            row = {name: line[start:columns[index+1][1] if index+1 < len(columns) else None].strip()
                   for index, (name, start) in enumerate(columns)}
            row.update(source=str(path), line=number)
            yield row


def chain_rows(paths: list[Path]) -> list[dict[str, Any]]:
    rows = {}
    for path in paths:
        if "chain" not in path.name.lower() or "cell" in path.name.lower():
            continue
        for row in report_rows(path, {"Chain", "Length", "Input", "Output", "Partition"}):
            if not re.fullmatch(r"(?:[IW]\s+\S+|\d+)", row["Chain"]) or not row["Length"].isdigit():
                continue
            key = tuple(row[name] for name in ("Chain", "Partition", "Input", "Output"))
            rows[key] = row
    return list(rows.values())


def partition_requirements(spec: str) -> dict[str, dict[str, str]]:
    result = {}
    headers = []
    for line in spec.splitlines():
        if "|" not in line:
            headers = []
            continue
        cells = [cell.strip().strip("`*") for cell in line.strip().strip("|").split("|")]
        if "chain_count" in cells and any("分区" in cell or cell.lower() == "partition" for cell in cells):
            headers = cells
            continue
        if not headers or len(cells) != len(headers):
            continue
        row = dict(zip(headers, cells))
        name = cells[next(i for i, header in enumerate(headers) if "分区" in header or header.lower() == "partition")]
        if row.get("chain_count", "").isdigit():
            result[name] = row
    return result


def scan_formats(spec: str) -> tuple[str, str] | None:
    for line in spec.splitlines():
        if "wrapper" in line.lower() or not re.search(r"扫描|scan", line, re.I):
            continue
        names = re.findall(r"`([^`\s]*%d[^`\s]*)`", line)
        if len(names) == 2 and re.search(r"命名|名称|format|named", line, re.I):
            return names[0], names[1]
    return None


def chain_problems(rows: list[dict[str, Any]], spec: str) -> list[str]:
    problems = []
    internal = [row for row in rows if not row["Chain"].startswith("W")]
    if re.search(r"不得跨时钟域|不允许.{0,20}混合.{0,20}时钟域|不允许.{0,20}混合不同时钟", spec):
        mixed = next((row for row in internal if len(set(re.split(r",\s*", row.get("Clocks", "")))) > 1), None)
        if mixed:
            problems.append(f"Chain {mixed['Chain']} mixes clock domains {mixed['Clocks']} contrary to the task")
    formats = scan_formats(spec)
    if formats:
        if not internal:
            problems.append("No typed scan-chain rows prove the requested data port naming")
        else:
            for column, pattern in zip(("Input", "Output"), formats):
                regex = re.escape(pattern).replace("%d", r"\d+")
                mismatch = next((row for row in internal if not re.fullmatch(regex, row[column])), None)
                if mismatch:
                    problems.append(f"Actual scan {column.lower()} port {mismatch[column]} does not match requested format {pattern}")
    by_partition = defaultdict(list)
    for row in internal:
        by_partition[row["Partition"]].append(row)
    for name, requested in partition_requirements(spec).items():
        actual = by_partition[name]
        count = int(requested["chain_count"])
        if len(actual) != count:
            problems.append(f"Partition {name} requires {count} chains; actual report proves {len(actual)}")
        limit = requested.get("max_length", "")
        if limit.isdigit() and actual and max(int(row["Length"]) for row in actual) > int(limit):
            problems.append(f"Partition {name} exceeds its own max_length {limit}")
        enable = requested.get("scan_enable")
        if enable and actual and any(row.get("ScanEnable") != enable for row in actual):
            problems.append(f"Partition {name} does not use its requested scan_enable {enable}")
        clock = next((value for key, value in requested.items() if "-clocks" in key or key.lower() == "clocks"), None)
        if clock and actual and any(row.get("Clocks") != clock for row in actual):
            problems.append(f"Partition {name} does not preserve its requested clock domain {clock}")
    return problems


def pseudo_clock_problems(paths: list[Path], expected: list[str]) -> list[str]:
    if not expected:
        return []
    actual = set()
    for path in paths:
        if "signal" in path.name.lower():
            for row in report_rows(path, {"Port", "PortProperty", "SignalType", "OffState"}):
                if row["PortProperty"] == "pseudo" and row["SignalType"] == "clock":
                    actual.add(row["Port"].lstrip("/"))
    missing = sorted(set(expected) - actual)
    return ["Actual signal reports do not prove these independent pseudo clocks: " + ", ".join(missing[:12])] if missing else []


def ctl_overlength_exceptions(rows: list[dict[str, Any]], paths: list[Path], spec: str,
                              log: Path, maximum: int) -> set[str]:
    """Accept only explicitly permitted, reported indivisible CTL wrapper atoms."""
    permission = any("SCAN-4902" in line and "wrapper" in line.lower() and
                     re.search(r"可忽略|允许|ignore", line, re.I) and
                     not re.search(r"不允许|不得|不可忽略|not allowed", line, re.I) for line in spec.splitlines())
    if not permission:
        return set()
    warning_partitions = set()
    with log.open(encoding="utf-8", errors="replace") as stream:
        for line in stream:
            if "[WARNING]" in line and "SCAN-4902" in line:
                match = re.search(r"Partition:\s*(\S+)\(Wrapper\)", line)
                if match:
                    warning_partitions.add(match.group(1))
    segments = []
    for path in paths:
        if "segment" in path.name.lower():
            segments.extend(row for row in report_rows(path, {"SegmentProperty", "Length", "ChainName"})
                            if row["SegmentProperty"] == "inferred_from_ctl" and row["Length"].isdigit())
    allowed = set()
    for row in rows:
        if not row["Chain"].startswith("W") or row["Partition"] not in warning_partitions:
            continue
        name = row["Chain"].split()[-1]
        if any(segment["ChainName"] == name and int(segment["Length"]) == int(row["Length"]) > maximum for segment in segments):
            allowed.add(row["Chain"])
    return allowed


def segment_problems(paths: list[Path], expected: list[dict[str, Any]]) -> list[str]:
    if not expected:
        return []
    rows = []
    for path in paths:
        if "segment" in path.name.lower():
            rows.extend(row for row in report_rows(path, {"Name", "Length", "SiPin", "SoPin"})
                        if row["Length"].isdigit())
    missing = 0
    for group in expected:
        def relative(value: str) -> str:
            return value.lstrip("/").removeprefix(group["root"] + "/")
        for indices in group["index_tuples"]:
            arguments = {f"i{number}": index for number, index in enumerate(indices)}
            si = group["start_template"].format(**arguments) + "/" + group["scan_data_in_pin"]
            so = group["end_template"].format(**arguments) + "/" + group["scan_data_out_pin"]
            if not any(relative(row["SiPin"]) == si and relative(row["SoPin"]) == so and
                       int(row["Length"]) == group["length"] for row in rows):
                missing += 1
    return [f"Actual scan-segment reports do not prove {missing} input-derived shift-register candidates"] if missing else []
