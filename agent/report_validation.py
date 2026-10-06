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
