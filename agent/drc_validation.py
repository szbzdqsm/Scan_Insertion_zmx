"""Read actual DRC result blocks without treating command/configuration names as fails."""
from __future__ import annotations

from pathlib import Path
import re


def rule_codes(text: str) -> set[str]:
    return {re.sub(r"[-_ ]", "", rule).upper()
            for rule in re.findall(r"\bDFTR[-_ ]?(?:TIE[01]|L[12]|\d+)\b", text, re.I)}


def drc_summaries(path: Path) -> list[dict]:
    """Collect each total and its tool-generated per-rule fail counts, streaming the file."""
    summaries = []
    current = None
    span = []
    with path.open(encoding="utf-8", errors="replace") as stream:
        for number, line in enumerate(stream, 1):
            total = re.fullmatch(r"\s*Total violations:\s*(\d+)\s*", line)
            if total:
                current = {"total": int(total.group(1)), "counts": {}, "line": number,
                           "end_line": number, "excerpt": line.strip()}
                span = [line.rstrip("\r\n")]
                summaries.append(current)
            elif current:
                if "CMD-0034" in line:
                    current = None
                    span = []
                    continue
                span.append(line.rstrip("\r\n"))
                counted = re.search(r"\[DFTDRC-7001\].*There were (\d+) DRC rule '([^']+)' fails", line)
                if counted:
                    codes = rule_codes(counted.group(2))
                    if len(codes) == 1:
                        code, count = next(iter(codes)), int(counted.group(1))
                        if code in current["counts"] and current["counts"][code] != count:
                            current["invalid_counts"] = True
                        current["counts"][code] = count
                    else:
                        current["invalid_counts"] = True
                    current.update(end_line=number, excerpt="\n".join(span))
    return summaries


def summary_permitted(summary: dict, permitted: set[str]) -> bool:
    if summary.get("invalid_counts"):
        return False
    counts = summary["counts"]
    if summary["total"] == 0:
        return all(count == 0 for count in counts.values())
    return bool(counts and sum(counts.values()) == summary["total"] and
                set(counts) <= permitted)


def excluded_scan_cells(paths: list[Path]) -> list[str]:
    """Keep real tool evidence of explicit scan-cell exclusions, regardless of total."""
    evidence = []
    for path in paths:
        with path.open(encoding="utf-8", errors="replace") as stream:
            for number, line in enumerate(stream, 1):
                if "DFTDRC-7006" in line and "set_scan_element" in line:
                    evidence.append(f"{path.name}:L{number}: {line.strip()}")
    return evidence


def residual_positive_evidence(files: list[Path], output_dir: Path, permitted: set[str],
                               repaired: set[str]) -> dict[str, str] | None:
    """Prove repair only when every related actual result agrees; retain visible residual counts."""
    if repaired & permitted:
        return None
    results = []
    for path in files:
        if (path.suffix.lower() != ".log" and
                (path.suffix.lower() not in {".rpt", ".report", ".txt"} or
                 not re.search(r"drc|violation", path.name, re.I))):
            continue
        results.extend((path, summary) for summary in drc_summaries(path))
    if not results or any(not summary_permitted(summary, permitted) for _, summary in results):
        return None
    if any(summary["total"] > 0 and not repaired for _, summary in results):
        # An unspecified violation cannot be called repaired while violations remain.
        return None
    if any(repaired & {code for code, count in summary["counts"].items() if count > 0}
           for _, summary in results):
        return None
    # Prefer an actual report block that displays the permitted residual and its counts.
    candidates = [(path, summary) for path, summary in results if summary["total"] > 0] or results
    reports = [(path, summary) for path, summary in candidates if path.suffix.lower() != ".log"]
    path, summary = (reports or candidates)[-1]
    first, last = summary["line"], summary["end_line"]
    return {"source": path.relative_to(output_dir).as_posix(),
            "locator": f"L{first}" if first == last else f"L{first}-L{last}",
            "excerpt": summary["excerpt"]}
