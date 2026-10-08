"""Read actual DRC result blocks without treating command/configuration names as fails."""
from __future__ import annotations

from pathlib import Path
import re


def rule_codes(text: str) -> set[str]:
    return {re.sub(r"[-_ ]", "", rule).upper()
            for rule in re.findall(r"(?<![A-Za-z0-9_])DFTR[-_ ]?(?:TIE[01]|L[12]|\d+)(?![A-Za-z0-9_])", text, re.I)}


_RULE_PATTERN = r"(?<![A-Za-z0-9_])DFTR[-_ ]?(?:TIE[01]|L[12]|\d+)(?![A-Za-z0-9_])"
_PERMISSION = re.compile(
    r"(?P<ignore>忽略|\bignore\w*\b)|(?P<retain>无需处理|不需要处理|不用处理)|"
    r"(?P<allow>允许|许可|可以|可|\b(?:allow\w*|permit\w*|can|may)\b)", re.I)
_BRIDGE_WORDS = re.compile(
    r"仅|只|以下|下列|这些|上述|该|的|可|可以|允许|许可|保留|剩余|残余|残留|遗留|存在|出现|"
    r"忽略|无需处理|不需要处理|不用处理|违例|违规|规则|检查|标号|编号|为|种|类|固有|特性|"
    r"形式|以|\b(?:the|following|these|above|them|can|may|be|are|is|as|to|"
    r"DRC|rule\w*|violation\w*|warning\w*|residual\w*|remaining|retain\w*|"
    r"remain\w*|exist\w*|allow\w*|permit\w*|inherent|intrinsic|ignored)\b", re.I)
_RESIDUAL_OBJECT = re.compile(
    r"保留|剩余|残余|残留|遗留|存在|出现|违例|违规|规则|无需处理|不需要处理|不用处理|"
    r"\b(?:DRC|rule\w*|violation\w*|warning\w*|residual\w*|remain\w*|retain\w*|exist\w*)\b", re.I)
_NON_DRC_OBJECT = re.compile(r"报告|格式|日志|文件|输出|显示|编码|\b(?:report|format|log|file|output|display|encoding)\w*\b", re.I)
_NEGATIVE_IGNORE = re.compile(
    r"(?:不允许|不得|禁止|不能|不可|不要|不).{0,16}(?:忽略|\bignore\w*)|"
    r"\b(?:must\s+not|do\s+not|cannot|never)\s+ignore\w*|\bnot\s+allowed\b", re.I)
_NEGATIVE_RESIDUAL = re.compile(
    r"修复|消除|清零|必须处理|(?:不允许|不得|禁止|不能|不可).{0,16}(?:保留|残留|存在|出现)|"
    r"\b(?:repair|fix|resolve)\w*|\b(?:must\s+not|do\s+not|cannot|never).{0,16}(?:remain|retain|exist)", re.I)
_CONDITIONAL_PERMISSION = re.compile(r"仅在|只有|如果|范围|指定实例|特定实例|\b(?:if|when|provided|instances?)\b", re.I)
_ACTION_START = (r"忽略|无需处理|不需要处理|不用处理|允许|许可|可以|可保留|不允许|不得|禁止|不能|不可|必须|修复|消除|清零|"
                 r"\b(?:ignore\w*|allow\w*|permit\w*|must|do|never|repair\w*|fix\w*|resolve\w*)\b")
_OTHER_ACTION_START = r"输出|生成|导出|保存|修改|显示|报告|记录|混合|保持|\b(?:keep|generate|dump|write|save|modify|report|display|mix)\w*\b"
_CLAUSE_SPLIT = re.compile(
    r"[，,]|但是|然而|但|\bbut\b|(?:并且|并|且|以及|和|与|及|\band\b)(?=\s*(?:" +
    _ACTION_START + r"|" + _OTHER_ACTION_START + r"|" + _RULE_PATTERN +
    r"[^，,;；。\n]{0,40}(?:" + _ACTION_START + r")))", re.I)


def _clear_drc_bridge(text: str) -> str:
    return re.sub(r"[\s`'\"()（）:：/\[\]_、.\-\d]|\band\b|与|及|和", "", _BRIDGE_WORDS.sub("", text), flags=re.I)


def _permission_sets(spec: str) -> tuple[set[str], set[str]]:
    """Scope each predicate separately, retaining uncertainty as no permission."""
    retained, ignored, denied_residual, denied_ignore = set(), set(), set(), set()
    for sentence in re.split(r"[\n;；。]", spec):
        pending: set[str] = set()
        carry_kind: str | None = None
        for clause in _CLAUSE_SPLIT.split(sentence):
            if not clause.strip():
                continue
            refs = list(re.finditer(_RULE_PATTERN, clause, re.I))
            codes = rule_codes(clause)
            clean = re.sub(r"无需处理|不需要处理|不用处理", "", clause)
            no_ignore = _NEGATIVE_IGNORE.search(clean)
            no_residual = _NEGATIVE_RESIDUAL.search(clean)
            conditional = _CONDITIONAL_PERMISSION.search(clause)
            if no_ignore or no_residual or conditional:
                target = codes
                if not target and pending:
                    stripped = _NEGATIVE_IGNORE.sub("", _NEGATIVE_RESIDUAL.sub("", clean))
                    if not _clear_drc_bridge(stripped):
                        target = pending
                if no_residual or conditional:
                    denied_residual.update(target)
                if no_ignore or no_residual or conditional:
                    denied_ignore.update(target)
                pending, carry_kind = set(), None
                continue
            granted_kind = None
            # A report/log/format permission cannot authorize the DRC condition,
            # even when its identifier immediately follows "allow".
            verbs = list(_PERMISSION.finditer(clause))
            object_start = min([ref.start() for ref in refs] + [verb.start() for verb in verbs], default=0)
            if not _NON_DRC_OBJECT.search(clause[object_start:]):
                for verb in _PERMISSION.finditer(clause):
                    kind = "ignore" if verb.lastgroup == "ignore" else "retain"
                    if kind == "retain" and not _RESIDUAL_OBJECT.search(clause):
                        continue
                    after = next((index for index, ref in enumerate(refs) if ref.start() >= verb.end()), None)
                    before = next((index for index in range(len(refs) - 1, -1, -1) if refs[index].end() <= verb.start()), None)
                    target: set[str] = set()
                    if after is not None and not _clear_drc_bridge(clause[verb.end():refs[after].start()]):
                        last = after
                        while last + 1 < len(refs) and not _clear_drc_bridge(clause[refs[last].end():refs[last + 1].start()]):
                            last += 1
                        # Keep the entire addressed object honest: a dangling
                        # unrelated action after the rule list is not a waiver.
                        if not _clear_drc_bridge(clause[refs[last].end():]):
                            target = set().union(*(rule_codes(ref.group()) for ref in refs[after:last + 1]))
                    elif before is not None and not _clear_drc_bridge(clause[refs[before].end():verb.start()]):
                        first = before
                        while first and not _clear_drc_bridge(clause[refs[first - 1].end():refs[first].start()]):
                            first -= 1
                        if not _clear_drc_bridge(clause[verb.end():]):
                            target = set().union(*(rule_codes(ref.group()) for ref in refs[first:before + 1]))
                    elif not refs and pending and not _clear_drc_bridge(clause[:verb.start()] + clause[verb.end():]):
                        target = pending
                    if target:
                        (ignored if kind == "ignore" else retained).update(target)
                        granted_kind = kind
                # A comma-separated bare list inherits only its own preceding
                # predicate, including the distinction between retain and ignore.
                if codes and carry_kind and not _clear_drc_bridge(re.sub(_RULE_PATTERN, "", clause, flags=re.I)):
                    (ignored if carry_kind == "ignore" else retained).update(codes)
                    granted_kind = carry_kind
            if codes:
                pending, carry_kind = codes, granted_kind
            elif granted_kind:
                carry_kind = granted_kind
            elif (re.search(r"固有特性|设计固有|inherent|intrinsic", clause, re.I) and
                  not re.search(r"允许|许可|allow|permit|时钟|clock|网表|netlist|输出|report", clause, re.I)):
                continue
            else:
                pending, carry_kind = set(), None
    retained -= denied_residual
    ignored -= denied_residual | denied_ignore
    return retained | ignored, ignored


def authorized_rule_codes(spec: str) -> set[str]:
    """Bind residual permission to its DRC object, never to an unrelated action."""
    return _permission_sets(spec)[0]


def authorized_ignored_rule_codes(spec: str) -> set[str]:
    """Only ignore predicates authorize suppression; residual Warning stays visible."""
    return _permission_sets(spec)[1]


def redirected_drc_codes(run_dir: Path, cache: dict) -> set[str]:
    """Preview growing actual reports so redirection does not hide blocking DRC from the monitor."""
    observed = set()
    for path in run_dir.rglob("*"):
        if path.suffix.lower() not in {".rpt", ".report", ".txt"} or path.name.startswith("llm_") or not path.is_file():
            continue
        try:
            info = path.stat()
            stamp = (info.st_mtime_ns, info.st_size)
            old = cache.get(path)
            if old and old[0] == stamp:
                observed.update(old[1])
                continue
            with path.open(encoding="utf-8", errors="replace") as stream:
                head = stream.read(8192)
                if "DRC Report" not in head or not re.search(r"(?m)^\s*Total violations:\s*[1-9]\d*\s*$", head):
                    codes = set()
                else:
                    stream.seek(max(0, info.st_size - 8192))
                    text = head + "\n" + stream.read(8192)
                    codes = set()
                    for line in text.splitlines():
                        if ("CMD-0034" not in line and
                                (re.search(r"\[(?:WARNING|INFO)\].*\[\s*DFTDRC-", line) or
                                 re.search(r"\[INFO\]\s+There were \d+ DRC rule '.+' fails", line))):
                            codes.update(rule_codes(line))
        except OSError:
            # The tool may rotate an output between directory enumeration and reading.
            continue
        cache[path] = (stamp, codes)
        observed.update(codes)
    return observed


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
                counted = re.search(r"\[INFO\]\s+(?:\[DFTDRC-7001\]\s+)?There were (\d+) DRC rule '([^']+)' fails", line)
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
