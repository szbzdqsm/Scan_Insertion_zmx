"""Parse explicit wall-time limits without silently enlarging a case budget."""
from __future__ import annotations

import math
import re


_LABEL = re.compile(
    r"(?:max[_\s-]*)?(?:wall[_\s-]*(?:clock[_\s-]*)?time|(?:execution|run|running)[_\s-]*time|runtime|"
    r"time[_\s-]*(?:limit|budget)|total[_\s-]*time)(?:[_\s-]*(?:limit|budget))?|最大(?:运行|执行|总)?时间|"
    r"(?:执行|运行)(?:总)?时间|总(?:运行|执行)?时间|时间(?:限制|上限|预算)|"
    r"(?:最大|最长)?(?:系统)?(?:总|整体|累计)?(?:墙钟|壁钟)(?:时间|时长|耗时)(?:限制|上限|预算)?|"
    r"(?:最大|最长)?(?:系统)?(?:总|整体|累计)?(?:运行|执行)?(?:时长|耗时|时限)(?:限制|上限|预算)?",
    re.I,
)
_TIME_HINT = re.compile(r"墙钟|壁钟|耗时|时长|时限|用时|wall[_\s-]*clock|\bduration\b|\btimeout\b", re.I)
_VALUE = re.compile(
    r"(?<![A-Za-z0-9_.-])(?P<number>\d+(?:\.\d+)?)\s*(?P<unit>milliseconds?|msecs?|ms|毫秒|"
    r"seconds?|secs?|s|秒(?:钟)?|minutes?|mins?|min|m|分钟|分|hours?|hrs?|h|小时)?(?![A-Za-z0-9_.])", re.I,
)
_KEY_UNIT = re.compile(r"[_\s-]*(?:[（(\[]\s*)?(milliseconds?|seconds?|minutes?|hours?|ms|secs?|mins?|hrs?|s|m|h|毫秒|秒|分钟|小时)(?:\s*[）)\]])?(?=\W|$)", re.I)


def _factor(unit: str) -> float:
    unit = unit.lower()
    if unit in {"毫秒", "ms"} or unit.startswith(("millisecond", "msec")):
        return 0.001
    if unit in {"分钟", "分", "m"} or unit.startswith("min"):
        return 60.0
    if unit in {"小时", "h"} or unit.startswith(("hour", "hr")):
        return 3600.0
    return 1.0


def parse_case_seconds(text: str, *, default: int = 1500) -> int:
    """Use the smallest explicit bound; malformed time statements fail closed."""
    values: list[float] = []
    empty_labels = False
    for line in text.splitlines():
        labels = list(_LABEL.finditer(line))
        if not labels and _TIME_HINT.search(line):
            raise ValueError("Explicit time statement has no supported wall-time label")
        for index, label in enumerate(labels):
            tail = line[label.end():labels[index + 1].start() if index + 1 < len(labels) else len(line)]
            keyed = _KEY_UNIT.match(tail)
            if keyed:
                tail = tail[keyed.end():]
            tail = re.split(r"[;；。\n]", tail, 1)[0]
            value = _VALUE.search(tail[:100])
            if not value:
                # Markdown headings and bilingual aliases carry no bound of
                # their own. A concrete duration must still occur elsewhere.
                empty = re.sub(r"[\s#*:：=|`'\"()（）{}\[\]_-]", "", tail)
                if not empty:
                    empty_labels = True
                    continue
                raise ValueError("Explicit wall-time limit has no supported numeric duration")
            before = tail[:value.start()]
            if re.search(r"\d|tool|调用|次数|score|得分", before, re.I):
                raise ValueError("Ambiguous wall-time limit")
            decoration = re.sub(r"[\s:：=≤<>|`'\"()（）{}\[\]_-]", "", before)
            decoration = re.sub(r"限制|上限|不超过|不得超过|小于|必须|应|须|为|最多|最大|设置|(?:maximum|max|limit|budget|atmost|upperlimit|upperbound)", "", decoration, flags=re.I)
            if decoration:
                raise ValueError("Unrecognized text between wall-time label and duration")
            unit = value["unit"] or (keyed.group(1) if keyed else "seconds")
            if keyed and value["unit"] and _factor(keyed.group(1)) != _factor(value["unit"]):
                raise ValueError("Conflicting wall-time units")
            after = tail[value.end():].lstrip()
            if not value["unit"] and not keyed and after and re.match(r"[A-Za-z\u4e00-\u9fff]", after):
                if not re.match(r"(?:以内|以下|上限|最多|最大|per\b|maximum\b)", after, re.I):
                    raise ValueError("Unsupported wall-time unit")
            if after.startswith(":") or re.match(r"\.\d", after):
                raise ValueError("Ambiguous duration notation")
            values.append(float(value["number"]) * _factor(unit))
    if empty_labels and not values:
        raise ValueError("Explicit wall-time limit has no supported numeric duration")
    seconds = math.floor(min(values)) if values else int(default)
    if seconds < 1:
        raise ValueError("Wall-time limit must allow at least one whole second")
    return seconds


def effective_case_seconds(text: str, override: str | None = None, *, default: int = 1500) -> int:
    """An explicit local timeout may tighten an organizer limit, never widen it."""
    official = parse_case_seconds(text, default=default)
    if not override:
        return official
    local = int(override)
    if local < 1:
        raise ValueError("Local case timeout must be positive")
    return min(official, local) if _LABEL.search(text) else local
