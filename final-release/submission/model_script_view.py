"""Present editable model code without anchoring repairs on runtime-owned recipes."""
from __future__ import annotations

import re
from bisect import bisect_right
from collections import Counter
import json


def model_owned_script(script: str) -> str:
    from eco_object_selection import restore
    script = restore(script)
    for start, end in (
        ("# Agent task-derived ICG protection", "# End agent task-derived ICG protection"),
        ("# Agent ECO object contract", "# End agent ECO object contract"),
        ("# Agent ECO pre-scan gate", "# End agent ECO pre-scan gate"),
        ("# Agent recipe from actual input shift-register connections", "# End agent shift-register recipe"),
        ("# Agent literal floating-clock inputs", "# End agent floating-clock inputs"),
        ("# Agent audit reports from actual tool state", "# End agent audit reports"),
        ("# Agent task-listed DRC reports", "# End agent task-listed DRC reports"),
    ):
        script = re.sub(r"(?ms)^" + re.escape(start) + r"\n.*?^" + re.escape(end) + r"(?:\n|$)", "", script)
    return script


def edit_anchor_context(base: str, old: str, *, max_chars: int = 1800) -> dict:
    """Suggest existing unique spans only; never choose or apply a replacement."""
    if not old or len(old) > 20000:
        return {}
    positions = []
    offset = 0
    while len(positions) < 5:
        position = base.find(old, offset)
        if position < 0:
            break
        positions.append(position)
        offset = position + 1  # Count overlapping literal matches too.
    starts = [0] + [m.end() for m in re.finditer('\n', base)]
    spans, used, consumed = [], set(), 0

    def add(first: int, last: int, kind: str) -> bool:
        nonlocal consumed
        for padding in range(4):
            left_line = max(0, first - padding)
            left = starts[left_line]
            right = starts[last + 1] if last + 1 < len(starts) else len(base)
            text = base[left:right]
            index = base.find(text)
            if not text or index < 0 or base.find(text, index + 1) >= 0:
                continue
            if text in used:
                return True
            if consumed + len(text) > max_chars:
                return False
            spans.append({'locator': f'L{left_line + 1}-L{last + 1}', 'old': text,
                          'scope': kind})
            used.add(text)
            consumed += len(text)
            return True
        return False

    lines = []
    for position in positions[:4]:
        first = bisect_right(starts, position) - 1
        last = bisect_right(starts, position + len(old) - 1) - 1
        lines.append(first + 1)
        add(first, last, 'one_location_context')
    if 1 < len(positions) <= 4:
        add(bisect_right(starts, positions[0]) - 1,
            bisect_right(starts, positions[-1] + len(old) - 1) - 1,
            'joint_context_explicit_new_text_required')
    return {'literal': old[:300], 'literal_truncated': len(old) > 300,
            'occurrence_lines': lines, 'occurrence_count_at_least': len(positions),
            'more_than_four_matches': len(positions) == 5, 'unique_spans': spans,
            'rule': 'Each edit old must occur exactly once in CURRENT. Select the intended object using '
                    'its surrounding commands. Joint spans require an explicit complete new span; '
                    'no automatic multiple-match replacement. Combine related edits if needed to stay '
                    'within the unchanged 12-edit limit; all edits use the same original base.'}


def repeated_edit_context(base: str) -> list[dict]:
    """Bounded literal anchors for repeated CURRENT lines, independent of case names."""
    lines = [line.strip() for line in base.splitlines()]
    counts = Counter(line for line in lines if 12 <= len(line) <= 300 and
                     re.match(r'^[A-Za-z_]\w*\s+\S', line) and not line.startswith('#'))
    groups, consumed = [], 0
    for line, count in counts.items():
        if count < 2:
            continue
        group = edit_anchor_context(base, line, max_chars=1500)
        size = len(json.dumps(group, ensure_ascii=False))
        if consumed + size > 4000 or len(groups) >= 6:
            break
        groups.append(group)
        consumed += size
    return groups
