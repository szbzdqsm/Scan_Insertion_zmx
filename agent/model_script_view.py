"""Present editable model code without anchoring repairs on runtime-owned recipes."""
from __future__ import annotations

import re


def model_owned_script(script: str) -> str:
    for start, end in (
        ("# Agent recipe from actual input shift-register connections", "# End agent shift-register recipe"),
        ("# Agent literal floating-clock inputs", "# End agent floating-clock inputs"),
        ("# Agent audit reports from actual tool state", "# End agent audit reports"),
    ):
        script = re.sub(r"(?ms)^" + re.escape(start) + r"\n.*?^" + re.escape(end) + r"(?:\n|$)", "", script)
    return script
