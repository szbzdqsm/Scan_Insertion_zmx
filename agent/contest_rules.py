"""Reviewed organizer clarifications; case exceptions never suppress diagnostics."""
from __future__ import annotations

import hashlib


QA_URL = "https://docs.qq.com/doc/DQkp3SGFOaGphZmZa"
QA_READ_DATE = "2026-10-08"
# Q19 applies only to this published task, irrespective of its mount directory.
# This identifies the task specification, not a solution or an expected report.
PUBLIC_TASK2_CASE2_SPEC_SHA256 = "67e012d73d0406da0d786a2ceb942dfb618ef48e89a3887df9b93e32d0f8e6fd"


def qa_residual_codes(task: str, task_spec: str) -> set[str]:
    digest = hashlib.sha256(task_spec.replace("\r\n", "\n").strip().encode()).hexdigest()
    return {"DFTR10"} if task == "task2" and digest == PUBLIC_TASK2_CASE2_SPEC_SHA256 else set()


def qa_context(task: str, task_spec: str) -> str:
    text = (
        f"Organizer Q&A ({QA_URL}, read {QA_READ_DATE}): Q0 gives reviewed Q&A the same "
        "normative status as the contest guide. Q15/A16 removes tool-call-count limits; "
        "the case wall-time limit still applies. Q22 uses the unversioned deepseek-v4-pro. "
        "Q24 permits positive verification from actual tool output or reports. Q26 requires "
        "the organizer's injected base URL at evaluation. Q30 says current Public cases "
        "do not require pre-scan edits; optional edits still need the guide's EQY proof."
    )
    if qa_residual_codes(task, task_spec):
        text += (
            " Q19 specifically permits residual DFTR10 in this Task 2 case2. Keep its actual "
            "warnings and counts visible; do not suppress DFTR10, exclude FFs to hide it, or "
            "invent a repair for the permitted condition. Other unpermitted violations "
            "still need repair. TIE0/TIE1 exceptions follow this task's own specification."
        )
    return text
