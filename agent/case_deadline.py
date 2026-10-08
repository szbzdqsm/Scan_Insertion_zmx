"""A main-thread POSIX deadline covering Python work and blocking calls.

The caller owns cleanup of tool process groups and failure artifacts. This
module temporarily owns SIGALRM/ITIMER_REAL and restores the previous handler
and timer on close, accounting for elapsed monotonic time.
"""
from __future__ import annotations

import math
import os
import signal
import threading
import time
from types import FrameType
from typing import Any, Callable


class CaseDeadlineExceeded(BaseException):
    """A case budget expired; ordinary model/retry Exception handlers cannot swallow it."""


class CaseDeadline:
    def __init__(self, deadline_monotonic: float, *, clock: Callable[[], float] = time.monotonic):
        self.deadline_monotonic = float(deadline_monotonic)
        if not math.isfinite(self.deadline_monotonic):
            raise ValueError("Case deadline must be a finite monotonic timestamp")
        self._armed = False
        self._closed = False
        self._previous_handler: Any = None
        self._previous_timer: tuple[float, float] | None = None
        self._saved_monotonic: float | None = None
        self._clock = clock

    @staticmethod
    def _require_supported_runtime() -> None:
        if (os.name != "posix" or not hasattr(signal, "SIGALRM") or not hasattr(signal, "ITIMER_REAL")
                or not all(callable(getattr(signal, name, None))
                           for name in ("setitimer", "getitimer", "signal", "getsignal"))):
            raise RuntimeError("CaseDeadline requires POSIX SIGALRM and ITIMER_REAL support")
        if threading.current_thread() is not threading.main_thread():
            raise RuntimeError("CaseDeadline must be armed and closed in the main thread")

    def arm(self) -> None:
        self._require_supported_runtime()
        if self._closed:
            raise RuntimeError("A closed CaseDeadline cannot be armed again")
        now = self._clock()
        remaining = self.deadline_monotonic - now
        if remaining <= 0:
            raise CaseDeadlineExceeded("Case wall-time deadline already expired")
        if self._armed:
            # Re-arming never extends the original absolute deadline or replaces
            # the saved preexisting timer with this instance's own timer.
            signal.setitimer(signal.ITIMER_REAL, remaining)
            return
        self._previous_handler = signal.getsignal(signal.SIGALRM)
        self._previous_timer = signal.getitimer(signal.ITIMER_REAL)
        self._saved_monotonic = now
        signal.signal(signal.SIGALRM, self._on_alarm)
        self._armed = True
        try:
            signal.setitimer(signal.ITIMER_REAL, remaining)
        except BaseException:
            self.close()
            raise

    def _on_alarm(self, _signum: int, _frame: FrameType | None) -> None:
        if not self._armed:
            return
        remaining = self.deadline_monotonic - self._clock()
        if remaining > 0:
            # A pending/external early alarm cannot shorten the case budget.
            signal.setitimer(signal.ITIMER_REAL, remaining)
            return
        signal.setitimer(signal.ITIMER_REAL, 0)
        raise CaseDeadlineExceeded("Case wall-time deadline exceeded")

    def close(self) -> None:
        if not self._armed:
            self._closed = True
            return
        self._require_supported_runtime()
        self._armed = False
        self._closed = True
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, self._previous_handler)
        previous = self._previous_timer
        saved = self._saved_monotonic
        if previous is not None and saved is not None:
            delay, interval = previous
            if delay > 0:
                # A preexisting alarm that became due while SIGALRM was owned
                # here is restored as immediately pending, never silently lost.
                delay = max(0.000001, delay - (self._clock() - saved))
            signal.setitimer(signal.ITIMER_REAL, delay, interval)
        self._previous_timer = None
        self._saved_monotonic = None
