import os
from pathlib import Path
import signal
import sys
import threading
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "agent"))
from case_deadline import CaseDeadline, CaseDeadlineExceeded


_SUPPORTED = os.name == "posix" and all(hasattr(signal, name) for name in ("SIGALRM", "ITIMER_REAL", "setitimer", "getitimer"))


@unittest.skipUnless(_SUPPORTED, "POSIX interval timers are unavailable")
class CaseDeadlineTests(unittest.TestCase):
    def setUp(self):
        self.handler = signal.getsignal(signal.SIGALRM)
        self.timer = signal.getitimer(signal.ITIMER_REAL)
        signal.setitimer(signal.ITIMER_REAL, 0)

    def tearDown(self):
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, self.handler)
        signal.setitimer(signal.ITIMER_REAL, *self.timer)

    def test_deadline_interrupts_synthetic_cpu_work(self):
        started = time.monotonic()
        deadline = CaseDeadline(started + 0.05)
        try:
            with self.assertRaises(CaseDeadlineExceeded):
                deadline.arm()
                while True:
                    sum(range(1000))
        finally:
            deadline.close()
        self.assertLess(time.monotonic() - started, 1)

    def test_deadline_interrupts_blocking_wait(self):
        deadline = CaseDeadline(time.monotonic() + 0.05)
        try:
            with self.assertRaises(CaseDeadlineExceeded):
                deadline.arm()
                threading.Event().wait(0.2)
        finally:
            deadline.close()

    def test_expired_arm_changes_no_existing_state(self):
        previous_handler = signal.getsignal(signal.SIGALRM)
        previous_timer = signal.getitimer(signal.ITIMER_REAL)
        with self.assertRaises(CaseDeadlineExceeded):
            CaseDeadline(time.monotonic() - 1).arm()
        self.assertEqual(signal.getsignal(signal.SIGALRM), previous_handler)
        self.assertEqual(signal.getitimer(signal.ITIMER_REAL), previous_timer)

    def test_close_cancels_own_timer_and_is_idempotent(self):
        deadline = CaseDeadline(time.monotonic() + 0.05)
        deadline.arm()
        deadline.close()
        deadline.close()
        self.assertEqual(signal.getitimer(signal.ITIMER_REAL), (0, 0))
        threading.Event().wait(0.075)
        with self.assertRaises(RuntimeError):
            deadline.arm()

    def test_restores_handler_timer_and_interval_accounting_for_elapsed_time(self):
        handler = lambda signum, frame: None
        signal.signal(signal.SIGALRM, handler)
        signal.setitimer(signal.ITIMER_REAL, 0.4, 0.2)
        deadline = CaseDeadline(time.monotonic() + 0.15)
        try:
            deadline.arm()
            threading.Event().wait(0.06)
        finally:
            deadline.close()
        self.assertIs(signal.getsignal(signal.SIGALRM), handler)
        remaining, interval = signal.getitimer(signal.ITIMER_REAL)
        self.assertGreater(remaining, 0.2)
        self.assertLess(remaining, 0.37)
        self.assertAlmostEqual(interval, 0.2, places=5)

    def test_preexisting_due_alarm_is_delivered_after_restoration(self):
        events = []
        signal.signal(signal.SIGALRM, lambda signum, frame: events.append(signum))
        signal.setitimer(signal.ITIMER_REAL, 0.05)
        deadline = CaseDeadline(time.monotonic() + 0.15)
        try:
            deadline.arm()
            threading.Event().wait(0.065)
            self.assertEqual(events, [])
        finally:
            deadline.close()
        threading.Event().wait(0.005)
        self.assertEqual(events, [signal.SIGALRM])

    def test_repeated_arm_does_not_replace_saved_original_handler(self):
        handler = lambda signum, frame: None
        signal.signal(signal.SIGALRM, handler)
        deadline = CaseDeadline(time.monotonic() + 0.15)
        deadline.arm()
        deadline.arm()
        deadline.close()
        self.assertIs(signal.getsignal(signal.SIGALRM), handler)
        self.assertEqual(signal.getitimer(signal.ITIMER_REAL), (0, 0))

    def test_baseexception_cannot_be_swallowed_by_ordinary_model_retry(self):
        self.assertTrue(issubclass(CaseDeadlineExceeded, BaseException))
        self.assertFalse(issubclass(CaseDeadlineExceeded, Exception))
        swallowed = False
        with self.assertRaises(CaseDeadlineExceeded):
            try:
                raise CaseDeadlineExceeded("synthetic")
            except Exception:
                swallowed = True
        self.assertFalse(swallowed)

    def test_unsupported_platform_and_worker_thread_are_explicitly_rejected(self):
        with patch("case_deadline.os.name", "nt"):
            with self.assertRaisesRegex(RuntimeError, "POSIX"):
                CaseDeadline(time.monotonic() + 1).arm()
        failures = []

        def worker():
            try:
                CaseDeadline(time.monotonic() + 1).arm()
            except RuntimeError as error:
                failures.append(str(error))

        thread = threading.Thread(target=worker)
        thread.start()
        thread.join(0.2)
        self.assertEqual(len(failures), 1)
        self.assertIn("main thread", failures[0])

    def test_nonfinite_deadlines_are_rejected_without_signals(self):
        for value in (float("nan"), float("inf"), float("-inf")):
            with self.subTest(value=value), self.assertRaises(ValueError):
                CaseDeadline(value)


if __name__ == "__main__":
    unittest.main()
