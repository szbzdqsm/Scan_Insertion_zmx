import json
import os
from pathlib import Path
import re
import sys
import tempfile
import threading
import time
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "agent"))
from case_deadline import CaseDeadline, CaseDeadlineExceeded
from tool_process import CommandTimingObservations, _command_stage, _observed_diagnostics, run_tool_process


class ToolCommandTimings(unittest.TestCase):
    def test_chunk_boundaries_keep_actual_lines_and_no_arguments(self):
        tracker = CommandTimingObservations(10.0)
        tracker.feed("ordinary\n[INFO] [ CMD-003", 10.1)
        tracker.feed("4] @7: load_netlist ARG_NOT_FOR_METADATA\n", 10.2)
        tracker.feed("[INFO] [CMD-0034] @9: examine_scan_drc\n", 10.4)
        timing = tracker.finish(10.6, "end_observed")
        self.assertEqual([r["source_line"] for r in timing["records"]], [2, 3])
        self.assertEqual([r["script_line"] for r in timing["records"]], [7, 9])
        self.assertEqual([r["stage"] for r in timing["records"]], ["load", "drc"])
        self.assertEqual([r["observed_duration_seconds"] for r in timing["records"]], [0.2, 0.2])
        self.assertNotIn("ARG_NOT_FOR_METADATA", json.dumps(timing))
        self.assertEqual(timing["source"], "stdout_echo")
        self.assertEqual(timing["poll_interval_seconds"], 0.1)

    def test_comments_and_non_echo_text_are_ignored_and_stages_are_explicit(self):
        tracker = CommandTimingObservations(0.0)
        tracker.feed("# [INFO] [CMD-0034] @1: load_lib nope\n"
                     "[INFO] [CMD-0034] @2: # examine_scan_drc\n"
                     "[DEBUG] [CMD-0034] @3: dump_netlist nope\n"
                     "[INFO] [CMD-0034] @4: rpt_scan_chain ARG_NOT_FOR_METADATA\n", 0.1)
        result = tracker.finish(0.2, "end_observed")
        self.assertEqual(result["observed_echo_count"], 1)
        self.assertEqual(result["records"][0]["source_line"], 4)
        expected = {"load_lib": "load", "set_scan_cfg": "config", "examine_scan_drc": "drc",
                    "examine_scan_chain": "chain_analysis", "insert_dft_logic": "insertion",
                    "rpt_scan_cfg": "report", "dump_ctl": "deliverable", "custom": "unknown"}
        self.assertEqual({name: _command_stage(name) for name in expected}, expected)

    def test_record_limit_retains_overflow_and_all_stage_observations(self):
        tracker = CommandTimingObservations(0.0, maximum=2)
        tracker.feed("".join(f"[INFO] [CMD-0034] @{i}: set_scan_cfg -opaque {i}\n" for i in range(5)), 0.1)
        result = tracker.finish(0.2, "end_observed")
        self.assertEqual(len(result["records"]), 2)
        self.assertEqual(result["observed_echo_count"], 5)
        self.assertEqual(result["overflow_count"], 3)
        self.assertEqual(result["stage_echo_counts"], {"config": 5})
        self.assertAlmostEqual(result["stage_observed_seconds"]["config"], 0.1)
        bounded = CommandTimingObservations(0.0, maximum=5000)
        bounded.feed("".join(f"[INFO] [CMD-0034] @{i}: exit\n" for i in range(1100)), 0.1)
        summary = bounded.finish(0.2, "end_observed")
        self.assertEqual(len(summary["records"]), 1024)
        self.assertEqual(summary["overflow_count"], 76)

    def test_diagnostic_regex_gates_preserve_the_previous_judgments(self):
        text = ("ordinary output\n[INFO] [CMD-0034] @1: set_scan_drc_rule_handling DFTR9 Warning\n"
                "[WARNING] [DFTDRC-4005] bad clock (DFTR9-1)\nTotal violations: 1\n"
                "not a Total violations: 90 line\n[ERROR] [SCAN-0010] failure\n")
        old_rules = set()
        old_total = 0
        from drc_validation import rule_codes
        for line in text.splitlines():
            if "CMD-0034" in line:
                continue
            if re.search(r"\[(?:WARNING|INFO)\].*\[\s*DFTDRC-", line):
                old_rules.update(rule_codes(line))
            total = re.fullmatch(r"\s*Total violations:\s*(\d+)\s*", line)
            if total:
                old_total = int(total[1])
        actual_rules = set()
        self.assertEqual(_observed_diagnostics(text, actual_rules, 0), old_total)
        self.assertEqual(actual_rules, old_rules)

    @unittest.skipUnless(os.name == "posix", "Process groups require POSIX")
    def test_fast_fake_tool_last_unterminated_echo_is_drained(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            log = root / "R1.log"
            result = run_tool_process([sys.executable, "-u", "-c",
                                       "print('[INFO] [CMD-0034] @3: dump_netlist ARG_NOT_FOR_METADATA', end='', flush=True)"],
                                      root, "R1", 2, log, abort_on_error=False)
            self.assertEqual(result["status"], "completed")
            timing = result["command_timing"]
            self.assertEqual(timing["observed_echo_count"], 1)
            self.assertEqual(timing["records"][0]["stage"], "deliverable")
            self.assertEqual(log.read_text(), "[INFO] [CMD-0034] @3: dump_netlist ARG_NOT_FOR_METADATA")
            self.assertNotIn("ARG_NOT_FOR_METADATA", json.dumps(timing))

    @unittest.skipUnless(os.name == "posix", "Process groups require POSIX")
    def test_timeout_kills_background_group_and_keeps_observations(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            marker = root / "background-survived"
            child = f"import time;from pathlib import Path;time.sleep(0.4);Path({str(marker)!r}).write_text('bad')"
            program = ("import subprocess,sys,time\nprint('[INFO] [CMD-0034] @4: insert_dft_logic -opaque',flush=True)\n"
                       f"subprocess.Popen([sys.executable,'-c',{child!r}])\ntime.sleep(2)\n")
            result = run_tool_process([sys.executable, "-u", "-c", program], root, "R2", 0.12, root / "R2.log")
            self.assertEqual(result["status"], "aborted")
            self.assertEqual(result["error"], "timeout")
            self.assertEqual(result["command_timing"]["records"][0]["stage"], "insertion")
            threading.Event().wait(0.3)
            self.assertFalse(marker.exists())

    @unittest.skipUnless(os.name == "posix", "Process groups require POSIX")
    def test_early_abort_and_original_r1_keep_the_raw_stdout(self):
        program = ("import time\nprint('[INFO] [CMD-0034] @4: set_scan_signal -opaque',flush=True)\n"
                   "print('[ERROR] [SCAN-0010] actual fake failure',flush=True)\ntime.sleep(0.3)\n")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            failed = run_tool_process([sys.executable, "-u", "-c", program], root, "R2", 2, root / "R2.log")
            original = run_tool_process([sys.executable, "-u", "-c", program], root, "R1", 2, root / "R1.log", abort_on_error=False)
            self.assertEqual(failed["status"], "aborted")
            self.assertEqual(failed["command_timing"]["records"][0]["end_observation"], "early_tool_error")
            self.assertEqual(original["status"], "completed")
            self.assertEqual((root / "R1.log").read_text(), "[INFO] [CMD-0034] @4: set_scan_signal -opaque\n[ERROR] [SCAN-0010] actual fake failure\n")

    @unittest.skipUnless(os.name == "posix", "POSIX signal deadline required")
    def test_case_deadline_record_retains_observations_and_actual_abort(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            deadline = CaseDeadline(time.monotonic() + 0.15)
            try:
                deadline.arm()
                with self.assertRaises(CaseDeadlineExceeded) as captured:
                    run_tool_process([sys.executable, "-u", "-c",
                                      "import time;print('[INFO] [CMD-0034] @2: load_netlist -opaque',flush=True);time.sleep(2)"],
                                     root, "R1", 2, root / "R1.log", abort_on_error=False)
            finally:
                deadline.close()
            record = captured.exception.tool_record
            self.assertEqual(record["status"], "aborted")
            self.assertEqual(record["error"], "case_deadline")
            self.assertEqual(record["command_timing"]["records"][0]["stage"], "load")


if __name__ == "__main__":
    unittest.main()
