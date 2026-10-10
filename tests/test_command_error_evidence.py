"""Tiny native-log and report fixtures for command repair evidence."""
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "agent"))
from command_error_evidence import (  # noqa: E402
    bare_configuration_evidence, failed_command, grouped_signal_evidence,
    mismatched_signal_target,
)
from scan_agent import literal_tcl_words  # noqa: E402


def signal_table(rows):
    widths = [20, 24, 16, 16, 24]
    return "Design: example\n" + "\n".join(
        "".join(value.ljust(width) for value, width in zip(row, widths))
        for row in [["Port", "SignalType", "OffState", "Usage", "OwnerPartition"],
                    *[row + ["Default_Partition"] for row in rows]]) + "\n"


class CommandErrorEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.run = self.root / "runs" / "R1"
        self.run.mkdir(parents=True)
        self.log = self.run / "R1.log"
        self.error = "[ERROR] [   CMD-0074] The command has at least one argument."
        self.log.write_text("[INFO] [   CMD-0034] @12: set_scan_cfg\n" + self.error + "\n")
        self.found = {"source": "runs/R1/R1.log", "run_ref": "R1", "locator": "L2", "excerpt": self.error}
        self.report = self.run / "scan_cfg.rpt"
        self.report.write_text("Design: example\nScanConfigurationParameter Value\n-------------------------------\nmax_length 100\n-------------------------------\n")

    def tearDown(self):
        self.temp.cleanup()

    def test_actual_error_identifies_exact_preceding_command(self):
        self.assertEqual(failed_command(self.found, self.root), "set_scan_cfg")
        self.log.write_text("[INFO] [   CMD-0034] @12: set_scan_cfg\n"
                            "[INFO] [   CMD-0034] @13: set_wrapper_cfg\n" + self.error + "\n")
        self.assertEqual(failed_command({**self.found, "locator": "L3"}, self.root), "set_wrapper_cfg")

    def test_wrong_run_path_line_and_excerpt_are_rejected(self):
        for changed in [{"run_ref": "R2"}, {"source": "../runs/R1/R1.log"},
                        {"source": str(self.log)}, {"locator": "L1"}, {"locator": "L99"},
                        {"locator": "line2"}, {"excerpt": "[ERROR] invented"},
                        {"excerpt": "The command has at least one argument."}]:
            with self.subTest(changed=changed):
                self.assertIsNone(failed_command({**self.found, **changed}, self.root))

    def test_symlink_log_is_not_native_command_evidence(self):
        target = self.run / "copy.log"
        target.write_text(self.log.read_text())
        self.log.unlink()
        self.log.symlink_to(target)
        self.assertIsNone(failed_command(self.found, self.root))

    def test_signal_target_is_bound_to_actual_failed_command(self):
        self.log.write_text("[INFO] [   CMD-0034] @12: set_scan_signal -type scan_enable -port {enable_a enable_b}\n" + self.error + "\n")
        self.assertTrue(mismatched_signal_target({"located_object": "port unrelated"}, self.found,
                                                self.root, literal_tcl_words))
        self.assertFalse(mismatched_signal_target({"located_object": "ports enable_a enable_b"}, self.found,
                                                 self.root, literal_tcl_words))
        self.assertFalse(mismatched_signal_target({"located_object": "set_scan_signal"}, self.found,
                                                 self.root, literal_tcl_words))

    def bare_issue(self, **changed):
        return {"found": {**self.found, **changed}, "attempts": [{"fix": {"action": "Remove bare set_scan_cfg"}}]}

    def bare_proof(self, issue=None, script="present_design example\nset_scan_cfg -max_length 100\n"):
        return bare_configuration_evidence(issue or self.bare_issue(), [self.report], self.root,
                                           script, literal_tcl_words)

    def test_removed_bare_command_requires_actual_error_and_native_config(self):
        proof = self.bare_proof()
        self.assertEqual(proof["source"], "runs/R1/scan_cfg.rpt")
        self.assertEqual(proof["locator"], "L2-L5")
        self.assertIn("max_length 100", proof["excerpt"])
        self.assertIsNone(self.bare_proof(self.bare_issue(excerpt="[ERROR] invented")))
        self.assertIsNone(self.bare_proof(script="set_scan_cfg\nset_scan_cfg -max_length 100\n"))
        self.report.write_text("The model says max_length 100\n")
        self.assertIsNone(self.bare_proof())

    def test_configuration_without_actual_numeric_state_is_not_positive(self):
        self.report.write_text("ScanConfigurationParameter Value\n-------------------------------\nmax_length unknown\n-------------------------------\n")
        self.assertIsNone(self.bare_proof())
        self.report.write_text("ScanConfigurationParameter Value\n-------------------------------\nstyle shared\n-------------------------------\n")
        self.assertIsNone(self.bare_proof())

    def test_unrelated_command_error_is_not_bare_config_removal(self):
        self.log.write_text("[INFO] [   CMD-0034] @12: load_netlist missing.v\n" + self.error + "\n")
        self.assertIsNone(self.bare_proof())

    def grouped_proof(self, rows, script=None):
        self.report = self.run / "scan_signal.rpt"
        self.report.write_text(signal_table(rows))
        issue = {"diagnosis": {"located_object": "ports enable_a enable_b"}}
        if script is None:
            script = ("present_design example\nset_current_scan_partition Default_Partition\n"
                      "set_scan_signal -type scan_enable -port enable_a -off_state 0 -usage all\n"
                      "set_scan_signal -type scan_enable -port enable_b -off_state 1 -usage scan\n")
        return grouped_signal_evidence(issue, [self.report], self.root, script, literal_tcl_words)

    def test_grouped_signal_proof_covers_every_requested_port(self):
        proof = self.grouped_proof([["enable_a", "scan_enable", "0", "all"],
                                   ["enable_b", "scan_enable", "1", "scan"]])
        self.assertEqual(proof["locator"], "L3-L4")
        self.assertIn("enable_a", proof["excerpt"])
        self.assertIn("enable_b", proof["excerpt"])

    def test_partial_or_conflicting_signal_rows_never_prove_group(self):
        valid = [["enable_a", "scan_enable", "0", "all"], ["enable_b", "scan_enable", "1", "scan"]]
        for rows in [valid[:1], [valid[0], ["enable_b", "scan_enable", "0", "scan"]],
                     [valid[0], ["enable_b", "clock", "1", "scan"]],
                     [valid[0], ["enable_b", "scan_enable", "1", "all"]],
                     [*valid, ["enable_b", "scan_enable", "0", "scan"]]]:
            with self.subTest(rows=rows):
                self.assertIsNone(self.grouped_proof(rows))

    def test_missing_literal_signal_declaration_is_not_proven_by_report_alone(self):
        rows = [["enable_a", "scan_enable", "0", "all"], ["enable_b", "scan_enable", "1", "scan"]]
        self.assertIsNone(self.grouped_proof(rows, "set_scan_signal -type scan_enable -port enable_a -off_state 0 -usage all\n"))


if __name__ == "__main__":
    unittest.main()
