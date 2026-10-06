"""Actual exclusion-state and nonempty-command evidence; no tool or model calls."""
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "agent"))
import scan_agent
from scan_exclusion_evidence import exclusion_command_evidence


class ExclusionEvidence(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.out = Path(self.temp.name)
        for run in ("R1", "R2"):
            (self.out / "runs" / run / "reports").mkdir(parents=True)
        self.original = self.out / "runs/R1/R1.log"
        self.error = "[ERROR] [CMD-0067] No valid value for 'instance_list'."
        self.original.write_text(
            "[INFO] [CMD-0034] @1: set_scan_element false [get_obj_insts -hier -filter {full_name == wrong}]\n"
            "[INFO] [CMD-0034] @2: }\n" + self.error + "\nCommand 'set_scan_element' execution failed\n")
        self.issue = {"found": {"source": "runs/R1/R1.log", "run_ref": "R1", "locator": "L3", "excerpt": self.error}}
        self.report = self.out / "runs/R2/reports/rpt_scan_element.audit.rpt"
        self.log = self.out / "runs/R2/R2.log"
        self.script = (
            'set targets [get_obj_insts -hier -filter {full_name =~ "u_ctrl/*" && '
            'full_name !~ "u_ctrl/keep*" && is_sequential == true}]\n'
            'if {[cluster_length $targets] > 0} {\n  set_scan_element false $targets\n}\n')
        self.rows = [("u_ctrl/ff1", "user_defined_nonscannable"),
                     ("u_ctrl/ff2", "user_defined_nonscannable"), ("u_ctrl/keep0", "scannable")]
        self.write_rows(self.rows)

    def tearDown(self):
        self.temp.cleanup()

    def write_rows(self, rows):
        headers = ["Name", "Type", "Length", "InstanceName", "ObjState"]
        self.report.write_text(''.join(f'{value:<32}' for value in headers) + '\n' +
                               ''.join(''.join(f'{value:<32}' for value in [name, "dff", "1", name, state]) + '\n'
                                       for name, state in rows))

    def evidence(self, script=None, issue=None):
        files = [path for path in (self.report, self.log) if path.exists()]
        return exclusion_command_evidence(issue or self.issue, files, self.out, script or self.script,
                                           scan_agent.literal_tcl_words)

    def test_actual_all_states_prove_nonempty_exclusion_and_preserved_exception(self):
        evidence = self.evidence()
        self.assertEqual(evidence["source"], "runs/R2/reports/rpt_scan_element.audit.rpt")
        self.assertEqual(evidence["locator"], "L2-L4")
        self.assertIn("user_defined_nonscannable", evidence["excerpt"])
        self.assertIn("u_ctrl/keep0", evidence["excerpt"])

    def test_selected_cell_or_exception_in_wrong_state_blocks_proof(self):
        for rows in ([self.rows[0], ("u_ctrl/ff2", "scannable"), self.rows[2]],
                     self.rows[:2] + [("u_ctrl/keep0", "user_defined_nonscannable")], self.rows[:2], []):
            with self.subTest(rows=rows):
                self.write_rows(rows)
                self.assertIsNone(self.evidence())

    def test_dynamic_rebound_or_unrelated_scope_is_not_guessed(self):
        for script in (self.script.replace('"u_ctrl/*"', '"$prefix/*"'),
                       self.script.replace('if {', 'set targets [custom_collection]\nif {', 1),
                       self.script.replace("u_ctrl/", "unrelated/"),
                       "foreach cell [custom_collection] {set_scan_element false $cell}\n"):
            with self.subTest(script=script):
                self.assertIsNone(self.evidence(script=script))

    def test_literal_endpoints_need_each_endpoint_in_the_actual_state_report(self):
        script = "set_scan_element false {u_ctrl/ff1 u_ctrl/ff2}\n"
        self.assertIsNotNone(self.evidence(script=script))
        self.write_rows([self.rows[0], self.rows[2]])
        self.assertIsNone(self.evidence(script=script))

    def test_original_failure_must_be_real_and_belong_to_set_scan_element_false(self):
        for changed in ({"locator": "L1"}, {"source": "runs/R2/R2.log"}, {"source": str(self.original)},
                        {"source": "runs/R1/../R2/R2.log"}):
            with self.subTest(changed=changed):
                issue = {"found": dict(self.issue["found"], **changed)}
                self.assertIsNone(self.evidence(issue=issue))
        self.original.write_text("[INFO] [CMD-0034] @1: get_obj_insts -hier\n\n" + self.error +
                                 "\nCommand 'set_scan_element' execution failed\n")
        self.assertIsNone(self.evidence())

    def test_older_scannable_report_can_verify_only_nonempty_command_execution(self):
        self.write_rows([self.rows[2]])
        self.log.write_text(
            "[INFO] [DFTDRC-7006] Cannot make cell 'u_ctrl/ff1' scannable due to 'set_scan_element' command.\n"
            "[INFO] [DFTDRC-7007] Cells with the same violation: u_ctrl/ff2.\n")
        evidence = self.evidence()
        self.assertEqual(evidence["source"], "runs/R2/R2.log")
        self.assertEqual(evidence["locator"], "L1-L2")
        self.log.write_text(self.log.read_text().replace("u_ctrl/ff2", "u_ctrl/keep0"))
        self.assertIsNone(self.evidence())

    def test_exclusion_echo_or_unrelated_exclusion_does_not_prove_execution(self):
        self.write_rows([self.rows[2]])
        for text in (
            "[INFO] [CMD-0034] @1: puts {[DFTDRC-7006] Cannot make cell 'u_ctrl/ff1' scannable due to 'set_scan_element' command.}\n",
            "[INFO] [DFTDRC-7006] Cannot make cell 'other/ff' scannable due to 'set_scan_element' command.\n"):
            with self.subTest(text=text):
                self.log.write_text(text)
                self.assertIsNone(self.evidence())


if __name__ == "__main__":
    unittest.main()
