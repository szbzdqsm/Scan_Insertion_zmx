"""Organizer rule scope, real DRC summaries, and optional local call budgets."""
import hashlib
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "agent"))
import contest_rules
import drc_validation
import scan_agent


class ContestRules(unittest.TestCase):
    def test_reviewed_exception_matches_only_the_identified_task(self):
        spec = "Synthetic task specification\n"
        digest = hashlib.sha256(spec.strip().encode()).hexdigest()
        with patch.object(contest_rules, "PUBLIC_TASK2_CASE2_SPEC_SHA256", digest):
            self.assertEqual(contest_rules.qa_residual_codes("task2", spec), {"DFTR10"})
            self.assertEqual(contest_rules.qa_residual_codes("task2", spec + "Other requirement"), set())
            self.assertEqual(contest_rules.qa_residual_codes("task1", spec), set())
            self.assertIn("Keep its actual warnings", contest_rules.qa_context("task2", spec))
            self.assertNotIn("Q19", contest_rules.qa_context("task1", spec))

    def test_public_exception_is_not_general_permission_to_suppress(self):
        public = Path(__file__).resolve().parents[1] / "public_cases/task_2/case2/input/task_spec.md"
        if not public.exists():
            self.skipTest("Optional official Public input is not installed")
        spec = public.read_text()
        self.assertIn("DFTR10", scan_agent.permitted_residual_drc_codes("task2", spec))
        self.assertNotIn("DFTR10", scan_agent.allowed_drc_codes(spec))
        self.assertNotIn("DFTR10", scan_agent.permitted_residual_drc_codes("task1", spec))
        self.assertNotIn("DFTR10", scan_agent.permitted_residual_drc_codes("task2", spec + "\nDifferent task"))

    def test_case_exception_does_not_authorize_scan_cell_exclusion(self):
        spec = "Synthetic DRC task"
        digest = hashlib.sha256(spec.encode()).hexdigest()
        with patch.object(contest_rules, "PUBLIC_TASK2_CASE2_SPEC_SHA256", digest), \
             patch.object(scan_agent.Path, "is_file", return_value=True), \
             patch.object(scan_agent.Path, "read_text", return_value="{}"):
            errors = scan_agent.unsupported_options("set_scan_element false {U1}\n", spec)
            self.assertTrue(any("exclusion" in error for error in errors))
            self.assertEqual(scan_agent.unsupported_options("set_scan_element false {U1}\n", "Other task"), [])

    def test_tool_calls_are_time_bounded_by_default(self):
        with patch.dict(os.environ, {}, clear=True):
            self.assertIsNone(scan_agent.parse_tool_limit("工具调用次数不超过 4 次"))
            self.assertIsNone(scan_agent.parse_tool_limit(""))
        with patch.dict(os.environ, {"AGENT_MAX_TOOL_CALLS": "7"}, clear=True):
            self.assertEqual(scan_agent.parse_tool_limit("工具调用次数不超过 4 次"), 7)

    def test_permission_after_commas_stays_bound_to_the_same_rule_sentence(self):
        self.assertEqual(scan_agent.allowed_drc_codes("ICG 产生 DFTR-TIE0/DFTR-TIE1 违例，属设计固有特性，允许忽略。"),
                         {"DFTRTIE0", "DFTRTIE1"})
        self.assertEqual(scan_agent.allowed_drc_codes("DFTR1 不允许忽略，但 DFTR2 是固有特性，允许忽略。"), {"DFTR2"})
        self.assertEqual(scan_agent.allowed_drc_codes("DFTR1 会发生。允许忽略其他问题。"), set())
        self.assertEqual(scan_agent.allowed_drc_codes("允许忽略 DFTR1，但 DFTR2 必须修复。"), {"DFTR1"})
        self.assertEqual(scan_agent.allowed_drc_codes("DFTR1 是固有特性，但不得忽略。"), set())


class DRCSummaries(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.path = self.root / "drc.rpt"

    def tearDown(self):
        self.temp.cleanup()

    def write_report(self, total=21, counts=None, extra=""):
        counts = {"DFTR10": 21} if counts is None else counts
        self.path.write_text("DRC Report\nTotal violations: " + str(total) + "\n" + extra + "\n" +
                             "\n".join(f"[INFO] [DFTDRC-7001] There were {n} DRC rule '{rule}' fails. (Description)"
                                       for rule, n in counts.items()) + "\n")
        return drc_validation.drc_summaries(self.path)[0]

    def test_actual_counts_allow_only_authorized_residual(self):
        summary = self.write_report(extra="DFTR1 Warning Warning all\nset_scan_drc_rule_handling DFTR2 Warning")
        self.assertTrue(drc_validation.summary_permitted(summary, {"DFTR10"}))
        self.assertFalse(drc_validation.summary_permitted(summary, set()))
        self.assertFalse(drc_validation.summary_permitted(self.write_report(counts={"DFTR1": 21}), {"DFTR10"}))
        self.assertFalse(drc_validation.summary_permitted(self.write_report(total=22), {"DFTR10"}))
        self.assertFalse(drc_validation.summary_permitted(self.write_report(counts={}), {"DFTR10"}))

    def test_zero_total_does_not_override_nonzero_or_conflicting_rule_counts(self):
        self.assertFalse(drc_validation.summary_permitted(self.write_report(total=0), {"DFTR10"}))
        self.assertTrue(drc_validation.summary_permitted(self.write_report(total=0, counts={}), set()))
        self.assertTrue(drc_validation.summary_permitted(self.write_report(total=0, counts={"DFTR10": 0}), set()))
        self.write_report(total=21)
        self.path.write_text(self.path.read_text() +
                             "[INFO] [DFTDRC-7001] There were 0 DRC rule 'DFTR10' fails.\n")
        self.assertFalse(drc_validation.summary_permitted(drc_validation.drc_summaries(self.path)[0], {"DFTR10"}))

    def test_multiple_actual_summaries_remain_separate(self):
        self.write_report()
        self.path.write_text(self.path.read_text() + "[INFO] [CMD-0034] @1: other_command\nDRC Report\nTotal violations: 0\n")
        summaries = drc_validation.drc_summaries(self.path)
        self.assertEqual([item["total"] for item in summaries], [21, 0])
        self.assertEqual(summaries[1]["counts"], {})

    def test_allowed_residual_can_verify_other_rules_but_not_itself(self):
        self.write_report()
        evidence = drc_validation.residual_positive_evidence([self.path], self.root, {"DFTR10"}, {"DFTR1"})
        self.assertEqual(evidence["excerpt"], "\n".join(self.path.read_text().splitlines()[1:4]))
        self.assertIn("21 DRC rule 'DFTR10' fails", evidence["excerpt"])
        self.assertEqual(evidence["locator"], "L2-L4")
        self.assertIsNone(drc_validation.residual_positive_evidence([self.path], self.root, {"DFTR10"}, {"DFTR10"}))
        self.assertIsNone(drc_validation.residual_positive_evidence([self.path], self.root, {"DFTR10"}, set()))
        self.write_report(total=22, counts={"DFTR10": 21, "DFTR1": 1})
        self.assertIsNone(drc_validation.residual_positive_evidence([self.path], self.root, {"DFTR10"}, {"DFTR1"}))

    def test_positive_evidence_checks_all_report_and_log_blocks(self):
        self.write_report(total=0, counts={})
        zero_report = self.path.read_text()
        log = self.root / "R2.log"
        self.write_report(total=1, counts={"DFTR1": 1})
        log.write_text(self.path.read_text())
        self.path.write_text(zero_report)
        for files in ([self.path, log], [log, self.path]):
            self.assertIsNone(drc_validation.residual_positive_evidence(files, self.root, {"DFTR10"}, {"DFTR1"}))
        log.write_text(zero_report)
        evidence = drc_validation.residual_positive_evidence([self.path, log], self.root, set(), {"DFTR1"})
        self.assertEqual(evidence["excerpt"], "Total violations: 0")

    def test_early_zero_cannot_claim_permitted_residual_itself_was_repaired(self):
        self.write_report()
        residual = self.path.read_text()
        self.write_report(total=0, counts={})
        self.path.write_text(self.path.read_text() + residual)
        self.assertIsNone(drc_validation.residual_positive_evidence([self.path], self.root, {"DFTR10"}, {"DFTR10"}))
        self.assertIsNone(drc_validation.residual_positive_evidence([self.path], self.root, {"DFTR10"}, set()))
        evidence = drc_validation.residual_positive_evidence([self.path], self.root, {"DFTR10"}, {"DFTR1"})
        self.assertIn("21 DRC rule 'DFTR10' fails", evidence["excerpt"])

    def test_zero_summaries_can_prove_an_unspecified_violation_was_cleared(self):
        self.write_report(total=0, counts={})
        evidence = drc_validation.residual_positive_evidence([self.path], self.root, set(), set())
        self.assertEqual(evidence["excerpt"], "Total violations: 0")

    def test_real_scan_exclusions_are_visible_even_if_residual_counts_are_permitted(self):
        self.write_report(extra="[INFO] [DFTDRC-7006] Cannot make cell 'U1' scannable due to 'set_scan_element' command.")
        self.assertTrue(drc_validation.summary_permitted(drc_validation.drc_summaries(self.path)[0], {"DFTR10"}))
        evidence = drc_validation.excluded_scan_cells([self.path])
        self.assertEqual(len(evidence), 1)
        self.assertIn("U1", evidence[0])


if __name__ == "__main__":
    unittest.main()
