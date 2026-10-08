import copy
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "agent"))
from audit_refresh import build_audit_refresh_request, current_evidence_catalog, validate_audit_refresh


class AuditRefreshTests(unittest.TestCase):
    def setUp(self):
        self.runs = [{"run_id": "R1", "status": "completed", "returncode": 0},
                     {"run_id": "R2", "status": "completed", "returncode": 0}]
        self.issues = [{"issue_id": "I1", "found": {"run_ref": "R1", "verified": True, "excerpt": "old real error"},
                        "diagnosis": {"root_cause": "bad reset"},
                        "attempts": [{"fix": {"action": "reset inactive 1", "artifact_ref": ["F1"]},
                                      "verify": {"run_ref": "R2", "resolved": False}}]}]
        self.catalog = {"V1": {"source": "runs/R2/reports/signal.rpt", "locator": "L5", "excerpt": "rst reset 1"}}
        self.response = {"verification_updates": [{"issue_id": "I1", "evidence_id": "V1"}]}

    def validate(self, response=None, **changes):
        return validate_audit_refresh(self.response if response is None else response, changes.get("issues", self.issues),
                                     changes.get("runs", self.runs), changes.get("current", "R2"),
                                     changes.get("catalog", self.catalog))

    def test_plan_selects_exact_evidence_without_mutation_or_success_claim(self):
        before = copy.deepcopy((self.runs, self.issues, self.catalog))
        plans = self.validate()
        self.assertEqual(plans, {"I1": {"source": "runs/R2/reports/signal.rpt", "locator": "L5",
                                       "expected_excerpt": "rst reset 1"}})
        self.assertEqual((self.runs, self.issues, self.catalog), before)
        self.assertNotIn("resolved", plans["I1"])

    def test_unknown_issue_or_evidence_is_rejected(self):
        for key, value in [("issue_id", "I999"), ("evidence_id", "V999")]:
            response = copy.deepcopy(self.response)
            response["verification_updates"][0][key] = value
            with self.assertRaises(ValueError):
                self.validate(response)

    def test_metadata_expansion_and_forged_evidence_are_rejected(self):
        for key, value in [("resolved", True), ("excerpt", "forged"), ("diagnosis", {}), ("fix", {}),
                           ("found", {}), ("run_ref", "R3"), ("withdraw", True)]:
            response = copy.deepcopy(self.response)
            response["verification_updates"][0][key] = value
            with self.assertRaises(ValueError):
                self.validate(response)
        for key in ("dofile", "netlist_edits", "success", "summary", "tool_runs"):
            with self.assertRaises(ValueError):
                self.validate(self.response | {key: True})

    def test_same_or_future_found_run_and_future_verification_are_rejected(self):
        for found in ("R2", "R3"):
            issues = copy.deepcopy(self.issues)
            issues[0]["found"]["run_ref"] = found
            with self.assertRaises(ValueError):
                self.validate(issues=issues)
        with self.assertRaises(ValueError):
            self.validate(current="R3")

    def test_incomplete_running_or_failed_tool_is_rejected(self):
        for status, code in [("running", 0), ("error", 1), ("aborted", -9), ("completed", 1)]:
            runs = copy.deepcopy(self.runs)
            runs[-1].update(status=status, returncode=code)
            with self.assertRaises(ValueError):
                self.validate(runs=runs)

    def test_catalog_cannot_reference_other_runs_or_private_paths(self):
        for source in ("runs/R1/R1.log", "runs/R3/R3.log", "runs/R2/../../.env", "/private/report.rpt", "runs/R2/.env"):
            with self.assertRaises(ValueError):
                self.validate(catalog={"V1": self.catalog["V1"] | {"source": source}})

    def test_duplicates_resolved_issues_and_missing_fixes_are_rejected(self):
        with self.assertRaises(ValueError):
            self.validate({"verification_updates": self.response["verification_updates"] * 2})
        for update in ({"resolved": True},):
            issues = copy.deepcopy(self.issues)
            issues[0]["attempts"][0]["verify"].update(update)
            with self.assertRaises(ValueError):
                self.validate(issues=issues)
        issues = copy.deepcopy(self.issues)
        issues[0]["attempts"][0]["fix"]["artifact_ref"] = []
        with self.assertRaises(ValueError):
            self.validate(issues=issues)

    def test_empty_plan_and_prompt_are_metadata_only(self):
        self.assertEqual(self.validate({"verification_updates": []}), {})
        messages = build_audit_refresh_request(self.issues, self.runs, "R2", self.catalog)
        self.assertEqual([message["role"] for message in messages], ["system", "user"])
        self.assertIn("No tool will run", messages[0]["content"])
        self.assertIn("rst reset 1", messages[1]["content"])

    def test_catalog_uses_only_actual_line_text_and_number(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            reports = root / "runs/R2/reports"
            reports.mkdir(parents=True)
            actual = "Design: chip\nPort SignalType OffState\nrst reset 1\n"
            (reports / "signal.rpt").write_text(actual)
            (reports / ".env").write_text("private fixture")
            catalog = current_evidence_catalog(root, "R2")
            self.assertEqual(catalog["V1"], {"source": "runs/R2/reports/signal.rpt", "locator": "L1-L3",
                                             "excerpt": actual.rstrip("\n")})
            self.assertNotIn("private fixture", repr(catalog))


if __name__ == "__main__":
    unittest.main()
