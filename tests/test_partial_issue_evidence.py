"""Small synthetic checks for scoped partial-flow repair evidence."""
import copy
import difflib
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "agent"))
from partial_issue_evidence import partial_issue_positive_evidence


class PartialIssueEvidence(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="partial-issue-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.spec = "不涉及扫描链的构建。\nTop 模块: top\n`u_pll` 模块不可扫描，回替普通 DFF。"
        requirement = {"applicable": True, "top": "top", "unscan_scopes": ["u_pll"],
                       "resolved_unscan_scopes": ["u_pll"], "ff_pairs": {"DFF": "SFF"}}
        self.good = {"applicable": True, "status": "pass", "problems": [], "unknown": [],
                     "unknown_count": 0, "requirements": requirement,
                     "counts": {"source_ff": 50, "final_ff": 50, "final_scan_ff": 40,
                                "source_unscan_ff": 5, "final_unscan_ff": 5,
                                "replace_only_scan_ff": 45},
                     "evidence": {"ff_violation_count": 0}}
        self.bad = copy.deepcopy(self.good)
        self.bad.update(status="fail", problems=[
            "Replaceable FF outside back-replacement scopes remained ordinary: 40 instance(s)"])
        self.bad["counts"]["final_scan_ff"] = 0
        self.bad["evidence"]["ff_violation_count"] = 40
        self.old_script = "insert_dft_logic -replace_only\nexamine_scan_drc\ninsert_dft_logic -replace_unscan\n"
        self.new_script = "insert_dft_logic -replace_only\ninsert_dft_logic -replace_unscan\n"
        self.issue = {"found": {"run_ref": "R1", "verified": True},
                      "diagnosis": {"summary": "Unnecessary examine_scan_drc causes outside-scope reversion",
                                    "located_object": "insert_dft_logic -replace_unscan",
                                    "root_cause": "DRC causes unintended reversion",
                                    "violated_requirement": "Preserve FFs outside u_pll"},
                      "attempts": [{"fix": {"action": "Remove examine_scan_drc", "artifact_ref": ["F1"]},
                                    "verify": {"resolved": False}}]}
        self.changes = [{"change_id": "F1", "type": "dofile", "path": "runs/R2/deliverables/R2.dofile",
                         "diff_path": "diffs/dofile_R1_to_R2.diff"}]
        for rid, proof, script in (("R1", self.bad, self.old_script), ("R2", self.good, self.new_script)):
            self.save_proof(rid, proof)
            path = self.root / f"runs/{rid}/deliverables/{rid}.dofile"
            path.parent.mkdir(parents=True)
            path.write_text(script)
        self.save_diff()

    def save_proof(self, run, proof):
        path = self.root / f"structural_checks/{run}.json"
        path.parent.mkdir(exist_ok=True)
        path.write_text(json.dumps(proof, indent=2))

    def save_diff(self):
        path = self.root / self.changes[0]["diff_path"]
        path.parent.mkdir(exist_ok=True)
        path.write_text("".join(difflib.unified_diff(
            self.old_script.splitlines(True), self.new_script.splitlines(True), fromfile="R1", tofile="R2")))

    def evidence(self, **kwargs):
        args = {"issue": self.issue, "output_dir": self.root, "current_run": "R2",
                "task_spec": self.spec, "structural_check": self.good, "changes": self.changes}
        args.update(kwargs)
        return partial_issue_positive_evidence(**args)

    def test_actual_scoped_repair_returns_saved_counts_and_exact_line_locator(self):
        evidence = self.evidence()
        self.assertIsNotNone(evidence)
        self.assertEqual(evidence["source"], "structural_checks/R2.json")
        lines = (self.root / evidence["source"]).read_text().splitlines()
        first, last = [int(item.removeprefix("L")) for item in evidence["locator"].split("-")]
        self.assertEqual(evidence["excerpt"], "\n".join(lines[first - 1:last]))
        self.assertIn('"final_scan_ff": 40', evidence["excerpt"])
        self.assertNotIn("Total violations", evidence["excerpt"])

    def test_unknown_or_failed_current_proof_cannot_resolve_issue(self):
        for status in ("fail", "unknown"):
            proof = copy.deepcopy(self.good)
            proof["status"] = status
            self.save_proof("R2", proof)
            self.assertIsNone(self.evidence(structural_check=proof))

    def test_nonpartial_or_explicit_drc_task_cannot_use_this_rule(self):
        self.assertIsNone(self.evidence(task_spec="Construct scan chains and fix DRC"))
        self.assertIsNone(self.evidence(task_spec=self.spec + "\nDRC 必须清零。"))

    def test_missing_scope_or_previous_matching_failure_cannot_resolve_issue(self):
        self.assertIsNone(self.evidence(task_spec="不涉及扫描链的构建。"))
        previous = copy.deepcopy(self.bad)
        previous["problems"] = ["ICG connection is wrong"]
        self.save_proof("R1", previous)
        self.assertIsNone(self.evidence())

    def test_unrelated_drc_diagnosis_cannot_resolve_issue(self):
        issue = copy.deepcopy(self.issue)
        issue["diagnosis"] = {"summary": "Fix uncontrolled clock", "located_object": "clk",
                              "root_cause": "Missing scan clock", "violated_requirement": "DRC zero"}
        self.assertIsNone(self.evidence(issue=issue))

    def test_missing_or_fabricated_change_cannot_resolve_issue(self):
        self.assertIsNone(self.evidence(changes=[]))
        (self.root / self.changes[0]["diff_path"]).write_text("fabricated diff\n")
        self.assertIsNone(self.evidence())

    def test_proof_mismatch_or_nonzero_unknown_cannot_resolve_issue(self):
        mismatched = copy.deepcopy(self.good)
        mismatched["counts"]["final_scan_ff"] = 41
        self.assertIsNone(self.evidence(structural_check=mismatched))
        unknown = copy.deepcopy(self.good)
        unknown["unknown_count"] = 1
        self.save_proof("R2", unknown)
        self.assertIsNone(self.evidence(structural_check=unknown))

    def test_same_run_and_unverified_discovery_cannot_resolve_issue(self):
        self.assertIsNone(self.evidence(current_run="R1"))
        issue = copy.deepcopy(self.issue)
        issue["found"]["verified"] = False
        self.assertIsNone(self.evidence(issue=issue))

    def test_missing_native_script_and_reintroduced_drc_cannot_resolve_issue(self):
        (self.root / "runs/R2/deliverables/R2.dofile").write_text(self.old_script)
        self.assertIsNone(self.evidence())
        (self.root / "runs/R2/deliverables/R2.dofile").unlink()
        self.assertIsNone(self.evidence())

    def test_inherited_change_can_close_later_actual_run_with_saved_proof(self):
        self.save_proof("R3", self.good)
        path = self.root / "runs/R3/deliverables/R3.dofile"
        path.parent.mkdir(parents=True)
        path.write_text(self.new_script)
        evidence = self.evidence(current_run="R3")
        self.assertIsNotNone(evidence)
        self.assertEqual(evidence["source"], "structural_checks/R3.json")

    def test_empty_matching_mapping_tables_are_valid(self):
        self.good["requirements"]["ff_pairs"] = {}
        self.bad["requirements"]["ff_pairs"] = {}
        self.save_proof("R1", self.bad)
        self.save_proof("R2", self.good)
        self.assertIsNotNone(self.evidence())

    def test_native_in_memory_driver_tuples_match_saved_json_arrays(self):
        self.good["evidence"]["icg_examples"] = [{
            "instance": "u_gate", "old_test_driver": ("$0", 0),
            "final_test_driver": ("top::scan_control", 1)}]
        self.save_proof("R2", self.good)
        self.assertIsNotNone(self.evidence())

    def test_conflicting_mapping_tables_still_block_resolution(self):
        self.good["requirements"]["ff_pairs"] = {}
        self.save_proof("R2", self.good)
        self.assertIsNone(self.evidence())


if __name__ == "__main__":
    unittest.main()
