"""Partial-flow admission checks use synthetic tool/model fixtures only."""
import importlib.util
import json
import unittest
from pathlib import Path
from unittest.mock import patch


_fixture_path = Path(__file__).with_name("test_audit_regressions.py")
_fixture_spec = importlib.util.spec_from_file_location("partial_audit_fixture", _fixture_path)
_fixture = importlib.util.module_from_spec(_fixture_spec)
_fixture_spec.loader.exec_module(_fixture)
agent = _fixture.agent


class PartialInsertionIntegration(unittest.TestCase):
    def setUp(self):
        self.fixture = _fixture.AuditRegression()
        self.fixture.setUp()
        self.addCleanup(self.fixture.tearDown)

    @staticmethod
    def proof(status="pass", problems=None, unknown=None):
        return {"applicable": True, "status": status,
                "problems": list(problems or []), "unknown": list(unknown or []),
                "unknown_count": len(unknown or []), "evidence": {"method": "synthetic structural fixture"}}

    def run_partial(self, proofs, checks=None, **kwargs):
        def artifacts(run_dir, spec):
            return [run_dir / "deliverables/post_scan.v"], []

        with patch.object(agent, "check_output", side_effect=checks, return_value=(True, [])), \
             patch.object(agent, "parse_tool_limit", return_value=kwargs.get("tool_limit", 2)), \
             patch.object(agent, "partial_flow_artifact_paths", side_effect=artifacts) as paths, \
             patch.object(agent, "partial_insertion_validation", side_effect=proofs) as validation:
            result = self.fixture.run_main(task_spec="Generate replacements without building scan chains.", **kwargs)
        return result, paths, validation

    def test_success_keeps_proof_outside_frozen_native_run_and_reuses_last_proof(self):
        proof = self.proof()
        (result, decision, captures, input_dir, output_dir), paths, validation = self.run_partial([proof])
        self.assertEqual(result, 0)
        self.assertEqual(len(captures["calls"]), 1)
        self.assertEqual(validation.call_count, 1)
        self.assertEqual(paths.call_count, 1)
        self.assertEqual(decision["partial_structure_validation"], proof)
        saved = output_dir / "structural_checks/R1.json"
        self.assertEqual(json.loads(saved.read_text()), proof)
        self.assertFalse(any((output_dir / "runs").rglob("structural_checks")))
        self.assertTrue(decision["tool_checks_passed"])
        self.assertIn("partial_structure_validation", decision["performance"]["stages_seconds"])
        positional = validation.call_args.args
        self.assertEqual(positional[0], [input_dir / "netlist/pre_scan.v"])
        self.assertEqual(positional[1], [output_dir / "runs/R1/deliverables/post_scan.v"])
        self.assertEqual(positional[2], [input_dir / "lib/stdcells.lib"])
        self.assertEqual(validation.call_args.kwargs["replacement_paths"], [])
        self.assertEqual(set(validation.call_args.kwargs["report_paths"]),
                         set((output_dir / "runs/R1/reports").glob("*.rpt")))

    def test_disproved_structure_blocks_final_pass_even_with_successful_native_tool(self):
        (result, decision, captures, _, _), _, _ = self.run_partial(
            [self.proof("fail", ["Outside target SFF reverted"])] * 2)
        self.assertEqual(result, 2)
        self.assertFalse(decision["tool_checks_passed"])
        self.assertEqual(decision["partial_structure_validation"]["status"], "fail")
        self.assertEqual([run["exit_status"] for run in decision["tool_runs"]], ["completed", "completed"])
        self.assertEqual(len(captures["calls"]), 2)
        self.assertIn("Outside target SFF reverted", captures["requests"][1]["messages"][1]["content"])

    def test_unknown_structure_blocks_final_pass_and_is_returned_to_model(self):
        unknown = "Unsupported reachable structural expression"
        (result, decision, captures, _, _), _, _ = self.run_partial(
            [self.proof("unknown", unknown=[unknown])] * 2)
        self.assertEqual(result, 2)
        self.assertFalse(decision["tool_checks_passed"])
        self.assertIn("Partial-flow structural proof incomplete: " + unknown,
                      captures["requests"][1]["messages"][1]["content"])

    def test_nonpass_without_diagnostics_still_blocks_adoption(self):
        (result, decision, captures, _, _), _, _ = self.run_partial([self.proof("unknown")] * 2)
        self.assertEqual(result, 2)
        self.assertFalse(decision["tool_checks_passed"])
        self.assertIn("Partial-flow structural proof did not pass",
                      captures["requests"][1]["messages"][1]["content"])

    def test_later_success_replaces_failed_proof_and_preserves_both_evidence_files(self):
        bad = self.proof("fail", ["Outside target SFF reverted"])
        good = self.proof()
        (result, decision, captures, _, output_dir), _, validation = self.run_partial([bad, good])
        self.assertEqual(result, 0)
        self.assertEqual(len(captures["calls"]), 2)
        self.assertEqual(validation.call_count, 2)
        self.assertEqual(decision["final_run"], "R2")
        self.assertEqual(decision["partial_structure_validation"], good)
        self.assertEqual(json.loads((output_dir / "structural_checks/R1.json").read_text()), bad)
        self.assertEqual(json.loads((output_dir / "structural_checks/R2.json").read_text()), good)

    def test_later_structural_failure_does_not_adopt_earlier_structural_success(self):
        (result, decision, captures, _, _), _, _ = self.run_partial(
            [self.proof(), self.proof("fail", ["Bad last structure"])],
            checks=[(False, ["Other native check failed"]), (True, [])])
        self.assertEqual(result, 2)
        self.assertEqual(len(captures["calls"]), 2)
        self.assertEqual(decision["final_run"], "R2")
        self.assertEqual(decision["partial_structure_validation"]["status"], "fail")
        self.assertFalse(decision["tool_checks_passed"])

    def test_full_flow_does_not_call_partial_validator(self):
        with patch.object(agent, "partial_insertion_validation") as validation:
            result, decision, _, _, output_dir = self.fixture.run_main()
        self.assertEqual(result, 0)
        validation.assert_not_called()
        self.assertIsNone(decision["partial_structure_validation"])
        self.assertFalse((output_dir / "structural_checks").exists())

    def test_changed_native_netlist_after_structural_proof_blocks_final_adoption(self):
        original = agent.record_issue_fixes

        def modify_after_proof(*args, **kwargs):
            original(*args, **kwargs)
            output_dir, run_id = args[3], args[5]
            (output_dir / "runs" / run_id / "deliverables/post_scan.v").write_text(
                "module changed_after_structural_proof(); endmodule\n")

        with patch.object(agent, "record_issue_fixes", side_effect=modify_after_proof):
            (result, decision, _, _, _), _, _ = self.run_partial([self.proof()])
        self.assertEqual(result, 2)
        self.assertFalse(decision["tool_checks_passed"])
        self.assertIn("Inputs/executed candidates/proofs changed before final adoption", decision["summary"])

    def test_changed_source_after_structural_proof_blocks_final_adoption(self):
        original = agent.record_issue_fixes

        def modify_after_proof(*args, **kwargs):
            original(*args, **kwargs)
            output_dir = args[3]
            input_dir = output_dir.parents[1] / "input/hidden_case_1/input"
            (input_dir / "netlist/pre_scan.v").write_text("module changed_input(); endmodule\n")

        with patch.object(agent, "record_issue_fixes", side_effect=modify_after_proof):
            (result, decision, _, _, _), _, _ = self.run_partial([self.proof()])
        self.assertEqual(result, 2)
        self.assertFalse(decision["tool_checks_passed"])
        self.assertIn("Inputs/executed candidates/proofs changed before final adoption", decision["summary"])

    def test_prompt_explains_partial_drc_collateral_replacement_risk(self):
        (_, _, captures, _, _), _, _ = self.run_partial([self.proof()])
        system = captures["requests"][0]["messages"][0]["content"]
        self.assertIn("partial connect/replace-only tasks", system)
        self.assertIn("-replace_unscan can revert both", system)
        self.assertIn("Do not add that DRC pass to a partial task", system)


if __name__ == "__main__":
    unittest.main()
