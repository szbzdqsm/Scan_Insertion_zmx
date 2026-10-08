import json
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "agent"))
from netlist_repair import RepairRejected, fingerprint_paths
from repair_deliverables import publish_repair_deliverables


class RepairDeliverablesTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.original = self.root / "input/top.v"
        self.original.parent.mkdir()
        self.original.write_bytes(b"module top; wire a; endmodule\n")
        self.candidate = self.root / "netlist_versions/R2/top.v"
        self.candidate.parent.mkdir(parents=True)
        self.candidate.write_bytes(b"module top; wire b; endmodule\n")
        self.active = {self.original: self.candidate}
        self.proof = self.root / "lec/R2"
        (self.proof / "proof").mkdir(parents=True)
        self.aggregate = self.proof / "aggregate.log"
        self.aggregate.write_bytes(b"actual retained EQY fixture log\n")
        self.summary = {"passed": True, "returncode": 0, "result": "PASS", "top": "top",
                        "candidate_netlists": [str(self.candidate)], "original_netlists": [str(self.original)]}
        (self.proof / "summary.json").write_text(json.dumps(self.summary))
        (self.proof / "eqy.log").write_bytes(b"actual EQY fixture log\n")
        (self.proof / "check.eqy").write_text("[gold]\nfixture\n[gate]\nfixture\n")
        (self.proof / "proof/PASS").touch()
        self.attempts = [{"run_ref": "R2", "admitted": True, "adopted": True, "lec_ref": "lec/R2/aggregate.log"}]
        self.library = self.root / "input/cells.lib"
        self.library.write_text("synthetic library fixture; never passed to actual EDA\n")

    def frozen(self):
        paths = list(self.active) + list(self.active.values()) + [path for path in self.proof.rglob("*") if path.is_file()]
        return fingerprint_paths(paths)

    def publish(self, **changes):
        arguments = {"task": "task2", "final_run": "R3", "active_netlists": self.active,
                     "repair_attempts": self.attempts, "protected_fingerprints": self.frozen()} | changes
        return publish_repair_deliverables(self.root, **arguments)

    def proof_fixture(self, originals, candidates, libraries, top, proof_root, deadline):
        proof_root.mkdir(parents=True, exist_ok=False)
        (proof_root / "proof").mkdir()
        (proof_root / "proof/PASS").touch()
        (proof_root / "eqy.log").write_text("actual retained synthetic exported proof fixture\n")
        (proof_root / "check.eqy").write_text("synthetic fixed proof fixture\n")
        summary = {"passed": True, "returncode": 0, "result": "PASS", "top": top,
                   "original_netlists": [str(path) for path in originals],
                   "candidate_netlists": [str(path) for path in candidates]}
        (proof_root / "summary.json").write_text(json.dumps(summary))
        return summary

    def add_second_file(self):
        original = self.root / "input/helper.v"
        original.write_bytes(b"module helper; endmodule")
        candidate = self.candidate.parent / "helper.v"
        candidate.write_bytes(original.read_bytes())
        self.active[original] = candidate
        self.summary["candidate_netlists"] = [str(candidate), str(self.candidate)]
        self.summary["original_netlists"] = [str(original), str(self.original)]
        (self.proof / "summary.json").write_text(json.dumps(self.summary))
        return original, candidate

    def test_single_file_and_report_are_complete_actual_bytes(self):
        manifest = self.publish()
        self.assertEqual((self.root / "final_results/deliverables/pre_scan_final.v").read_bytes(), self.candidate.read_bytes())
        self.assertEqual((self.root / "final_results/reports/lec_report.rpt").read_bytes(), self.aggregate.read_bytes())
        self.assertEqual(manifest["format"], "byte_exact_single_file")
        self.assertEqual(manifest["final_run"], "R3")
        self.assertEqual(manifest["sources"][0]["sha256"], self.frozen()[str(self.candidate)]["sha256"])

    def test_unchanged_or_task1_does_not_publish(self):
        self.assertIsNone(self.publish(task="task1"))
        self.assertIsNone(self.publish(active_netlists={self.original: self.original}))
        self.assertFalse((self.root / "final_results").exists())

    def test_unadopted_missing_or_failed_proof_cannot_publish(self):
        with self.assertRaises(RepairRejected):
            self.publish(repair_attempts=[self.attempts[0] | {"adopted": False}])
        (self.proof / "proof/PASS").unlink()
        with self.assertRaises(RepairRejected):
            self.publish()
        (self.proof / "proof/PASS").touch()
        (self.proof / "proof/FAIL").touch()
        with self.assertRaises(RepairRejected):
            self.publish()
        self.assertFalse((self.root / "final_results/deliverables/pre_scan_final.v").exists())

    def test_modified_candidate_original_or_proof_is_rejected(self):
        for source in (self.candidate, self.original, self.aggregate, self.proof / "summary.json"):
            frozen = self.frozen()
            before = source.read_bytes()
            source.write_bytes(before + b"\n")
            with self.assertRaises(RepairRejected):
                self.publish(protected_fingerprints=frozen)
            source.write_bytes(before)

    def test_unfingerprinted_summary_and_wrong_proof_family_are_rejected(self):
        frozen = self.frozen()
        del frozen[str(self.proof / "summary.json")]
        with self.assertRaises(RepairRejected):
            self.publish(protected_fingerprints=frozen)
        (self.proof / "summary.json").write_text(json.dumps(self.summary | {"original_netlists": ["/wrong/original.v"]}))
        with self.assertRaises(RepairRejected):
            self.publish()

    def test_deleted_affected_proof_cannot_be_silently_dropped(self):
        affected = self.proof / "affected_1"
        (affected / "proof").mkdir(parents=True)
        (affected / "summary.json").write_text(json.dumps(self.summary | {"top": "helper"}))
        (affected / "eqy.log").write_text("actual affected module proof log\n")
        (affected / "check.eqy").write_text("actual affected config\n")
        (affected / "proof/PASS").touch()
        frozen = self.frozen()
        import shutil
        shutil.rmtree(affected)
        with self.assertRaises(RepairRejected):
            self.publish(protected_fingerprints=frozen)

    def test_multiple_files_preserve_bytes_order_and_transparent_offsets(self):
        _, candidate = self.add_second_file()
        # Proof read order, not alphabetical filename order, controls publication.
        with patch("repair_deliverables.run_proof", side_effect=self.proof_fixture) as proof:
            manifest = self.publish(libraries=[self.library], deadline=time.monotonic() + 10)
        self.assertEqual(proof.call_count, 1)
        self.assertTrue(Path(manifest["export_candidate"]).is_file())
        self.assertTrue(manifest["exported_single_file_proved"])
        self.assertTrue(manifest["export_proof_refs"])
        actual = (self.root / "final_results/deliverables/pre_scan_final.v").read_bytes()
        self.assertEqual(actual, candidate.read_bytes() + b"\n" + self.candidate.read_bytes())
        self.assertEqual(manifest["format"], "source_file_concatenation")
        self.assertEqual(manifest["sources"][1]["separator_bytes_before"], 1)
        for item in manifest["sources"]:
            self.assertEqual(actual[item["start_byte"]:item["start_byte"] + item["size_bytes"]],
                             Path(item["candidate_path"]).read_bytes())
        self.assertIn("listed candidate files", manifest["proof_scope"])
        self.assertTrue(manifest["proof_refs"])

    def test_mutation_during_copy_does_not_publish(self):
        from artifact_operations import independent_copy as actual_copy

        def mutating_copy(source, destination):
            result = actual_copy(source, destination)
            if Path(source) == self.candidate:
                self.candidate.write_bytes(b"changed after copy")
            return result

        with patch("repair_deliverables.independent_copy", side_effect=mutating_copy):
            with self.assertRaises(RepairRejected):
                self.publish()
        self.assertFalse((self.root / "final_results/deliverables/pre_scan_final.v").exists())

    def test_publication_failure_rolls_back_partial_files(self):
        from repair_deliverables import _publish_new as actual_publish

        def failing_publish(source_fd, destination_fd, name):
            if name == "lec_report.rpt":
                raise OSError("publication failure")
            return actual_publish(source_fd, destination_fd, name)

        with patch("repair_deliverables._publish_new", side_effect=failing_publish):
            with self.assertRaises(OSError):
                self.publish()
        self.assertFalse((self.root / "final_results/deliverables/pre_scan_final.v").exists())
        self.assertFalse((self.root / "final_results/reports/lec_report.rpt").exists())

    def test_symlink_final_directory_or_ancestor_never_writes_through(self):
        outside = self.root / "outside"
        outside.mkdir()
        final = self.root / "final_results"
        final.mkdir()
        (final / "reports").symlink_to(outside, target_is_directory=True)
        with self.assertRaises(RepairRejected):
            self.publish()
        self.assertFalse(list(outside.iterdir()))
        (final / "reports").unlink()
        (final / "deliverables").rmdir()
        final.rmdir()
        final.symlink_to(outside, target_is_directory=True)
        with self.assertRaises(RepairRejected):
            self.publish()
        self.assertFalse(list(outside.iterdir()))

    def test_existing_target_is_never_overwritten(self):
        directory = self.root / "final_results/deliverables"
        directory.mkdir(parents=True)
        target = directory / "pre_scan_final.v"
        target.write_text("retained successful original target")
        with self.assertRaises(RepairRejected):
            self.publish()
        self.assertEqual(target.read_text(), "retained successful original target")

    def test_multifile_without_real_proof_budget_or_libraries_is_refused(self):
        self.add_second_file()
        for arguments in ({}, {"libraries": [self.library]}, {"deadline": time.monotonic() + 10},
                          {"libraries": [self.library], "deadline": time.monotonic() - 1}):
            with self.assertRaises(RepairRejected):
                self.publish(**arguments)
        self.assertFalse((self.root / "final_results").exists())

    def test_multifile_failed_export_proof_remains_failure_and_preserves_scene(self):
        self.add_second_file()
        with patch("repair_deliverables.run_proof", return_value={"passed": False, "returncode": 1, "result": "UNPROVEN"}):
            with self.assertRaisesRegex(RepairRejected, "UNPROVEN"):
                self.publish(libraries=[self.library], deadline=time.monotonic() + 10)
        self.assertTrue((self.root / "netlist_versions/export_R3/pre_scan_final.v").is_file())
        self.assertFalse((self.root / "final_results/deliverables/pre_scan_final.v").exists())

    def test_multifile_also_proves_every_affected_module(self):
        self.add_second_file()
        directory = self.proof / "affected_1"
        self.proof_fixture([Path(path) for path in self.summary["original_netlists"]],
                           [Path(path) for path in self.summary["candidate_netlists"]], [self.library],
                           "helper", directory, time.monotonic() + 10)
        with patch("repair_deliverables.run_proof", side_effect=self.proof_fixture) as proof:
            manifest = self.publish(libraries=[self.library], deadline=time.monotonic() + 10)
        self.assertEqual([call.args[3] for call in proof.call_args_list], ["top", "helper"])
        self.assertEqual(manifest["export_proof_tops"], ["top", "helper"])

    def test_baseexception_after_atomic_rename_rolls_back_own_files(self):
        from case_deadline import CaseDeadlineExceeded
        from repair_deliverables import _publish_new as actual_publish

        def interrupted_publish(source_fd, destination_fd, name):
            actual_publish(source_fd, destination_fd, name)
            raise CaseDeadlineExceeded("synthetic publication deadline")

        with patch("repair_deliverables._publish_new", side_effect=interrupted_publish):
            with self.assertRaises(CaseDeadlineExceeded):
                self.publish()
        self.assertFalse((self.root / "final_results/deliverables/pre_scan_final.v").exists())


if __name__ == "__main__":
    unittest.main()
