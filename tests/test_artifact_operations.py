from pathlib import Path
import errno
import os
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "agent"))
from artifact_operations import RunValidationCache, independent_copy


class IndependentCopyTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source = self.root / "source.v"
        self.source.write_text("module original; endmodule\n")
        self.source.chmod(0o640)
        self.target = self.root / "target.v"

    def test_copy_preserves_metadata_and_files_are_independent(self):
        before = self.source.stat()
        returned = independent_copy(self.source, self.target)
        self.assertEqual(returned, str(self.target))
        self.assertEqual(self.source.read_bytes(), self.target.read_bytes())
        self.assertEqual(self.target.stat().st_mode & 0o777, 0o640)
        self.assertEqual(self.target.stat().st_mtime_ns, before.st_mtime_ns)
        self.assertNotEqual(self.target.stat().st_ino, before.st_ino)
        self.target.write_text("changed output")
        self.assertEqual(self.source.read_text(), "module original; endmodule\n")
        self.assertEqual(self.source.stat().st_mtime_ns, before.st_mtime_ns)

    def test_failed_clone_falls_back_to_copy2(self):
        with patch("artifact_operations._clone_file", return_value=False), \
                patch("artifact_operations.shutil.copy2", wraps=shutil.copy2) as copier:
            independent_copy(self.source, self.target)
        copier.assert_called_once()
        self.assertEqual(self.target.read_bytes(), self.source.read_bytes())

    @unittest.skipUnless(sys.platform == "linux", "FICLONE is Linux-specific")
    def test_ioctl_failure_falls_back_to_copy2(self):
        with patch("fcntl.ioctl", side_effect=OSError(errno.EXDEV, "cross-filesystem")):
            independent_copy(self.source, self.target)
        self.assertEqual(self.target.read_bytes(), self.source.read_bytes())

    def test_failed_copy_leaves_existing_target_and_no_temporary_file(self):
        self.target.write_text("known good")
        before = self.target.stat()
        with patch("artifact_operations._clone_file", return_value=False), \
                patch("artifact_operations.shutil.copy2", side_effect=OSError("disk full")):
            with self.assertRaises(OSError):
                independent_copy(self.source, self.target)
        self.assertEqual(self.target.read_text(), "known good")
        self.assertEqual(self.target.stat().st_ino, before.st_ino)
        self.assertFalse(list(self.root.glob(".artifact-copy-*")))

    def test_failed_metadata_leaves_existing_target(self):
        self.target.write_text("known good")
        with patch("artifact_operations._clone_file", return_value=True), \
                patch("artifact_operations.shutil.copystat", side_effect=OSError("metadata failure")):
            with self.assertRaises(OSError):
                independent_copy(self.source, self.target)
        self.assertEqual(self.target.read_text(), "known good")

    def test_target_directory_and_symlinks_follow_copy2_defaults(self):
        folder = self.root / "delivery"
        folder.mkdir()
        self.assertEqual(independent_copy(self.source, folder), str(folder / self.source.name))
        actual = self.root / "actual.v"
        self.target.symlink_to(actual)
        source_link = self.root / "source-link.v"
        source_link.symlink_to(self.source)
        independent_copy(source_link, self.target)
        self.assertTrue(self.target.is_symlink())
        self.assertEqual(actual.read_bytes(), self.source.read_bytes())
        self.assertNotEqual(actual.stat().st_ino, self.source.stat().st_ino)

    def test_same_file_is_rejected(self):
        with self.assertRaises(shutil.SameFileError):
            independent_copy(self.source, self.source)


class RunValidationCacheTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.run = self.root / "R1"
        self.run.mkdir()
        self.report = self.run / "scan.rpt"
        self.report.write_text("PASS\n")
        self.cache = RunValidationCache()
        self.calls = 0
        self.parameters = {"dofile": "scan\n", "task_spec": "full scan", "status": "completed",
                           "expected": {"task": "task1", "segments": [{"name": "a", "length": 2}]},
                           "tool_finished": True}

    def checker(self):
        self.calls += 1
        return True, ["example"]

    def check(self, validator=None, **changes):
        return self.cache.validate(self.run, validator or self.checker, **(self.parameters | changes))

    def test_unchanged_result_is_reused_with_independent_problem_lists(self):
        ok, problems = self.check()
        self.assertTrue(ok)
        problems.append("caller mutation")
        self.assertEqual(self.check(), (True, ["example"]))
        self.assertEqual(self.calls, 1)
        self.assertEqual(self.cache.stats["hits"], 1)
        self.assertEqual(self.cache.stats["full_validations"], 1)
        self.assertEqual(self.cache.stats["signature_scans"], 4)
        self.assertNotIn("full scan", repr(self.cache._entry))

    def test_same_length_rewrite_with_original_mtime_is_not_reused(self):
        self.check()
        old = self.report.stat()
        self.report.write_text("FAIL\n")
        os.utime(self.report, ns=(old.st_atime_ns, old.st_mtime_ns))
        self.check()
        self.assertEqual(self.calls, 2)
        self.assertEqual(self.cache.stats["hits"], 0)

    def test_addition_and_removal_invalidate(self):
        self.check()
        extra = self.run / "new.rpt"
        extra.write_text("new report")
        self.check()
        extra.unlink()
        self.check()
        self.assertEqual(self.calls, 3)

    def test_parameter_changes_invalidate_including_nested_expected(self):
        self.check()
        self.check(dofile="different Tcl")
        self.check(task_spec="different task")
        self.check(status="aborted")
        self.parameters["expected"]["segments"][0]["length"] = 3
        self.check()
        self.assertEqual(self.calls, 5)

    def test_running_tool_neither_seeds_nor_uses_cache(self):
        self.check(tool_finished=False)
        self.check(tool_finished=False)
        self.check()
        self.check(tool_finished=False)
        self.assertEqual(self.calls, 4)
        self.assertEqual(self.cache.stats["hits"], 0)

    def test_validation_that_changes_artifacts_is_rejected_and_not_cached(self):
        def changing_checker():
            self.calls += 1
            self.report.write_text("changed")
            return True, []

        ok, problems = self.check(changing_checker)
        self.assertFalse(ok)
        self.assertIn("changed during validation", problems[0])
        self.assertEqual(self.cache.stats["unstable_validations"], 1)
        self.check()
        self.assertEqual(self.calls, 2)

    def test_validation_that_mutates_expected_is_rejected(self):
        def changing_checker():
            self.parameters["expected"]["segments"].append({"name": "b"})
            return True, []

        ok, problems = self.check(changing_checker)
        self.assertFalse(ok)
        self.assertIn("parameters changed", problems[0])
        self.assertIsNone(self.cache._entry)

    def test_symlink_target_and_retargeting_invalidate(self):
        external = self.root / "external.rpt"
        external.write_text("PASS\n")
        link = self.run / "linked.rpt"
        link.symlink_to(external)
        self.check()
        self.check()
        self.assertEqual(self.calls, 1)
        old = external.stat()
        external.write_text("FAIL\n")
        os.utime(external, ns=(old.st_atime_ns, old.st_mtime_ns))
        self.check()
        another = self.root / "another.rpt"
        another.write_text("PASS\n")
        link.unlink()
        link.symlink_to(another)
        self.check()
        self.assertEqual(self.calls, 3)

    def test_ancestor_directory_replacement_invalidates(self):
        external_dir = self.root / "external"
        external_dir.mkdir()
        external = external_dir / "scan.rpt"
        external.write_text("PASS\n")
        (self.run / "linked.rpt").symlink_to(external)
        self.check()
        external_dir.rename(self.root / "external_old")
        external_dir.mkdir()
        (external_dir / "scan.rpt").write_text("PASS\n")
        self.check()
        self.assertEqual(self.calls, 2)

    def test_intermediate_symlink_change_to_same_final_target_invalidates(self):
        external = self.root / "external.rpt"
        external.write_text("PASS\n")
        intermediate = self.root / "alias.rpt"
        intermediate.symlink_to(external)
        (self.run / "linked.rpt").symlink_to(intermediate)
        self.check()
        intermediate.unlink()
        intermediate.symlink_to(external)
        self.check()
        self.assertEqual(self.calls, 2)

    def test_run_deleted_during_validation_is_rejected(self):
        def deleting_checker():
            self.report.unlink()
            self.run.rmdir()
            return True, []

        ok, problems = self.check(deleting_checker)
        self.assertFalse(ok)
        self.assertIn("changed during validation", problems[0])
        self.assertIsNone(self.cache._entry)

    def test_input_subtree_is_not_walked_or_read(self):
        input_dir = self.run / "input"
        input_dir.mkdir()
        source = input_dir / "source.v"
        source.write_text("original input")
        self.check()
        source.write_text("changed input: caller integrity gate is required")
        self.check()
        self.assertEqual(self.calls, 1)
        self.assertNotIn("original input", repr(self.cache._entry))

    def test_directory_symlinks_disable_cache(self):
        directory = self.root / "external"
        directory.mkdir()
        (directory / "report.rpt").write_text("PASS")
        (self.run / "external").symlink_to(directory, target_is_directory=True)
        self.check()
        self.check()
        self.assertEqual(self.calls, 2)
        self.assertEqual(self.cache.stats["hits"], 0)

    def test_permission_or_stat_failure_invalidates_and_calls_checker(self):
        self.check()
        with patch("artifact_operations._run_signature", return_value=None):
            self.check()
        self.assertEqual(self.calls, 2)
        self.assertIsNone(self.cache._entry)

    def test_final_signature_reread_can_prevent_cache_hit(self):
        self.check()
        original_snapshot = self.cache._snapshot
        reads = 0

        def moving_snapshot(run_dir):
            nonlocal reads
            reads += 1
            if reads == 2:
                self.report.write_text("FAIL\n")
            return original_snapshot(run_dir)

        with patch.object(self.cache, "_snapshot", side_effect=moving_snapshot):
            self.check()
        self.assertEqual(self.calls, 2)
        self.assertEqual(self.cache.stats["hits"], 0)


if __name__ == "__main__":
    unittest.main()
