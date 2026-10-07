"""Public batch resume regressions; every Docker/agent execution is mocked."""
from contextlib import redirect_stderr, redirect_stdout
from copy import deepcopy
import fcntl
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import run_public_cases as runner  # noqa: E402


IMAGE_ID = "sha256:" + "a" * 64


class PublicResumeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="scan-public-resume-")
        self.root = Path(self.temp.name)
        (self.root / "agent").mkdir()
        # This is an empty fixture, never the private workspace .env.
        (self.root / "agent/.env").write_text("")
        self.cases = self.root / "public_cases"
        for relative in ("task_1/case1", "task_1/case2", "task_2/case1"):
            self.make_case(relative)
        self.batch = self.root / "outputs/public-live-old-subset"
        self.batch.mkdir(parents=True)
        self.old_result = {"case": "task_1_case1", "agent_passed": True,
                           "summary": "existing real result", "tool_calls": 2,
                           "elapsed_seconds": 12.0}
        self.summary = {"image": "original-tag", "image_id": IMAGE_ID, "model": "deepseek-v4-pro",
                        "mode": "live_model", "answers_exposed": False, "thinking": "runtime_default",
                        "case_count": 1, "cases": [deepcopy(self.old_result)], "agent_pass_count": 1}
        self.save_original()
        self.inspection = patch.object(runner.subprocess, "run", return_value=SimpleNamespace(stdout=IMAGE_ID))
        self.root_patch = patch.object(runner, "ROOT", self.root)
        self.inspection_mock = self.inspection.start()
        self.root_patch.start()
        self.addCleanup(self.inspection.stop)
        self.addCleanup(self.root_patch.stop)

    def tearDown(self):
        self.temp.cleanup()

    def make_case(self, relative):
        source = self.cases / relative / "input"
        source.mkdir(parents=True, exist_ok=True)
        (source / "task_spec.md").write_text("Public fixture task\n")
        (source / "limitations.md").write_text("整个 case 的执行总时间不超过 150 秒\n")
        (source / "netlist").mkdir(exist_ok=True)
        (source / "netlist/test.v").write_text("module test; endmodule\n")
        return source.parent

    def save_original(self):
        raw = (json.dumps(self.summary, ensure_ascii=False, indent=3) + "\n").encode()
        (self.batch / "summary.json").write_bytes(raw)
        return raw

    def fake_case(self, case, batch, image, env_file, thinking):
        self.assertEqual(image, IMAGE_ID)
        self.assertEqual(env_file, self.root / "agent/.env")
        tag = runner._case_tag(case)
        (batch / tag).mkdir()
        return {"case": tag, "agent_passed": True, "summary": "mock execution", "output_directory": str(batch / tag)}

    def run_main(self, extra=(), resume=True, side_effect=None):
        args = ["run_public_cases.py", "--cases", str(self.cases), "--image", "requested-tag"]
        if resume:
            args += ["--resume-batch", str(self.batch)]
        args += list(extra)
        with patch.object(sys, "argv", args), redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()), \
                patch.object(runner, "run_case", side_effect=side_effect or self.fake_case) as execute:
            result = runner.main()
        return result, execute

    def test_resume_retains_original_case_and_only_runs_remaining_sources(self):
        original = (self.batch / "summary.json").read_bytes()
        result, execute = self.run_main()
        self.assertEqual(result, 0)
        self.assertEqual(execute.call_count, 2)
        self.assertEqual({runner._case_tag(call.args[0]) for call in execute.call_args_list},
                         {"task_1_case2", "task_2_case1"})
        summary = json.loads((self.batch / "summary.json").read_text())
        self.assertEqual(next(row for row in summary["cases"] if row["case"] == "task_1_case1"), self.old_result)
        self.assertEqual(summary["image"], "original-tag")
        self.assertEqual(summary["image_id"], IMAGE_ID)
        self.assertEqual(summary["case_count"], 3)
        self.assertEqual(summary["completed_case_count"], 3)
        self.assertEqual(summary["agent_pass_count"], 3)
        self.assertEqual(summary["run_status"], "complete")
        self.assertEqual(summary["pending_cases"], [])
        self.assertEqual(summary["original_subset"]["recorded_cases"], ["task_1_case1"])
        self.assertIsNone(summary["original_subset"]["cases_root"])
        history = summary["resume_history"][-1]
        self.assertEqual(history["preserved_cases"], ["task_1_case1"])
        self.assertEqual(history["cases_root"], str(self.cases))
        self.assertEqual({row["case"] for row in history["remaining_sources"]}, {"task_1_case2", "task_2_case1"})
        self.assertEqual((self.batch / history["summary_backup"]).read_bytes(), original)
        self.inspection_mock.assert_called_once_with(["docker", "image", "inspect", "--format", "{{.Id}}", "requested-tag"],
                                                    check=True, capture_output=True, text=True)

    def test_four_recorded_cases_can_complete_the_same_image_eleven_case_plan(self):
        for task, count in (("task_1", 6), ("task_2", 5)):
            for number in range(1, count + 1):
                self.make_case(f"{task}/case{number}")
        tags = ["task_1_case1", "task_1_case6", "task_2_case2", "task_2_case5"]
        self.summary.update(case_count=4, agent_pass_count=4,
                            cases=[{"case": tag, "agent_passed": True, "original": tag} for tag in tags])
        original_rows = deepcopy(self.summary["cases"])
        self.save_original()
        result, execute = self.run_main()
        self.assertEqual(result, 0)
        self.assertEqual(execute.call_count, 7)
        summary = json.loads((self.batch / "summary.json").read_text())
        self.assertEqual(summary["case_count"], 11)
        self.assertEqual(summary["agent_pass_count"], 11)
        for original in original_rows:
            self.assertIn(original, summary["cases"])

    def test_failed_recorded_case_is_retained_and_never_retried(self):
        self.summary["cases"][0]["agent_passed"] = False
        self.summary["cases"][0]["runner_error"] = "ExistingFailure"
        self.summary["agent_pass_count"] = 0
        original = deepcopy(self.summary["cases"][0])
        self.save_original()
        result, execute = self.run_main()
        self.assertEqual(result, 2)
        self.assertEqual(execute.call_count, 2)
        summary = json.loads((self.batch / "summary.json").read_text())
        self.assertIn(original, summary["cases"])
        self.assertEqual(summary["agent_pass_count"], 2)

    def test_no_remaining_cases_is_noop_without_env_or_backup(self):
        original = (self.batch / "summary.json").read_bytes()
        (self.root / "agent/.env").unlink()
        before = {path.name for path in self.batch.iterdir()}
        result, execute = self.run_main(["--select", "task_1/case1"])
        self.assertEqual(result, 0)
        execute.assert_not_called()
        self.assertEqual((self.batch / "summary.json").read_bytes(), original)
        self.assertEqual({path.name for path in self.batch.iterdir()}, before)

    def test_noop_with_recorded_failure_reports_failure_without_modifying_history(self):
        self.summary["cases"][0]["agent_passed"] = False
        self.summary["agent_pass_count"] = 0
        original = self.save_original()
        result, execute = self.run_main(["--select", "task_1/case1"])
        self.assertEqual(result, 2)
        execute.assert_not_called()
        self.assertEqual((self.batch / "summary.json").read_bytes(), original)

    def test_live_identity_and_thinking_mismatches_fail_before_any_mutation(self):
        valid = deepcopy(self.summary)
        for key, value in (("mode", "replay"), ("answers_exposed", True), ("answers_exposed", 0),
                           ("model", "other-model"), ("image_id", "sha256:" + "b" * 64),
                           ("thinking", "off")):
            with self.subTest(key=key, value=value):
                self.summary = dict(valid, **{key: value})
                original = self.save_original()
                with self.assertRaises(SystemExit) as error:
                    self.run_main()
                self.assertEqual(error.exception.code, 2)
                self.assertEqual((self.batch / "summary.json").read_bytes(), original)
                self.assertEqual(list(self.batch.glob("summary.before-resume-*")), [])

    def test_explicit_thinking_mode_must_match_and_is_forwarded(self):
        self.summary["thinking"] = "off"
        self.save_original()
        result, execute = self.run_main(["--thinking", "off"])
        self.assertEqual(result, 0)
        self.assertTrue(all(call.args[4] == "off" for call in execute.call_args_list))

    def test_outside_or_symlink_summary_is_rejected(self):
        outside = self.root / "outside"
        outside.mkdir()
        (outside / "summary.json").write_bytes((self.batch / "summary.json").read_bytes())
        with self.assertRaises(ValueError):
            runner._resume_path(outside)
        with self.assertRaises(ValueError):
            runner._resume_path(self.root / "outputs")
        target = outside / "summary.json"
        (self.batch / "summary.json").unlink()
        (self.batch / "summary.json").symlink_to(target)
        with self.assertRaises(ValueError):
            runner._resume_path(self.batch)

    def test_invalid_case_rows_and_pass_counts_are_rejected(self):
        valid = deepcopy(self.summary)
        changes = [dict(cases=valid["cases"] * 2, case_count=2),
                   dict(cases=[{"case": "task_9_case9", "agent_passed": True}]),
                   dict(cases=[{"case": "task_1_case1", "agent_passed": "true"}]),
                   dict(case_count=False), dict(agent_pass_count=0), dict(agent_pass_count=True),
                   dict(cases=[dict(self.old_result, output_directory=str(self.root / "outside"))]),
                   dict(resume_history={}), dict(run_status="unknown"), dict(run_status="complete", case_count=2)]
        for changed in changes:
            with self.subTest(changed=changed):
                self.summary = dict(valid, **changed)
                self.save_original()
                with self.assertRaises(SystemExit):
                    self.run_main()

    def test_unrecorded_existing_output_or_staged_input_is_never_overwritten(self):
        for path in (self.batch / "task_1_case2", self.batch / ".inputs/task_1_case2"):
            with self.subTest(path=path):
                path.mkdir(parents=True)
                marker = path / "preserve.txt"
                marker.write_text("keep unfinished work")
                original = (self.batch / "summary.json").read_bytes()
                with self.assertRaises(SystemExit):
                    self.run_main()
                self.assertEqual(marker.read_text(), "keep unfinished work")
                self.assertEqual((self.batch / "summary.json").read_bytes(), original)
                marker.unlink()
                path.rmdir()

    def test_legacy_batch_must_finish_original_plan_before_resume(self):
        self.summary["case_count"] = 3
        original = self.save_original()
        with self.assertRaises(SystemExit):
            self.run_main()
        self.assertEqual((self.batch / "summary.json").read_bytes(), original)

    def test_current_runner_lock_prevents_concurrent_resume(self):
        lock = self.batch / ".public-runner.lock"
        with lock.open("a") as held:
            fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
            original = (self.batch / "summary.json").read_bytes()
            with self.assertRaises(SystemExit):
                self.run_main()
            self.assertEqual((self.batch / "summary.json").read_bytes(), original)
            self.assertEqual(list(self.batch.glob("summary.before-resume-*")), [])

    def test_initial_snapshot_exposes_pending_cases_and_runner_failure_is_recorded(self):
        snapshots = []
        original_writer = runner._write_summary
        def write(batch, summary):
            snapshots.append(deepcopy(summary))
            original_writer(batch, summary)
        def fail(case, *args):
            raise RuntimeError("mock failure")
        with patch.object(runner, "_write_summary", side_effect=write):
            result, execute = self.run_main(side_effect=fail)
        self.assertEqual(result, 2)
        self.assertEqual(execute.call_count, 2)
        initial = snapshots[0]
        self.assertEqual(initial["case_count"], 3)
        self.assertEqual(initial["completed_case_count"], 1)
        self.assertEqual(initial["pending_cases"], ["task_1_case2", "task_2_case1"])
        self.assertEqual(initial["run_status"], "in_progress")
        final = snapshots[-1]
        self.assertEqual(final["run_status"], "complete")
        self.assertEqual(final["agent_pass_count"], 1)
        self.assertEqual(sum(row.get("runner_error") == "RuntimeError" for row in final["cases"]), 2)

    def test_backup_exclusive_creation_preserves_existing_backups(self):
        with patch.object(runner, "_stamp", return_value="same-stamp"):
            first = runner._backup_summary(self.batch, b"first")
            second = runner._backup_summary(self.batch, b"second")
        self.assertNotEqual(first, second)
        self.assertEqual((self.batch / first).read_bytes(), b"first")
        self.assertEqual((self.batch / second).read_bytes(), b"second")

    def test_modern_incomplete_plan_with_no_started_output_can_resume(self):
        self.summary.update(case_count=3, run_status="in_progress",
                            planned_cases=["task_1_case1", "task_1_case2", "task_2_case1"])
        self.save_original()
        result, execute = self.run_main()
        self.assertEqual(result, 0)
        self.assertEqual(execute.call_count, 2)

    def test_selected_remaining_subset_retains_all_original_records(self):
        result, execute = self.run_main(["--select", "task_1/case2"])
        self.assertEqual(result, 0)
        self.assertEqual(execute.call_count, 1)
        summary = json.loads((self.batch / "summary.json").read_text())
        self.assertEqual(summary["case_count"], 2)
        self.assertEqual({row["case"] for row in summary["cases"]}, {"task_1_case1", "task_1_case2"})

    def test_new_batch_still_uses_live_runner_and_records_its_original_subset(self):
        result, execute = self.run_main(["--select", "task_1/case2"], resume=False)
        self.assertEqual(result, 0)
        self.assertEqual(execute.call_count, 1)
        batch = execute.call_args.args[1]
        summary = json.loads((batch / "summary.json").read_text())
        self.assertEqual(summary["case_count"], 1)
        self.assertEqual(summary["selected_cases"], ["task_1/case2"])
        self.assertEqual(summary["cases_root"], str(self.cases))
        self.assertFalse(summary["answers_exposed"])
        self.assertEqual(summary["run_status"], "complete")

    def test_execute_case_still_hides_answers_and_mounts_inputs_readonly_with_own_budget(self):
        case = self.cases / "task_2/case1"
        source = case / "input"
        (source / "original.dofile").write_text("exit\n")
        (source / "golden.dofile").write_text("forbidden fixture answer\n")
        (source / "expected_issues.json").write_text("[]")
        (source / "lib").mkdir()
        (source / "lib/test.lib").write_text("fixture library")
        with patch.object(runner.subprocess, "run", return_value=SimpleNamespace(returncode=0)) as docker, \
                redirect_stdout(io.StringIO()):
            runner.execute_case(case, self.batch, IMAGE_ID, self.root / "agent/.env", "off")
        staged = self.batch / ".inputs/task_2_case1"
        self.assertEqual({path.name for path in staged.iterdir()},
                         {"task_spec.md", "limitations.md", "original.dofile", "netlist", "lib"})
        command = docker.call_args.args[0]
        self.assertIn("LLM_ENABLE_THINKING=false", command)
        input_mounts = [arg for arg in command if "target=/input" in arg]
        self.assertTrue(input_mounts)
        self.assertTrue(all(arg.endswith("readonly") for arg in input_mounts))
        self.assertEqual(docker.call_args.kwargs["timeout"], 160)
        self.assertEqual(command[-5:], [IMAGE_ID, "-input", "/input", "-output", "/output"])


if __name__ == "__main__":
    unittest.main()
