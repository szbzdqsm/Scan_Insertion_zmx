"""Check safe Docker arguments without calling Docker or using API credentials."""
import importlib.util
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

path = Path(__file__).resolve().parents[1] / "scripts/run_case.py"
spec = importlib.util.spec_from_file_location("run_case", path)
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class RunCaseTests(unittest.TestCase):
    def test_readonly_input_fresh_outputs_and_exit_status(self):
        with tempfile.TemporaryDirectory(prefix="scan-runner-") as temp:
            root = Path(temp)
            case = root / "cases with spaces" / "case1"
            inputs = case / "input"
            inputs.mkdir(parents=True)
            (inputs / "task_spec.md").write_text("fixture")
            (root / "agent").mkdir()
            (root / "agent/.env").write_text("LLM_API_KEY=\n")
            with patch.object(runner, "ROOT", root), \
                 patch.object(sys, "argv", ["run_case.py", str(case)]), \
                 patch.object(runner.subprocess, "call", side_effect=[0, 2]) as docker:
                self.assertEqual(runner.main(), 0)
                self.assertEqual(runner.main(), 2)
            commands = [call.args[0] for call in docker.call_args_list]
            for command in commands:
                self.assertIn(f"type=bind,source={inputs},target=/input,readonly", command)
                self.assertIn(str(root / "agent/.env"), command)
                self.assertIn("CASE_ID=case1", command)
                self.assertEqual(command[command.index("--user") + 1], f"{os.getuid()}:{os.getgid()}")
            output_mounts = [next(arg for arg in command if arg.endswith(",target=/output"))
                             for command in commands]
            self.assertNotEqual(output_mounts[0], output_mounts[1])
            self.assertEqual(len(list((root / "outputs").iterdir())), 2)

    def test_missing_input_prevents_docker_launch(self):
        with patch.object(sys, "argv", ["run_case.py", "/nonexistent-scan-case"]), \
             patch.object(runner.subprocess, "call") as docker:
            with self.assertRaises(SystemExit) as error:
                runner.main()
            self.assertEqual(error.exception.code, 2)
            docker.assert_not_called()

    def test_missing_configuration_prevents_docker_launch(self):
        with tempfile.TemporaryDirectory(prefix="scan-runner-") as temp:
            root = Path(temp)
            (root / "task_spec.md").write_text("fixture")
            with patch.object(runner, "ROOT", root), \
                 patch.object(sys, "argv", ["run_case.py", str(root)]), \
                 patch.object(runner.subprocess, "call") as docker:
                with self.assertRaises(SystemExit) as error:
                    runner.main()
                self.assertEqual(error.exception.code, 2)
                docker.assert_not_called()
            self.assertFalse((root / "outputs").exists())


if __name__ == "__main__":
    unittest.main()
