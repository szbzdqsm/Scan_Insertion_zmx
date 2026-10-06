"""Redirected real-format DRC cannot bypass generated-round early stopping."""
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "agent"))
from drc_validation import redirected_drc_codes
import scan_agent


class RedirectedMonitor(unittest.TestCase):
    def test_preview_requires_nonzero_actual_summary_and_ignores_configuration(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report = root / "drc.rpt"
            cache = {}
            report.write_text("DFTR1 Warning Warning all\n")
            self.assertEqual(redirected_drc_codes(root, cache), set())
            report.write_text("DRC Report\nTotal violations: 1\n[WARNING] [DFTDRC-4001] Clock uncontrolled. (DFTR1-1)\n")
            self.assertEqual(redirected_drc_codes(root, cache), {"DFTR1"})
            self.assertEqual(redirected_drc_codes(root, cache), {"DFTR1"})
            report.write_text("DRC Report\nTotal violations: 0\n")
            self.assertEqual(redirected_drc_codes(root, cache), set())
            (root / "llm_context.txt").write_text("DRC Report\nTotal violations: 1\n[INFO] There were 1 DRC rule 'DFTR2' fails.\n")
            self.assertEqual(redirected_drc_codes(root, cache), set())

    def test_redirected_failure_stops_generated_but_preserves_original_run(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            tool = root / "test-tool"
            tool.write_text("#!/usr/bin/env python3\nimport pathlib,time\n"
                            "pathlib.Path('reports/drc.rpt').write_text(\"DRC Report\\nTotal violations: 1\\n"
                            "[INFO] There were 1 DRC rule 'DFTR9' fails. (Clock inactive)\\n\")\n"
                            "time.sleep(0.7)\npathlib.Path('insert_started').write_text('yes')\n")
            tool.chmod(0o700)
            with patch.object(scan_agent, "TOOL", str(tool)):
                generated = scan_agent.tool_run("exit\n", root / "R2", "R2", 3, allowed_drc=set())
                original = scan_agent.tool_run("exit\n", root / "R1", "R1", 3,
                                               abort_on_error=False, allowed_drc=set())
                allowed = scan_agent.tool_run("exit\n", root / "R3", "R3", 3, allowed_drc={"DFTR9"})
            self.assertEqual(generated["error"], "unallowed_drc")
            self.assertFalse((root / "R2/insert_started").exists())
            self.assertEqual(original["status"], "completed")
            self.assertTrue((root / "R1/insert_started").exists())
            self.assertEqual(allowed["status"], "completed")


if __name__ == "__main__":
    unittest.main()
