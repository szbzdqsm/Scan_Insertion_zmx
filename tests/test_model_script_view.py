from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "agent"))
from model_script_view import model_owned_script


class ModelScriptView(unittest.TestCase):
    def test_runtime_blocks_are_hidden_without_changing_editable_commands(self):
        script = ("set_scan_signal -type clock -port clk -off_state 0\n"
                  "# Agent literal floating-clock inputs\nadd_pseudo_pi {g/clk_out}\n"
                  "# End agent floating-clock inputs\nexamine_scan_drc\n"
                  "# Agent audit reports from actual tool state\nrpt_scan_cfg > audit.rpt\n"
                  "# End agent audit reports\nexit\n")
        shown = model_owned_script(script)
        self.assertEqual(shown, "set_scan_signal -type clock -port clk -off_state 0\nexamine_scan_drc\nexit\n")
        self.assertIn("add_pseudo_pi", script)

    def test_unclosed_or_user_blocks_are_preserved(self):
        script = "# Custom recipe\nset_scan_cfg -max_length 100\n# Agent literal floating-clock inputs\n"
        self.assertEqual(model_owned_script(script), script)


if __name__ == "__main__":
    unittest.main()
