"""Source-only discovery fixtures, no Public answers or tool calls."""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "agent"))
from floating_inputs import floating_clock_outputs  # noqa: E402
from dofile_recipe import configure_floating_inputs  # noqa: E402


class FloatingInputTests(unittest.TestCase):
    def test_only_disconnected_input_clocks_are_selected_with_actual_hierarchy(self):
        with tempfile.TemporaryDirectory(prefix="floating-source-") as temp:
            source = Path(temp) / "input.v"
            source.write_text("module gated_clk_cell(input clk_in,en,output clk_out);\nassign clk_out=clk_in;\nendmodule\n"
                              "module block(input c,output q);\ngated_clk_cell bad(.clk_in(),.en(),.clk_out(q));\n"
                              "gated_clk_cell connected(.clk_in(c),.en(),.clk_out());\nendmodule\n"
                              "module top(input c,output q);\nblock u(.c(c),.q(q));\nendmodule\n")
            before = source.read_bytes()
            self.assertEqual(floating_clock_outputs([source]), {"top": ["u/bad/clk_out"]})
            self.assertEqual(source.read_bytes(), before)

    def test_recipe_declares_actual_pseudo_input_and_independent_clock(self):
        script = "present_design top\nadd_pseudo_pi wrong/CLK\nexamine_scan_drc\ninsert_dft_logic\nexit\n"
        result, references = configure_floating_inputs(script, {"top": ["u/bad/clk_in"]})
        self.assertNotIn("wrong/CLK", result)
        self.assertIn("add_pseudo_pi [list {u/bad/clk_in}]", result)
        self.assertIn("set_scan_signal -type clock -port {u/bad/clk_in}", result)
        self.assertEqual(len(references), 2)
        self.assertEqual(configure_floating_inputs(result, {"top": ["u/bad/clk_in"]})[0], result)


if __name__ == "__main__":
    unittest.main()
