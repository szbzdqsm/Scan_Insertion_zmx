"""Source-only discovery fixtures, no Public answers or tool calls."""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "agent"))
from floating_inputs import floating_clock_outputs  # noqa: E402
from dofile_recipe import configure_floating_inputs  # noqa: E402


class FloatingInputTests(unittest.TestCase):
    def test_keyword_substrings_and_pin_continuations_do_not_change_hierarchy(self):
        with tempfile.TemporaryDirectory(prefix="floating-source-") as temp:
            source = Path(temp) / "input.v"
            source.write_text("module icg_cell(input CK, input en, output clock_out);\nendmodule\n"
                              "module top(input input_data, output output_data);\n"
                              "wire module_status, endmodule_status;\n"
                              "sky130_fd_sc_hd__buf_1 primitive(.A(input_data), .X(output_data));\n"
                              "icg_cell \\generated.clock[0] (\n.CK(),\n.en(input_data),\n.clock_out(output_data));\n"
                              "endmodule\n")
            self.assertEqual(floating_clock_outputs([source]), {"top": ["generated.clock[0]/clock_out"]})

    def test_ansi_direction_changes_and_comments_preserve_actual_pin_roles(self):
        with tempfile.TemporaryDirectory(prefix="floating-source-") as temp:
            source = Path(temp) / "input.v"
            source.write_text("module clock_gate(input unsigned clk_in, en, output logic clk_out, inout io);\n"
                              "endmodule\nmodule top(input c, output q);\n"
                              "clock_gate good(.clk_in(c), .en(), .clk_out(q)); // input fabricated_clk;\n"
                              "clock_gate bad(.clk_in(), .en(c), .clk_out(q));\nendmodule\n")
            self.assertEqual(floating_clock_outputs([source]), {"top": ["bad/clk_out"]})

    def test_primitive_prefix_filter_only_excludes_the_original_library_prefix(self):
        with tempfile.TemporaryDirectory(prefix="floating-source-") as temp:
            source = Path(temp) / "input.v"
            source.write_text("module gated_user(input clk, output ck);\nendmodule\n"
                              "module top(input c, output q);\n"
                              "gated_user sky130_fd_sc_named_instance(.clk(), .ck(q));\nendmodule\n")
            self.assertEqual(floating_clock_outputs([source]), {"top": ["sky130_fd_sc_named_instance/ck"]})

    def test_recursive_module_instances_remain_bounded(self):
        with tempfile.TemporaryDirectory(prefix="floating-source-") as temp:
            source = Path(temp) / "input.v"
            source.write_text("module gated_user(input clk, output ck);\nendmodule\n"
                              "module cycle(input c, output q);\ncycle recurse(.c(c), .q(q));\n"
                              "gated_user gate(.clk(), .ck(q));\nendmodule\n"
                              "module top(input c, output q);\ncycle body(.c(c), .q(q));\nendmodule\n")
            self.assertEqual(floating_clock_outputs([source]), {"top": ["body/gate/ck"]})

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

    def test_managed_literal_clock_declarations_move_with_pseudo_input(self):
        for port in ('u/g/clk_out', '{u/g/clk_out}', '"u/g/clk_out"'):
            script = ("present_design top\nset_scan_signal -type clock -port clk -off_state 1\n"
                      f"set_scan_signal -port {port} -type clock -off_state 0\n"
                      "examine_scan_drc\ninsert_dft_logic\n")
            result, _ = configure_floating_inputs(script, {"top": ["u/g/clk_out"]})
            self.assertEqual(result.count("-port {u/g/clk_out}"), 1)
            self.assertLess(result.index("add_pseudo_pi"), result.index("-port {u/g/clk_out}"))
            self.assertIn("set_scan_signal -type clock -port clk -off_state 1", result)
            self.assertEqual(configure_floating_inputs(result, {"top": ["u/g/clk_out"]})[0], result)

    def test_managed_clock_does_not_drop_other_commands(self):
        script = ("present_design top\n"
                  "set_scan_signal -type clock -port {u/g/clk_out}; set_scan_cfg -max_length 10\n"
                  "examine_scan_drc\n")
        with self.assertRaisesRegex(ValueError, "separate statements"):
            configure_floating_inputs(script, {"top": ["u/g/clk_out"]})

    def test_unrelated_same_suffix_and_nonclock_signals_are_preserved(self):
        script = ("present_design top\n"
                  "set_scan_signal -type clock -port {other/g/clk_out} -off_state 1\n"
                  "set_scan_signal -type constant -port {u/g/clk_out} -constant_value 0\n"
                  "examine_scan_drc\n")
        result, _ = configure_floating_inputs(script, {"top": ["u/g/clk_out"]})
        self.assertIn("-port {other/g/clk_out} -off_state 1", result)
        self.assertIn("-type constant -port {u/g/clk_out} -constant_value 0", result)


if __name__ == "__main__":
    unittest.main()
