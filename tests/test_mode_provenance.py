from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "agent"))
from mode_control_context import (
    _expected, mode_control_context, mode_control_hints, mode_control_problems,
    mode_control_report_problems, requested_constant_modes,
)
from scan_agent import literal_tcl_words


class ModeProvenance(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source = self.root / "unfamiliar.v"
        self.source.write_text("""module gadget(input scan_mode_n, input mbist_mode,
 input rescue_selector, input diagnostic_gate_b, input ordinary_flag,
 input [1:0] mode_bus, output result);
endmodule
""")
        self.hints = mode_control_hints([self.source])
        self.generic = "Mode controls must be constants to enter scan test mode and disable MBIST."
        self.explicit = self.generic + "\nrescue_selector must be constant 0; diagnostic_gate_b must be constant 1."
        self.script = ("present_design gadget\n"
                       "set_scan_signal -type constant -port rescue_selector -constant_value 0\n"
                       "set_scan_signal -type constant -port diagnostic_gate_b -constant_value 1\n"
                       "examine_scan_drc\nexit\n")

    def problems(self, script, spec=None):
        return mode_control_problems(script, spec or self.explicit, self.hints, literal_tcl_words)

    def report_problems(self, rows, spec=None, script=None):
        path = self.root / "mode_signal.rpt"
        columns = ["Port", "SignalType", "ConstantValue"]
        path.write_text("Design: gadget\n" + "".join(f"{column:<28}" for column in columns) + "\n" +
                        "".join("".join(f"{field:<28}" for field in row) + "\n" for row in rows))
        return mode_control_report_problems([path], script or self.script,
                                            spec or self.explicit, self.hints, literal_tcl_words)

    def test_conventional_names_and_suffixes_prove_no_active_value(self):
        self.assertEqual(_expected(self.hints[0], self.generic), {})
        self.assertTrue(all(candidate["active_level"] is None for candidate in self.hints[0]["mode_candidates"]))
        self.assertTrue(all(candidate["confidence"] == "name_hint_only" for candidate in self.hints[0]["mode_candidates"]))
        for value in ("0", "1"):
            self.assertEqual(self.problems("present_design gadget\nset_scan_signal -type constant -port scan_mode_n -constant_value " + value,
                                           self.generic), [])
        self.assertEqual(self.report_problems([], self.generic), [])

    def test_explicit_values_accept_unfamiliar_control_names(self):
        self.assertEqual(_expected(self.hints[0], self.explicit), {"rescue_selector": 0, "diagnostic_gate_b": 1})
        self.assertEqual(self.problems(self.script), [])
        self.assertEqual(self.report_problems([("rescue_selector", "constant", "0"),
                                               ("diagnostic_gate_b", "constant", "1")]), [])

    def test_counterconventional_polarities_are_accepted_when_task_is_explicit(self):
        spec = self.generic + "\nscan_mode_n must be constant 1; mbist_mode must be constant 1."
        self.assertEqual(_expected(self.hints[0], spec), {"scan_mode_n": 1, "mbist_mode": 1})
        script = ("present_design gadget\nset_scan_signal -type constant -port scan_mode_n -constant_value 1\n"
                  "set_scan_signal -type constant -port mbist_mode -constant_value 1\n")
        self.assertEqual(self.problems(script, spec), [])
        self.assertTrue(self.problems(script.replace("-port scan_mode_n -constant_value 1", "-port scan_mode_n -constant_value 0"), spec))

    def test_unknown_mode_name_with_explicit_value_enables_investigation(self):
        spec = "Lock rescue_selector to constant 0."
        self.assertIn("explicit_literal", requested_constant_modes(spec))
        self.assertEqual(_expected(self.hints[0], spec), {"rescue_selector": 0})
        self.assertTrue(self.problems("present_design gadget\n", spec))

    def test_chain_length_or_an_unrelated_fixed_number_does_not_trigger_mode_scan(self):
        for spec in ("固定扫描链最大长度 1000", "A fixed scan chain length of 100 is required."):
            with self.subTest(spec=spec):
                self.assertEqual(requested_constant_modes(spec), set())

    def test_chinese_verilog_literal_and_high_low_bindings(self):
        for spec in ("rescue_selector 锁定为常量 1'b0；diagnostic_gate_b 为常量 1'b1。",
                     "Tie rescue_selector low; diagnostic_gate_b must be tied to high."):
            with self.subTest(spec=spec):
                self.assertEqual(_expected(self.hints[0], spec), {"rescue_selector": 0, "diagnostic_gate_b": 1})

    def test_explicit_constant_table_has_source_provenance(self):
        spec = "| 控制端口 | 常量值 |\n|---|---|\n| `rescue_selector` | 0 |\n| diagnostic_gate_b | 1 |"
        context = mode_control_context([], spec, hints=self.hints)
        self.assertEqual(_expected(self.hints[0], spec), {"rescue_selector": 0, "diagnostic_gate_b": 1})
        self.assertIn('"confidence": "explicit_task_value"', context)
        self.assertIn('"source": "task_spec.md"', context)
        self.assertIn('"line": 3', context)

    def test_an_unrelated_following_table_does_not_inherit_constant_column(self):
        spec = ("| Port | ConstantValue |\n|---|---|\n| rescue_selector | 0 |\n"
                "| Port | Depth |\n|---|---|\n| diagnostic_gate_b | 1 |")
        self.assertEqual(_expected(self.hints[0], spec), {"rescue_selector": 0})

    def test_wrong_type_value_duplicate_and_missing_literal_values_are_rejected(self):
        scripts = ["present_design gadget\n", self.script.replace("-constant_value 0", "-constant_value 1"),
                   self.script.replace("-type constant -port rescue_selector", "-type scan_enable -port rescue_selector"),
                   self.script + "set_scan_signal -type constant -port rescue_selector -constant_value 0\n"]
        for script in scripts:
            with self.subTest(script=script):
                self.assertTrue(self.problems(script))

    def test_explicit_unknown_controls_require_real_report_rows_even_with_dynamic_tcl(self):
        script = "unknown_setup\n" + self.script
        self.assertEqual(len(self.report_problems([], script=script)), 2)
        self.assertTrue(self.report_problems([("rescue_selector", "scan_enable", "0"),
                                             ("diagnostic_gate_b", "constant", "1")], script=script))

    def test_no_ordinary_input_is_locked_without_an_explicit_binding(self):
        self.assertNotIn("ordinary_flag", _expected(self.hints[0], self.explicit))
        self.assertNotIn("scan_mode_n", _expected(self.hints[0], self.explicit))
        self.assertEqual(self.problems(self.script + "set_scan_signal -type clock -port ordinary_flag\n"), [])

    def test_conflicting_conditional_and_prohibited_values_abstain(self):
        specs = ["Lock rescue_selector to constant 0; lock rescue_selector to constant 1.",
                 "Do not lock rescue_selector to constant 1.",
                 "When in functional mode, lock rescue_selector to constant 0.",
                 "禁止 rescue_selector 为常量 1。"]
        for spec in specs:
            with self.subTest(spec=spec):
                self.assertEqual(_expected(self.hints[0], spec), {})
        context = mode_control_context([], specs[0], hints=self.hints)
        self.assertIn("conflicting_explicit_task_values", context)

    def test_vector_and_output_names_are_not_promoted_to_scalar_inputs(self):
        spec = "Lock mode_bus to constant 1; lock result to constant 0."
        self.assertEqual(_expected(self.hints[0], spec), {})


if __name__ == "__main__":
    unittest.main()
