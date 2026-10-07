from pathlib import Path
import sys
import tempfile
import unittest


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "agent"))
from mode_control_context import mode_control_context, mode_control_hints, mode_control_problems, mode_control_report_problems, requested_constant_modes
from scan_agent import literal_tcl_words


class ModeControlContext(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.netlist = Path(self.temporary.name) / "chip.v"
        self.spec = "模式控制端口应锁定为使设计进入扫描测试模式、不进入 MBIST 的常量"
        self.source = """module chip (clk, scan_mode, mbist_mode, ordinary_flag, scan_enable);
input clk;
input scan_mode;
input mbist_mode;
input ordinary_flag;
input scan_enable;
child core (.test_mode(scan_mode));
endmodule
module child (test_mode);
input test_mode;
endmodule
"""
        self.script = """present_design chip
set_scan_signal -type clock -port clk -off_state 0
set_scan_signal -type constant -port scan_mode -constant_value 1
set_scan_signal -type constant -port mbist_mode -constant_value 0
examine_scan_drc
exit
"""
        self.netlist.write_text(self.source)
        self.hints = mode_control_hints([self.netlist])

    def problems(self, script=None, spec=None, hints=None):
        return mode_control_problems(self.script if script is None else script,
                                     self.spec if spec is None else spec,
                                     self.hints if hints is None else hints, literal_tcl_words)

    def test_source_root_and_actual_input_ports_are_traced(self):
        self.assertEqual([hint["root"] for hint in self.hints], ["chip"])
        hint = self.hints[0]
        self.assertTrue(hint["source_ports_complete"])
        self.assertIn("scan_mode", hint["input_ports"])
        self.assertNotIn("test_mode", hint["input_ports"])
        self.assertEqual({candidate["port"] for candidate in hint["mode_candidates"]}, {"scan_mode", "mbist_mode"})
        self.assertEqual(self.problems(), [])

    def test_typo_and_missing_real_mode_are_rejected(self):
        problems = self.problems(self.script.replace("-port scan_mode", "-port test_mode"))
        self.assertTrue(any("test_mode is not a real input" in problem for problem in problems))
        self.assertTrue(any("chip/scan_mode" in problem for problem in problems))

    def test_missing_mode_is_rejected_before_wasting_a_tool_run(self):
        script = self.script.replace("set_scan_signal -type constant -port scan_mode -constant_value 1\n", "")
        self.assertEqual(len(self.problems(script)), 1)
        self.assertIn("chip/scan_mode", self.problems(script)[0])

    def test_wrong_type_polarity_and_duplicates_are_rejected(self):
        for change in [self.script.replace("-port scan_mode -constant_value 1", "-port scan_mode -constant_value 0"),
                       self.script.replace("-type constant -port scan_mode", "-type scan_enable -port scan_mode"),
                       self.script + "set_scan_signal -type constant -port scan_mode -constant_value 1\n"]:
            with self.subTest(script=change):
                self.assertTrue(self.problems(change))

    def test_nonmode_functional_inputs_are_not_locked_or_checked(self):
        self.assertEqual(self.problems(), [])
        context = mode_control_context([], self.spec, hints=self.hints)
        self.assertIn('"scan_mode": 1', context)
        self.assertIn('"mbist_mode": 0', context)
        self.assertNotIn('"ordinary_flag": 1', context)
        self.assertNotIn('"scan_enable": 1', context)

    def test_unrequested_or_nonconstant_task_does_not_infer_modes(self):
        for spec in ["Complete Scan Insertion", "使设计进入扫描测试模式、不进入 MBIST", "扫描链使用 scan_enable"]:
            with self.subTest(spec=spec):
                self.assertEqual(requested_constant_modes(spec), set())
                self.assertEqual(self.problems("present_design chip\n", spec), [])

    def test_english_explicit_modes_are_recognized(self):
        spec = "Mode controls must be constants to enter scan test mode and disable MBIST."
        self.assertEqual(requested_constant_modes(spec), {"scan_test", "mbist"})
        self.assertEqual(self.problems(spec=spec), [])

    def test_active_low_literal_names_invert_only_the_requested_mode(self):
        self.netlist.write_text("""module low (input scan_mode_n, input mbist_en_b);
endmodule
""")
        hints = mode_control_hints([self.netlist])
        script = "present_design low\nset_scan_signal -type constant -port scan_mode_n -constant_value 0\nset_scan_signal -type constant -port mbist_en_b -constant_value 1\n"
        self.assertEqual(self.problems(script, hints=hints), [])
        self.assertTrue(self.problems(script.replace("-port scan_mode_n -constant_value 0", "-port scan_mode_n -constant_value 1"), hints=hints))

    def test_ansi_ports_and_multiline_nonansi_declarations(self):
        self.netlist.write_text("""module chip(input wire clk,
input logic scan_mode, mbist_mode,
output [3:0] result);
endmodule
""")
        self.assertEqual(self.problems(hints=mode_control_hints([self.netlist])), [])
        self.netlist.write_text("""module chip(clk, scan_mode, mbist_mode);
input clk,
scan_mode,
mbist_mode;
endmodule
""")
        self.assertEqual(self.problems(hints=mode_control_hints([self.netlist])), [])

    def test_vectors_and_unknown_widths_never_infer_constant_values(self):
        self.netlist.write_text("""module chip(input [1:0] scan_mode, input [1:0] mbist_mode);
endmodule
""")
        hints = mode_control_hints([self.netlist])
        self.assertEqual(self.problems("present_design chip\n", hints=hints), [])
        self.assertTrue(all(candidate["confidence"] == "vector_not_inferred" for candidate in hints[0]["mode_candidates"]))
        self.netlist.write_text("""module chip(input [WIDTH-1:0] scan_mode, input mbist_mode);
endmodule
""")
        self.assertEqual(self.problems("present_design chip\n", hints=mode_control_hints([self.netlist])), [])

    def test_ambiguous_same_role_does_not_infer_a_scan_mode(self):
        self.netlist.write_text("""module chip(input scan_mode, input test_mode, input mbist_mode);
endmodule
""")
        hints = mode_control_hints([self.netlist])
        script = "present_design chip\nset_scan_signal -type constant -port mbist_mode -constant_value 0\n"
        self.assertEqual(self.problems(script, hints=hints), [])

    def test_dynamic_tcl_or_ports_skip_the_narrow_check(self):
        for script in ["if {1} {\n" + self.script + "}\n", self.script.replace("-port scan_mode", "-port $mode"),
                       self.script.replace("-constant_value 1", "-constant_value $enabled"),
                       self.script.replace("present_design chip", "present_design $top"),
                       self.script.replace("examine_scan_drc", "source extra.tcl"),
                       self.script.replace("examine_scan_drc", "catch {set_scan_signal -type constant -port scan_mode -constant_value 1}"),
                       self.script.replace("-port scan_mode", "-port [get_ports scan_mode]"),
                       self.script.replace("-port scan_mode", "-port \\\n scan_mode")]:
            with self.subTest(script=script):
                self.assertEqual(self.problems(script), [])

    def test_unrelated_literal_cell_query_does_not_disable_the_check(self):
        script = self.script.replace("set_scan_signal -type constant -port scan_mode -constant_value 1\n", "")
        script += "set tap_cells [get_cells -hier -filter {full_name =~ */tap/*}]\n"
        self.assertTrue(self.problems(script))

    def test_comments_do_not_invent_modules_or_modes(self):
        self.netlist.write_text("""/* module fake(input test_mode); endmodule */
""" + self.source.replace("input scan_mode;", "input scan_mode; // input test_mode;"))
        hints = mode_control_hints([self.netlist])
        self.assertEqual([hint["root"] for hint in hints], [hint["root"] for hint in self.hints])
        self.assertEqual(hints[0]["input_ports"], self.hints[0]["input_ports"])
        self.assertEqual([candidate["port"] for candidate in hints[0]["mode_candidates"]],
                         [candidate["port"] for candidate in self.hints[0]["mode_candidates"]])

    def test_duplicate_and_parameterized_sources_fail_closed(self):
        self.netlist.write_text(self.source + self.source)
        self.assertEqual(mode_control_hints([self.netlist]), [])
        self.netlist.write_text("""module chip #(parameter WIDTH=1) (input scan_mode, input mbist_mode);
endmodule
""")
        self.assertEqual(self.problems("present_design chip\n", hints=mode_control_hints([self.netlist])), [])

    def test_scalar_zero_width_range_is_a_literal_single_bit(self):
        self.netlist.write_text("module chip(input [0:0] scan_mode, input [0:0] mbist_mode);\nendmodule\n")
        self.assertEqual(self.problems(hints=mode_control_hints([self.netlist])), [])

    def test_selected_root_scopes_the_mode_requirements(self):
        self.assertEqual(self.problems(self.script.replace("present_design chip", "present_design child")), [])

    def test_literal_load_top_selects_the_real_mode_root(self):
        script = self.script.replace("present_design chip", "load_netlist chip.v -top chip")
        self.assertEqual(self.problems(script), [])
        script = script.replace("set_scan_signal -type constant -port scan_mode -constant_value 1\n", "")
        self.assertTrue(any("chip/scan_mode" in problem for problem in self.problems(script)))

    def test_safe_output_guards_do_not_hide_missing_scan_mode(self):
        script = self.script.replace("set_scan_signal -type constant -port scan_mode -constant_value 1\n", "")
        setup = 'set out_dir "/tmp/results"\nif {![file exists $out_dir]} {file mkdir $out_dir}\n'
        self.assertTrue(self.problems(setup + script))

    def test_unreviewed_guard_body_or_expression_stays_with_actual_tool(self):
        for setup in ['if {1} {set_scan_signal -type constant -port scan_mode -constant_value 1}\n',
                      'if {[exec custom_setup]} {file mkdir /tmp/results}\n']:
            with self.subTest(setup=setup):
                self.assertEqual(self.problems(setup + self.script), [])

    def test_static_continuation_and_command_separator_are_checked(self):
        script = self.script.replace("-port scan_mode -constant_value 1", "-port scan_mode \\\n -constant_value 0")
        self.assertTrue(self.problems(script))
        script = self.script.replace("-port scan_mode -constant_value 1", "-port scan_mode -constant_value 0;")
        self.assertTrue(self.problems(script))

    def test_loading_an_unselected_netlist_clears_the_previous_scope(self):
        script = "present_design unrelated\nload_netlist chip.v\nset_scan_signal -type constant -port test_mode -constant_value 1\n"
        self.assertEqual(self.problems(script), [])

    def test_output_mode_port_is_not_promoted_to_a_constant_input(self):
        self.netlist.write_text("module chip(input scan_mode, output mbist_mode);\nendmodule\n")
        hints = mode_control_hints([self.netlist])
        self.assertEqual([candidate["port"] for candidate in hints[0]["mode_candidates"]], ["scan_mode"])
        self.assertTrue(any("mbist_mode is not a real input" in problem for problem in self.problems(hints=hints)))

    def test_unknown_nonansi_ports_disable_missing_port_enforcement(self):
        self.netlist.write_text("module chip(scan_mode, mbist_mode, unknown);\ninput scan_mode;\ninput mbist_mode;\nendmodule\n")
        hints = mode_control_hints([self.netlist])
        self.assertFalse(hints[0]["source_ports_complete"])
        self.assertEqual(self.problems("present_design chip\n", hints=hints), [])

    def test_quoted_and_grouped_single_literal_ports_are_accepted(self):
        self.assertEqual(self.problems(self.script.replace("-port scan_mode", '-port "scan_mode"').replace("-port mbist_mode", "-port {mbist_mode}")), [])

    def report(self, rows=None, *, root="chip", columns=None):
        columns = columns or ["Port", "SignalType", "ConstantValue"]
        rows = [("scan_mode", "constant", "1"), ("mbist_mode", "constant", "0")] if rows is None else rows
        return f"Design: {root}\n" + ''.join(f'{name:<24}' for name in columns) + '\n' + ''.join(
            ''.join(f'{value:<24}' for value in row) + '\n' for row in rows)

    def report_problems(self, contents, script=None):
        report = Path(self.temporary.name) / "scan_signal.rpt"
        report.write_text(contents)
        return mode_control_report_problems([report], self.script if script is None else script,
                                            self.spec, self.hints, literal_tcl_words)

    def test_actual_signal_rows_prove_both_real_mode_constants(self):
        self.assertEqual(self.report_problems(self.report()), [])

    def test_dofile_constants_do_not_substitute_for_missing_report_evidence(self):
        self.assertEqual(len(self.report_problems("")), 2)
        self.assertTrue(self.report_problems(self.script))

    def test_foreign_or_missing_design_header_cannot_prove_source_top_modes(self):
        self.assertEqual(len(self.report_problems(self.report(root="unrelated"))), 2)
        self.assertEqual(len(self.report_problems(self.report().replace("Design: chip\n", ""))), 2)

    def test_actual_wrong_value_or_type_is_rejected_even_with_good_duplicate(self):
        for row in [("scan_mode", "constant", "0"), ("scan_mode", "scan_enable", "1")]:
            with self.subTest(row=row):
                report = self.report() + self.report(rows=[row])
                self.assertTrue(any("reports scan_mode" in problem for problem in self.report_problems(report)))

    def test_actual_signal_header_requires_all_typed_columns(self):
        for columns, rows in [(["Port", "SignalType"], [("scan_mode", "constant")]),
                              (["Port", "ConstantValue"], [("scan_mode", "1")])]:
            with self.subTest(columns=columns):
                self.assertTrue(any("lacks typed mode columns" in problem for problem in self.report_problems(self.report(rows, columns=columns))))

    def test_foreign_design_rows_never_inherit_previous_root_header(self):
        report = self.report(rows=[("mbist_mode", "constant", "0")]) + self.report(rows=[("scan_mode", "constant", "1")], root="unrelated")
        self.assertEqual(len(self.report_problems(report)), 1)
        self.assertIn("chip input scan_mode", self.report_problems(report)[0])

    def test_unknown_script_cannot_waive_unique_source_top_requirements(self):
        for script in [self.script.replace("present_design chip", "present_design $top"),
                       self.script.replace("exit\n", "present_design another_top\nexit\n"),
                       self.script.replace("present_design chip\n", "")]:
            with self.subTest(script=script):
                self.assertEqual(len(self.report_problems("", script)), 2)
                self.assertEqual(self.report_problems(self.report(), script), [])

    def test_unknown_output_or_exclusion_tcl_cannot_hide_wrong_actual_mode(self):
        wrong = self.report(rows=[("scan_mode", "scan_enable", ""), ("mbist_mode", "constant", "0")])
        missing = self.report(rows=[("mbist_mode", "constant", "0")])
        for command in ["custom_output_setup $out_dir", "custom_exclude $jtag_cells", "source local_exclusions.tcl"]:
            script = self.script.replace("examine_scan_drc", command + "\nexamine_scan_drc")
            with self.subTest(command=command):
                self.assertEqual(self.problems(script), [])  # Preflight abstains.
                self.assertTrue(any("reports scan_mode" in problem for problem in self.report_problems(wrong, script)))
                self.assertTrue(any("chip input scan_mode" in problem for problem in self.report_problems(missing, script)))
                self.assertEqual(self.report_problems(self.report(), script), [])

    def test_unique_source_fallback_rejects_foreign_report_root(self):
        script = "unknown_output_setup\n" + self.script
        self.assertEqual(len(self.report_problems(self.report(root="unrelated"), script)), 2)

    def test_ambiguous_source_roots_or_mode_ports_do_not_gain_a_fallback(self):
        report = Path(self.temporary.name) / "scan_signal.rpt"
        report.write_text("")
        unknown_script = "unknown_output_setup\n" + self.script
        duplicate_root = {**self.hints[0], "root": "second_top"}
        self.assertEqual(mode_control_report_problems([report], unknown_script, self.spec,
                                                     self.hints + [duplicate_root], literal_tcl_words), [])
        ambiguous = {**self.hints[0], "mode_candidates": self.hints[0]["mode_candidates"] +
                     [{**self.hints[0]["mode_candidates"][1], "port": "test_mode"}]}
        self.assertEqual(mode_control_report_problems([report], unknown_script, self.spec,
                                                     [ambiguous], literal_tcl_words), [])
        incomplete = {**self.hints[0], "source_ports_complete": False}
        self.assertEqual(mode_control_report_problems([report], unknown_script, self.spec,
                                                     [incomplete], literal_tcl_words), [])

    def test_model_context_requires_constant_scan_mode_and_separate_enable(self):
        context = mode_control_context([], self.spec, hints=self.hints)
        self.assertIn("MUST remain type constant", context)
        self.assertIn("separate scan-enable", context)

    def test_actual_mode_proof_supports_safe_jtag_exclusion_guard(self):
        script = self.script.replace("present_design chip", "load_netlist chip.v -top chip")
        script = script.replace("examine_scan_drc", """set jtag_cells [get_obj_insts -hier -filter {full_name =~ *tap* && is_sequential == true}]
if {[cluster_length $jtag_cells] > 0} {
  cluster_foreach c $jtag_cells {set_scan_element false $c}
}
examine_scan_drc""")
        self.assertEqual(self.problems(script), [])
        self.assertTrue(self.report_problems("", script))
        self.assertEqual(self.report_problems(self.report(), script), [])


if __name__ == "__main__":
    unittest.main()
