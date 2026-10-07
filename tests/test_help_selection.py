from pathlib import Path
import re
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "agent"))
from help_selection import CORE_COMMANDS, ROLE_COMMANDS, render_selected_help, select_help_commands


class HelpSelection(unittest.TestCase):
    def setUp(self):
        names = set(CORE_COMMANDS)
        names.update(name for _, commands in ROLE_COMMANDS for name in commands)
        names.update({"get_ports", "get_nets", "get_pins", "list_properties", "rpt_property", "new_tool_api"})
        self.syntax = {name: f"FULL HELP {name}\n-last_supported_option tail for {name}\n"
                       for name in sorted(names)}
        self.spec = "对门级网表完成 Scan Insertion，扫描链最大链长 100，输出扫描链报告。"

    def test_core_and_entire_property_table_are_retained(self):
        text, metadata = render_selected_help(self.syntax, self.spec)
        self.assertTrue(set(CORE_COMMANDS).issubset(metadata["selected_commands"]))
        for name in metadata["selected_commands"]:
            self.assertIn(self.syntax[name], text)
        self.assertIsNone(metadata["fallback_reason"])

    def test_unrelated_optional_help_is_omitted(self):
        selected = select_help_commands(self.syntax, self.spec)
        for name in ("get_nets", "get_pins", "get_ports", "list_properties", "rpt_property",
                     "load_ctl", "dump_ctl", "dump_def", "set_wrapper_cfg", "add_pseudo_pi"):
            self.assertNotIn(name, selected)

    def test_actual_commands_in_every_input_are_retained(self):
        selected = select_help_commands(
            self.syntax, self.spec, current="get_nets -hier; [get_pins -filter $filter]",
            original="list_properties -sys\n# API evidence: rpt_property",
            diagnostics="[ERROR] new_tool_api: unknown -wrong option; get_ports failed")
        self.assertTrue({"get_nets", "get_pins", "get_ports", "list_properties", "rpt_property",
                         "new_tool_api"}.issubset(selected))

    def test_exact_command_tokens_do_not_match_a_longer_identifier(self):
        selected = select_help_commands(self.syntax, self.spec, current="custom_get_nets get_pins_extra")
        self.assertNotIn("get_nets", selected)
        self.assertNotIn("get_pins", selected)

    def test_unknown_or_ambiguous_tasks_fall_back_to_all_available_help(self):
        for spec, reason in (("", "empty_task_spec"), ("Please make it faster", "unrecognized_task_domain"),
                             ("Scan Insertion", "ambiguous_task_spec"),
                             ("Scan clock", "ambiguous_task_spec"),
                             ("扫描链", "ambiguous_task_spec")):
            with self.subTest(spec=spec):
                text, metadata = render_selected_help(self.syntax, spec)
                self.assertEqual(set(metadata["selected_commands"]), set(self.syntax))
                self.assertEqual(metadata["fallback_reason"], reason)
                for entry in self.syntax.values():
                    self.assertIn(entry, text)

    def test_output_and_feature_roles_in_chinese_and_english(self):
        cases = (
            ("Scan partition by clock; partition report", {"add_scan_partition", "set_current_scan_partition", "rpt_scan_partition"}),
            ("扫描分区独立配置链长，输出分区报告", {"add_scan_partition", "set_current_scan_partition", "rpt_scan_partition"}),
            ("Scan wrapper with CTL black-box; wrapper report", {"load_ctl", "set_wrapper_cfg", "add_dedicated_wrapper_cell_type", "rpt_wrapper_implementation", "dump_ctl"}),
            ("扫描黑盒 Wrapper 配置报告、CTL 文件", {"load_ctl", "set_wrapper_cfg", "rpt_wrapper_cfg", "dump_ctl"}),
            ("Scan pseudo input for floating clock; report", {"add_pseudo_pi", "rpt_pseudo_pi"}),
            ("悬空时钟创建伪输入，完成插链并导出网表", {"add_pseudo_pi", "rpt_pseudo_pi"}),
            ("Scan shift-register and scan segment report", {"rpt_shift_register", "set_scan_segment", "rpt_scan_segment"}),
            ("插链后输出自然移位寄存器报告和扫描段报告", {"rpt_shift_register", "set_scan_segment", "rpt_scan_segment"}),
            ("Scan clock gating ICG and netlist replacement", {"set_dft_clock_gating_cfg", "set_scan_element"}),
            ("扫描门控重连；排除非扫描域触发器并回替；输出网表", {"set_dft_clock_gating_cfg", "set_scan_element"}),
            ("Scan DRC report; allow residual DFTR10; SCANDEF", {"rpt_scan_drc_violation", "set_scan_drc_rule_handling", "rpt_scan_drc_rule_handling", "dump_def"}),
            ("扫描 DRC 报告，忽略 DFTR-TIE0，导出 post_scan.def", {"rpt_scan_drc_violation", "set_scan_drc_rule_handling", "rpt_scan_drc_rule_handling", "dump_def"}),
            ("Scan chain cell report, scan configuration report, scan signal report and insertion info report", {"rpt_scan_chain_cell", "rpt_scan_cfg", "rpt_scan_signal", "rpt_insertion_info"}),
            ("扫描链上单元明细报告、插链配置报告、插链信号报告、插链信息报告", {"rpt_scan_chain_cell", "rpt_scan_cfg", "rpt_scan_signal", "rpt_insertion_info"}),
            ("Scan element report and register report", {"rpt_scan_element"}),
            ("插链后网表内寄存器报告和扫描单元报告", {"rpt_scan_element"}),
        )
        for spec, expected in cases:
            with self.subTest(spec=spec):
                self.assertTrue(expected.issubset(select_help_commands(self.syntax, spec)))

    def test_large_selected_entries_are_never_truncated(self):
        self.syntax["__cell_properties"] = "property row\n" * 10000 + "LAST PROPERTY ROW\n"
        text, metadata = render_selected_help(self.syntax, self.spec)
        self.assertIn(self.syntax["__cell_properties"], text)
        self.assertIn("LAST PROPERTY ROW", text)
        self.assertGreater(metadata["rendered_chars"], 30000)
        self.assertEqual(metadata["selected_entry_chars"], sum(len(self.syntax[name]) for name in metadata["selected_commands"]))

    def test_selection_is_stable_despite_cache_insertion_order(self):
        reverse = dict(reversed(list(self.syntax.items())))
        self.assertEqual(render_selected_help(self.syntax, self.spec), render_selected_help(reverse, self.spec))

    def test_missing_or_empty_help_entries_are_not_invented(self):
        syntax = {"load_lib": "actual load_lib help", "get_nets": "", "get_ports": None}
        text, metadata = render_selected_help(syntax, self.spec)
        self.assertEqual(text, syntax["load_lib"])
        self.assertEqual(metadata["selected_commands"], ["load_lib"])
        self.assertEqual(metadata["available_commands"], 1)
        self.assertEqual(render_selected_help({}, self.spec)[0], "")

    def test_metadata_contains_no_input_source_or_diagnostic_content(self):
        _, metadata = render_selected_help(self.syntax, self.spec, current="get_nets PRIVATE_OBJECT",
                                           diagnostics="new_tool_api PRIVATE_DIAGNOSTIC")
        self.assertNotIn("PRIVATE_OBJECT", str(metadata))
        self.assertNotIn("PRIVATE_DIAGNOSTIC", str(metadata))

    def test_all_public_specs_and_original_dofile_commands_are_preserved(self):
        root = Path(__file__).resolve().parents[1] / "public_cases"
        specs = sorted(root.glob("task_*/case*/input/task_spec.md"))
        if not specs:
            self.skipTest("Public inputs are not installed")
        self.assertEqual(len(specs), 11)
        for path in specs:
            with self.subTest(case=str(path.parent)):
                spec = path.read_text()
                original_path = path.with_name("original.dofile")
                original = original_path.read_text() if original_path.is_file() else ""
                text, metadata = render_selected_help(self.syntax, spec, current=original,
                                                      original=original, diagnostics="get_nets unknown -invalid")
                self.assertIsNone(metadata["fallback_reason"])
                required = set(re.findall(r"\b[A-Za-z_][A-Za-z0-9_]*\b", original)) & self.syntax.keys()
                self.assertTrue(required.issubset(metadata["selected_commands"]))
                self.assertIn(self.syntax["get_nets"], text)


if __name__ == "__main__":
    unittest.main()
