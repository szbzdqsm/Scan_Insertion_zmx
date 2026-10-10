from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "agent"))
from dft_signal_requirements import (explicit_signal_role_requirements,
                                     preflight_signal_role_problems, signal_role_report_problems)
from scan_agent import literal_tcl_words


class DFTSignalRequirements(unittest.TestCase):
    def setUp(self):
        self.spec = "`shift_control` 控制 SFF 的 shift/capture 切换；`gate_control` 确保移位阶段 ICG 保持导通"

    def preflight(self, script, spec=None):
        return preflight_signal_role_problems(script, self.spec if spec is None else spec, literal_tcl_words)

    def reports(self, rows, spec=None, headers=None):
        headers = headers or ["Port", "PortProperty", "SignalType", "OffState", "Usage"]
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / "actual_signal.rpt"
            text = "Design: arbitrary_chip\n" + "".join(f"{column:<32}" for column in headers) + "\n"
            text += "-" * (32 * len(headers)) + "\n"
            text += "".join("".join(f"{row.get(column, ''):<32}" for column in headers) + "\n" for row in rows)
            report.write_text(text)
            return signal_role_report_problems([report], self.spec if spec is None else spec)

    @staticmethod
    def row(port, usage, kind="scan_enable(spec)", off_state="0"):
        return {"Port": port, "PortProperty": "pre_existing", "SignalType": kind,
                "OffState": off_state, "Usage": usage}

    def test_distinct_explicit_roles_are_bound_to_their_ports(self):
        requirements = explicit_signal_role_requirements(self.spec)
        self.assertEqual({r.port: r.roles for r in requirements},
                         {"shift_control": {"scan"}, "gate_control": {"clock_gating"}})
        self.assertTrue(all(r.off_state is None for r in requirements))
        script = ("set_scan_signal -type scan_enable -port shift_control -off_state 0 -usage scan\n"
                  "set_scan_signal -type scan_enable -port gate_control -off_state 1 -usage clock_gating\n")
        self.assertEqual(self.preflight(script), [])
        self.assertEqual(self.reports([self.row("shift_control", "scan"), self.row("gate_control", "clock_gating")]), [])

    def test_unrelated_all_enable_cannot_replace_the_named_gate_port(self):
        script = "set_scan_signal -type scan_enable -port shift_control -usage all\n"
        problems = self.preflight(script)
        self.assertEqual(len(problems), 1)
        self.assertIn("gate_control", problems[0])
        self.assertEqual(len(self.reports([self.row("shift_control", "all")])), 1)

    def test_named_gate_role_accepts_all_but_rejects_scan_only_and_invented_type(self):
        spec = "顶层端口 `opaque_control` 驱动 ICG 的 SCE 引脚"
        for usage in ("clock_gating", "all"):
            self.assertEqual(self.preflight(f"set_scan_signal -type scan_enable -port opaque_control -usage {usage}", spec), [])
            self.assertEqual(self.reports([self.row("opaque_control", usage)], spec), [])
        self.assertTrue(self.preflight("set_scan_signal -type scan_enable -port opaque_control -usage scan", spec))
        self.assertTrue(self.reports([self.row("opaque_control", "scan")], spec))
        self.assertTrue(self.preflight("set_scan_signal -type clock_gating -port opaque_control -usage clock_gating", spec))
        self.assertTrue(self.reports([self.row("opaque_control", "clock_gating", kind="clock_gating")], spec))

    def test_shared_scan_and_gate_control_requires_all(self):
        spec = "| 端口 | 功能 |\n|------|------|\n| `shared` | 扫描模式下使能所有 ICG，同时控制扫描 FF 的 shift/capture 切换 |"
        self.assertEqual(explicit_signal_role_requirements(spec)[0].roles, {"scan", "clock_gating"})
        self.assertEqual(self.preflight("set_scan_signal -type scan_enable -port shared -usage all", spec), [])
        for usage in ("scan", "clock_gating"):
            self.assertTrue(self.preflight(f"set_scan_signal -type scan_enable -port shared -usage {usage}", spec))
            self.assertTrue(self.reports([self.row("shared", usage)], spec))

    def test_no_polarity_is_inferred_from_identifier_suffixes(self):
        for port in ("control_n", "control_b", "assert_high", "strange_name"):
            spec = f"端口 `{port}` 确保 ICG 保持导通"
            self.assertIsNone(explicit_signal_role_requirements(spec)[0].off_state)
            for level in ("0", "1"):
                self.assertEqual(self.preflight(f"set_scan_signal -type scan_enable -port {port} -usage all -off_state {level}", spec), [])
                self.assertEqual(self.reports([self.row(port, "all", off_state=level)], spec), [])

    def test_explicit_off_state_is_checked_in_script_and_actual_row(self):
        spec = "端口 `mode_b` 作为 scan_enable，off_state = 0"
        self.assertEqual(explicit_signal_role_requirements(spec)[0].off_state, "0")
        self.assertTrue(self.preflight("set_scan_signal -type scan_enable -port mode_b -usage all -off_state 1", spec))
        self.assertEqual(self.preflight("set_scan_signal -type scan_enable -port mode_b -usage all -off_state 0", spec), [])
        self.assertTrue(self.reports([self.row("mode_b", "all", off_state="1")], spec))
        self.assertTrue(self.reports([self.row("mode_b", "all")], spec, headers=["Port", "SignalType", "Usage"]))

    def test_missing_literal_usage_does_not_assume_a_tool_default(self):
        self.assertTrue(self.preflight("set_scan_signal -type scan_enable -port gate_control", "端口 `gate_control` 驱动 ICG SCE"))

    def test_explicit_port_name_may_itself_be_a_role_keyword(self):
        spec = "端口 `scan_enable` 控制扫描 FF 的 shift/capture 切换"
        self.assertEqual(explicit_signal_role_requirements(spec)[0].port, "scan_enable")
        self.assertTrue(self.preflight("", spec))
        self.assertEqual(self.preflight("set_scan_signal -port scan_enable -type scan_enable -usage scan", spec), [])

    def test_semicolons_continuations_and_literal_quoting(self):
        script = ('set_scan_signal -port {shift_control} -type scan_enable -usage scan; '
                  'set_scan_signal -port "gate_control" \\\n -type scan_enable -usage clock_gating\n')
        self.assertEqual(self.preflight(script), [])

    def test_comments_and_string_values_do_not_prove_a_literal_declaration(self):
        for script in ("# set_scan_signal -port gate_control -type scan_enable -usage all\n",
                       'puts {set_scan_signal -port gate_control -type scan_enable -usage all}\n'):
            # A dynamic/opaque command is conservatively left to the actual report.
            if script.startswith("#"):
                self.assertTrue(self.preflight(script, "端口 `gate_control` 驱动 ICG SCE"))
            else:
                self.assertEqual(self.preflight(script, "端口 `gate_control` 驱动 ICG SCE"), [])
        self.assertTrue(self.reports([], "端口 `gate_control` 驱动 ICG SCE"))

    def test_dynamic_configuration_abstains_in_preflight_but_requires_actual_rows(self):
        spec = "端口 `opaque_control` 驱动 ICG SCE"
        scripts = [
            "set_scan_signal -type scan_enable -port $control -usage all",
            "set_scan_signal -type scan_enable -port opaque_control -usage $usage",
            "if {$enabled} {set_scan_signal -type scan_enable -port opaque_control -usage all}",
            "foreach p {opaque_control} {set_scan_signal -type scan_enable -port $p -usage all}",
            "source configured_controls.tcl",
            "proc configure {} {set_scan_signal -type scan_enable -port opaque_control -usage all}\nconfigure",
        ]
        for script in scripts:
            with self.subTest(script=script):
                self.assertEqual(self.preflight(script, spec), [])
        self.assertTrue(self.reports([], spec))
        self.assertEqual(self.reports([self.row("opaque_control", "all")], spec), [])

    def test_prohibitions_conditions_and_examples_do_not_create_requirements(self):
        sentences = [
            "不得将端口 `unclear` 配置为 scan_enable",
            "如果采用门控方案，端口 `unclear` 驱动 ICG SCE",
            "只有选择该模式时，端口 `unclear` 控制 SFF shift/capture",
            "Optional port `unclear` is a scan_enable signal",
            "Do not use port `unclear` for clock_gating",
            "例如端口 `unclear` 作为 scan_enable",
            "```tcl\n端口 `unclear` 作为 scan_enable\n```",
            "> 端口 `unclear` 作为 scan_enable",
            "## 反例\n端口 `unclear` 驱动 ICG SCE\n## 正文\n普通说明",
            "以下为示例：\n\n| 端口 | 功能 |\n|------|------|\n| `unclear` | scan_enable |",
        ]
        for sentence in sentences:
            with self.subTest(spec=sentence):
                self.assertEqual(explicit_signal_role_requirements(sentence), [])

    def test_contradictory_role_or_levels_abstain_for_that_port(self):
        cases = [
            "端口 `unclear` 作为 scan_enable\n禁止将端口 `unclear` 用于 scan_enable",
            "端口 `unclear` 作为 scan_enable\n端口 `unclear` 配置为复位信号",
            "端口 `unclear` 作为 scan_enable，off_state=0\n端口 `unclear` off_state=1",
        ]
        for spec in cases:
            self.assertEqual(explicit_signal_role_requirements(spec), [])

    def test_unnamed_roles_and_ambiguous_names_do_not_invent_a_port(self):
        for spec in ("配置一个 scan_enable 信号", "ICG 在移位阶段保持打开", "`left` 和 `right` 中选择一个作为 scan_enable",
                     "设计包含时钟门控单元（ICG，类型 `arbitrary_cell`），其扫描控制端的处理要求见验收标准"):
            self.assertEqual(explicit_signal_role_requirements(spec), [])

    def test_markdown_partition_scan_enable_column_and_table_context(self):
        spec = ("按功能域配置独立的 scan_enable 信号：\n\n"
                "| 使能信号 | 归属分区 | 说明 |\n|------|------|------|\n| `enable_a` | domain_a | 独立控制 |\n"
                "\n| 分区 | clocks | scan_enable |\n|------|------|------|\n| domain_b | clk | `enable_b` |")
        self.assertEqual({r.port: r.roles for r in explicit_signal_role_requirements(spec)},
                         {"enable_a": {"scan"}, "enable_b": {"scan"}})

    def test_multiline_requirement_retains_the_named_port(self):
        spec = "4. 配置扫描使能（scan_enable）信号，新建端口 `shared`，需覆盖\n   **扫描单元与时钟门控** 两类。"
        self.assertEqual(explicit_signal_role_requirements(spec)[0].roles, {"scan", "clock_gating"})

    def test_only_actual_typed_port_signal_and_usage_rows_are_evidence(self):
        spec = "端口 `gate_control` 驱动 ICG SCE"
        self.assertTrue(self.reports([self.row("gate_control", "all")], spec, headers=["Port", "Usage"]))
        self.assertTrue(self.reports([self.row("gate_control", "all")], spec, headers=["Port", "SignalType"]))
        self.assertTrue(self.reports([self.row("gate_control", "all", kind="constant")], spec))
        self.assertTrue(self.reports([self.row("gate_control_other", "all")], spec))
        self.assertEqual(self.reports([dict(self.row("gate_control", "all"), Typed="I")], spec,
                                      headers=["Typed", "Port", "SignalType", "Usage"]), [])

    def test_conflicting_actual_rows_do_not_allow_one_valid_row_to_hide_failure(self):
        spec = "端口 `gate_control` 驱动 ICG SCE"
        self.assertTrue(self.reports([self.row("gate_control", "all"), self.row("gate_control", "scan")], spec))

    def test_reused_mode_signal_has_one_unambiguous_explicit_global_off_state(self):
        spec = ("| 端口 | 功能 |\n|------|------|\n| `mode` | 该信号同时复用为 scan_enable 信号源 |\n"
                "\n1 个 `scan_enable` 信号（off_state = 0）。")
        self.assertEqual(explicit_signal_role_requirements(spec)[0].off_state, "0")

    def test_actual_case4_requirement_and_saved_v56_signal_evidence(self):
        repo = Path(__file__).resolve().parents[1]
        spec = (repo / "public_cases/task_1/case4/input/task_spec.md").read_text()
        requirements = explicit_signal_role_requirements(spec)
        self.assertEqual([(r.port, r.roles, r.off_state) for r in requirements],
                         [("pad_yy_gate_clk_en_b", {"clock_gating"}, None)])
        saved = repo / "outputs/public-live-20261008T113903939155Z/task_1_case4/final_results"
        if not saved.exists():
            self.skipTest("Saved local v56 artifacts are not available")
        script = (saved / "deliverables/final.dofile").read_text()
        self.assertEqual(self.preflight(script, spec), [])
        self.assertEqual(signal_role_report_problems([saved / "reports/rpt_scan_signal.audit.rpt"], spec), [])
        without_named_port = "\n".join(line for line in script.splitlines()
                                       if not line.startswith("set_scan_signal") or "pad_yy_gate_clk_en_b" not in line)
        self.assertTrue(self.preflight(without_named_port, spec))


if __name__ == "__main__":
    unittest.main()
