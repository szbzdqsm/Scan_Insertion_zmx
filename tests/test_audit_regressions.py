"""Local regression checks for audit bookkeeping; no API/tool calls or answer files."""
import importlib.util
import json
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch

openai_stub = types.ModuleType("openai")
openai_stub.OpenAI = object
agent_path = Path(__file__).resolve().parents[1] / "agent" / "scan_agent.py"
sys.path.insert(0, str(agent_path.parent))
spec = importlib.util.spec_from_file_location("scan_agent", agent_path)
agent = importlib.util.module_from_spec(spec)
with patch.dict(sys.modules, {"openai": openai_stub}):
    spec.loader.exec_module(agent)


class AuditRegression(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="scan-audit-")
        self.root = Path(self.temp.name)
        self.out = self.root / "arbitrary results"
        for rid in ("R1", "R2"):
            run = self.out / "runs" / rid
            (run / "reports").mkdir(parents=True)
            (run / f"{rid}.log").write_text("tool start\n", encoding="utf-8")
        self.cited = "Error: Clock input CK of DFF U1 is uncontrolled. (DFTR1-1)"
        (self.out / "runs/R1/reports/drc.rpt").write_text("header\n" + self.cited + "\n", encoding="utf-8")
        self.item = {"issue_id": "not-an-id", "phenomenon": "uncontrolled clock",
                     "evidence_excerpt": self.cited, "diagnosis": "trace clock source",
                     "located_object": "clk_b", "root_cause": "missing test clock",
                     "violated_requirement": "", "fix": "declare clock"}

    def tearDown(self):
        self.temp.cleanup()

    def record(self, item=None):
        issues, plans = [], {}
        agent.record_issue_fixes({"issue_resolutions": [item or self.item]}, issues, plans,
                                 self.out, "R1", "R2", "F1")
        return issues, plans

    def test_old_round_evidence_and_closed_change_ids(self):
        issues, plans = self.record()
        issue = issues[0]
        self.assertEqual(issue["issue_id"], "I1")
        self.assertEqual(issue["found"]["run_ref"], "R1")
        self.assertEqual(issue["found"]["source"], "runs/R1/reports/drc.rpt")
        self.assertEqual(issue["found"]["locator"], "L2")
        self.assertEqual(issue["attempts"][0]["fix"]["artifact_ref"], ["F1"])
        (self.out / "runs/R2/reports/drc.rpt").write_text("header\nDRC Report\nTotal violations: 0\n")
        agent.verify_issue_fixes(issues, plans, self.out, "R2", True)
        verify = issue["attempts"][0]["verify"]
        self.assertTrue(verify["resolved"])
        self.assertEqual(verify["source"], "runs/R2/reports/drc.rpt")
        self.assertEqual(verify["locator"], "L3")
        self.assertEqual(verify["excerpt"], "Total violations: 0")
        self.assertEqual(agent.issue_audit_problems("task2", issues, [{"change_id": "F1"}]), [])

    def test_new_round_cannot_supply_discovery_evidence(self):
        item = dict(self.item, evidence_excerpt="an invented old diagnostic")
        (self.out / "runs/R2/R2.log").write_text(item["evidence_excerpt"] + "\n")
        self.assertEqual(self.record(item)[0], [])

    def test_tcl_echo_and_comments_cannot_supply_discovery_evidence(self):
        path = self.out / "runs/R1/reports/drc.rpt"
        path.write_text("# " + self.cited + "\n")
        log = self.out / "runs/R1/R1.log"
        log.write_text("[INFO] [CMD-0034] @1: " + self.cited + "\n")
        self.assertEqual(self.record()[0], [])
        path.write_text("[WARNING] " + self.cited + "\n")
        self.assertEqual(len(self.record()[0]), 1)

    def test_disappearance_is_not_positive_verification(self):
        issues, plans = self.record()
        agent.verify_issue_fixes(issues, plans, self.out, "R2", True)
        self.assertFalse(issues[0]["attempts"][0]["verify"]["resolved"])
        self.assertTrue(agent.issue_audit_problems("task2", issues, [{"change_id": "F1"}]))

    def test_config_needs_its_own_report_value(self):
        item = dict(self.item, evidence_excerpt="Number of chains: 4", located_object="set_scan_cfg -chain_count",
                    root_cause="chain count wrong", violated_requirement="扫描链数量应为 8 条",
                    verification={"source": "drc.rpt", "expected_excerpt": "Total violations: 0"})
        (self.out / "runs/R1/reports/scan_chain.rpt").write_text("Number of chains: 4\n")
        (self.out / "runs/R2/reports/drc.rpt").write_text("Total violations: 0\n")
        issues, plans = self.record(item)
        agent.verify_issue_fixes(issues, plans, self.out, "R2", True)
        self.assertFalse(issues[0]["attempts"][0]["verify"]["resolved"])
        plans["I1"] = {"source": "reports/scan_chain.rpt", "expected_excerpt": "Number of chains: 8"}
        (self.out / "runs/R2/reports/scan_chain.rpt").write_text("header\nNumber of chains: 83\n")
        agent.verify_issue_fixes(issues, plans, self.out, "R2", True)
        self.assertFalse(issues[0]["attempts"][0]["verify"]["resolved"])
        (self.out / "runs/R2/reports/scan_chain.rpt").write_text("header\nNumber of chains: 8\n")
        agent.verify_issue_fixes(issues, plans, self.out, "R2", True)
        self.assertEqual(issues[0]["attempts"][0]["verify"]["locator"], "L2")

    def test_command_echo_cannot_prove_completion(self):
        item = dict(self.item, evidence_excerpt="ERROR: unknown argument for add_scan_chains",
                    located_object="add_scan_chains argument", root_cause="wrong option",
                    verification={"source": "R2.log", "expected_excerpt": "add_scan_chains completed"})
        (self.out / "runs/R1/R1.log").write_text(item["evidence_excerpt"] + "\n")
        issues, plans = self.record(item)
        log = self.out / "runs/R2/R2.log"
        log.write_text("[INFO] [CMD-0034] @1: # add_scan_chains completed\nTotal violations: 0\n")
        agent.verify_issue_fixes(issues, plans, self.out, "R2", True)
        self.assertFalse(issues[0]["attempts"][0]["verify"]["resolved"])
        log.write_text("[INFO] [CMD-0034] @1: # add_scan_chains completed\n[INFO] add_scan_chains completed\n")
        agent.verify_issue_fixes(issues, plans, self.out, "R2", True)
        self.assertEqual(issues[0]["attempts"][0]["verify"]["locator"], "L2")

    def test_report_command_fix_requires_its_actual_output_block(self):
        item = dict(self.item,
                    evidence_excerpt="[ERROR] Unknown option '-file' for command 'rpt_scan_drc_violation'.",
                    located_object="rpt_scan_drc_violation", root_cause="unsupported -file option",
                    violated_requirement="produce a DRC report")
        (self.out / "runs/R1/R1.log").write_text(item["evidence_excerpt"] + "\n")
        issues, plans = self.record(item)
        log = self.out / "runs/R2/R2.log"
        log.write_text("Total violations: 0\n[INFO] [CMD-0034] @2: # rpt_scan_drc_violation\n1\n")
        agent.verify_issue_fixes(issues, plans, self.out, "R2", True)
        self.assertFalse(issues[0]["attempts"][0]["verify"]["resolved"])
        log.write_text("[INFO] [CMD-0034] @3: rpt_scan_drc_violation\nDRC Report\nTotal violations: 0\n1\n")
        agent.verify_issue_fixes(issues, plans, self.out, "R2", True)
        self.assertTrue(issues[0]["attempts"][0]["verify"]["resolved"])
        self.assertEqual(issues[0]["attempts"][0]["verify"]["locator"], "L3")

    def test_command_preflight_ignores_nested_query_options(self):
        path = self.root / "tool_help.json"
        path.write_text(json.dumps({"set_scan_cfg": "[-max_length length] [-internal_clocks none]",
                                    "set_scan_element": "set_scan_element false instance_list"}))
        with patch.object(agent, "__file__", str(self.root / "scan_agent.py")):
            self.assertTrue(agent.unsupported_options("set_scan_cfg -scan_data_in_prefix si"))
            self.assertEqual(agent.unsupported_options("set_scan_cfg -internal_clock none"), [])
            self.assertEqual(agent.unsupported_options(
                "set_scan_element false [get_cells -hierarchical {u_core/*}]"), [])

    def test_report_file_adapter_preserves_supported_file_options(self):
        path = self.root / "tool_help.json"
        path.write_text(json.dumps({"rpt_scan_drc_violation": "[-verbose]",
                                    "rpt_scan_chain": "[-file filename]"}))
        with patch.object(agent, "__file__", str(self.root / "scan_agent.py")):
            text = agent.normalize_report_redirection(
                'rpt_scan_drc_violation -verbose -file "report with spaces.rpt"\n'
                'rpt_scan_chain -file "chain.rpt"\n')
        self.assertIn('rpt_scan_drc_violation -verbose > "report with spaces.rpt"', text)
        self.assertIn('rpt_scan_chain -file "chain.rpt"', text)

    def test_cell_filter_preflight_uses_real_properties_and_skips_pin_queries(self):
        (self.root / "tool_help.json").write_text(json.dumps({"__cell_properties": "ref_name cell string A,R\nis_sequential cell boolean A,R"}))
        with patch.object(agent, "__file__", str(self.root / "scan_agent.py")):
            self.assertTrue(agent.unsupported_options('get_cells -hier -filter "is_scan_cell == true"'))
            self.assertEqual(agent.unsupported_options('get_cells -hier -filter "is_sequential == true"'), [])
            self.assertEqual(agent.unsupported_options('get_pins -filter "is_clock_pin == true"'), [])

    def test_chain_order_fix_requires_positive_success_counts(self):
        item = dict(self.item, evidence_excerpt="[ERROR] Cannot execute command 'examine_scan_chain' "
                    "after executing 'insert_dft_logic' command.", located_object="examine_scan_chain",
                    violated_requirement="build scan chains", fix="move examination before insertion")
        (self.out / "runs/R1/R1.log").write_text(item["evidence_excerpt"] + "\n")
        issues, plans = self.record(item)
        log = self.out / "runs/R2/R2.log"
        log.write_text("Total scan chains checked: 4\nSuccess: 3\nFail: 1\n")
        agent.verify_issue_fixes(issues, plans, self.out, "R2", True)
        self.assertFalse(issues[0]["attempts"][0]["verify"]["resolved"])
        log.write_text("Total scan chains checked: 4\nSuccess: 4\nFail: 0\n")
        agent.verify_issue_fixes(issues, plans, self.out, "R2", True)
        self.assertTrue(issues[0]["attempts"][0]["verify"]["resolved"])

    def test_liberty_context_includes_actual_scan_pins(self):
        path = self.root / "cells.lib"
        path.write_text('cell ("sky130_fd_sc_hd__sdfxtp_1") {\n'
                        'pin ("SCD") { }\npin ("SCE") { }\npin ("CLK") { }\n}\n')
        summary = agent.liberty_summary(path)
        self.assertIn('"SCD", "SCE", "CLK"', summary)

    def test_scan_signal_fix_requires_matching_typed_tool_row(self):
        item = dict(self.item, evidence_excerpt="[ERROR] Port 'wb_clk' does not exist.",
                    located_object="set_scan_signal -type clock -port wb_clk",
                    fix="Use set_scan_signal -type clock -port wb_clk_i -off_state 0")
        (self.out / "runs/R1/R1.log").write_text(item["evidence_excerpt"] + "\n")
        issues, plans = self.record(item)
        run = self.out / "runs/R2"
        (run / "deliverables").mkdir()
        (run / "deliverables/R2.dofile").write_text("set_scan_signal -type clock -port wb_clk_i -off_state 0\n")
        report = run / "reports/rpt_scan_signal.audit.rpt"
        header = f"{'Port':16}{'PortProperty':18}{'SignalType':22}{'OffState':12}\n"
        report.write_text(header + f"{'wb_clk_i':16}{'pre_existing':18}{'reset':22}{'0':12}\n")
        agent.verify_issue_fixes(issues, plans, self.out, "R2", True)
        self.assertFalse(issues[0]["attempts"][0]["verify"]["resolved"])
        report.write_text(header + f"{'wb_clk_i':16}{'pre_existing':18}{'clock':22}{'0':12}\n")
        agent.verify_issue_fixes(issues, plans, self.out, "R2", True)
        self.assertTrue(issues[0]["attempts"][0]["verify"]["resolved"])
        self.assertEqual(issues[0]["attempts"][0]["verify"]["locator"], "L2")

    def test_config_option_fix_requires_actual_report_value(self):
        item = dict(self.item, evidence_excerpt="[ERROR] set_scan_cfg execution failed",
                    located_object="set_scan_cfg -mix_edges wrong", fix="set_scan_cfg -mix_edges true")
        (self.out / "runs/R1/R1.log").write_text(item["evidence_excerpt"] + "\n")
        issues, plans = self.record(item)
        run = self.out / "runs/R2"
        (run / "deliverables").mkdir()
        (run / "deliverables/R2.dofile").write_text("set_scan_cfg -mix_edges true\n")
        report = run / "reports/rpt_scan_cfg.audit.rpt"
        report.write_text("mix_edges False\n")
        agent.verify_issue_fixes(issues, plans, self.out, "R2", True)
        self.assertFalse(issues[0]["attempts"][0]["verify"]["resolved"])
        report.write_text("mix_edges True\n")
        agent.verify_issue_fixes(issues, plans, self.out, "R2", True)
        self.assertTrue(issues[0]["attempts"][0]["verify"]["resolved"])

    def test_audit_report_commands_are_inserted_before_exit(self):
        path = self.root / "tool_help.json"
        path.write_text(json.dumps({"rpt_scan_cfg": "rpt_scan_cfg"}))
        with patch.object(agent, "__file__", str(self.root / "scan_agent.py")):
            text = agent.append_audit_reports("insert_dft_logic\nexit\n", self.out / "runs/R2")
        self.assertLess(text.index("rpt_scan_cfg >"), text.index("exit"))
        self.assertIn("insert_dft_logic", text)

    def test_later_successful_round_can_verify_an_earlier_fix(self):
        issues, plans = self.record()
        agent.verify_issue_fixes(issues, plans, self.out, "R2", False)
        run = self.out / "runs/R3"
        (run / "reports").mkdir(parents=True)
        (run / "reports/drc.rpt").write_text("DRC Report\nTotal violations: 0\n")
        agent.verify_issue_fixes(issues, plans, self.out, "R3", True)
        self.assertEqual(issues[0]["attempts"][0]["verify"]["run_ref"], "R3")
        self.assertTrue(issues[0]["attempts"][0]["verify"]["resolved"])

    def test_missing_design_fix_requires_actual_report_for_correct_design(self):
        item = dict(self.item, evidence_excerpt="[ERROR] Nothing matched for 'design'.",
                    located_object="present_design cpu", root_cause="missing netlist load")
        (self.out / "runs/R1/R1.log").write_text(item["evidence_excerpt"] + "\n")
        issues, plans = self.record(item)
        report = self.out / "runs/R2/reports/scan_cfg.rpt"
        report.write_text("Design: unrelated_cpu\n")
        agent.verify_issue_fixes(issues, plans, self.out, "R2", True)
        self.assertFalse(issues[0]["attempts"][0]["verify"]["resolved"])
        report.write_text("Design: cpu\n")
        agent.verify_issue_fixes(issues, plans, self.out, "R2", True)
        self.assertTrue(issues[0]["attempts"][0]["verify"]["resolved"])

    def test_multiline_and_late_log_evidence_preserve_real_lines(self):
        path = self.out / "runs/R1/R1.log"
        path.write_text(("prefix\n" * 18000) + "first diagnostic\nsecond diagnostic\n")
        evidence = agent.locate_evidence([path], self.out, "first diagnostic\nsecond diagnostic")
        self.assertEqual(evidence["locator"], "L18001-L18002")

    def test_model_context_retains_early_errors_in_long_log(self):
        path = self.root / "large.log"
        error = "[ERROR] Unknown option '-active_state' for command 'set_scan_signal'.\n"
        path.write_text(error + ("ordinary progress\n" * 20000) + "[INFO] tool finished\n")
        context = agent.diagnostic_excerpt(path)
        self.assertIn(error.strip(), context)
        self.assertIn("tool finished", context)
        self.assertLessEqual(len(context), 18000)

    def test_multiline_modules_and_actual_parent_instance_names_are_summarized(self):
        path = self.root / "hierarchy.v"
        path.write_text("module child (\nclk\n);\ninput clk;\nendmodule\n"
                        "module top (\nclk\n);\ninput clk;\nchild u_cpu (.clk(clk));\nendmodule\n")
        summary = agent.netlist_summary([path], "Top 模块 top")
        self.assertIn("u_cpu:child", summary)
        self.assertIn("Root modules (not instantiated by another module in this file): top", summary)

    def test_requirement_reference_resolves_multiple_and_continued_commands(self):
        dofile = "# comment\nset_scan_signal -type clock -port clk\nset_scan_cfg \\\n    -chain_count 4 -max_length 100\nexit\n"
        self.assertEqual(agent.config_reference(dofile, "set_scan_signal -type clock -port clk; set_scan_cfg -chain_count 4"), "L2-L4")
        self.assertEqual(agent.config_reference(dofile, "set_scan_element false [SFFs in PLL]"), "")
        self.assertEqual(agent.config_reference(dofile, "set_scan_cfg -chain_count 40"), "")

    def test_many_module_names_cannot_overflow_model_context(self):
        path = self.root / "many_modules.v"
        path.write_text("".join(f"module SNPS_CLOCK_GATE_HIGH_{i}();\nendmodule\n" for i in range(12000)) +
                        "module actual_top();\nendmodule\n")
        summary = agent.netlist_summary([path], "Top 模块 actual_top")
        self.assertLessEqual(len(summary), 50000)
        self.assertIn("actual_top", summary)
        self.assertIn("only 40 names shown", summary)

    def test_late_error_is_not_hidden_by_output_prefix_limit(self):
        run = self.out / "runs/R2"
        (run / "deliverables").mkdir()
        (run / "deliverables/post_scan.v").write_text("module top(); endmodule\n")
        (run / "R2.log").write_text("progress\n" * 20000 + "[ERROR] late command failure\n")
        ok, problems = agent.check_output(run, "Generate Verilog.", "task1", "exit\n", "completed")
        self.assertFalse(ok)
        self.assertIn("Tool log or DRC report contains an ERROR/FATAL diagnostic", problems)

    def run_main(self, task2=False, diagnosed=False, generation_seconds=17):
        input_dir = self.root / "work/input/hidden_case_1/input"
        output_dir = self.root / "work/output/hidden_case_1"
        (input_dir / "netlist").mkdir(parents=True)
        (input_dir / "lib").mkdir()
        (input_dir / "task_spec.md").write_text("Generate a real post-scan netlist.")
        (input_dir / "limitations.md").write_text("总时间 100 秒\n工具调用次数 2")
        (input_dir / "netlist/pre_scan.v").write_text("module top(); endmodule\n")
        (input_dir / "lib/stdcells.lib").write_text("cell(DFF) {}\n")
        if task2:
            (input_dir / "original.dofile").write_text("bad original\n")
        clock = types.SimpleNamespace(now=0)
        captures = {"calls": [], "requests": []}
        item = self.item

        class Client:
            def with_options(self, **kwargs):
                captures["request_timeout"] = kwargs["timeout"]
                return self

            class chat:
                class completions:
                    @staticmethod
                    def create(**kwargs):
                        captures["requests"].append(kwargs)
                        clock.now += generation_seconds
                        response = {"dofile": "exit\n", "requirement_mapping": [{"requirement": "Finish script", "dft_config": "exit"}],
                                    "issue_resolutions": [item] if diagnosed else []}
                        return types.SimpleNamespace(choices=[types.SimpleNamespace(
                            message=types.SimpleNamespace(content=json.dumps(response)))])

        def tool(dofile, run_dir, run_id, timeout, execution_path):
            captures["calls"].append(timeout)
            delivery = run_dir / "deliverables"
            reports = run_dir / "reports"
            delivery.mkdir(exist_ok=True)
            reports.mkdir(exist_ok=True)
            (delivery / f"{run_id}.dofile").write_text(dofile)
            (delivery / "post_scan.v").write_text("module scanned(); endmodule\n")
            (reports / "scan_chain.rpt").write_text("Number of chains: 1\n")
            bad = task2 and run_id == "R1"
            (reports / "drc.rpt").write_text(item["evidence_excerpt"] + "\n" if bad else "Total violations: 0\n")
            log_path = run_dir / f"{run_id}.log"
            log_path.write_text("test fixture log\n" * 6000)
            clock.now += 2
            return {"run_id": run_id, "status": "error" if bad else "completed",
                    "returncode": 1 if bad else 0, "error": None, "elapsed_seconds": 2,
                    "log_path": log_path, "artifacts": ["deliverables/post_scan.v"]}

        with patch.object(agent, "time", types.SimpleNamespace(monotonic=lambda: clock.now)), \
             patch.object(agent, "get_client", return_value=Client()), \
             patch.object(agent, "manual_context", return_value="manual fixture"), \
             patch.object(agent, "tool_run", side_effect=tool), \
             patch.dict(agent.os.environ, {"SCANINSERTION_LICENSE_SERVER": "test"}, clear=True), \
             patch.object(sys, "argv", ["scan_agent.py", "-input", str(input_dir), "-output", str(output_dir)]):
            result = agent.main()
        decision = json.loads((output_dir / "decision_log.json").read_text())
        return result, decision, captures, input_dir, output_dir

    def test_main_paths_budget_and_full_final_log(self):
        result, decision, captures, input_dir, output_dir = self.run_main()
        self.assertEqual(result, 0)
        self.assertEqual(decision["case_id"], "hidden_case_1")
        self.assertEqual(captures["calls"], [53])
        system = captures["requests"][0]["messages"][0]["content"]
        user = captures["requests"][0]["messages"][1]["content"]
        self.assertIn(str(input_dir), system)
        self.assertIn(str(output_dir / "runs/R1"), system)
        self.assertIn(str(input_dir / "netlist/pre_scan.v"), user)
        self.assertIn("Task 1 strictly forbids", system)
        self.assertGreater((output_dir / "runs/R1/R1.log").stat().st_size, 100000)
        self.assertEqual((output_dir / "runs/R1/R1.log").read_bytes(), (output_dir / "final_results/final.log").read_bytes())

    def test_successful_tool_with_empty_task2_diagnosis_is_audit_incomplete(self):
        result, decision, _, _, _ = self.run_main(task2=True)
        self.assertEqual(result, 2)
        self.assertTrue(decision["tool_checks_passed"])
        self.assertFalse(decision["issue_audit_complete"])
        self.assertEqual(decision["tool_runs"][-1]["exit_status"], "completed")
        self.assertEqual(decision["issue_resolutions"], [])

    def test_main_real_evidence_diagnosis_passes(self):
        result, decision, _, _, _ = self.run_main(task2=True, diagnosed=True)
        self.assertEqual(result, 0)
        self.assertTrue(decision["issue_audit_complete"])
        issue = decision["issue_resolutions"][0]
        self.assertEqual(issue["found"]["run_ref"], "R1")
        self.assertEqual(issue["attempts"][0]["fix"]["artifact_ref"], ["F1"])
        self.assertEqual(issue["attempts"][0]["verify"]["run_ref"], "R2")

    def test_tool_is_not_started_when_generation_consumes_reserve(self):
        result, decision, captures, _, _ = self.run_main(generation_seconds=75)
        self.assertEqual(result, 1)
        self.assertEqual(captures["calls"], [])
        self.assertEqual(decision["tool_runs"], [])

    def test_supported_case_directory_names(self):
        with patch.dict(agent.os.environ, {}, clear=True):
            self.assertEqual(agent.case_id_for(Path("/work/input/hidden_case_1/input")), "hidden_case_1")
            self.assertEqual(agent.case_id_for(Path("/work/input/public_case_1/input")), "public_case_1")

    def test_wrong_contest_model_is_rejected_before_client_creation(self):
        with patch.dict(agent.os.environ, {"LLM_MODEL": "other-model", "LLM_API_KEY": "test"}, clear=True):
            with self.assertRaisesRegex(RuntimeError, "Contest requires DeepSeek V4 Pro"):
                agent.get_client()


if __name__ == "__main__":
    unittest.main()
