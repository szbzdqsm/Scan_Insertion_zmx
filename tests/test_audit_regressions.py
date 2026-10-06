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

    def test_model_evidence_id_expands_only_actual_prior_excerpt(self):
        catalog = agent.evidence_catalog(self.out / "runs/R1", self.out)
        evidence_id = next(key for key, value in catalog.items() if self.cited in value["excerpt"])
        (self.root / "task_spec.md").write_text("Repair the real clock diagnostic.")
        reply = {"dofile": "exit\n", "issue_resolutions": [dict(self.item, evidence_id=evidence_id, evidence_excerpt="invented")],
                 "requirement_mapping": [{"requirement": "Finish script", "dft_config": "exit"}]}
        with patch.object(agent, "ask", return_value=json.dumps(reply)), \
             patch.object(agent, "__file__", str(self.root / "scan_agent.py")):
            _, meta = agent.call_for_dofile(object(), "task1", "fixture", None, self.root,
                                           self.out / "runs/R2", catalog=catalog)
        self.assertEqual(meta["issue_resolutions"][0]["evidence_excerpt"], self.cited)
        reply["issue_resolutions"][0]["evidence_id"] = "E999"
        with patch.object(agent, "ask", return_value=json.dumps(reply)), \
             patch.object(agent, "__file__", str(self.root / "scan_agent.py")):
            with self.assertRaisesRegex(ValueError, "Unknown evidence_id"):
                agent.call_for_dofile(object(), "task1", "fixture", None, self.root,
                                      self.out / "runs/R2", catalog=catalog)

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

    def test_report_file_adapter_keeps_complete_tcl_substitution(self):
        (self.root / "tool_help.json").write_text(json.dumps({"rpt_scan_drc_violation": "[-verbose]"}))
        with patch.object(agent, "__file__", str(self.root / "scan_agent.py")):
            text = agent.normalize_report_redirection('rpt_scan_drc_violation -verbose -file [file join $out_dir "drc report.rpt"]\n')
        self.assertEqual(text, 'rpt_scan_drc_violation -verbose > [file join $out_dir "drc report.rpt"]\n')

    def test_global_wrapper_none_and_empty_port_are_invalid(self):
        (self.root / "tool_help.json").write_text("{}")
        with patch.object(agent, "__file__", str(self.root / "scan_agent.py")):
            for command in ('set_wrapper_cfg -style none', 'set_wrapper_cfg -style none -port {}'):
                self.assertTrue(agent.unsupported_options(command))
            self.assertEqual(agent.unsupported_options('set_wrapper_cfg disable'), [])
            self.assertEqual(agent.unsupported_options('set_wrapper_cfg -style none -port functional_in'), [])

    def test_cell_filter_preflight_uses_real_properties_and_skips_pin_queries(self):
        (self.root / "tool_help.json").write_text(json.dumps({"__cell_properties": "ref_name cell string A,R\nis_sequential cell boolean A,R"}))
        with patch.object(agent, "__file__", str(self.root / "scan_agent.py")):
            self.assertTrue(agent.unsupported_options('get_cells -hier -filter "is_scan_cell == true"'))
            self.assertEqual(agent.unsupported_options('get_cells -hier -filter "is_sequential == true"'), [])
            self.assertEqual(agent.unsupported_options('get_pins -filter "is_clock_pin == true"'), [])

    def test_multiple_input_files_are_one_tcl_list_argument(self):
        text = agent.normalize_load_file_lists('load_netlist -top top "/input/a.v" "/input/path with spaces/b.v"\n'
                                               'load_lib /input/a.lib /input/b.lib\n')
        self.assertIn('load_netlist -top top [list "/input/a.v" "/input/path with spaces/b.v"]', text)
        self.assertIn('load_lib [list /input/a.lib /input/b.lib]', text)
        self.assertEqual(agent.normalize_load_file_lists(text), text)
        self.assertEqual(agent.normalize_load_file_lists('load_netlist {/a.v /b.v} -top top\n'),
                         'load_netlist {/a.v /b.v} -top top\n')

    def test_indexed_data_ports_use_documented_format_configuration(self):
        text = agent.normalize_scan_port_formats('set_scan_signal -type scan_data_in -port scan_si_%d\n'
                                                'set_scan_signal -port scan_so_%d -type scan_data_out\n'
                                                'set_scan_signal -type scan_data_in -port existing_si\n')
        self.assertIn('set_scan_cfg -si_port_format scan_si_%d', text)
        self.assertIn('set_scan_cfg -so_port_format scan_so_%d', text)
        self.assertIn('set_scan_signal -type scan_data_in -port existing_si', text)
        self.assertEqual(agent.normalize_scan_port_formats(text), text)

    def test_auxiliary_wrapper_load_retains_both_roots_and_present_design(self):
        text = ('load_netlist -top main [list /input/main.v /input/wrapper.v]\n'
                'present_design main\nadd_dedicated_wrapper_cell_type -design_name helper -interface {}\n')
        adapted = agent.normalize_wrapper_roots(text)
        self.assertIn('load_netlist [list /input/main.v /input/wrapper.v]', adapted)
        self.assertIn('present_design main', adapted)
        self.assertNotIn('-top', adapted)
        self.assertEqual(agent.normalize_wrapper_roots(adapted), adapted)
        self.assertEqual(agent.normalize_wrapper_roots('load_netlist -top main /input/main.v\npresent_design main\n'),
                         'load_netlist -top main /input/main.v\npresent_design main\n')

    def test_unsupported_drc_ignore_is_rejected_before_execution(self):
        (self.root / "tool_help.json").write_text("{}")
        with patch.object(agent, "__file__", str(self.root / "scan_agent.py")):
            self.assertTrue(agent.unsupported_options('set_scan_drc_rule_handling {DFTR10} Ignore'))
            self.assertTrue(agent.unsupported_options('set_scan_drc_rule_handling {DFTR1 DFTR9} Info'))
            self.assertEqual(agent.unsupported_options('set_scan_drc_rule_handling {DFTR-TIE0 DFTR17} Ignore'), [])
            self.assertEqual(agent.unsupported_options('set_scan_drc_rule_handling {DFTR10} Warning'), [])

    def test_drc_exceptions_need_explicit_task_authorization(self):
        self.assertEqual(agent.allowed_drc_codes("不允许忽略 DFTR10"), set())
        self.assertEqual(agent.allowed_drc_codes("禁止修改网表，但允许忽略 DFTR-TIE0/DFTR-TIE1"), {"DFTRTIE0", "DFTRTIE1"})
        (self.root / "tool_help.json").write_text("{}")
        with patch.object(agent, "__file__", str(self.root / "scan_agent.py")):
            self.assertTrue(agent.unsupported_options('set_scan_drc_rule_handling {DFTR-TIE0} Ignore', "DRC 必须无违例"))
            self.assertEqual(agent.unsupported_options('set_scan_drc_rule_handling {DFTR-TIE0} Ignore', "允许忽略 DFTR-TIE0"), [])

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

    def test_drc_order_fix_requires_actual_zero_before_insertion(self):
        item = dict(self.item, evidence_excerpt="[ERROR] Cannot execute command 'examine_scan_drc' after executing 'insert_dft_logic' command.",
                    located_object="examine_scan_drc", root_cause="wrong execution order", fix="check before insertion")
        (self.out / "runs/R1/R1.log").write_text(item["evidence_excerpt"] + "\n")
        issues, plans = self.record(item)
        log = self.out / "runs/R2/R2.log"
        log.write_text("[INFO] [CMD-0034] @1: insert_dft_logic\n[INFO] [CMD-0034] @2: examine_scan_drc\nTotal violations: 0\n")
        agent.verify_issue_fixes(issues, plans, self.out, "R2", True)
        self.assertFalse(issues[0]["attempts"][0]["verify"]["resolved"])
        log.write_text("[INFO] [CMD-0034] @1: examine_scan_drc\nDRC Report\nTotal violations: 0\n[INFO] [CMD-0034] @2: insert_dft_logic\n")
        agent.verify_issue_fixes(issues, plans, self.out, "R2", True)
        self.assertTrue(issues[0]["attempts"][0]["verify"]["resolved"])

    def test_order_and_signal_conflicts_are_preflight_errors(self):
        (self.root / "tool_help.json").write_text("{}")
        with patch.object(agent, "__file__", str(self.root / "scan_agent.py")):
            self.assertTrue(agent.unsupported_options("insert_dft_logic\nexamine_scan_drc -file late.rpt\n"))
            self.assertTrue(agent.unsupported_options("set_scan_signal -type scan_enable -port se\nset_scan_signal -type wrp_in_shift_en -port se\n"))
            self.assertTrue(agent.unsupported_options("set_scan_signal -type clock -port clk\nset_scan_signal -type clock -port clk -associated_internal_clocks latch/Q\n"))
            self.assertEqual(agent.unsupported_options("set_scan_signal -type scan_enable -port se -view existing\nset_scan_signal -type scan_enable -port se -view spec\n"), [])

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

    def test_incremental_round_replaces_owned_audit_block(self):
        (self.root / "tool_help.json").write_text(json.dumps({"rpt_scan_cfg": "rpt_scan_cfg"}))
        with patch.object(agent, "__file__", str(self.root / "scan_agent.py")):
            first = agent.append_audit_reports("insert_dft_logic\nexit\n", self.out / "runs/R1")
            second = agent.append_audit_reports(first, self.out / "runs/R2")
            repeated = agent.append_audit_reports(second, self.out / "runs/R2")
        self.assertEqual(second, repeated)
        self.assertEqual(second.count("rpt_scan_cfg >"), 1)
        self.assertNotIn(str(self.out / "runs/R1"), second)
        self.assertIn(str(self.out / "runs/R2"), second)

    def test_round_rebases_script_and_mapping_without_mutating_evidence(self):
        before, after = self.out / "runs/R1", self.out / "runs/R2"
        script = f'dump_netlist "{before}/deliverables/post.v"\nexit\n'
        mapping = [{"requirement": "Produce netlist", "dft_config": script.splitlines()[0], "dofile_ref": "L1"}]
        rebased, copied = agent.rebase_round(script, mapping, before, after)
        self.assertNotIn(str(before), rebased)
        self.assertIn(str(after), copied[0]["dft_config"])
        self.assertEqual(agent.config_reference(rebased, copied[0]["dft_config"]), "L1")
        self.assertNotIn("dofile_ref", copied[0])
        self.assertIn(str(before), mapping[0]["dft_config"])
        self.assertEqual(mapping[0]["dofile_ref"], "L1")

    def generate_patch(self, responses, base="set_scan_cfg -chain_count 4\nexit\n", mapping=None):
        run = self.out / "runs/R2"
        (self.root / "task_spec.md").write_text("Configure a scan chain count.")
        if mapping is None:
            mapping = [{"requirement": "Four scan chains", "dft_config": "set_scan_cfg -chain_count 4"}]
        with patch.object(agent, "ask", side_effect=[json.dumps(item) for item in responses]), \
             patch.object(agent, "__file__", str(self.root / "scan_agent.py")):
            return agent.call_for_dofile(object(), "task1", "local fixture", None,
                                         self.root, run, base_dofile=base, previous_mapping=mapping)

    def test_localized_dofile_repair_inherits_valid_mapping(self):
        dofile, meta = self.generate_patch([{"dofile_edits": [{"old": "exit\n", "new": "rpt_scan_cfg\nexit\n"}]}])
        self.assertEqual(dofile, "set_scan_cfg -chain_count 4\nrpt_scan_cfg\nexit\n")
        self.assertEqual(meta["requirement_mapping"][0]["dft_config"], "set_scan_cfg -chain_count 4")

    def test_changed_configuration_requires_updated_mapping(self):
        edit = {"dofile_edits": [{"old": "-chain_count 4", "new": "-chain_count 8"}]}
        fixed = dict(edit, requirement_mapping=[{"requirement": "Eight scan chains", "dft_config": "set_scan_cfg -chain_count 8"}])
        dofile, meta = self.generate_patch([edit, fixed])
        self.assertIn("-chain_count 8", dofile)
        self.assertEqual(meta["requirement_mapping"][0]["dft_config"], "set_scan_cfg -chain_count 8")
        validation = json.loads((self.out / "runs/R2/llm_validation.json").read_text())
        self.assertIn("has no actual Tcl match", validation["problems"][0])

    def test_ambiguous_including_overlapping_dofile_edit_is_rejected(self):
        for base, old in [("exit\nexit\n", "exit"), ("aaa\nexit\n", "aa")]:
            edit = {"dofile_edits": [{"old": old, "new": "new"}]}
            with self.assertRaisesRegex(ValueError, "unique"):
                self.generate_patch([edit, edit], base=base)

    def test_edits_use_original_spans_and_reject_overlap(self):
        self.assertEqual(agent.apply_dofile_edits("A\nB\n", [{"old": "A", "new": "B"}, {"old": "B", "new": "C"}]), "B\nC\n")
        with self.assertRaisesRegex(ValueError, "overlap"):
            agent.apply_dofile_edits("A\nB\n", [{"old": "A\nB", "new": "X"}, {"old": "B", "new": "C"}])

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
        self.assertEqual(agent.config_reference(dofile, "set_scan_cfg -max_length 100 -chain_count 4"), "L3-L4")
        self.assertEqual(agent.config_reference(dofile, "set_scan_cfg -max_length 100 (in all partitions)"), "")

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

    def test_generated_error_terminates_tool_process_group(self):
        run = self.out / "runs/R2"
        pid_file = self.root / "child.pid"
        wrapper = self.root / "tool_fixture.py"
        wrapper.write_text(f"#!{sys.executable}\nimport subprocess,sys,time\n"
                           "child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(20)'])\n"
                           f"open({str(pid_file)!r}, 'w').write(str(child.pid))\n"
                           "print('[ERROR] local fixture diagnostic', flush=True)\ntime.sleep(20)\n")
        wrapper.chmod(0o700)
        with patch.object(agent, "TOOL", str(wrapper)):
            result = agent.tool_run("exit\n", run, "R2", 4, abort_on_error=True)
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["error"], "early_tool_error")
        self.assertLess(result["elapsed_seconds"], 3)
        state = Path("/proc") / pid_file.read_text() / "stat"
        self.assertTrue(not state.exists() or state.read_text().split()[2] == "Z")
        self.assertIn("remaining commands were not executed", (run / "R2.log").read_text())

    def test_original_script_is_not_stopped_at_an_error(self):
        wrapper = self.root / "tool_fixture.py"
        wrapper.write_text(f"#!{sys.executable}\nimport time\n"
                           "print('[ERROR] original fixture diagnostic', flush=True)\ntime.sleep(0.2)\n"
                           "print('original reached its end', flush=True)\n")
        wrapper.chmod(0o700)
        with patch.object(agent, "TOOL", str(wrapper)):
            result = agent.tool_run("exit\n", self.out / "runs/R1", "R1", 4, abort_on_error=False)
        self.assertEqual(result["returncode"], 0)
        self.assertIn("original reached its end", (self.out / "runs/R1/R1.log").read_text())

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

        def tool(dofile, run_dir, run_id, timeout, execution_path, abort_on_error=True):
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
        self.assertEqual(captures["calls"], [75])
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
        result, decision, captures, _, _ = self.run_main(generation_seconds=95)
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
