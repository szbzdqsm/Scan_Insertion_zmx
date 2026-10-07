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

    def test_clean_drc_summary_cannot_discover_an_unrelated_fault(self):
        item = dict(self.item, evidence_excerpt="Total violations: 0", root_cause="missing wrapper configuration")
        (self.out / "runs/R1/reports/drc.rpt").write_text("DRC Report\nTotal violations: 0\n")
        self.assertEqual(self.record(item)[0], [])

    def test_configuration_table_cannot_discover_a_missing_file(self):
        text = "ScanConfigurationParameter Value\nmax_length 100"
        (self.out / "runs/R1/reports/scan_cfg.rpt").write_text(text + "\n")
        item = dict(self.item, evidence_excerpt=text, located_object="reports/drc.rpt", diagnosis="No drc.rpt is written", root_cause="missing report")
        self.assertEqual(self.record(item)[0], [])

    def test_unrelated_wrapper_row_cannot_discover_a_missing_file(self):
        text = "120 key_data[0] (I) dedicated User Specified user_defined Default_Partition"
        (self.out / "runs/R1/reports/wrapper_implementation.rpt").write_text(text + "\n")
        item = dict(self.item, evidence_excerpt=text, located_object="examine_scan_drc command",
                    diagnosis="No drc.rpt file was written to the reports directory.", root_cause="Missing -file argument")
        self.assertEqual(self.record(item)[0], [])

    def test_configuration_table_does_not_prove_redundant_commands(self):
        text = "WrapperConfigurationParameter Value\nmax_length 100"
        (self.out / "runs/R1/reports/wrapper_cfg.rpt").write_text(text + "\n")
        item = dict(self.item, evidence_excerpt=text, located_object="set_wrapper_cfg -max_length 100", diagnosis="Redundant wrapper configuration", root_cause="duplicate configuration")
        self.assertEqual(self.record(item)[0], [])

    def test_scan_configuration_table_does_not_discover_path_or_report_faults(self):
        text = "ScanConfigurationParameter Value\nmax_length 100\nreplace True"
        (self.out / "runs/R1/reports/scan_cfg.rpt").write_text(text + "\n")
        item = dict(self.item, evidence_excerpt=text, located_object="examine_scan_drc command", diagnosis="No drc.rpt was written", root_cause="Missing output report")
        self.assertEqual(self.record(item)[0], [])

    def test_scan_configuration_table_cannot_discover_exclusion_query_fault_by_mentioning_chain_count(self):
        text = "ScanConfigurationParameter Value\nchain_count 55\nmax_length 100"
        (self.out / "runs/R1/reports/scan_cfg.rpt").write_text(text + "\n")
        for located in ("set_scan_element false $targets", "get_obj_insts -hier -filter wrong"):
            item = dict(self.item, evidence_excerpt=text, located_object=located,
                        diagnosis="The query failed earlier; scan_cfg confirms chain_count 55.", root_cause="empty query result")
            self.assertEqual(self.record(item)[0], [])

    def test_error_in_another_command_is_not_discovery_for_a_dump_command(self):
        text = "[ERROR] Command 'set_scan_drc_rule_handling' execution failed"
        (self.out / "runs/R1/R1.log").write_text(text + "\n")
        item = dict(self.item, evidence_excerpt=text, located_object="dump_scan_def", fix="Replace with dump_def -section scan_chain")
        self.assertEqual(self.record(item)[0], [])

    def test_generic_failures_keep_distinct_signal_objects_and_real_error_lines(self):
        text = "[ERROR] [CMD-0074] Command 'set_scan_signal' execution failed"
        (self.out / "runs/R1/R1.log").write_text(
            "[INFO] [CMD-0034] @1: set_scan_signal -type clock -port resetn -off_state 0\n" + text + "\n" +
            "[INFO] [CMD-0034] @2: set_scan_signal -type scan_enable -port test_se -usage scan\n" + text + "\n")
        clock = dict(self.item, phenomenon="wrong clock port", evidence_excerpt=text,
                     located_object="set_scan_signal -type clock -port resetn", root_cause="wrong clock port",
                     fix="set_scan_signal -type clock -port clk -off_state 0")
        enable = dict(self.item, phenomenon="wrong scan enable usage", evidence_excerpt=text,
                      located_object="set_scan_signal -type scan_enable -port test_se -usage scan",
                      root_cause="wrong scan enable usage", fix="set_scan_signal -type scan_enable -port test_se -usage all")
        issues, plans = [], {}
        agent.record_issue_fixes({"issue_resolutions": [clock, enable]}, issues, plans, self.out, "R1", "R2", "F1")
        self.assertEqual(len(issues), 2)
        self.assertEqual([issue["found"]["locator"] for issue in issues], ["L2", "L4"])
        self.assertEqual([issue["phenomenon"] for issue in issues], [clock["phenomenon"], enable["phenomenon"]])
        run = self.out / "runs/R2"
        (run / "deliverables").mkdir()
        (run / "deliverables/R2.dofile").write_text(clock["fix"] + "\n" + enable["fix"] + " -off_state 0\nexit\n")
        headers = ["Port", "PortProperty", "SignalType", "OffState", "Usage"]
        rows = [["clk", "pre_existing", "clock", "0", ""], ["test_se", "tool_created", "scan_enable(spec)", "0", "all"]]
        (run / "reports/scan_signal.rpt").write_text(
            ''.join(f'{value:<28}' for value in headers) + '\n' +
            ''.join(''.join(f'{value:<28}' for value in row) + '\n' for row in rows))
        agent.verify_issue_fixes(issues, plans, self.out, "R2", True)
        self.assertEqual([issue["attempts"][-1]["verify"]["resolved"] for issue in issues], [True, True])
        self.assertEqual([issue["attempts"][-1]["verify"]["locator"] for issue in issues], ["L2", "L3"])

    def test_generic_failure_without_matching_command_echo_is_not_discovery(self):
        text = "[ERROR] Command 'set_scan_signal' execution failed"
        item = dict(self.item, evidence_excerpt=text, located_object="set_scan_signal -type clock -port clk")
        log = self.out / "runs/R1/R1.log"
        log.write_text(text + "\n")
        self.assertEqual(self.record(item)[0], [])
        log.write_text("[INFO] [CMD-0034] @1: set_scan_signal -type scan_enable -port test_se\n" + text + "\n")
        self.assertEqual(self.record(item)[0], [])

    def test_port_diagnosis_recovers_only_the_actual_failed_signal_command(self):
        cases = [
            ("set_scan_signal -type clock -port wb_clk -off_state 0",
             "[ERROR] [SCAN-1315] Port 'wb_clk' does not exist in the design.", "port wb_clk",
             "Changed -port wb_clk to -port wb_clk_i.", "set_scan_signal -type clock -port wb_clk_i -off_state 0",
             ["wb_clk_i", "pre_existing", "clock", "0", ""]),
            ("set_scan_signal -type clock -port mrx_clk_pad_i -off_state 0 -usage all",
             "[ERROR] [SCAN-1604] Signal type does not match option '-usage'.", "port mrx_clk_pad_i",
             "Removed -usage all from mrx_clk_pad_i clock declaration.",
             "set_scan_signal -type clock -port mrx_clk_pad_i -off_state 0",
             ["mrx_clk_pad_i", "pre_existing", "clock", "0", ""]),
            ("set_scan_signal -type scan_enable -port se_wb -active_state 1",
             "[ERROR] [CMD-0074] Unknown option '-active_state' for command 'set_scan_signal'.", "scan_enable se_wb",
             "Replaced -active_state 1 with -off_state 0 -usage all.",
             "set_scan_signal -type scan_enable -port se_wb -off_state 0 -usage all",
             ["se_wb", "tool_created", "scan_enable(spec)", "0", "all"]),
        ]
        run = self.out / "runs/R2"
        (run / "deliverables").mkdir()
        headers = ["Port", "PortProperty", "SignalType", "OffState", "Usage"]
        for original, error, located, fix, repaired, row in cases:
            with self.subTest(located=located):
                item = dict(self.item, evidence_excerpt=error, located_object=located, fix=fix)
                (self.out / "runs/R1/R1.log").write_text("[INFO] [CMD-0034] @1: " + original + "\n" + error + "\n")
                issues, plans = self.record(item)
                (run / "deliverables/R2.dofile").write_text(repaired + "\nexit\n")
                report = run / "reports/scan_signal.rpt"
                wrong = list(row)
                wrong[3] = "1"
                report.write_text(''.join(f'{value:<28}' for value in headers) + '\n' +
                                  ''.join(f'{value:<28}' for value in wrong) + '\n')
                agent.verify_issue_fixes(issues, plans, self.out, "R2", True)
                self.assertFalse(issues[0]["attempts"][-1]["verify"]["resolved"])
                report.write_text(''.join(f'{value:<28}' for value in headers) + '\n' +
                                  ''.join(f'{value:<28}' for value in row) + '\n')
                agent.verify_issue_fixes(issues, plans, self.out, "R2", True)
                self.assertTrue(issues[0]["attempts"][-1]["verify"]["resolved"])
                self.assertIn("scan_signal.rpt", issues[0]["attempts"][-1]["verify"]["source"])

    def test_signal_command_recovery_requires_exact_log_source_locator_and_object(self):
        error = "[ERROR] [SCAN-1315] Port 'wb_clk' does not exist in the design."
        item = dict(self.item, evidence_excerpt=error, located_object="port wb_clk", fix="Changed wb_clk to wb_clk_i")
        original = "set_scan_signal -type clock -port wb_clk -off_state 0"
        (self.out / "runs/R1/R1.log").write_text("[INFO] [CMD-0034] @1: " + original + "\n" + error + "\n")
        issues, _ = self.record(item)
        run = self.out / "runs/R2"
        headers = ["Port", "PortProperty", "SignalType", "OffState", "Usage"]
        (run / "reports/scan_signal.rpt").write_text(''.join(f'{value:<28}' for value in headers) + '\n' +
                                                    ''.join(f'{value:<28}' for value in ["wb_clk_i", "pre_existing", "clock", "0", ""]) + '\n')
        dofile = "set_scan_signal -type clock -port wb_clk_i -off_state 0\n"
        files = [run / "reports/scan_signal.rpt"]
        (self.out / "runs/R1/reports/failure.rpt").write_text(error + "\n")
        for fields in ({"source": "runs/R1/reports/failure.rpt", "locator": "L1"}, {"locator": "L1"},
                       {"source": "runs/R1/../R2/R2.log"}, {"source": str((self.out / "runs/R1/R1.log").resolve())}):
            with self.subTest(fields=fields):
                changed = dict(issues[0], found=dict(issues[0]["found"], **fields))
                self.assertIsNone(agent.configuration_evidence(changed, files, self.out, dofile))
        (self.out / "runs/R1/R1.log").write_text("[INFO] [CMD-0034] @1: set_scan_signal -type clock -port other_clk\n" + error + "\n")
        self.assertIsNone(agent.configuration_evidence(issues[0], files, self.out, dofile))

    def test_partition_clock_fix_needs_all_actual_rows_in_the_named_partition(self):
        item = dict(self.item, located_object="partition wb_partition", root_cause="wrong partition clock",
                    fix="Changed -clocks {tx_clk} to -clocks {wb_clk}")
        issues, _ = self.record(item)
        path = self.out / "runs/R2/reports/scan_chain.rpt"
        headers = ["Chain", "Length", "Input", "Output", "ScanEnable", "Clocks", "Partition"]
        rows = [["I 1", "10", "si1", "so1", "se_wb", "wb_clk", "wb_partition"],
                ["I 2", "10", "si2", "so2", "se_wb", "tx_clk", "wb_partition"]]
        def write(rows):
            path.write_text(''.join(f'{value:<24}' for value in headers) + '\n' +
                            ''.join(''.join(f'{value:<24}' for value in row) + '\n' for row in rows))
        dofile = "add_scan_partition wb_partition -clocks {wb_clk}\n"
        write(rows)
        self.assertIsNone(agent.configuration_evidence(issues[0], [path], self.out, dofile))
        rows[1][5] = "wb_clk"
        write(rows)
        evidence = agent.configuration_evidence(issues[0], [path], self.out, dofile)
        self.assertEqual(evidence["locator"], "L2-L3")
        self.assertEqual(evidence["excerpt"], '\n'.join(path.read_text().splitlines()[1:3]))
        write([])
        self.assertIsNone(agent.configuration_evidence(issues[0], [path], self.out, dofile))

    def test_complete_chain_discovery_checks_each_literal_partition_count_clock_and_enable(self):
        old = self.out / "runs/R1/reports/scan_chain.rpt"
        final = self.out / "runs/R2/reports/scan_chain.rpt"
        headers = ["Chain", "Length", "Input", "Output", "ScanEnable", "Clocks", "Partition"]
        def write(path, rows):
            path.write_text(''.join(f'{value:<24}' for value in headers) + '\n' +
                            ''.join(''.join(f'{value:<24}' for value in row) + '\n' for row in rows))
        write(old, [["I 1", "1", "si1", "so1", "test_se", "tx_clk", "wb_partition"]])
        item = dict(self.item, evidence_excerpt=old.read_text().rstrip('\n'), located_object="scan chains",
                    root_cause="wrong partition configuration", fix="Fixed all partition settings")
        issues, _ = self.record(item)
        dofile = ("add_scan_partition wb_partition -clocks {wb_clk}\nadd_scan_partition tx_partition -clocks {tx_clk}\n"
                  "set_current_scan_partition wb_partition\nset_scan_cfg -chain_count 2\n"
                  "set_scan_signal -type scan_enable -port se_wb -off_state 0\n"
                  "set_current_scan_partition tx_partition\nset_scan_cfg -chain_count 1\n"
                  "set_scan_signal -type scan_enable -port se_tx -off_state 0\n")
        rows = [["I 1", "10", "si1", "so1", "se_wb", "wb_clk", "wb_partition"],
                ["I 2", "10", "si2", "so2", "se_tx", "tx_clk", "tx_partition"],
                ["I 3", "10", "si3", "so3", "se_wb", "wb_clk", "wb_partition"]]
        write(final, rows)
        evidence = agent.configuration_evidence(issues[0], [final], self.out, dofile)
        self.assertEqual(evidence["locator"], "L2-L4")
        header_only = dict(issues[0], found=dict(issues[0]["found"], excerpt=old.read_text().splitlines()[0], locator="L1-L2"))
        self.assertIsNone(agent.configuration_evidence(header_only, [final], self.out, dofile))
        for column, wrong in ((4, "wrong_se"), (5, "wrong_clk"), (6, "wb_partition")):
            changed = [list(row) for row in rows]
            changed[1][column] = wrong
            write(final, changed)
            self.assertIsNone(agent.configuration_evidence(issues[0], [final], self.out, dofile))
        write(final, rows)
        write(old, [["I 1", "1", "si1", "so1", "test_se", "tx_clk", "wb_partition"],
                    ["I 2", "1", "si2", "so2", "test_se", "tx_clk", "wb_partition"]])
        self.assertIsNone(agent.configuration_evidence(issues[0], [final], self.out, dofile))
    def test_command_only_generic_failure_cannot_choose_between_different_objects(self):
        text = "[ERROR] Command 'set_scan_signal' execution failed"
        item = dict(self.item, evidence_excerpt=text, located_object="set_scan_signal")
        (self.out / "runs/R1/R1.log").write_text(
            "[INFO] [CMD-0034] @1: set_scan_signal -type clock -port clk\n" + text + "\n" +
            "[INFO] [CMD-0034] @2: set_scan_signal -type scan_enable -port test_se\n" + text + "\n")
        self.assertEqual(self.record(item)[0], [])

    def test_repeated_concrete_root_cause_retains_discovery_and_reopens_verification(self):
        issues, plans = self.record()
        original_found = dict(issues[0]["found"])
        (self.out / "runs/R2/reports/drc.rpt").write_text("DRC Report\nTotal violations: 0\n")
        agent.verify_issue_fixes(issues, plans, self.out, "R2", True)
        self.assertTrue(issues[0]["attempts"][-1]["verify"]["resolved"])
        (self.out / "runs/R2/reports/drc.rpt").write_text(self.cited + "\n")
        agent.record_issue_fixes({"issue_resolutions": [self.item]}, issues, plans, self.out, "R2", "R3", "F2")
        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0]["found"], original_found)
        self.assertEqual(len(issues[0]["attempts"]), 2)
        self.assertTrue(issues[0]["attempts"][0]["verify"]["resolved"])
        self.assertFalse(issues[0]["attempts"][-1]["verify"]["resolved"])
        self.assertTrue(agent.issue_audit_problems("task2", issues, [{"change_id": "F1"}, {"change_id": "F2"}]))

    def test_identical_diagnostic_does_not_merge_different_concrete_root_causes(self):
        issues, plans = self.record()
        other = dict(self.item, root_cause="different concrete cause")
        agent.record_issue_fixes({"issue_resolutions": [other]}, issues, plans, self.out, "R1", "R2", "F1")
        self.assertEqual(len(issues), 2)

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

    def test_allowed_residual_does_not_use_an_earlier_zero_as_repair_evidence(self):
        item = dict(self.item, evidence_excerpt="Warning: clock on data pin (DFTR10-1)",
                    located_object="U1/D", root_cause="clock connected to data input")
        (self.out / "runs/R1/reports/drc.rpt").write_text(item["evidence_excerpt"] + "\n")
        issues, plans = self.record(item)
        (self.out / "runs/R2/reports/drc.rpt").write_text(
            "DRC Report\nTotal violations: 0\nDRC Report\nTotal violations: 21\n" +
            "[INFO] [DFTDRC-7001] There were 21 DRC rule 'DFTR10' fails.\n")
        agent.verify_issue_fixes(issues, plans, self.out, "R2", True, {"DFTR10"})
        self.assertFalse(issues[0]["attempts"][-1]["verify"]["resolved"])

    def test_rule_handling_table_requires_actual_parameter_evidence_even_when_drc_is_zero(self):
        row = "DFTR-TIE1 Warning Warning all"
        item = dict(self.item, evidence_excerpt=row, located_object="set_scan_drc_rule_handling DFTR-TIE1 Warning",
                    root_cause="permitted constant rule was not ignored", fix="set_scan_drc_rule_handling DFTR-TIE1 Ignore")
        (self.out / "runs/R1/reports/rpt_scan_drc_rule_handling.audit.rpt").write_text(row + "\n")
        issues, plans = self.record(item)
        run = self.out / "runs/R2"
        (run / "deliverables").mkdir()
        (run / "deliverables/R2.dofile").write_text(item["fix"] + "\nexit\n")
        (run / "reports/drc.rpt").write_text("DRC Report\nTotal violations: 0\n")
        report = run / "reports/rpt_scan_drc_rule_handling.audit.rpt"
        report.write_text(row + "\n")
        agent.verify_issue_fixes(issues, plans, self.out, "R2", True, {"DFTRTIE1"})
        self.assertFalse(issues[0]["attempts"][-1]["verify"]["resolved"])
        report.write_text("DFTR-TIE1 Warning Ignore all\n")
        agent.verify_issue_fixes(issues, plans, self.out, "R2", True, {"DFTRTIE1"})
        verify = issues[0]["attempts"][-1]["verify"]
        self.assertTrue(verify["resolved"])
        self.assertIn("rule_handling", verify["source"])
        self.assertEqual(verify["excerpt"], "DFTR-TIE1 Warning Ignore all")

    def test_rule_table_without_command_name_is_not_a_drc_violation(self):
        item = dict(self.item, evidence_excerpt="DFTR7 Warning Warning all", located_object="DFTR7 level",
                    root_cause="wrong configured severity", fix="change configured severity")
        (self.out / "runs/R1/reports/rpt_scan_drc_rule_handling.audit.rpt").write_text(item["evidence_excerpt"] + "\n")
        issues, plans = self.record(item)
        (self.out / "runs/R2/reports/drc.rpt").write_text("DRC Report\nTotal violations: 0\n")
        agent.verify_issue_fixes(issues, plans, self.out, "R2", True)
        self.assertFalse(issues[0]["attempts"][-1]["verify"]["resolved"])

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

    def test_scan_port_format_fix_uses_complete_percent_format_value(self):
        item = dict(self.item, evidence_excerpt="si_port_format test_si%d", located_object="set_scan_cfg -si_port_format",
                    root_cause="wrong port format", fix="Set -si_port_format scan_si_%d")
        (self.out / "runs/R1/reports/scan_cfg.rpt").write_text(item["evidence_excerpt"] + "\n")
        issues, plans = self.record(item)
        run = self.out / "runs/R2"
        (run / "deliverables").mkdir()
        (run / "deliverables/R2.dofile").write_text('set_scan_cfg -si_port_format "scan_si_%d"\nexit\n')
        (run / "reports/scan_cfg.rpt").write_text("si_port_format scan_si_%d\n")
        agent.verify_issue_fixes(issues, plans, self.out, "R2", True)
        self.assertTrue(issues[0]["attempts"][0]["verify"]["resolved"])

    def test_cell_mapping_fix_needs_actual_target_cell_type(self):
        item = dict(self.item, evidence_excerpt="[ERROR] Command 'set_scan_cell_mapping' execution failed",
                    located_object="set_scan_cell_mapping DFF NAND", root_cause="wrong mapping target", fix="Map DFF to SFF")
        (self.out / "runs/R1/R1.log").write_text(
            "[INFO] [CMD-0034] @1: set_scan_cell_mapping DFF NAND\n" + item["evidence_excerpt"] + "\n")
        issues, plans = self.record(item)
        run = self.out / "runs/R2"
        (run / "deliverables").mkdir()
        (run / "deliverables/R2.dofile").write_text("set_scan_cell_mapping DFF SFF\nexit\n")
        report = run / "reports/scan_cell.rpt"
        report.write_text("InstanceName                RefName\nff                          NAND\n")
        agent.verify_issue_fixes(issues, plans, self.out, "R2", True)
        self.assertFalse(issues[0]["attempts"][0]["verify"]["resolved"])
        report.write_text("InstanceName                RefName\nff                          SFF\n")
        agent.verify_issue_fixes(issues, plans, self.out, "R2", True)
        self.assertTrue(issues[0]["attempts"][0]["verify"]["resolved"])

    def test_model_timeout_keeps_small_deadlines_and_allows_longer_case_budget(self):
        with patch.dict(agent.os.environ, {}, clear=True):
            self.assertEqual(agent.model_request_timeout(290), 120)
            self.assertEqual(agent.model_request_timeout(140), 90)
            self.assertEqual(agent.model_request_timeout(20), 20)

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

    def test_unrequested_reset_is_rejected_before_tool_call(self):
        (self.root / "tool_help.json").write_text("{}")
        with patch.object(agent, "__file__", str(self.root / "scan_agent.py")):
            self.assertTrue(agent.unsupported_options("set_scan_signal -type reset -port reset", "Single-clock scan insertion"))
            self.assertTrue(agent.unsupported_options("set_scan_signal -type reset -port reset_n", "没有复位端口，reset_n 不作为 reset"))

    def test_implicit_reset_can_follow_actual_trace_or_uncontrolled_reset_diagnostic(self):
        (self.root / "tool_help.json").write_text("{}")
        script = "set_scan_signal -type reset -port reset_n -off_state 1"
        with patch.object(agent, "__file__", str(self.root / "scan_agent.py")):
            self.assertEqual(agent.unsupported_options(script, "Complete insertion", known_reset_ports={"reset_n"}), [])
            self.assertEqual(agent.unsupported_options(script, "Complete insertion", permit_reset_inference=True), [])
            self.assertTrue(agent.unsupported_options(script, "没有复位端口，reset_n 不作为 reset", permit_reset_inference=True))

    def test_admitted_reset_survives_an_intervening_round_without_drc_output(self):
        (self.root / "task_spec.md").write_text("Complete insertion and clear all DRC")
        (self.root / "tool_help.json").write_text("{}")
        script = "set_scan_signal -type reset -port rst_l -off_state 1\nexit\n"
        response = json.dumps({"dofile": script, "summary": "Preserve the source-supported reset", "issue_resolutions": []})
        with patch.object(agent, "__file__", str(self.root / "scan_agent.py")), patch.object(agent, "ask", return_value=response):
            for state in ({"known_reset_ports": {"rst_l"}}, {"reset_inference_evidenced": True}):
                candidate, _ = agent.call_for_dofile(object(), "task2", "Actual previous uncontrolled reset; latest run failed before DRC",
                    "exit\n", self.root, self.out / "runs/R2", previous_unallowed_codes=set(), **state)
                self.assertIn("-type reset -port rst_l", candidate)

    def test_bare_partition_name_binds_to_its_real_old_chain_row(self):
        headers = ["Chain", "Length", "Input", "Output", "ScanEnable", "Clocks", "Partition"]
        def table(clock):
            return ''.join(f'{value:<24}' for value in headers) + '\n' + ''.join(
                f'{value:<24}' for value in ["I 1", "10", "si1", "so1", "se_wb", clock, "wb_partition"]) + '\n'
        old = self.out / "runs/R1/reports/scan_chain.rpt"
        new = self.out / "runs/R2/reports/scan_chain.rpt"
        old.write_text(table("tx_clk"))
        new.write_text(table("wb_clk"))
        row = old.read_text().splitlines()[1].strip()
        item = dict(self.item, evidence_excerpt=row, located_object="wb_partition", root_cause="wrong partition clock",
                    fix="Changed -clocks {tx_clk} to -clocks {wb_clk}")
        issues, _ = self.record(item)
        proof = agent.configuration_evidence(issues[0], [new], self.out, "add_scan_partition wb_partition -clocks {wb_clk}\n")
        self.assertIsNotNone(proof)
        self.assertIn("wb_clk", proof["excerpt"])

    def test_global_wrapper_default_cannot_discover_a_port_override_fault(self):
        text = "WrapperConfigurationParameter Value\nstyle shared\nenable Y"
        (self.out / "runs/R1/reports/wrapper_cfg.rpt").write_text(text + "\n")
        item = dict(self.item, evidence_excerpt=text, located_object="Port functional_input", root_cause="wrong port style",
                    fix="set_wrapper_cfg -style none -port {functional_input}")
        self.assertEqual(self.record(item)[0], [])

    def test_associated_clock_fix_requires_actual_typed_pin_value(self):
        item = dict(self.item, evidence_excerpt="[ERROR] Pin 'wrong/Q' defined in option '-associated_internal_clocks' does not exist.",
                    located_object="wrong/Q", root_cause="wrong pin path", fix="Change associated_internal_clocks to latch/Q")
        (self.out / "runs/R1/R1.log").write_text(item["evidence_excerpt"] + "\n")
        issues, plans = self.record(item)
        run = self.out / "runs/R2"
        (run / "deliverables").mkdir()
        (run / "deliverables/R2.dofile").write_text("set_scan_signal -type clock -port clk -associated_internal_clocks latch/Q\nexit\n")
        headers = ["Port", "PortProperty", "SignalType", "OffState", "AssociatedInternal", "Usage"]
        report = run / "reports/rpt_scan_signal.audit.rpt"
        report.write_text(''.join(f'{value:<28}' for value in headers) + '\n' +
                          ''.join(f'{value:<28}' for value in ["clk", "pre_existing", "clock", "0", "wrong/Q", ""]) + '\n')
        agent.verify_issue_fixes(issues, plans, self.out, "R2", True)
        self.assertFalse(issues[0]["attempts"][0]["verify"]["resolved"])
        report.write_text(report.read_text().replace("wrong/Q", "latch/Q"))
        agent.verify_issue_fixes(issues, plans, self.out, "R2", True)
        self.assertTrue(issues[0]["attempts"][0]["verify"]["resolved"])

    def test_wrapper_disable_needs_actual_configuration_row(self):
        item = dict(self.item, evidence_excerpt="W wrp_1 10 wrp_si1 wrp_so1", located_object="wrapper chain wrp_1",
                    root_cause="unrequested wrapper", fix="Removed all set_wrapper_cfg enable commands")
        (self.out / "runs/R1/reports/scan_chain.rpt").write_text(item["evidence_excerpt"] + "\n")
        issues, plans = self.record(item)
        report = self.out / "runs/R2/reports/rpt_wrapper_cfg.audit.rpt"
        report.write_text("WrapperConfigurationParameter Value\nenable Y\n")
        agent.verify_issue_fixes(issues, plans, self.out, "R2", True)
        self.assertFalse(issues[0]["attempts"][0]["verify"]["resolved"])
        report.write_text("WrapperConfigurationParameter Value\nenable N\n")
        agent.verify_issue_fixes(issues, plans, self.out, "R2", True)
        self.assertTrue(issues[0]["attempts"][0]["verify"]["resolved"])

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

    def test_drc_level_is_a_direct_positional_argument(self):
        (self.root / "tool_help.json").write_text("{}")
        with patch.object(agent, "__file__", str(self.root / "scan_agent.py")):
            self.assertTrue(agent.unsupported_options("set_scan_drc_rule_handling DFTR10 - Warning\n"))
            self.assertTrue(agent.unsupported_options("set_scan_drc_rule_handling DFTR10\n"))
            self.assertEqual(agent.unsupported_options("set_scan_drc_rule_handling DFTR10 Warning\n"), [])

    def test_drc_exceptions_need_explicit_task_authorization(self):
        self.assertEqual(agent.allowed_drc_codes("不允许忽略 DFTR10"), set())
        self.assertEqual(agent.allowed_drc_codes("禁止修改网表，但允许忽略 DFTR-TIE0/DFTR-TIE1"), {"DFTRTIE0", "DFTRTIE1"})
        (self.root / "tool_help.json").write_text("{}")
        with patch.object(agent, "__file__", str(self.root / "scan_agent.py")):
            self.assertTrue(agent.unsupported_options('set_scan_drc_rule_handling {DFTR-TIE0} Ignore', "DRC 必须无违例"))
            self.assertEqual(agent.unsupported_options('set_scan_drc_rule_handling {DFTR-TIE0} Ignore', "允许忽略 DFTR-TIE0"), [])

    def test_drc_rule_ranges_and_unknown_ids_are_not_real_rule_names(self):
        (self.root / "tool_help.json").write_text("{}")
        with patch.object(agent, "__file__", str(self.root / "scan_agent.py")):
            self.assertTrue(agent.unsupported_options("set_scan_drc_rule_handling {DFTR1-12 DFTR999} Warning"))
            self.assertEqual(agent.unsupported_options("set_scan_drc_rule_handling {DFTR1 DFTR17 DFTR-TIE0 DFTR-L1} Warning"), [])

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

    def test_constant_mode_fix_requires_actual_constant_value(self):
        item = dict(self.item, evidence_excerpt="[ERROR] Port 'test_mode' does not exist.",
                    located_object="set_scan_signal -type constant -port test_mode",
                    fix="Replace with set_scan_signal -type constant -port scan_mode -constant_value 1")
        (self.out / "runs/R1/R1.log").write_text(item["evidence_excerpt"] + "\n")
        issues, plans = self.record(item)
        run = self.out / "runs/R2"
        (run / "deliverables").mkdir()
        (run / "deliverables/R2.dofile").write_text("set_scan_signal -type constant -port scan_mode -constant_value 1\n")
        report = run / "reports/rpt_scan_signal.audit.rpt"
        header = f"{'Port':16}{'PortProperty':18}{'SignalType':22}{'OffState':12}{'ConstantValue':16}\n"
        for value in ("0", "N/A"):
            report.write_text(header + f"{'scan_mode':16}{'pre_existing':18}{'constant':22}{'N/A':12}{value:16}\n")
            agent.verify_issue_fixes(issues, plans, self.out, "R2", True)
            self.assertFalse(issues[0]["attempts"][-1]["verify"]["resolved"])
        report.write_text(header + f"{'scan_mode':16}{'pre_existing':18}{'constant':22}{'N/A':12}{'1':16}\n")
        agent.verify_issue_fixes(issues, plans, self.out, "R2", True)
        self.assertTrue(issues[0]["attempts"][-1]["verify"]["resolved"])

    def test_chain_row_cannot_discover_missing_parameters_on_multiple_ports(self):
        row = "I wb_chain_0 266 scan_data_in_0 scan_data_out_0 test_se wb_clk_i wb_partition"
        (self.out / "runs/R1/reports/scan_chain.rpt").write_text(row + "\n")
        for located in ("ports se_rx, test_se", "se_rx and test_se", "partition wb_partition"):
            item = dict(self.item, evidence_excerpt=row, located_object=located,
                        root_cause="Missing -off_state and -usage parameters", fix="Declare off_state 0 and usage all")
            self.assertEqual(self.record(item)[0], [])

    def test_artifacts_include_direct_tool_outputs_and_exclude_rejected_proposals(self):
        run = self.out / "runs/R2"
        (run / "deliverables").mkdir()
        (run / "deliverables/R2.dofile").write_text("exit\n")
        (run / "deliverables/post_scan.v").write_text("module scanned(); endmodule\n")
        (run / "reports/scan_signal.rpt").write_text("Actual report\n")
        rejected = run / "rejected_proposals/P1"
        rejected.mkdir(parents=True)
        (rejected / "rejection.json").write_text('{"tool_called":false}\n')
        (rejected / "llm_response.json").write_text('{"content":"invalid"}\n')
        produced = {p.relative_to(run).as_posix() for p in agent.collect_tool_outputs(run, "R2")}
        self.assertEqual(produced, {"deliverables/post_scan.v", "reports/scan_signal.rpt"})
        self.assertFalse((run / "deliverables/rejected_proposals").exists())

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

    def test_exclusion_audit_requests_actual_all_states_once_and_rebases_the_report(self):
        (self.root / "tool_help.json").write_text(json.dumps({"rpt_scan_cfg": "rpt_scan_cfg",
                                                            "rpt_scan_element": "rpt_scan_element -type all"}))
        with patch.object(agent, "__file__", str(self.root / "scan_agent.py")):
            first = agent.append_audit_reports("set_scan_element false {U1}\nexit\n", self.out / "runs/R1")
            second = agent.append_audit_reports(first, self.out / "runs/R2")
            repeated = agent.append_audit_reports(second, self.out / "runs/R2")
            ordinary = agent.append_audit_reports("insert_dft_logic\nexit\n", self.out / "runs/R2")
        self.assertEqual(second, repeated)
        self.assertEqual(second.count("rpt_scan_element -type all >"), 1)
        self.assertIn(str(self.out / "runs/R2/reports/rpt_scan_element.audit.rpt"), second)
        self.assertNotIn(str(self.out / "runs/R1"), second)
        self.assertNotIn("rpt_scan_element", ordinary)

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

    def test_reset_level_normalization_follows_observed_input_paths(self):
        hints = {"top": {"rst_ni": {"inactive_level": 1, "traced_targets": 10}}}
        script = "present_design top\nset_scan_signal -type reset -port rst_ni -off_state 0\nexit\n"
        self.assertIn("-off_state 1", agent.normalize_reset_levels(script, hints))
        mapping = "set_scan_signal -type reset -port rst_ni -off_state 0"
        self.assertIn("-off_state 1", agent.normalize_reset_levels(mapping, hints, script))
        self.assertEqual(agent.normalize_reset_levels(script, {}), script)

    def test_wrong_associated_prefix_is_corrected_only_with_actual_direct_pin(self):
        instances = {"top": {"core": {"type": "child", "pins": ["clk"]}, "latch": {"type": "DL", "pins": ["D", "Q"]}},
                     "child": {"real_latch": {"type": "DL", "pins": ["D", "Q"]}}}
        line = "set_scan_signal -type clock -port clk -associated_internal_clocks core/latch/Q\n"
        fixed = agent.normalize_associated_pin_paths("present_design top\n" + line, instances)
        self.assertIn("-associated_internal_clocks {latch/Q}", fixed)
        self.assertIn("core/real_latch/Q", agent.normalize_associated_pin_paths("present_design top\n" + line.replace("core/latch", "core/real_latch"), instances))
        self.assertEqual(agent.normalize_associated_pin_paths(line, {}), line)

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

    def test_explicit_empty_patch_keeps_current_valid_script(self):
        dofile, _ = self.generate_patch([{"dofile_edits": [], "summary": "Keep the current valid configuration"}])
        self.assertEqual(dofile, "set_scan_cfg -chain_count 4\nexit\n")

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

    def test_mapping_prose_is_removed_only_after_matching_complete_actual_tcl(self):
        script = "set_scan_cfg -chain_count 4 -max_length 100\n"
        self.assertEqual(agent.normalize_mapping_annotation(script, "set_scan_cfg -chain_count 4 (applied to all partitions)"), "set_scan_cfg -chain_count 4")
        invalid = "set_scan_cfg -chain_count 40 (applied globally)"
        self.assertEqual(agent.normalize_mapping_annotation(script, invalid), invalid)
        incomplete = "set_scan_cfg -chain_count ($count)"
        self.assertEqual(agent.normalize_mapping_annotation(script, incomplete), incomplete)

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

    def test_generated_unallowed_drc_stops_but_permitted_rule_is_retained(self):
        wrapper = self.root / "tool_fixture.py"
        wrapper.write_text(f"#!{sys.executable}\nimport time\n"
                           "print('[WARNING] [DFTDRC-4001] uncontrolled clock (DFTR1-1)', flush=True)\n"
                           "print('Total violations: 1', flush=True)\ntime.sleep(0.3)\nprint('reached end', flush=True)\n")
        wrapper.chmod(0o700)
        with patch.object(agent, "TOOL", str(wrapper)):
            bad = agent.tool_run("exit\n", self.out / "runs/R2", "R2", 4, allowed_drc=set())
            allowed = agent.tool_run("exit\n", self.out / "runs/R1", "R1", 4, allowed_drc={"DFTR1"})
        self.assertEqual(bad["error"], "unallowed_drc")
        self.assertEqual(allowed["status"], "completed")
        self.assertIn("reached end", (self.out / "runs/R1/R1.log").read_text())

    def run_main(self, task2=False, diagnosed=False, generation_seconds=17, task_spec="Generate a real post-scan netlist.",
                 rejected_edit=False, tool_limit=2, netlist_repairs=False, fingerprint_seconds=0,
                 failing_runs=None):
        input_dir = self.root / "work/input/hidden_case_1/input"
        output_dir = self.root / "work/output/hidden_case_1"
        (input_dir / "netlist").mkdir(parents=True)
        (input_dir / "lib").mkdir()
        (input_dir / "task_spec.md").write_text(task_spec)
        (input_dir / "limitations.md").write_text(f"总时间 100 秒\n工具调用次数 {tool_limit}")
        (input_dir / "netlist/pre_scan.v").write_text("module top(); wire original; endmodule\n" if netlist_repairs else
                                                     "module top(); endmodule\n")
        (input_dir / "lib/stdcells.lib").write_text("cell(DFF) {}\n")
        if task2:
            (input_dir / "original.dofile").write_text("bad original\n")
        clock = types.SimpleNamespace(now=0)
        captures = {"calls": [], "requests": [], "scripts": [], "repair_inputs": [], "fingerprints": []}
        item = self.item
        original_prepare = agent.prepare_repair
        original_fingerprint = agent.fingerprint_paths

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
                        if rejected_edit and len(captures["requests"]) == 1:
                            response["netlist_edits"] = [{"file": str(input_dir / "netlist/pre_scan.v"),
                                "old": "not present in the real source", "new": "module top(); endmodule",
                                "reason": "A model-proposed structural change", "evidence_excerpt": item["evidence_excerpt"]}]
                        if netlist_repairs:
                            proposal = len(captures["requests"])
                            response["dofile"] = (f"load_netlist {input_dir / 'netlist/pre_scan.v'} -top top\nexit\n"
                                                  if proposal == 1 else captures["scripts"][-1])
                            response["netlist_edits"] = [{"file": str(input_dir / "netlist/pre_scan.v"),
                                "old": "wire original;" if proposal == 1 else f"wire repaired_{proposal - 1};",
                                "new": f"wire repaired_{proposal};", "reason": "Synthetic fixture repair",
                                "evidence_excerpt": item["evidence_excerpt"]}]
                        return types.SimpleNamespace(choices=[types.SimpleNamespace(
                            message=types.SimpleNamespace(content=json.dumps(response)))])

        def tool(dofile, run_dir, run_id, timeout, execution_path, abort_on_error=True, allowed_drc=None):
            captures["calls"].append(timeout)
            captures["scripts"].append(dofile)
            delivery = run_dir / "deliverables"
            reports = run_dir / "reports"
            delivery.mkdir(exist_ok=True)
            reports.mkdir(exist_ok=True)
            (delivery / f"{run_id}.dofile").write_text(dofile)
            (delivery / "post_scan.v").write_text("module scanned(); endmodule\n")
            (reports / "scan_chain.rpt").write_text("Number of chains: 1\n")
            bad = run_id in failing_runs if failing_runs is not None else task2 and run_id == "R1"
            (reports / "drc.rpt").write_text(item["evidence_excerpt"] + "\n" if bad else "Total violations: 0\n")
            log_path = run_dir / f"{run_id}.log"
            log_path.write_text("test fixture log\n" * 6000)
            clock.now += 2
            return {"run_id": run_id, "status": "error" if bad else "completed",
                    "returncode": 1 if bad else 0, "error": None, "elapsed_seconds": 2,
                    "log_path": log_path, "artifacts": ["deliverables/post_scan.v"]}

        def prepare(task, task_spec, original_dofile, input_root, originals, active, libs, edits, output_root, run_id, deadline):
            if not netlist_repairs:
                return original_prepare(task, task_spec, original_dofile, input_root, originals, active,
                                        libs, edits, output_root, run_id, deadline)
            # These are synthetic admitted-proof fixtures. No EQY or EDA process is started.
            captures["repair_inputs"].append(dict(active))
            source = originals[0]
            candidate = output_root / "netlist_versions" / run_id / source.name
            candidate.parent.mkdir(parents=True)
            candidate.write_text(active[source].read_text().replace(edits[0]["old"], edits[0]["new"]))
            proof = output_root / "lec" / run_id / "aggregate.log"
            proof.parent.mkdir(parents=True)
            proof.write_text("Synthetic admitted EQY proof fixture\n")
            diff = output_root / "diffs" / f"netlist_{run_id}_fixture.diff"
            diff.parent.mkdir(exist_ok=True)
            diff.write_text("Synthetic retained candidate diff fixture\n")
            return {source: candidate}, [{"type": "netlist", "path": candidate.relative_to(output_root).as_posix(),
                                          "diff_path": diff.relative_to(output_root).as_posix(),
                                          "lec_ref": proof.relative_to(output_root).as_posix()}]

        def fingerprint(paths):
            captures["fingerprints"].append(list(paths))
            clock.now += fingerprint_seconds
            return original_fingerprint(paths)

        with patch.object(agent, "time", types.SimpleNamespace(monotonic=lambda: clock.now)), \
             patch.object(agent, "get_client", return_value=Client()), \
             patch.object(agent, "manual_context", return_value="manual fixture"), \
             patch.object(agent, "tool_run", side_effect=tool), \
             patch.object(agent, "prepare_repair", side_effect=prepare), \
             patch.object(agent, "fingerprint_paths", side_effect=fingerprint), \
             patch.dict(agent.os.environ, {"SCANINSERTION_LICENSE_SERVER": "test"}, clear=True), \
             patch.object(sys, "argv", ["scan_agent.py", "-input", str(input_dir), "-output", str(output_dir)]):
            result = agent.main()
        decision = json.loads((output_dir / "decision_log.json").read_text())
        return result, decision, captures, input_dir, output_dir

    def test_admitted_candidate_without_tool_time_keeps_last_actual_final_script_and_changes(self):
        result, decision, captures, input_dir, output_dir = self.run_main(
            task2=True, diagnosed=True, netlist_repairs=True, fingerprint_seconds=73)
        self.assertEqual(result, 2)
        self.assertEqual([record["tool_call_id"] for record in decision["tool_runs"]], ["R1"])
        self.assertEqual(decision["final_run"], "R1")
        self.assertEqual(len(captures["calls"]), 1)
        self.assertEqual(len(captures["fingerprints"]), 1)
        self.assertEqual(decision["file_changes"], [])
        attempt = decision["netlist_repair_attempts"][0]
        self.assertTrue(attempt["admitted"])
        self.assertFalse(attempt["adopted"])
        self.assertTrue((output_dir / attempt["lec_ref"]).is_file())
        self.assertTrue((output_dir / "netlist_versions/R2/pre_scan.v").is_file())
        self.assertIn("Insufficient time after fingerprinting before R2", decision["summary"])
        self.assertEqual((output_dir / "final_results/deliverables/final.dofile").read_text(),
                         (output_dir / "runs/R1/deliverables/R1.dofile").read_text())
        self.assertEqual((output_dir / "final_results/final.log").read_bytes(),
                         (output_dir / "runs/R1/R1.log").read_bytes())
        self.assertFalse((output_dir / "runs/R2/deliverables/R2.dofile").exists())
        self.assertEqual((input_dir / "netlist/pre_scan.v").read_text(), "module top(); wire original; endmodule\n")

    def test_consecutive_repairs_rebind_inherited_absolute_path_to_current_proven_candidate(self):
        result, decision, captures, input_dir, output_dir = self.run_main(
            task2=True, diagnosed=True, netlist_repairs=True, tool_limit=3, failing_runs={"R1", "R2"})
        self.assertEqual(result, 0)
        self.assertEqual([record["tool_call_id"] for record in decision["tool_runs"]], ["R1", "R2", "R3"])
        first_candidate = output_dir / "netlist_versions/R2/pre_scan.v"
        current_candidate = output_dir / "netlist_versions/R3/pre_scan.v"
        self.assertIn(str(first_candidate), captures["scripts"][1])
        # The second response inherits the R2 absolute path; runtime must replace it.
        inherited = json.loads((output_dir / "runs/R3/llm_response.json").read_text())["content"]
        self.assertIn(str(first_candidate), json.loads(inherited)["dofile"])
        self.assertIn(str(current_candidate), captures["scripts"][2])
        self.assertNotIn(str(first_candidate), captures["scripts"][2])
        original = input_dir / "netlist/pre_scan.v"
        self.assertEqual(captures["repair_inputs"][1][original], first_candidate)
        self.assertEqual((output_dir / "runs/R3/input/netlist").resolve(), current_candidate.parent)
        self.assertIn(current_candidate, captures["fingerprints"][-1])
        self.assertEqual(current_candidate.read_text(), "module top(); wire repaired_2; endmodule\n")
        self.assertEqual((output_dir / "final_results/deliverables/final.dofile").read_text(), captures["scripts"][2])
        self.assertEqual(decision["final_run"], "R3")
        self.assertTrue(all(attempt["adopted"] for attempt in decision["netlist_repair_attempts"]))

    def test_rejected_candidate_is_retained_and_followed_by_a_real_configuration_retry(self):
        result, decision, captures, input_dir, output_dir = self.run_main(task2=True, diagnosed=True, rejected_edit=True)
        self.assertEqual(result, 0)
        self.assertEqual(len(captures["calls"]), 2)
        self.assertEqual([record["tool_call_id"] for record in decision["tool_runs"]], ["R1", "R2"])
        self.assertEqual(len(decision["generation_rejections"]), 1)
        self.assertFalse(decision["generation_rejections"][0]["tool_called"])
        self.assertFalse(decision["netlist_repair_attempts"][0]["adopted"])
        self.assertTrue((output_dir / "runs/R2/rejected_proposals/P1/rejection.json").is_file())
        self.assertTrue((output_dir / "runs/R2/rejected_proposals/P1/llm_response.json").is_file())
        self.assertEqual((input_dir / "netlist/pre_scan.v").read_text(), "module top(); endmodule\n")
        feedback = captures["requests"][-1]["messages"][-1]["content"]
        self.assertIn("NO tool call and NO candidate adoption", feedback)

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

    def test_final_check_keeps_shift_register_evidence_requirement(self):
        groups = [{"root": "top", "start_template": "sff", "end_template": "ff", "index_tuples": [[]],
                   "length": 10, "scan_data_in_pin": "SI", "scan_data_out_pin": "Q"}]
        with patch.object(agent, "shift_register_groups", return_value=groups), \
             patch.object(agent, "configure_shift_segments", side_effect=lambda script, groups, spec: (script, [])):
            result, decision, _, _, _ = self.run_main(task_spec="所有长移位寄存器均配置为 scan segment")
        self.assertEqual(result, 2)
        self.assertFalse(decision["tool_checks_passed"])
        self.assertIn("input-derived shift-register", decision["summary"])

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
