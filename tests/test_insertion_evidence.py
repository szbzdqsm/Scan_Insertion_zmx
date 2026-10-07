"""Synthetic regression fixtures for zero-replacement audit closure."""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "agent"))
from insertion_evidence import insertion_replacement_evidence  # noqa: E402
from scan_agent import literal_tcl_words  # noqa: E402


def table(headers, rows, design="top"):
    return (f"Design: {design}\n" + "".join(f"{name:<28}" for name in headers) + "\n" +
            "-" * (28 * len(headers)) + "\n" +
            "".join("".join(f"{value:<28}" for value in row) + "\n" for row in rows))


class InsertionEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="scan-insertion-evidence-")
        self.out = Path(self.temp.name) / "results with spaces"
        for rid in ("R1", "R2"):
            (self.out / "runs" / rid / "reports").mkdir(parents=True)
        self.zero = "[INFO] [  SCAN-7600] There were 0 'D' flip-flops that have been replaced."
        self.positive = "[INFO] [  SCAN-7600] There were 4 'D' flip-flops that have been replaced."
        self.old = self.out / "runs/R1/R1.log"
        self.old.write_text("[INFO] [CMD-0034] @1: present_design top\n"
                            "[INFO] [CMD-0034] @2: insert_dft_logic\n" + self.zero + "\n")
        self.issue = {"found": {"verified": True, "run_ref": "R1", "source": "runs/R1/R1.log",
                                "locator": "L3", "excerpt": self.zero},
                      "diagnosis": {"located_object": "insert_dft_logic output"}}
        self.dofile = ("load_lib /input/lib/test.lib\nload_netlist /input/netlist/test.v -top top\n"
                       "set_scan_signal -type clock -port clk -off_state 0\n"
                       "set_scan_signal -type scan_enable -port se -off_state 0\n"
                       "examine_scan_drc\nexamine_scan_chain\ninsert_dft_logic\nexit\n")
        self.log = self.out / "runs/R2/R2.log"
        self.log.write_text("[INFO] [CMD-0034] @1: load_netlist /input/netlist/test.v -top top\n"
                            "[INFO] [CMD-0034] @2: set_scan_signal -type scan_enable -port se -off_state 0\n"
                            "[INFO] [CMD-0034] @3: insert_dft_logic\n" + self.positive + "\n")
        self.chain = self.out / "runs/R2/reports/scan_chain.rpt"
        self.headers = ["Chain", "Length", "Input", "Output", "ScanEnable", "Clocks", "Partition"]
        self.rows = [["I 1", "5", "si1", "so1", "se", "clk", "Default_Partition"]]
        self.chain.write_text(table(self.headers, self.rows))
        self.insertion = self.out / "runs/R2/reports/insertion_info.rpt"
        self.values = {"Total FF Bit Count": "6", "Scannable FF Bit Count": "5",
                       "Nonscannable FF Bit Count": "1", "Scan Chain Cell Bit Count": "5",
                       "Wrapper Chain Cell Bit Count": "-", "Shared Wrapper Cell Bit Count": "-",
                       "Dedicated Wrapper Cell Bit Count": "-"}
        self.write_insertion()
        self.files = [self.chain, self.insertion, self.log]

    def tearDown(self):
        self.temp.cleanup()

    def write_insertion(self, values=None, design="top", path=None):
        values = self.values if values is None else values
        path = self.insertion if path is None else path
        path.write_text(f"Design: {design}\nNO.    Item                                      Quantity\n" +
                        "-" * 60 + "\n" +
                        "".join(f"{number:<7}{name:<42}{value}\n" for number, (name, value) in
                                enumerate(values.items(), 1)))

    def evidence(self, issue=None, files=None, dofile=None):
        return insertion_replacement_evidence(self.issue if issue is None else issue,
                                              self.files if files is None else files, self.out,
                                              self.dofile if dofile is None else dofile, literal_tcl_words)

    def test_returns_exact_actual_later_replacement_line_after_full_proof(self):
        self.assertEqual(self.evidence(), {"source": "runs/R2/R2.log", "locator": "L4", "excerpt": self.positive})

    def test_literal_present_design_and_quoted_ports_are_supported(self):
        script = self.dofile.replace(" -top top", "").replace("set_scan_signal -type clock",
                                                            "present_design {top}\nset_scan_signal -type clock")
        script = script.replace("-port se", '-port "se"')
        self.assertIsNotNone(self.evidence(dofile=script))

    def test_zero_or_unverified_or_inaccurate_discovery_is_rejected(self):
        for fields in ({"verified": False}, {"excerpt": self.positive}, {"locator": "L2"},
                       {"run_ref": "R2"}, {"source": "runs/R1/reports/fake.log"},
                       {"source": str(self.old.resolve())}, {"source": "runs/R1/../R1/R1.log"}, {"locator": "L3-L3"}):
            with self.subTest(fields=fields):
                issue = dict(self.issue, found=dict(self.issue["found"], **fields))
                self.assertIsNone(self.evidence(issue=issue))

    def test_discovery_must_be_in_an_actual_insert_command_block(self):
        self.old.write_text(self.old.read_text().replace("insert_dft_logic", 'puts "pretend"'))
        self.assertIsNone(self.evidence())

    def test_still_zero_replacement_cannot_close_issue(self):
        self.log.write_text(self.log.read_text().replace(self.positive, self.zero))
        self.assertIsNone(self.evidence())

    def test_printed_echo_or_comment_cannot_close_issue(self):
        for replacement in ("[INFO] [CMD-0034] @4: # " + self.positive,
                            "[INFO] [CMD-0034] @4: puts " + self.positive,
                            "[INFO] [CMD-0034] @4: puts fake\n" + self.positive):
            with self.subTest(replacement=replacement):
                self.log.write_text("[INFO] [CMD-0034] @3: insert_dft_logic\n" + replacement + "\n")
                self.assertIsNone(self.evidence())

    def test_wrong_log_design_and_repeated_insertions_are_rejected(self):
        original = self.log.read_text()
        self.log.write_text(original.replace("-top top", "-top other"))
        self.assertIsNone(self.evidence())
        self.log.write_text(original + "[INFO] [CMD-0034] @9: insert_dft_logic\n" + self.positive + "\n")
        self.assertIsNone(self.evidence())

    def test_chain_proof_needs_current_design_nonempty_rows_and_all_enable_connections(self):
        self.chain.write_text(table(self.headers, self.rows, design="other"))
        self.assertIsNone(self.evidence())
        self.chain.write_text(table(self.headers, []))
        self.assertIsNone(self.evidence())
        for column, value in ((0, "W 1"), (1, "0"), (1, "bad"), (2, ""), (3, ""), (4, ""),
                              (4, "other_se"), (5, ""), (6, "unknown_partition")):
            with self.subTest(column=column, value=value):
                changed = [list(self.rows[0])]
                changed[0][column] = value
                self.chain.write_text(table(self.headers, changed))
                self.assertIsNone(self.evidence())

    def test_one_valid_chain_does_not_hide_invalid_second_chain(self):
        other = ["I 2", "1", "si2", "so2", "wrong", "clk", "Default_Partition"]
        self.chain.write_text(table(self.headers, self.rows + [other]))
        self.assertIsNone(self.evidence())

    def test_conflicting_duplicate_chain_reports_are_rejected(self):
        other = self.chain.with_name("another_chain.rpt")
        row = list(self.rows[0])
        row[1] = "4"
        other.write_text(table(self.headers, [row]))
        self.assertIsNone(self.evidence(files=self.files + [other]))

    def test_inserted_ff_proof_requires_all_three_count_identities(self):
        for name, wrong in (("Total FF Bit Count", "7"), ("Scan Chain Cell Bit Count", "4"),
                            ("Shared Wrapper Cell Bit Count", "1")):
            with self.subTest(name=name):
                values = dict(self.values, **{name: wrong})
                self.write_insertion(values)
                self.assertIsNone(self.evidence())

    def test_wrong_design_incomplete_or_invalid_ff_accounting_is_rejected(self):
        self.write_insertion(design="other")
        self.assertIsNone(self.evidence())
        values = dict(self.values)
        del values["Nonscannable FF Bit Count"]
        self.write_insertion(values)
        self.assertIsNone(self.evidence())
        self.write_insertion(dict(self.values, **{"Total FF Bit Count": "bad"}))
        self.assertIsNone(self.evidence())
        self.write_insertion(dict(self.values, **{"Scannable FF Bit Count": "0", "Scan Chain Cell Bit Count": "0",
                                                 "Total FF Bit Count": "1"}))
        self.assertIsNone(self.evidence())

    def test_conflicting_ff_summaries_and_impossible_replacement_total_are_rejected(self):
        other = self.insertion.with_name("other_insertion.rpt")
        values = dict(self.values, **{"Total FF Bit Count": "7", "Nonscannable FF Bit Count": "2"})
        self.write_insertion(values, path=other)
        self.assertIsNone(self.evidence(files=self.files + [other]))
        self.log.write_text(self.log.read_text().replace("There were 4", "There were 6"))
        self.assertIsNone(self.evidence())

    def test_missing_log_chain_or_ff_summary_is_rejected(self):
        for removed in self.files:
            with self.subTest(removed=removed.name):
                self.assertIsNone(self.evidence(files=[path for path in self.files if path != removed]))

    def test_mixed_rounds_or_external_artifacts_cannot_supply_current_proof(self):
        self.assertIsNone(self.evidence(files=self.files + [self.old]))
        elsewhere = self.out / "outside.rpt"
        elsewhere.write_text(self.insertion.read_text())
        self.assertIsNone(self.evidence(files=self.files + [elsewhere]))
        symlink = self.chain.with_name("symlink_chain.rpt")
        symlink.symlink_to(self.chain)
        self.assertIsNone(self.evidence(files=self.files + [symlink]))

    def test_unresolved_or_multiple_literal_scan_enables_are_rejected(self):
        for statement in ("set_scan_signal -type scan_enable -port $enable -off_state 0",
                          "set_scan_signal -type scan_enable -port se",
                          "set_scan_signal -type scan_enable -port se -off_state 2",
                          "set_scan_signal -type scan_enable -port se -off_state 0 -usage clock_gating"):
            with self.subTest(statement=statement):
                self.assertIsNone(self.evidence(dofile=self.dofile.replace(
                    "set_scan_signal -type scan_enable -port se -off_state 0", statement)))
        script = self.dofile.replace("examine_scan_drc", "set_scan_signal -type scan_enable -port other -off_state 0\nexamine_scan_drc")
        self.assertIsNone(self.evidence(dofile=script))

    def test_dynamic_partial_repeated_and_ctl_flows_are_outside_scope(self):
        for statement in ("if {1} {insert_dft_logic}", "insert_dft_logic -replace_unscan", "insert_dft_logic -scan_only",
                          "insert_dft_logic\ninsert_dft_logic", "source extra.tcl\ninsert_dft_logic",
                          "if {1} {source extra.tcl}\ninsert_dft_logic", "rename custom insert_dft_logic\ninsert_dft_logic",
                          "proc hidden {} {noop}\nhidden\ninsert_dft_logic",
                          "eval insert_dft_logic", "set hidden [insert_dft_logic]\ninsert_dft_logic",
                          "load_ctl input.ctl\ninsert_dft_logic"):
            with self.subTest(statement=statement):
                self.assertIsNone(self.evidence(dofile=self.dofile.replace("insert_dft_logic", statement)))
        self.assertIsNone(self.evidence(dofile=self.dofile.replace(" -top top", " -top $top")))

    def test_configuration_after_insertion_or_after_changing_design_is_rejected(self):
        self.assertIsNone(self.evidence(dofile=self.dofile.replace("exit", "set_scan_signal -type scan_enable -port other -off_state 0\nexit")))
        self.assertIsNone(self.evidence(dofile=self.dofile.replace("examine_scan_drc", "present_design other\nexamine_scan_drc")))

    def test_literal_partition_enable_and_clock_gate_enable_are_supported(self):
        script = self.dofile.replace("set_scan_signal -type scan_enable -port se -off_state 0",
                                    "add_scan_partition part -clocks {clk}\nset_current_scan_partition part\n"
                                    "set_scan_signal -type scan_enable -port se -off_state 0 -usage all\n"
                                    "set_scan_signal -type scan_enable -port cg -off_state 0 -usage clock_gating")
        row = list(self.rows[0])
        row[6] = "part"
        self.chain.write_text(table(self.headers, [row]))
        self.assertIsNotNone(self.evidence(dofile=script))

    def test_replacement_count_with_only_unbound_configuration_never_proves_insertion(self):
        script = self.dofile.replace("set_scan_signal -type scan_enable -port se -off_state 0\n", "")
        self.assertIsNone(self.evidence(dofile=script))


if __name__ == "__main__":
    unittest.main()
