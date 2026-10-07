"""Regression fixtures for typed, streamed real-report validation."""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "agent"))
from report_validation import chain_problems, chain_rows, coverage_problems, ctl_overlength_exceptions, pseudo_clock_problems, report_rows, segment_problems  # noqa: E402


def table(headers, rows, width=28):
    return "Design: top\n" + "".join(f"{name:<{width}}" for name in headers) + "\n" + "-" * (width*len(headers)) + "\n" + "".join(
        "".join(f"{value:<{width}}" for value in row) + "\n" for row in rows)


class ReportValidation(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="scan-report-")
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def report(self, rows):
        path = self.root / "scan_chain.rpt"
        path.write_text(table(["Chain", "Length", "Input", "Output", "ScanEnable", "Clocks", "Partition"], rows))
        return path

    def insertion_report(self, values=None, design="top", name="insertion_info.rpt"):
        if values is None:
            values = {"Total FF Bit Count": "8920", "Scannable FF Bit Count": "8920",
                      "Nonscannable FF Bit Count": "-", "Scan Chain Cell Bit Count": "8680",
                      "Wrapper Chain Cell Bit Count": "240", "Shared Wrapper Cell Bit Count": "128",
                      "Dedicated Wrapper Cell Bit Count": "112"}
        path = self.root / name
        path.write_text(f"Design: {design}\nNO.    Item                                      Quantity\n" + "-" * 60 + "\n" +
                        "".join(f"{index + 31:<7}{item:<42}{value}\n" for index, (item, value) in enumerate(values.items())))
        return path

    def test_coverage_counts_natural_shift_dffs_within_chain_not_again(self):
        path = self.insertion_report()
        with path.open("a") as stream:
            stream.write("77     Single Data Flip-Flop (DFF) Count         6814\n")
        self.assertEqual(coverage_problems([path], "present_design top\ninsert_dft_logic\n"), [])

    def test_coverage_scopes_literal_load_top_without_present_design(self):
        path = self.insertion_report()
        path.write_text(path.read_text().replace("8680", "8679"))
        for name in ('top', '{top}', '"top"'):
            self.assertTrue(coverage_problems([path], f"load_netlist /input/pre.v -top {name}\ninsert_dft_logic\n"))
        self.assertEqual(coverage_problems([path], "load_netlist /input/pre.v -top $top\ninsert_dft_logic\n"), [])
        self.assertEqual(coverage_problems([path], "load_netlist /input/pre.v -top top\nload_netlist /input/other.v\ninsert_dft_logic\n"), [])

    def test_coverage_each_accounting_identity_is_checked(self):
        path = self.insertion_report()
        valid = path.read_text()
        for item, old, new in (("Scan Chain Cell Bit Count", "8680", "8679"),
                               ("Total FF Bit Count", "8920", "8919"),
                               ("Dedicated Wrapper Cell Bit Count", "112", "111")):
            with self.subTest(item=item):
                lines = valid.splitlines(keepends=True)
                path.write_text("".join(line.replace(old, new) if item in line else line for line in lines))
                self.assertEqual(len(coverage_problems([path], "present_design top\ninsert_dft_logic\n")), 1)

    def test_coverage_allows_reported_nonscannable_bits(self):
        values = {"Total FF Bit Count": "799125", "Scannable FF Bit Count": "799031",
                  "Nonscannable FF Bit Count": "94", "Scan Chain Cell Bit Count": "799031",
                  "Wrapper Chain Cell Bit Count": "-", "Shared Wrapper Cell Bit Count": "-",
                  "Dedicated Wrapper Cell Bit Count": "-"}
        self.assertEqual(coverage_problems([self.insertion_report(values)], "present_design top\ninsert_dft_logic -stitch\n"), [])

    def test_coverage_missing_entire_summary_remains_unverified(self):
        path = self.report([["I 1", "10", "si", "so", "se", "clk", "P"]])
        self.assertEqual(coverage_problems([path], "present_design top\ninsert_dft_logic\n"), [])
        self.assertEqual(coverage_problems([], "present_design top\ninsert_dft_logic\n"), [])

    def test_coverage_missing_actual_field_is_not_assumed_zero(self):
        path = self.insertion_report()
        path.write_text("".join(line for line in path.read_text().splitlines(keepends=True) if "Nonscannable FF Bit Count" not in line))
        problems = coverage_problems([path], "present_design top\ninsert_dft_logic\n")
        self.assertIn("missing fields: Nonscannable FF Bit Count", problems[0])

    def test_coverage_missing_design_cannot_be_inferred_from_dofile(self):
        path = self.insertion_report()
        path.write_text(path.read_text().replace("Design: top\n", ""))
        problems = coverage_problems([path], "present_design top\ninsert_dft_logic\n")
        self.assertIn("missing Design header", problems[0])

    def test_coverage_conflicting_or_invalid_quantity_cannot_prove_coverage(self):
        for value in ("8919", "unknown"):
            with self.subTest(value=value):
                path = self.insertion_report()
                with path.open("a") as stream:
                    stream.write(f"90     Total FF Bit Count                        {value}\n")
                problems = coverage_problems([path], "present_design top\ninsert_dft_logic\n")
                self.assertIn("Incomplete actual insertion coverage summary", problems[0])
                self.assertIn("Total FF Bit Count", problems[0])

    def test_coverage_duplicate_copy_is_not_added_and_conflict_is_reported(self):
        path = self.insertion_report()
        copy = self.root / "insertion_copy.rpt"
        copy.write_bytes(path.read_bytes())
        script = "present_design top\ninsert_dft_logic\n"
        self.assertEqual(coverage_problems([path, copy], script), [])
        copy.write_text(copy.read_text().replace("8920", "8921").replace("8680", "8681"))
        self.assertIn("Conflicting actual insertion coverage summaries", coverage_problems([path, copy], script)[0])

    def test_coverage_design_blocks_are_not_summed_or_cross_matched(self):
        path = self.insertion_report()
        second = self.insertion_report(design="second", name="second.rpt")
        second.write_text(second.read_text().replace("8680", "8679"))
        with path.open("a") as stream:
            stream.write(second.read_text())
        self.assertEqual(coverage_problems([path], "present_design top\ninsert_dft_logic\n"), [])
        problems = coverage_problems([path], "present_design top\ninsert_dft_logic\npresent_design second\ninsert_dft_logic\n")
        self.assertEqual(len(problems), 1)
        self.assertIn("Design second", problems[0])

    def test_coverage_skips_actual_ctl_and_all_partial_insertions(self):
        path = self.insertion_report()
        path.write_text(path.read_text().replace("8680", "8679"))
        scripts = ["present_design top\nload_ctl -module aes aes.ctl\ninsert_dft_logic\n",
                   "present_design top\ninsert_dft_logic\nload_ctl -module aes aes.ctl\n"]
        scripts.extend(f"present_design top\ninsert_dft_logic {option}\n" for option in
                       ("-replace_only", "-connect_clock_gating_only", "-replace_unscan", "-replace_unscan_only"))
        for script in scripts:
            with self.subTest(script=script):
                self.assertEqual(coverage_problems([path], script), [])

    def test_coverage_comment_or_string_ctl_text_does_not_skip_actual_full_insert(self):
        path = self.insertion_report()
        path.write_text(path.read_text().replace("8680", "8679"))
        script = '# load_ctl aes.ctl\nputs "load_ctl is a command"\npresent_design {top}\ninsert_dft_logic \\\n+    -stitch\n'
        self.assertEqual(len(coverage_problems([path], script)), 1)

    def test_coverage_conditional_dynamic_or_unscoped_insert_is_unverified(self):
        path = self.insertion_report()
        path.write_text(path.read_text().replace("8680", "8679"))
        for script in ("present_design top\nif {0} { insert_dft_logic }\n",
                       "insert_dft_logic\n", "present_design $top\ninsert_dft_logic\n",
                       "present_design top; insert_dft_logic\n",
                       "present_design top\nputs ok; load_ctl aes.ctl\ninsert_dft_logic\n"):
            with self.subTest(script=script):
                self.assertEqual(coverage_problems([path], script), [])

    def test_streamed_chain_validation_reads_rows_beyond_prefix_limit(self):
        rows = [[f"I {i}", "99", f"scan_si_{i}", f"scan_so_{i}", "se", "clk", "P"] for i in range(1, 601)]
        rows[-1][1] = "301"
        actual = chain_rows([self.report(rows)])
        self.assertEqual(len(actual), 600)
        self.assertEqual(actual[-1]["Length"], "301")

    def test_header_transitions_preserve_every_row_and_original_line_number(self):
        path = self.report([["I 1", "10", "Input_suffix", "Output_suffix", "se", "clk", "Partition_suffix"]])
        second = table(["Partition", "Output", "Chain", "Input", "Length"],
                       [["Q", "so_2", "I 2", "si_2", "20"]]).replace("Design: top", "Design: second")
        with path.open("a") as stream:
            stream.write(second)
            stream.write("".join(f"{value:<28}" for value in ["Q", "Output", "I 3", "Input", "30"]) + "\n")
        rows = list(report_rows(path, {"Chain", "Length", "Input", "Output", "Partition"}))
        self.assertEqual([row["line"] for row in rows], [4, 8, 9])
        self.assertEqual([row["Chain"] for row in rows], ["I 1", "I 2", "I 3"])
        self.assertEqual(rows[0]["Partition"], "Partition_suffix")
        self.assertEqual(rows[1]["Partition"], "Q")
        self.assertEqual(rows[2]["Input"], "Input")
        self.assertEqual({row["source"] for row in rows}, {str(path)})

    def test_duplicate_header_keeps_last_column_and_incomplete_header_keeps_layout(self):
        path = self.root / "duplicate.rpt"
        path.write_text(table(["Chain", "Length", "Input", "Output", "Partition", "Length"],
                              [["I 1", "10", "si", "so", "P", "20"],
                               ["Chain", "Length", "Input", "Output", "missing", "30"],
                               ["I 2", "40", "si_2", "so_2", "Q", "50"]]))
        rows = list(report_rows(path, {"Chain", "Length", "Input", "Output", "Partition"}))
        self.assertEqual([row["Length"] for row in rows], ["20", "30", "50"])
        self.assertEqual([row["line"] for row in rows], [4, 5, 6])
        self.assertEqual(rows[1]["Partition"], "missing")
        self.assertEqual(list(report_rows(path, set())), [])

    def test_duplicate_report_does_not_double_count_channels(self):
        path = self.report([["I 1", "10", "si_1", "so_1", "se", "clk", "P"]])
        duplicate = self.root / "scan_chain_copy.rpt"
        duplicate.write_bytes(path.read_bytes())
        self.assertEqual(len(chain_rows([path, duplicate])), 1)

    def test_wrapper_chain_names_are_included_in_actual_lengths(self):
        rows = chain_rows([self.report([["W wrp_1", "301", "wrp_si1", "wrp_so1", "wrp_se", "clk", "P"],
                                       ["I 1", "99", "scan_si_1", "scan_so_1", "se", "clk", "P"]])])
        self.assertEqual(len(rows), 2)
        self.assertEqual(chain_problems(rows, "扫描端口命名为 `scan_si_%d` / `scan_so_%d`"), [])

    def test_actual_ports_must_match_requested_format(self):
        rows = chain_rows([self.report([["I 1", "10", "test_si1", "scan_so_1", "se", "clk", "P"]])])
        spec = "扫描输入/输出端口命名格式：`scan_si_%d` / `scan_so_%d`"
        self.assertIn("does not match", chain_problems(rows, spec)[0])
        rows[0]["Input"] = "scan_si_1"
        self.assertEqual(chain_problems(rows, spec), [])

    def test_independent_pseudo_clocks_need_actual_signal_rows(self):
        report = self.root / "scan_signal.rpt"
        report.write_text(table(["Port", "PortProperty", "SignalType", "OffState"],
                                [["gate/clk_out", "pseudo", "constant", "0"]]))
        self.assertTrue(pseudo_clock_problems([report], ["gate/clk_out"]))
        report.write_text(table(["Port", "PortProperty", "SignalType", "OffState"],
                                [["gate/clk_out", "pseudo", "clock", "0"]]))
        self.assertEqual(pseudo_clock_problems([report], ["gate/clk_out"]), [])

    def test_unallowed_clock_domain_mixing_is_rejected(self):
        rows = chain_rows([self.report([["I 1", "10", "si1", "so1", "se", "clk_a, clk_b", "P"]])])
        self.assertTrue(chain_problems(rows, "不得跨时钟域"))
        self.assertEqual(chain_problems(rows, "允许混合时钟域"), [])

    def test_partitions_have_individual_length_enable_and_clock_limits(self):
        spec = "| 分区 | chain_count | max_length | scan_enable | 划分（-clocks） |\n|---|---|---|---|---|\n| P | 1 | 10 | se | clk |\n| Q | 1 | 300 | se_q | clk_q |\n"
        rows = chain_rows([self.report([["I 1", "11", "si1", "so1", "wrong", "wrong_clk", "P"],
                                       ["I 2", "299", "si2", "so2", "se_q", "clk_q", "Q"]])])
        problems = chain_problems(rows, spec)
        self.assertEqual(len(problems), 3)
        self.assertTrue(any("own max_length 10" in item for item in problems))
        rows[0].update(Length="10", ScanEnable="se", Clocks="clk")
        self.assertEqual(chain_problems(rows, spec), [])

    def test_every_derived_shift_register_needs_real_endpoint_evidence(self):
        groups = [{"root": "top", "start_template": "u/r[{i0}]", "end_template": "u/t[{i0}]", "index_tuples": [[0], [1]],
                   "length": 10, "scan_data_in_pin": "SI", "scan_data_out_pin": "Q"}]
        path = self.root / "scan_segment.rpt"
        path.write_text(table(["Name", "Length", "SiPin", "SoPin"], [["seg0", "10", "/top/u/r[0]/SI", "/top/u/t[0]/Q"]]))
        self.assertIn("1 input-derived", segment_problems([path], groups)[0])
        path.write_text(table(["Name", "Length", "SiPin", "SoPin"], [["seg0", "10", "u/r[0]/SI", "u/t[0]/Q"],
                                                                    ["seg1", "10", "u/r[1]/SI", "u/t[1]/Q"]]))
        self.assertEqual(segment_problems([path], groups), [])

    def test_ctl_overlength_needs_permission_warning_and_same_indivisible_atom(self):
        rows = chain_rows([self.report([["W wrp_1", "128", "wsi1", "wso1", "wse", "clk", "P"],
                                       ["W wrp_2", "140", "wsi2", "wso2", "wse", "clk", "P"]])])
        segment = self.root / "scan_segment.rpt"
        segment.write_text(table(["Name", "SegmentProperty", "Length", "ChainName"],
                                 [["ip/wrp", "inferred_from_ctl", "128", "wrp_1"], ["ip/wrp2", "inferred_from_ctl", "128", "wrp_2"]]))
        log = self.root / "R1.log"
        log.write_text("[WARNING] [SCAN-4902] max_length cannot be satisfied (Partition: P(Wrapper)).\n")
        permission = "CTL 段不可拆分，wrapper 长度可超过上限，SCAN-4902 警告可忽略"
        self.assertEqual(ctl_overlength_exceptions(rows, [segment], permission, log, 100), {"W wrp_1"})
        self.assertEqual(ctl_overlength_exceptions(rows, [segment], "wrapper 上限 100", log, 100), set())
        self.assertEqual(ctl_overlength_exceptions(rows, [], permission, log, 100), set())
        log.write_text("no actual warning\n")
        self.assertEqual(ctl_overlength_exceptions(rows, [segment], permission, log, 100), set())


if __name__ == "__main__":
    unittest.main()
