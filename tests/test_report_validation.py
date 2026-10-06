"""Regression fixtures for typed, streamed real-report validation."""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "agent"))
from report_validation import chain_problems, chain_rows, ctl_overlength_exceptions, segment_problems  # noqa: E402


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

    def test_streamed_chain_validation_reads_rows_beyond_prefix_limit(self):
        rows = [[f"I {i}", "99", f"scan_si_{i}", f"scan_so_{i}", "se", "clk", "P"] for i in range(1, 601)]
        rows[-1][1] = "301"
        actual = chain_rows([self.report(rows)])
        self.assertEqual(len(actual), 600)
        self.assertEqual(actual[-1]["Length"], "301")

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
