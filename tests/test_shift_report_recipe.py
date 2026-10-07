from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "agent"))
from scan_agent import literal_tcl_words
from shift_report_recipe import configure, natural_shift_report_problems, requested_shift_reports


class ShiftReportRecipe(unittest.TestCase):
    def setUp(self):
        self.spec = "| `shift_register.rpt` | 移位寄存器报告 |"
        self.script = ("load_netlist /input/chip.v -top chip\n"
                       "examine_scan_drc\nexamine_scan_chain\ninsert_dft_logic\n"
                       "rpt_scan_segment -file reports/shift_register.rpt\n"
                       "rpt_scan_segment -file reports/explicit_segments.rpt\nexit\n")

    def test_native_api_replaces_wrong_report_role_and_preserves_segment_report(self):
        result, references = configure(self.script, self.spec, literal_tcl_words)
        self.assertIn("rpt_shift_register -file {reports/shift_register.rpt}", result)
        self.assertIn("rpt_scan_segment -file reports/explicit_segments.rpt", result)
        self.assertNotIn("rpt_scan_segment -file reports/shift_register.rpt", result)
        self.assertGreater(result.index("rpt_shift_register"), result.index("insert_dft_logic"))
        self.assertLess(result.index("rpt_shift_register"), result.index("exit"))
        self.assertEqual(len(references), 1)
        self.assertEqual(configure(result, self.spec, literal_tcl_words), (result, references))

    def test_output_role_uses_task_filename_and_existing_literal_absolute_path(self):
        spec = "Output `natural_shifts.txt`: tool identified shift register report"
        self.assertEqual(requested_shift_reports(spec), {"natural_shifts.txt"})
        base = self.script.replace("reports/shift_register.rpt", '"/output/current reports/natural_shifts.txt"')
        result, _ = configure(base, spec, literal_tcl_words)
        self.assertIn("rpt_shift_register -file {/output/current reports/natural_shifts.txt}", result)
        absent = self.script.replace("rpt_scan_segment -file reports/shift_register.rpt\n", "")
        result, _ = configure(absent, spec, literal_tcl_words)
        self.assertIn("rpt_shift_register -file {reports/natural_shifts.txt}", result)
        self.assertEqual(configure(self.script, "Scan Segment output `segments.rpt`", literal_tcl_words), (self.script, []))

    def test_report_before_analysis_is_moved_after_insertion(self):
        base = self.script.replace("rpt_scan_segment -file reports/shift_register.rpt\n", "")
        base = base.replace("examine_scan_drc", "rpt_shift_register -file reports/shift_register.rpt\nexamine_scan_drc")
        result, _ = configure(base, self.spec, literal_tcl_words)
        self.assertGreater(result.index("rpt_shift_register"), result.index("insert_dft_logic"))

    def test_unknown_dynamic_or_design_switching_tcl_is_preserved(self):
        additions = ("source other.tcl", "present_design other_chip", "unknown_command", "proc custom {} {}",
                     "if {1} { rpt_scan_segment -file reports/shift_register.rpt }")
        for addition in additions:
            with self.subTest(addition=addition):
                script = self.script.replace("exit", addition + "\nexit")
                self.assertEqual(configure(script, self.spec, literal_tcl_words), (script, []))
        dynamic = self.script.replace("reports/shift_register.rpt", "$reports/shift_register.rpt")
        self.assertEqual(configure(dynamic, self.spec, literal_tcl_words), (dynamic, []))
        diagnostic = self.script.replace("examine_scan_chain\n", "")
        self.assertEqual(configure(diagnostic, self.spec, literal_tcl_words), (diagnostic, []))

    @staticmethod
    def table(members, design="chip", chain=False):
        headers = (["ChainName", "CellNo", "InstanceName", "ShiftRegID/CellNo"] if chain else
                   ["InstanceName", "ShiftRegID/CellNo"])
        result = "Design: " + design + "\n" + "".join(f"{name:<30}" for name in headers) + "\n"
        for number, (instance, identity) in enumerate(members):
            values = (["I 1", str(number), instance, identity] if chain else [instance, identity])
            result += "".join(f"{value:<30}" for value in values) + "\n"
        return result

    def test_empty_segment_table_cannot_prove_identified_natural_shift_registers(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report = root / "shift_register.rpt"
            chain = root / "chain_cells.rpt"
            log = root / "R2.log"
            members = [("core/first_sff", "7/0"), ("core/retained_dff", "7/1")]
            chain.write_text(self.table(members, chain=True))
            log.write_text("Examine Chain Report\nDesign : chip\nShiftReg7 (s)\n")
            report.write_text("Design: chip\nName SegmentProperty Length SiPin SoPin\n")
            paths = [report, chain, log]
            self.assertTrue(natural_shift_report_problems(paths, self.spec))
            report.write_text(self.table(members[:1]))
            self.assertTrue(natural_shift_report_problems(paths, self.spec))
            report.write_text(self.table(members, design="other_chip"))
            self.assertTrue(natural_shift_report_problems(paths, self.spec))
            report.write_text(self.table(members))
            self.assertEqual(natural_shift_report_problems(paths, self.spec), [])

    def test_actual_log_group_alone_requires_nonempty_typed_report(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report = root / "shift_register.rpt"
            log = root / "R2.log"
            log.write_text("Examine Chain Report\nDesign : chip\nShiftReg7 (s)\n")
            self.assertTrue(natural_shift_report_problems([report, log], self.spec))
            report.write_text(self.table([]))
            self.assertTrue(natural_shift_report_problems([report, log], self.spec))
            report.write_text(self.table([("core/first_sff", "7/0")]))
            self.assertEqual(natural_shift_report_problems([report, log], self.spec), [])
            log.write_text("Examine Chain Report\nDesign : chip\nShiftReg3 (s)\n"
                           "Examine Chain Report\nDesign : chip\nShiftReg7 (s)\n")
            self.assertEqual(natural_shift_report_problems([report, log], self.spec), [])
            log.write_text("No ShiftReg groups identified\n")
            report.write_text(self.table([]))
            self.assertEqual(natural_shift_report_problems([report, log], self.spec), [])


if __name__ == "__main__":
    unittest.main()
