from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "agent"))
from wrapper_validation import wrapper_problems, wrapper_style_evidence, wrapper_targets


def table(rows):
    names = ["No.", "PortName(I/O)", "WrapperStyle", "DWCType"]
    widths = [8, 22, 20, 22]
    return "\n".join("".join(value.ljust(width) for value, width in zip(row, widths))
                     for row in [names, *rows]) + "\n"


class WrapperValidation(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.report = self.root / "wrapper_implementation.rpt"
        self.spec = "wrapper requirements\n- 端口 `payload` 仅传输功能数据，不参与扫描路径\n- 端口 `test_in` 必须使用输入中提供的 dedicated wrapper cell"

    def tearDown(self):
        self.temp.cleanup()

    def test_explicit_task_targets_are_generic(self):
        self.assertEqual(wrapper_targets(self.spec), {"payload": ("none", None), "test_in": ("dedicated", "user_defined")})
        self.assertEqual(wrapper_targets("端口 `clk` 是时钟"), {})

    def test_every_reported_bit_and_user_defined_type_is_checked(self):
        rows = [["0", "payload[0] (I)", "none", "--"], ["1", "payload[1] (I)", "none", "--"],
                ["2", "test_in[0] (I)", "dedicated", "user_defined"]]
        self.report.write_text(table(rows))
        self.assertEqual(wrapper_problems([self.report], self.spec), [])
        proof = wrapper_style_evidence([self.report], self.root, "payload", "none")
        self.assertEqual(proof["locator"], "L2-L3")
        rows[1][2] = "shared"
        self.report.write_text(table(rows))
        self.assertTrue(wrapper_problems([self.report], self.spec))
        self.assertIsNone(wrapper_style_evidence([self.report], self.root, "payload", "none"))
        rows[1][2] = "none"
        rows[2][3] = "WC_D1"
        self.report.write_text(table(rows))
        self.assertIn("DWCType", wrapper_problems([self.report], self.spec)[0])

    def test_global_default_does_not_prove_a_port_override(self):
        (self.root / "wrapper_cfg.rpt").write_text("WrapperConfigurationParameter Value\nstyle shared\n")
        self.assertTrue(wrapper_problems([self.root / "wrapper_cfg.rpt"], self.spec))


if __name__ == "__main__":
    unittest.main()
