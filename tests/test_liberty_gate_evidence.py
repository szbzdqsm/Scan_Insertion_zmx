"""Literal Liberty gate evidence; no EDA or model calls."""
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "agent"))
from scan_agent import liberty_summary


class LibertyGateEvidenceTests(unittest.TestCase):
    def summary(self, source):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "actual.lib"
            path.write_text(source)
            return liberty_summary(path)

    def facts(self, summary):
        line = next(line for line in summary.splitlines() if line.startswith("Actual Liberty"))
        return json.loads(line.split(": ", 1)[1])

    def test_literal_table_and_pin_source_lines(self):
        source = '''cell (gate_x) {
 statetable ("CK EN TEST", "Q") {
  table : "L L H : - : H,L L L : - : L";
 }
 pin (TEST) {
  clock_gate_test_pin : true;
 }
}
'''
        summary = self.summary(source)
        facts = self.facts(summary)[0]
        self.assertEqual(facts["cell"], "gate_x")
        self.assertEqual([f["line"] for f in facts["literal_facts"]], [2, 3, 6])
        self.assertEqual(facts["literal_facts"][-1]["pin"], "TEST")
        for fact in facts["literal_facts"]:
            self.assertEqual(fact["text"], source.splitlines()[fact["line"] - 1])
        self.assertNotIn("-off_state", summary)

    def test_table_after_pin_and_next_cell_do_not_leak(self):
        summary = self.summary('''cell (gate) {
 pin (TE) {
  clock_gate_test_pin : true;
 }
 statetable ("CK TE", "Q") {
  table : "L H : - : H";
 }
}
cell (plain) {
 pin (TE) { }
}
''')
        facts = self.facts(summary)
        self.assertEqual(len(facts), 1)
        self.assertEqual(facts[0]["literal_facts"][-1]["pin"], "")

    def test_non_gate_state_table_is_not_promoted(self):
        summary = self.summary('''cell (sdf_x) {
 pin (D) { }
 statetable ("D", "Q") {
  table : "L : - : L";
 }
}
''')
        self.assertNotIn("Actual Liberty clock-gate", summary)
        self.assertIn('"sdf_x": ["D"]', summary)

    def test_bounded_complete_json_and_original_pin_summary(self):
        source = "".join(f'''cell (clk_gate_{n}) {{
 pin (TEST) {{
  clock_gate_test_pin : true;
 }}
 statetable ("CK TE", "Q") {{
  table : "L H : - : H";
 }}
}}
''' for n in range(30))
        summary = self.summary(source)
        self.assertLessEqual(len(summary), 8000)
        self.assertLessEqual(len(self.facts(summary)), 8)
        self.assertIn("30 cells", summary)
        self.assertIn("Actual sequential/clock cell pin names", summary)


if __name__ == "__main__":
    unittest.main()
