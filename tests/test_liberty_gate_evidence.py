"""Literal Liberty gate evidence; no EDA or model calls."""
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "agent"))
from scan_agent import liberty_summary, mapping_cell_problems


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

    def test_cell_inventory_is_complete_and_literal_mapping_is_checked(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "actual.lib"
            path.write_text('cell (dff) {\n}\ncell (sff) {\n}\ncell (other) {\n}\n')
            names = set()
            liberty_summary(path, cell_names=names)
            self.assertEqual(names, {"dff", "sff", "other"})
            self.assertEqual(mapping_cell_problems('set_scan_cell_mapping {dff} "sff"\n', names), [])
            problems = mapping_cell_problems('set_scan_cell_mapping dff missing\n', names)
            self.assertEqual(len(problems), 1)
            self.assertIn("missing", problems[0])

    def test_dynamic_mapping_and_comments_are_not_interpreted(self):
        self.assertEqual(mapping_cell_problems(
            '# set_scan_cell_mapping absent absent\nset_scan_cell_mapping $from $to\n', {"dff"}), [])
        self.assertEqual(mapping_cell_problems('set_scan_cell_mapping absent absent\n', set()), [])

    def test_gate_evidence_does_not_shrink_pin_summary_budget(self):
        cells = ''.join(f'cell (sdf_cell_{n:03d}) {{\n' +
                        ''.join(f' pin (pin_{p:02d}) {{ }}\n' for p in range(24)) + '}\n'
                        for n in range(100))
        without = self.summary(cells)
        with_gate = self.summary(cells + '''cell (clk_gate) {
 pin (TEST) {
  clock_gate_test_pin : true;
 }
}
''')
        # Cell count changes, but the original capped pin text stays complete.
        self.assertEqual(without.split("Actual sequential", 1)[1],
                         with_gate.split("Actual sequential", 1)[1].split("\nActual Liberty", 1)[0])


if __name__ == "__main__":
    unittest.main()
