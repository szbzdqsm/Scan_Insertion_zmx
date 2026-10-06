from pathlib import Path
import sys
import unittest
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "agent"))
from clock_association_recipe import clock_association_problems, configure_clock_associations
from scan_agent import literal_tcl_words


class ClockAssociationRecipe(unittest.TestCase):
    def setUp(self):
        self.hint = {"root": "chip", "root_primary_clock_candidate": "main_clk",
                     "clock_output_candidates": ["clock_sub/gate/O", "clock_sub/local_clk"],
                     "enable_latch_q_pin": "clock_sub/gate/en_latch/Q"}
        self.spec = "CE latch 的时钟值传播正确"
        self.script = "present_design chip\nset_scan_signal -type clock -port main_clk -off_state 0\nexamine_scan_drc\nexit\n"

    def compile(self, script=None, spec=None, hint=None):
        return configure_clock_associations(script or self.script, [hint or self.hint],
                                             self.spec if spec is None else spec, literal_tcl_words)

    def test_source_relation_is_compiled_and_idempotent(self):
        result, refs = self.compile()
        self.assertIn("-associated_internal_clocks {clock_sub/local_clk}", result)
        self.assertEqual(len(refs), 1)
        self.assertEqual(self.compile(result)[0], result)
        self.assertNotIn("en_latch/Q", result)

    def test_unrequested_or_other_root_relation_is_not_injected(self):
        self.assertEqual(self.compile(spec="Generic insertion"), (self.script, []))
        self.assertEqual(self.compile(hint=dict(self.hint, root="another_root")), (self.script, []))

    def test_ambiguous_or_dynamic_declaration_stays_with_the_model(self):
        duplicate = self.script.replace("examine_scan_drc", "set_scan_signal -type clock -port main_clk -off_state 0\nexamine_scan_drc")
        self.assertEqual(self.compile(duplicate), (duplicate, []))
        dynamic = self.script.replace("main_clk", "$clock")
        self.assertEqual(self.compile(dynamic), (dynamic, []))

    def test_existing_actual_clock_association_is_preserved(self):
        base = self.script.replace("-off_state 0", "-off_state 0 -associated_internal_clocks {another_branch/clk}")
        result, _ = self.compile(base)
        self.assertIn("another_branch/clk clock_sub/local_clk", result)

    def test_enable_data_q_is_never_promoted_to_clock(self):
        base = self.script.replace("-off_state 0", "-off_state 0 -associated_internal_clocks {clock_sub/gate/en_latch/Q}")
        with self.assertRaises(ValueError):
            self.compile(base)

    def test_actual_typed_signal_must_prove_the_clock_output(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "scan_signal.rpt"
            headers = ["Port", "SignalType", "AssociatedInternal"]
            def table(output):
                return ''.join(f'{value:<32}' for value in headers) + '\n' + ''.join(
                    f'{value:<32}' for value in ["main_clk", "clock", output]) + '\n'
            script, _ = self.compile()
            path.write_text(table("clock_sub/gate/en_latch/Q"))
            self.assertTrue(clock_association_problems([path], script, [self.hint], self.spec, literal_tcl_words))
            path.write_text(table("clock_sub/local_clk"))
            self.assertEqual(clock_association_problems([path], script, [self.hint], self.spec, literal_tcl_words), [])


if __name__ == "__main__":
    unittest.main()
