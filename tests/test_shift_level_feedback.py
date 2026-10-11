"""Feedback computes literal shift levels without choosing a library polarity."""
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'agent'))
import scan_agent as agent


class ShiftLevelFeedbackTests(unittest.TestCase):
    def context(self, original, codes):
        script = 'present_design chip\nexit\n'
        with tempfile.TemporaryDirectory() as name:
            root = Path(name); run = root / 'R2'; run.mkdir()
            (root / 'task_spec.md').write_text('Repair clock gating without changing the input netlist.')
            with patch.object(agent, 'ask', return_value=json.dumps({'dofile': script})) as ask:
                candidate, _ = agent.call_for_dofile(object(), 'task2', 'Actual evidence', None, root, run,
                    base_dofile=script, previous_actual_dofile=original, previous_unallowed_codes=codes)
            self.assertEqual(candidate, script)
            return ask.call_args.args[2]

    def test_complements_both_literal_levels_without_rewriting_script(self):
        original = ('set_scan_signal -type scan_enable -port enable_a -usage all -off_state 1\n'
                    'set_scan_signal -type scan_enable -port enable_b -usage all -off_state 0\n')
        text = self.context(original, {'DFTR9'})
        self.assertIn('"port": "enable_a", "capture_off_state": 1, "shift_level": 0', text)
        self.assertIn('"port": "enable_b", "capture_off_state": 0, "shift_level": 1', text)
        self.assertIn('Neither high nor low polarity is assumed', text)

    def test_dynamic_values_and_other_usage_are_not_inferred(self):
        original = ('set_scan_signal -type scan_enable -port enable_a -usage all -off_state $off\n'
                    'set_scan_signal -type scan_enable -port $port -usage all -off_state 1\n'
                    'set_scan_signal -type scan_enable -port enable_b -usage scan -off_state 0\n')
        self.assertNotIn('shift = 1 - off_state', self.context(original, {'DFTR9'}))

    def test_feedback_requires_actual_blocking_clock_drc(self):
        original = 'set_scan_signal -type scan_enable -port enable_a -usage all -off_state 1\n'
        self.assertNotIn('shift = 1 - off_state', self.context(original, {'DFTR10'}))


if __name__ == '__main__':
    unittest.main()
