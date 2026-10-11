"""Regression: model omits expanded segments; the existing compiler retains all."""
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'agent'))
import scan_agent as agent


class SegmentPromptRegression(unittest.TestCase):
    def test_compact_response_retains_all_input_coordinates_and_evidence(self):
        groups = [{'root': 'design', 'start_template': 'u/head[{i0}]', 'end_template': 'u/tail[{i0}]',
                   'index_tuples': [[0], [1], [2]], 'length': 10,
                   'scan_data_in_pin': 'SCD', 'scan_enable_pin': 'SCE', 'scan_data_out_pin': 'Q'}]
        script = 'present_design design\nexamine_scan_drc\ninsert_dft_logic\nexit\n'
        reply = {'dofile': script, 'requirement_mapping': [
            {'requirement': 'Use supplied design', 'dft_config': 'present_design design'}]}
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); run = root / 'R1'; run.mkdir()
            (root / 'task_spec.md').write_text('Configure all long shift registers as scan segments.')
            with patch.object(agent, 'ask', return_value=json.dumps(reply)) as ask:
                actual, metadata = agent.call_for_dofile(object(), 'task1', 'Fixture', None,
                                                        root, run, segments=groups)
            prompt = ask.call_args.args[1]
            self.assertIn('Omit your own segment', prompt)
            self.assertIn('do not expand the supplied index tuples', prompt)
            self.assertIn('For a gated scan partition, configure its scan_enable with usage all', prompt)
            self.assertNotIn('its scan_enable usually needs usage all', prompt)
            self.assertIn('Include exception predicates in the same query', prompt)
            self.assertIn('pass its returned collection directly to set_scan_element', prompt)
            self.assertIn('{{0} {1} {2}}', actual)
            self.assertIn('-respect_sff_se_connection true', actual)
            self.assertIn('set_scan_segment agent_shift', actual)
            self.assertLess(actual.index('set_scan_segment agent_shift'), actual.index('examine_scan_drc'))
            self.assertEqual(len(metadata['requirement_mapping']), 2)
            evidence = json.loads((run / 'llm_shift_register_recipe.json').read_text())
            self.assertEqual(evidence['input_groups'], groups)


if __name__ == '__main__':
    unittest.main()
