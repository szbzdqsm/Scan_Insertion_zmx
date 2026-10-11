"""Regression: a partial repair mapping must not erase unchanged admitted mappings."""
import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'agent'))
import scan_agent as agent


class Task1MappingUpdateTests(unittest.TestCase):
    script = 'present_design chip\nset_scan_cfg -max_length 100\nexit\n'
    prior = [{'requirement': 'Select design', 'dft_config': 'present_design chip'},
             {'requirement': 'Bound length', 'dft_config': 'set_scan_cfg -max_length 100'}]

    def test_partial_update_retains_unchanged_mapping_without_mutation(self):
        before = copy.deepcopy(self.prior)
        update = [{'requirement': 'Bound length', 'dft_config': 'set_scan_cfg -max_length 100'}]
        merged = agent.retain_unchanged_task1_mappings(self.prior, update, self.script)
        self.assertEqual(merged, self.prior)
        self.assertEqual(self.prior, before)

    def test_changed_or_missing_literal_is_not_retained(self):
        script = self.script.replace('-max_length 100', '-max_length 200')
        update = [{'requirement': 'Select design', 'dft_config': 'present_design chip'}]
        merged = agent.retain_unchanged_task1_mappings(self.prior, update, script)
        self.assertEqual(merged, update)

    def test_supplied_invalid_update_is_not_hidden_by_old_valid_mapping(self):
        update = [{'requirement': 'Bound length', 'dft_config': 'set_scan_cfg -max_length 200'}]
        merged = agent.retain_unchanged_task1_mappings(self.prior, update, self.script)
        self.assertTrue(agent.requirement_mapping_problems('task1', merged, self.script))

    def test_empty_task1_mapping_still_fails_existing_requirement(self):
        merged = agent.retain_unchanged_task1_mappings(self.prior, [], self.script)
        self.assertEqual(merged, [])
        self.assertTrue(agent.requirement_mapping_problems('task1', merged, self.script))

    def test_real_generation_merges_and_writes_provenance(self):
        update = [{'requirement': 'Bound length', 'dft_config': 'set_scan_cfg -max_length 100'}]
        with tempfile.TemporaryDirectory() as name:
            root = Path(name); run = root / 'R2'; run.mkdir()
            (root / 'task_spec.md').write_text('Configure scan insertion.')
            with patch.object(agent, 'ask', return_value=json.dumps({'dofile': self.script, 'requirement_mapping': update})):
                _, result = agent.call_for_dofile(object(), 'task1', 'Fixture', None, root, run,
                                                 base_dofile=self.script, previous_mapping=self.prior)
            self.assertEqual(result['requirement_mapping'], self.prior)
            self.assertEqual(len(json.loads((run / 'llm_mapping_inheritance.json').read_text())['retained']), 1)


if __name__ == '__main__':
    unittest.main()
