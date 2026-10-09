"""Small mapping regressions; model replies are fixtures, no EDA/API calls."""
import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'agent'))
import scan_agent as agent


class RequirementMappingTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        (self.root / 'task_spec.md').write_text('Configure the supplied arbitrary design.')
        self.run = self.root / 'runs/R2'
        self.run.mkdir(parents=True)
        self.script = 'present_design arbitrary\nset_scan_cfg -max_length 23\nexit\n'
        self.mapping = [{'requirement': 'Replace flip-flops', 'dft_config': 'set_scan_cfg -replace true'}]

    def generate(self, replies, **options):
        with patch.object(agent, 'ask', side_effect=[json.dumps(reply) for reply in replies]) as ask:
            candidate, metadata = agent.call_for_dofile(object(), 'task2', 'Local fixture', 'exit\n',
                                                       self.root, self.run, **options)
        return candidate, metadata, ask

    def test_task2_mapping_is_optional_but_task1_requires_it(self):
        self.assertEqual(agent.requirement_mapping_problems('task2', [], self.script), [])
        self.assertTrue(agent.requirement_mapping_problems('task1', [], self.script))

    def test_implicit_default_has_no_literal_locator_and_is_rejected(self):
        self.assertEqual(agent.config_reference(self.script, self.mapping[0]['dft_config']), '')
        problems = agent.requirement_mapping_problems('task2', self.mapping, self.script)
        self.assertIn('has no actual Tcl match', problems[0])
        self.assertIn('implicit tool default', problems[0])

    def test_explicit_combined_options_have_actual_locator(self):
        script = 'present_design renamed\nset_scan_cfg -max_length 23 -replace true\nexit\n'
        self.assertEqual(agent.requirement_mapping_problems('task2', self.mapping, script), [])
        self.assertEqual(agent.config_reference(script, self.mapping[0]['dft_config']), 'L2')

    def test_continued_command_has_actual_line_range(self):
        script = 'present_design renamed\nset_scan_cfg -max_length 23 ' + chr(92) + '\n -replace true\nexit\n'
        self.assertEqual(agent.requirement_mapping_problems('task2', self.mapping, script), [])
        self.assertEqual(agent.config_reference(script, self.mapping[0]['dft_config']), 'L2-L3')

    def test_comments_and_wrong_values_do_not_prove_the_mapping(self):
        for script in ['# set_scan_cfg -replace true\nexit\n', 'set_scan_cfg -replace false\nexit\n']:
            with self.subTest(script=script):
                self.assertTrue(agent.requirement_mapping_problems('task2', self.mapping, script))

    def test_bad_mapping_shape_is_rejected_without_string_coercion(self):
        for mappings in [None, {}, 'text', [None], [{'requirement': 'r', 'dft_config': 3}],
                         [{'requirement': '', 'dft_config': 'exit'}]]:
            with self.subTest(mappings=mappings):
                self.assertTrue(agent.requirement_mapping_problems('task2', mappings, self.script))

    def test_generation_corrects_missing_command_before_tool_call(self):
        valid = self.script.replace('-max_length 23', '-max_length 23 -replace true')
        before = copy.deepcopy(self.mapping)
        candidate, metadata, ask = self.generate([
            {'dofile': self.script, 'requirement_mapping': self.mapping},
            {'dofile': valid, 'requirement_mapping': self.mapping}])
        self.assertEqual(ask.call_count, 2)
        self.assertEqual(self.mapping, before)
        self.assertEqual(agent.config_reference(candidate, metadata['requirement_mapping'][0]['dft_config']), 'L2')
        self.assertIn('has no actual Tcl match', json.loads((self.run / 'llm_validation.json').read_text())['problems'][0])
        self.assertFalse((self.run / 'R2.log').exists())

    def test_task2_explicit_empty_mapping_clears_inherited_optional_mapping(self):
        candidate, metadata, ask = self.generate([{'dofile': self.script, 'requirement_mapping': []}],
                                               previous_mapping=self.mapping)
        self.assertEqual(metadata['requirement_mapping'], [])
        self.assertEqual(ask.call_count, 1)
        self.assertEqual(candidate, self.script)

    def test_unchanged_valid_mapping_can_be_inherited(self):
        valid = [{'requirement': 'Bound length', 'dft_config': 'set_scan_cfg -max_length 23'}]
        _, metadata, ask = self.generate([{'dofile_edits': []}], base_dofile=self.script, previous_mapping=valid)
        self.assertEqual(ask.call_count, 1)
        self.assertEqual(metadata['requirement_mapping'], valid)

    def test_changed_configuration_cannot_inherit_stale_mapping(self):
        valid = [{'requirement': 'Bound length', 'dft_config': 'set_scan_cfg -max_length 23'}]
        edit = {'dofile_edits': [{'old': '-max_length 23', 'new': '-max_length 29'}]}
        candidate, metadata, ask = self.generate([edit, edit | {'requirement_mapping': []}],
                                               base_dofile=self.script, previous_mapping=valid)
        self.assertEqual(ask.call_count, 2)
        self.assertIn('-max_length 29', candidate)
        self.assertEqual(metadata['requirement_mapping'], [])

    def run_publication_fixture(self, proposals):
        """Exercise metadata publication with explicitly mocked model/tool checks."""
        input_dir = self.root / 'input'
        (input_dir / 'netlist').mkdir(parents=True)
        (input_dir / 'lib').mkdir()
        (input_dir / 'netlist/top.v').write_text('module arbitrary(); endmodule\n')
        (input_dir / 'lib/cells.lib').write_text('library(arbitrary){}\n')
        (input_dir / 'task_spec.md').write_text('A local metadata fixture.')
        (input_dir / 'limitations.md').write_text('时间限制：60秒')
        (input_dir / 'original.dofile').write_text('exit\n')
        output = self.root / 'actual-fixture-output'
        class Client:
            def with_options(self, **_options):
                return self
        def fake_tool(script, run, rid, *_args, **_kwargs):
            (run / 'deliverables').mkdir(exist_ok=True)
            (run / 'reports').mkdir(exist_ok=True)
            (run / 'deliverables' / (rid+'.dofile')).write_text(script)
            (run / 'deliverables/post_scan.v').write_text('module fixture(); endmodule\n')
            log = run / (rid+'.log')
            log.write_text('Unit fixture, no native tool was run.\n')
            return {'run_id':rid,'status':'completed','returncode':0,'error':None,
                    'log_path':log,'elapsed_seconds':0,'artifacts':[]}
        counter = [0]
        def fake_check(*_args, **_kwargs):
            counter[0] += 1
            return (counter[0] >= len(proposals)+1, ['Fixture requests next round'] if counter[0] <= len(proposals) else [])
        with patch.dict(agent.os.environ, {'LLM_API_KEY':'unit-fixture-key',
                'SCANINSERTION_LICENSE_SERVER':'unit-fixture-license',
                'AGENT_MAX_TOOL_CALLS':str(len(proposals)+1)}), \
                patch.object(agent, 'OpenAI', return_value=Client()), \
                patch.object(agent, 'context_for_run', return_value='Unit context'), \
                patch.object(agent, 'call_for_dofile', side_effect=proposals), \
                patch.object(agent, 'tool_run', side_effect=fake_tool), \
                patch.object(agent, 'check_output', side_effect=fake_check), \
                patch.object(agent, 'issue_audit_problems', return_value=[]), \
                patch.object(sys, 'argv', ['agent','-input',str(input_dir),'-output',str(output)]):
            status = agent.main()
        return status, json.loads((output / 'decision_log.json').read_text())

    def test_final_publication_clears_optional_mapping_on_explicit_empty_array(self):
        mapping = [{'requirement':'Length','dft_config':'set_scan_cfg -max_length 23'}]
        status, decision = self.run_publication_fixture([
            (self.script, {'requirement_mapping':mapping}),
            (self.script.replace('23','29'), {'requirement_mapping':[]})])
        self.assertEqual(status, 0)
        self.assertEqual(decision['final_run'], 'R3')
        self.assertEqual(decision['requirement_mapping'], [])

    def test_final_boundary_cannot_publish_success_for_unbound_mapping(self):
        status, decision = self.run_publication_fixture([(self.script, {'requirement_mapping':self.mapping})])
        self.assertEqual(status, 2)
        self.assertFalse(decision['tool_checks_passed'])
        self.assertIn('has no actual Tcl match', decision['summary'])
        self.assertEqual(decision['tool_runs'][-1]['exit_status'], 'completed')
        self.assertEqual(decision['tool_runs'][-1]['returncode'], 0)


if __name__ == '__main__':
    unittest.main()
