"""Unknown-design integration fixtures; no model, EDA or answer files."""
import copy
import json
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'agent'))
import scan_agent as agent
from artifact_operations import _run_signature
from case_deadline import CaseDeadline, CaseDeadlineExceeded
from netlist_repair import fingerprint_paths


class GeneralWorkflowIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.input = self.root / 'input'
        self.input.mkdir()
        self.source = self.input / 'arbitrary.v'
        self.source.write_text('module unfamiliar(input x,output y); assign y=x; endmodule\n')
        self.output = self.root / 'output'
        (self.output / 'audit_reviews').mkdir(parents=True)
        for rid in ('R1', 'R2'):
            run = self.output / 'runs' / rid
            (run / 'reports').mkdir(parents=True)
            (run / f'{rid}.log').write_text('actual saved fixture log\n')
        self.report = self.output / 'runs/R2/reports/drc.rpt'
        self.report.write_text('DRC Report\nTotal violations: 0\n\n')
        self.records = [{'run_id': 'R1', 'status': 'completed', 'returncode': 0},
                        {'run_id': 'R2', 'status': 'completed', 'returncode': 0}]
        self.issues = [{'issue_id': 'I1', 'found': {'run_ref': 'R1', 'verified': True, 'excerpt': 'DFTR3'},
                       'diagnosis': {'located_object': 'unfamiliar/x', 'root_cause': 'old control'},
                       'attempts': [{'fix': {'action': 'existing real F1', 'artifact_ref': ['F1']},
                                     'verify': {'run_ref': 'R2', 'resolved': False}}]}]
        self.plans = {}
        self.reviews = []

    def refresh(self, ask):
        class Client:
            def with_options(self, **_options):
                return self
        source_snapshot = fingerprint_paths([self.source])
        source_signature = agent.input_tree_signature(self.input)
        artifact_signature = _run_signature(self.output / 'runs/R2')
        with patch.object(agent, 'ask', side_effect=ask), patch.object(agent, 'verify_issue_fixes') as verify:
            result = agent.refresh_existing_audit(Client(), self.output, self.issues, self.plans,
                self.records, 'R2', source_snapshot, source_signature, self.input,
                artifact_signature, time.monotonic() + 5, self.reviews, set())
        return result, verify

    def test_readonly_refresh_reuses_actual_R2_and_preserves_found_fix_and_runs(self):
        before = copy.deepcopy((self.issues, self.records))
        result, verify = self.refresh(lambda *args, **kwargs: json.dumps(
            {'verification_updates': [{'issue_id': 'I1', 'evidence_id': 'V1'}]}))
        self.assertTrue(result)
        self.assertEqual((self.issues, self.records), before)
        self.assertEqual(verify.call_args.args[3], 'R2')
        self.assertEqual(self.plans['I1']['source'], 'runs/R2/reports/drc.rpt')
        self.assertEqual(self.plans['I1']['locator'], 'L1-L2')
        self.assertFalse((self.output / 'runs/R3').exists())
        self.assertFalse((self.output / 'diffs').exists())
        self.assertFalse(self.reviews[0]['tool_called'])

    def test_same_size_input_edit_with_restored_mtime_rejects_the_refresh(self):
        def altered(*_args, **_kwargs):
            st = self.source.stat()
            self.source.write_text(self.source.read_text().replace('y=x', 'y=0'))
            os.utime(self.source, ns=(st.st_atime_ns, st.st_mtime_ns))
            return json.dumps({'verification_updates': [{'issue_id': 'I1', 'evidence_id': 'V1'}]})
        result, verify = self.refresh(altered)
        self.assertFalse(result)
        self.assertFalse(verify.called)
        self.assertEqual(self.plans, {})
        self.assertEqual(self.reviews[0]['status'], 'rejected')

    def test_artifact_edit_or_model_schema_expansion_cannot_apply_a_plan(self):
        def changed(*_args, **_kwargs):
            self.report.write_text('DRC Report\nTotal violations: 1\n')
            return json.dumps({'verification_updates': [{'issue_id': 'I1', 'evidence_id': 'V1'}]})
        result, verify = self.refresh(changed)
        self.assertFalse(result)
        self.assertFalse(verify.called)
        self.assertEqual(self.plans, {})

    def test_case_deadline_terminates_the_actual_child_group_and_records_abort(self):
        tool = self.root / 'fixture_tool.py'
        tool.write_text(f'#!{sys.executable}\nimport os,time\nfrom pathlib import Path\n'
                        'Path("started.pid").write_text(str(os.getpid()))\ntime.sleep(3)\n')
        tool.chmod(0o700)
        run = self.output / 'runs/R3'
        run.mkdir()
        guard = CaseDeadline(time.monotonic() + 0.2)
        guard.arm()
        try:
            with patch.object(agent, 'TOOL', str(tool)), self.assertRaises(CaseDeadlineExceeded) as caught:
                agent.tool_run('exit\n', run, 'R3', 10)
        finally:
            guard.close()
        record = caught.exception.tool_record
        self.assertEqual(record['run_id'], 'R3')
        self.assertEqual(record['status'], 'aborted')
        self.assertNotEqual(record['returncode'], 0)
        pid = (run / 'started.pid').read_text()
        state = Path('/proc') / pid / 'stat'
        self.assertTrue(not state.exists() or state.read_text().split()[2] == 'Z')
        self.assertIn('case interruption', (run / 'R3.log').read_text())

    def test_verify_mutation_rolls_back_the_entire_audit_update(self):
        source_snapshot = fingerprint_paths([self.source])
        source_signature = agent.input_tree_signature(self.input)
        artifacts = _run_signature(self.output / 'runs/R2')
        original_issues = copy.deepcopy(self.issues)
        class Client:
            def with_options(self, **_options):
                return self
        def corrupt(issues, *_args, **_kwargs):
            issues[0]['attempts'][-1]['verify']['resolved'] = True
            self.report.write_text('DRC Report\nTotal violations: 999\n')
        with patch.object(agent, 'ask', return_value=json.dumps(
                {'verification_updates': [{'issue_id': 'I1', 'evidence_id': 'V1'}]})), \
                patch.object(agent, 'verify_issue_fixes', side_effect=corrupt):
            result = agent.refresh_existing_audit(Client(), self.output, self.issues, self.plans,
                self.records, 'R2', source_snapshot, source_signature, self.input, artifacts,
                time.monotonic() + 5, self.reviews, set())
        self.assertFalse(result)
        self.assertEqual(self.issues, original_issues)
        self.assertEqual(self.plans, {})

    def test_only_declared_input_roles_are_read_for_fingerprints(self):
        for name in ('golden.dofile', 'preset_issues.json', '.env'):
            (self.input / name).write_text('forbidden input fixture')
        libs = self.input / 'lib.lib'
        libs.write_text('library(arbitrary){}')
        selected = agent.role_input_files(self.input, [self.source], [libs], None)
        self.assertEqual(set(selected), {self.source, libs})

    def test_original_tool_execution_and_delivery_receive_full_raw_bytes(self):
        original = self.input / 'original.dofile'
        raw = b'\xef\xbb\xbf' + b'# unfamiliar \xff\r\n' * 6000 + b'exit\r\n'
        original.write_bytes(raw)
        tool = self.root / 'reader.py'
        tool.write_text(f'#!{sys.executable}\nimport sys\nfrom pathlib import Path\n'
                        'p=Path(sys.argv[sys.argv.index("-f")+1])\n'
                        'Path("executed.raw").write_bytes(p.read_bytes())\n')
        tool.chmod(0o700)
        run = self.output / 'runs/R3'
        run.mkdir()
        with patch.object(agent, 'TOOL', str(tool)):
            result = agent.tool_run(agent.read_original_text(original), run, 'R3', 5,
                                    abort_on_error=False, original_source=original)
        self.assertEqual(result['status'], 'completed')
        self.assertEqual((run / 'executed.raw').read_bytes(), raw)
        self.assertEqual((run / 'deliverables/R3.dofile').read_bytes(), raw)
        self.assertEqual(original.read_bytes(), raw)

    def test_finished_leader_cannot_leave_a_late_report_writer(self):
        tool = self.root / 'background.py'
        worker = 'import time;from pathlib import Path;time.sleep(0.5);Path("late.rpt").write_text("forged late output")'
        tool.write_text(f'#!{sys.executable}\nimport subprocess,sys\n'
                        f'subprocess.Popen([sys.executable,"-c",{worker!r}])\n')
        tool.chmod(0o700)
        run = self.output / 'runs/R3'
        run.mkdir()
        with patch.object(agent, 'TOOL', str(tool)):
            result = agent.tool_run('exit\n', run, 'R3', 5)
        self.assertEqual(result['status'], 'completed')
        time.sleep(0.6)
        self.assertFalse((run / 'late.rpt').exists())

    def test_final_publication_directory_must_not_be_a_symlink(self):
        from artifact_operations import assert_output_directories
        final = self.output / 'final_results'
        final.mkdir()
        elsewhere = self.root / 'elsewhere'
        elsewhere.mkdir()
        (final / 'reports').symlink_to(elsewhere, target_is_directory=True)
        with self.assertRaises(ValueError):
            assert_output_directories(self.output, ['final_results/reports'])


if __name__ == '__main__':
    unittest.main()
