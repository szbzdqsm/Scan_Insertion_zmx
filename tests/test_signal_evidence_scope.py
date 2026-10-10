"""Small structural fixtures for design and partition scoped native evidence."""
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'agent'))
from command_error_evidence import grouped_signal_evidence  # noqa: E402
from scan_agent import literal_tcl_words  # noqa: E402


def signal_report(design='example', rows=None):
    widths = [20, 24, 16, 16, 24]
    values = [['Port', 'SignalType', 'OffState', 'Usage', 'OwnerPartition']]
    values.extend(rows if rows is not None else [
        ['enable_a', 'scan_enable(spec)', '0', 'all', 'domain_a'],
        ['enable_b', 'scan_enable(spec)', '1', 'scan', 'domain_b'],
    ])
    return 'Design: ' + design + '\n' + '\n'.join(
        ''.join(value.ljust(width) for value, width in zip(row, widths)) for row in values) + '\n'


SCRIPT = '''present_design example
set_current_scan_partition domain_a
set_scan_signal -type scan_enable -port enable_a -off_state 0 -usage all
set_current_scan_partition domain_b
set_scan_signal -type scan_enable -port enable_b -off_state 1 -usage scan
'''


class SignalEvidenceScopeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.path = self.root / 'runs' / 'R2' / 'reports' / 'scan_signal.rpt'
        self.path.parent.mkdir(parents=True)
        self.issue = {'diagnosis': {'located_object': 'ports enable_a, enable_b'}}

    def tearDown(self):
        self.temp.cleanup()

    def proof(self, script=SCRIPT, report=None):
        self.path.write_text(report if report is not None else signal_report())
        return grouped_signal_evidence(self.issue, [self.path], self.root, script, literal_tcl_words)

    def test_literal_design_and_each_effective_partition_are_proven(self):
        proof = self.proof()
        self.assertEqual(proof['source'], 'runs/R2/reports/scan_signal.rpt')
        self.assertEqual(proof['locator'], 'L3-L4')
        self.assertIn('domain_a', proof['excerpt'])
        self.assertIn('domain_b', proof['excerpt'])

    def test_default_partition_is_supported_without_selection_command(self):
        script = SCRIPT.replace('set_current_scan_partition domain_a\n', '').replace(
            'set_current_scan_partition domain_b\n', '')
        report = signal_report().replace('domain_a', 'Default_Partition').replace('domain_b', 'Default_Partition')
        self.assertIsNotNone(self.proof(script, report))

    def test_report_for_another_or_ambiguous_design_is_rejected(self):
        for report in [signal_report('unrelated'), signal_report().replace('Design: example\n', ''),
                       signal_report() + 'Design: example\n']:
            with self.subTest(report=report):
                self.assertIsNone(self.proof(report=report))

    def test_wrong_or_missing_partition_is_rejected(self):
        for report in [signal_report().replace('domain_a', 'domain_b'),
                       signal_report().replace('domain_b', ''),
                       signal_report().replace('OwnerPartition', 'UnrelatedField')]:
            with self.subTest(report=report):
                self.assertIsNone(self.proof(report=report))

    def test_duplicate_target_declarations_and_rows_are_ambiguous(self):
        declaration = 'set_scan_signal -type scan_enable -port enable_a -off_state 0 -usage all\n'
        self.assertIsNone(self.proof(SCRIPT + declaration))
        self.assertIsNone(self.proof(report=signal_report(rows=[
            ['enable_a', 'scan_enable(spec)', '0', 'all', 'domain_a'],
            ['enable_b', 'scan_enable(spec)', '1', 'scan', 'domain_b'],
            ['enable_a', 'scan_enable(spec)', '0', 'all', 'domain_a'],
        ])))

    def test_dynamic_or_conditional_scopes_are_not_guessed(self):
        scripts = [SCRIPT.replace('present_design example', 'present_design $top'),
                   SCRIPT.replace('domain_a', '$partition'),
                   SCRIPT.replace('enable_a', '$port'),
                   SCRIPT.replace('example', 'example$variant'),
                   'if {$flag} {set_current_scan_partition other}\n' + SCRIPT,
                   'source helper.tcl\n' + SCRIPT,
                   SCRIPT.replace('set_current_scan_partition domain_a',
                                  'set_current_scan_partition domain_a; set_current_scan_partition domain_b')]
        for script in scripts:
            with self.subTest(script=script):
                self.assertIsNone(self.proof(script))

    def test_multiple_design_selections_or_declarations_before_design_are_rejected(self):
        self.assertIsNone(self.proof(SCRIPT + 'present_design unrelated\n'))
        self.assertIsNone(self.proof(SCRIPT + 'present_design example\n'))
        self.assertIsNone(self.proof(SCRIPT.replace('present_design example\n', '') + 'present_design example\n'))

    def test_literal_multiline_declarations_are_supported(self):
        script = SCRIPT.replace('-port enable_a -off_state', '-port enable_a ' + '\\' + '\n    -off_state')
        self.assertIsNotNone(self.proof(script))

    def test_wrong_usage_and_off_state_still_rejected(self):
        self.assertIsNone(self.proof(report=signal_report().replace('all', 'scan')))
        self.assertIsNone(self.proof(report=signal_report().replace('scan_enable(spec)', 'clock')))
        self.assertIsNone(self.proof(SCRIPT.replace('-off_state 0', '-off_state 2')))
        self.assertIsNone(self.proof(SCRIPT.replace('-usage all', '')))

    def test_symlink_and_outside_report_are_not_native_evidence(self):
        self.path.write_text(signal_report())
        target = self.path.with_name('copy.rpt')
        target.write_text(self.path.read_text())
        self.path.unlink()
        self.path.symlink_to(target)
        self.assertIsNone(grouped_signal_evidence(self.issue, [self.path], self.root, SCRIPT, literal_tcl_words))
        with tempfile.TemporaryDirectory() as outside:
            path = Path(outside) / 'scan_signal.rpt'
            path.write_text(signal_report())
            self.assertIsNone(grouped_signal_evidence(self.issue, [path], self.root, SCRIPT, literal_tcl_words))


if __name__ == '__main__':
    unittest.main()
