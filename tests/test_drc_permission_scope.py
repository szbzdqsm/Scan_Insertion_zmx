from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'agent'))
from drc_validation import authorized_ignored_rule_codes, authorized_rule_codes


class DrcPermissionScopeTests(unittest.TestCase):
    def test_real_permission_and_code_lists(self):
        for text, wanted in [('忽略 DFTR-TIE0 和 DFTR-TIE1 违例', {'DFTRTIE0', 'DFTRTIE1'}),
                             ('允许保留 DFTR17 违例', {'DFTR17'}),
                             ('DFTR3 违例，可忽略', {'DFTR3'}),
                             ('Ignore DFTR-TIE0, DFTR-TIE1', {'DFTRTIE0', 'DFTRTIE1'}),
                             ('禁止修改网表，但允许忽略 DFTR-TIE0', {'DFTRTIE0'}),
                             ('DFTR3 违规，允许这些违例保留', {'DFTR3'})]:
            with self.subTest(text=text):
                self.assertEqual(authorized_rule_codes(text), wanted)

    def test_unrelated_permission_is_not_drc_authority(self):
        for text in ['修复 DFTR3 违例，允许混合时钟沿。',
                     'DFTR3 must be repaired, allow mixed clock edges.',
                     '允许混合时钟沿并修复DFTR3违例。',
                     'DFTR3违例，允许修改网表。',
                     '允许报告DFTR3违例。', 'DFTR3违例允许在报告中显示。',
                     'DFTR3违例，允许混合时钟沿，DFTR4违例。',
                     '不允许忽略DFTR3', '忽略DFTR3；必须修复DFTR3',
                     '仅在指定实例范围允许DFTR3违例']:
            with self.subTest(text=text):
                self.assertEqual(authorized_rule_codes(text), set())

    def test_residual_permission_does_not_suppress_diagnostics(self):
        text = '允许保留DFTR17，忽略DFTR-TIE0、DFTR-TIE1'
        self.assertEqual(authorized_rule_codes(text), {'DFTR17', 'DFTRTIE0', 'DFTRTIE1'})
        self.assertEqual(authorized_ignored_rule_codes(text), {'DFTRTIE0', 'DFTRTIE1'})
        self.assertEqual(authorized_ignored_rule_codes('DFTR17违例，可忽略'), {'DFTR17'})
        self.assertEqual(authorized_ignored_rule_codes('允许保留DFTR17'), set())

    def test_report_format_and_log_actions_do_not_authorize_residuals(self):
        for text in ['允许 DFTR17 违例报告采用文本格式。',
                     '允许 DFTR9 的诊断日志使用独立文件。',
                     'Allow DFTR-L1 report files to use another format.',
                     '允许忽略 DFTR-L2 报告里的空白行。',
                     'DFTR7 的日志可保留，但违例必须修复。']:
            with self.subTest(text=text):
                self.assertEqual(authorized_rule_codes(text), set())
                self.assertEqual(authorized_ignored_rule_codes(text), set())

    def test_each_predicate_scopes_its_own_rule_group(self):
        for text in ['允许保留 DFTR17 并忽略 DFTR-TIE0。',
                     '允许保留 DFTR17 且忽略 DFTR-TIE0。',
                     '允许保留 DFTR17，并且忽略 DFTR-TIE0。',
                     'Allow DFTR17 to remain and ignore DFTR-TIE0.']:
            with self.subTest(text=text):
                self.assertEqual(authorized_rule_codes(text), {'DFTR17', 'DFTRTIE0'})
                self.assertEqual(authorized_ignored_rule_codes(text), {'DFTRTIE0'})

    def test_conjunctions_between_codes_are_still_one_rule_list(self):
        for text in ['Ignore DFTR-L1 and DFTR-L2', '忽略 DFTR-L1 与 DFTR-L2',
                     '忽略DFTR-L1、DFTR-L2', '忽略 DFTR-L1, DFTR-L2']:
            with self.subTest(text=text):
                self.assertEqual(authorized_rule_codes(text), {'DFTRL1', 'DFTRL2'})
                self.assertEqual(authorized_ignored_rule_codes(text), {'DFTRL1', 'DFTRL2'})

    def test_forbidding_ignore_does_not_cancel_explicit_visible_residual_permission(self):
        text = '允许 DFTR17 以 Warning 形式保留，但不得忽略。'
        self.assertEqual(authorized_rule_codes(text), {'DFTR17'})
        self.assertEqual(authorized_ignored_rule_codes(text), set())

    def test_unrelated_conjoined_actions_do_not_change_clear_residual_scope(self):
        for text in ['允许保留 DFTR17 并输出扫描网表。',
                     '允许保留 DFTR17，允许 DFTR9 的报告采用文本格式。']:
            with self.subTest(text=text):
                self.assertEqual(authorized_rule_codes(text), {'DFTR17'})
                self.assertEqual(authorized_ignored_rule_codes(text), set())

    def test_warning_need_not_be_processed_but_is_not_ignore_permission(self):
        for text in ['DFTR17 违例无需处理', '允许遗留标号为 DFTR17 的违例，无需处理。']:
            with self.subTest(text=text):
                self.assertEqual(authorized_rule_codes(text), {'DFTR17'})
                self.assertEqual(authorized_ignored_rule_codes(text), set())

    def test_leading_report_context_does_not_change_an_explicit_residual_object(self):
        text = '最终DRC报告允许保留DFTR17违例。'
        self.assertEqual(authorized_rule_codes(text), {'DFTR17'})
        self.assertEqual(authorized_ignored_rule_codes(text), set())


if __name__ == '__main__':
    unittest.main()
