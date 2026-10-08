from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'agent'))
from runtime_limits import effective_case_seconds, parse_case_seconds


class RuntimeLimitsTests(unittest.TestCase):
    def test_units_and_explicit_fields(self):
        for text, wanted in [('时间限制：2.5分钟', 150), ('Wall time limit: 2m', 120),
                             ('max_wall_time_seconds:137', 137), ('Time limit:73seconds', 73),
                             ('最大运行时间：1.25小时', 4500), ('wall-time(ms):123000', 123),
                             ('运行总时间不超过83秒', 83), ('total_time_limit:2.9s', 2),
                             ('时间上限（分钟）：0.5', 30), ('最大墙钟时间：1分钟', 60),
                             ('总耗时：60秒', 60), ('最长执行时长：90秒', 90),
                             ('系统整体耗时不得超过75秒', 75), ('执行时限：45秒', 45),
                             ('wall_clock_time_seconds:64', 64)]:
            with self.subTest(text=text):
                self.assertEqual(parse_case_seconds(text), wanted)

    def test_smallest_bound_and_local_override_never_widen(self):
        self.assertEqual(parse_case_seconds('wall time:130s\n时间限制：2分钟'), 120)
        self.assertEqual(effective_case_seconds('时间限制：73秒', '900'), 73)
        self.assertEqual(effective_case_seconds('时间限制：73秒', '31'), 31)
        self.assertEqual(effective_case_seconds('', '31'), 31)
        self.assertEqual(effective_case_seconds('最大墙钟时间：1分钟', '900'), 60)
        self.assertEqual(effective_case_seconds('总耗时：60秒', '900'), 60)

    def test_missing_statement_and_unrelated_numbers(self):
        self.assertEqual(parse_case_seconds('max_tool_calls:99', default=91), 91)
        self.assertEqual(parse_case_seconds('', default=97), 97)

    def test_section_headings_and_bilingual_labels(self):
        for text in ['# 系统运行限制\n\n## 时间限制\n- 整个 case 的执行总时间（wall time）不超过 150 秒',
                     '时间限制：\nwall time: 2.5 minutes',
                     '## 最大墙钟时间\n执行总时间 (wall time): 83秒']:
            with self.subTest(text=text):
                self.assertEqual(parse_case_seconds(text), 150 if '150' in text or '2.5' in text else 83)
        for text in ['## 时间限制', '时间限制：\n没有说明', '## 时间限制\nwall time: 73ticks']:
            with self.subTest(text=text), self.assertRaises(ValueError):
                parse_case_seconds(text)

    def test_malformed_ambiguous_and_conflicting_bound_is_not_a_generous_default(self):
        for text in ['时间限制：没有说明', 'Time limit:73ticks', 'max_wall_time_ticks:83',
                     'wall time:01:20', 'max_wall_time_seconds:2minutes', '时间限制：0.3秒',
                     'wall time calls7 time87秒', '时间限制：-3秒',
                     '墙钟限额：90ticks', '所需用时：60秒', 'duration budget:90ticks',
                     '最长时长：没有提供数值']:
            with self.subTest(text=text), self.assertRaises(ValueError):
                parse_case_seconds(text)


if __name__ == '__main__':
    unittest.main()
