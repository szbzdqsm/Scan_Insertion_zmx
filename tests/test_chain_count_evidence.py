"""Exact partition counts distinguish a real failure from a satisfied report."""
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "agent"))
import scan_agent as agent


def report(count, partition="wb_partition", kind="I"):
    widths = (9, 10, 12, 12, 14, 17, 17, 17, 10)
    def line(values):
        return ''.join(f'{value:<{width}}' for value, width in zip(values, widths)).rstrip() + '\n'
    return (line(('Chain', 'Length', 'Input', 'Output', 'ScanEnable', 'Clocks', 'Partition', 'ChainProperty', 'IPGroup')) +
            '-' * sum(widths) + '\n' +
            ''.join(line((f'{kind} {i}', 1, f'si{i}', f'so{i}', 'se', 'clk', partition, 'tool_created', ''))
                    for i in range(1, count + 1)))


class ChainCountEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        for rid, count in (("R1", 2), ("R2", 34)):
            path = self.root / "runs" / rid / "reports/scan_chain.rpt"
            path.parent.mkdir(parents=True)
            path.write_text(report(count))
        self.item = {"issue_id": "I1", "phenomenon": "chain_count 34 cannot be satisfied in wb_partition",
                     "located_object": "wb_partition chain_count 34", "diagnosis": "Only two chains in partition",
                     "root_cause": "Clock assignment", "fix": "Resolved by the actual clock assignment fix",
                     "evidence_excerpt": report(2).strip()}

    def tearDown(self):
        self.temp.cleanup()

    def record(self, previous="R1", current="R2"):
        issues, plans = [], {}
        agent.record_issue_fixes({"issue_resolutions": [self.item]}, issues, plans,
                                 self.root, previous, current, "F1")
        return issues, plans

    def test_actual_two_to_thirty_four_has_complete_positive_rows(self):
        issues, plans = self.record()
        self.assertEqual(len(issues), 1)
        agent.verify_issue_fixes(issues, plans, self.root, "R2", True)
        verification = issues[0]["attempts"][-1]["verify"]
        self.assertTrue(verification["resolved"])
        self.assertIn("wb_partition", verification["excerpt"])
        self.assertEqual(len(verification["excerpt"].splitlines()), 34)
        self.assertNotEqual(verification["run_ref"], issues[0]["found"]["run_ref"])

    def test_satisfied_count_cannot_discover_the_same_failure(self):
        self.item["evidence_excerpt"] = report(34).strip()
        issues, _ = self.record("R2", "R3")
        self.assertEqual(issues, [])

    def test_partial_excerpt_cannot_hide_the_full_satisfied_count(self):
        lines = report(34).splitlines()
        self.item["evidence_excerpt"] = "\n".join(lines[:4])
        self.assertEqual(self.record("R2", "R3")[0], [])

    def test_wrong_count_and_wrapper_rows_do_not_prove_internal_count(self):
        issues, plans = self.record()
        target = self.root / "runs/R2/reports/scan_chain.rpt"
        for data in (report(33), report(34, "other_partition"), report(34, kind="W")):
            target.write_text(data)
            agent.verify_issue_fixes(issues, plans, self.root, "R2", True)
            self.assertFalse(issues[0]["attempts"][-1]["verify"]["resolved"])

    def test_failed_artifact_checks_and_ambiguous_claims_do_not_close(self):
        issues, plans = self.record()
        agent.verify_issue_fixes(issues, plans, self.root, "R2", False)
        self.assertFalse(issues[0]["attempts"][-1]["verify"]["resolved"])
        rows = agent.chain_rows([self.root / "runs/R2/reports/scan_chain.rpt"])
        self.assertIsNone(agent.chain_count_claim("wb_partition chain_count 34 and chain_count 35", rows))
        self.assertIsNone(agent.chain_count_claim("unrelated chain_count 34", rows))

    def test_count_evidence_does_not_close_an_unrelated_clock_issue(self):
        issues, plans = self.record()
        issues[0]['phenomenon'] = 'Incorrect clock signal'
        issues[0]['diagnosis']['located_object'] = 'wb_partition clock'
        issues[0]['diagnosis']['summary'] = 'Related chain_count 34 is incorrect'
        files = [self.root / 'runs/R2/reports/scan_chain.rpt']
        self.assertIsNone(agent.chain_count_positive_evidence(issues[0], files, self.root))


if __name__ == "__main__":
    unittest.main()
