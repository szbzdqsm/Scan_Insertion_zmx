"""Regression checks for the bounded private repair policy; no API or EDA calls."""
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "agent"))
import netlist_repair as repair  # noqa: E402


class RepairTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="netlist-repair-")
        self.root = Path(self.temp.name)
        self.input = self.root / "input"
        (self.input / "netlist").mkdir(parents=True)
        self.source = self.input / "netlist/top.v"
        self.source.write_text("module top(input a,b, output y);\nassign y = a & b;\nendmodule\n")
        self.old = self.source.read_bytes()
        self.edit = {"file": "netlist/top.v", "old": "assign y = a & b;",
                     "new": "assign y = ~(~a | ~b);", "reason": "localized structural rewrite"}
        self.active = {self.source: self.source}

    def tearDown(self):
        self.temp.cleanup()

    def test_task1_and_explicit_no_edit_cases_are_refused(self):
        self.assertFalse(repair.edits_allowed("task1", "repair"))
        self.assertFalse(repair.edits_allowed("task2", "不允许修改 Pre-scan 网表"))
        self.assertFalse(repair.edits_allowed("task2", "Do not modify the netlist"))
        self.assertTrue(repair.edits_allowed("task2", "Correct the scan DRC"))

    def test_patch_crossing_chunk_boundary_is_exact_and_keeps_original(self):
        self.source.write_bytes(b"x" * 65530 + b"unique matching span\n" + b"z" * 80000)
        original = self.source.read_bytes()
        target = self.root / "patched.v"
        repair.patch_unique(self.source, target, "unique matching span", "replacement")
        self.assertEqual(target.read_bytes(), original.replace(b"unique matching span", b"replacement"))
        self.assertEqual(self.source.read_bytes(), original)

    def test_ambiguous_and_overlapping_spans_are_rejected(self):
        self.source.write_text("aaa")
        with self.assertRaises(repair.RepairRejected):
            repair.patch_unique(self.source, self.root / "patched.v", "aa", "b")
        self.assertFalse((self.root / "patched.v").exists())

    def test_external_paths_and_module_interfaces_are_rejected(self):
        with self.assertRaises(repair.RepairRejected):
            repair.patch_unique(self.source, self.root / "patched.v", "module top", "module other")
        with self.assertRaises(repair.RepairRejected):
            repair.prepare_repair("task2", "", "present_design top\n", self.input,
                                  [self.source], self.active, [],
                                  [dict(self.edit, file="../private.env")], self.root / "output", "R2", float("inf"))

    def test_unproven_candidate_cannot_replace_active_version(self):
        with patch.object(repair, "run_proof", return_value={"passed": False, "result": "UNPROVEN"}):
            with self.assertRaises(repair.RepairRejected):
                repair.prepare_repair("task2", "", "present_design top\n", self.input,
                                      [self.source], self.active, [], [self.edit], self.root / "output", "R2", float("inf"))
        self.assertEqual(self.active[self.source], self.source)
        self.assertEqual(self.source.read_bytes(), self.old)

    def test_proof_script_uses_functional_library_and_no_model_constraints(self):
        config = repair.eqy_configuration([self.source], [self.source], [self.root / "cells.lib"], "top")
        self.assertIn('read_liberty -ignore_miss_func -ignore_miss_dir ' + json.dumps(str(self.root / "cells.lib")), config)
        self.assertNotIn("read_liberty -lib", config)
        self.assertIn("hierarchy -check -top top", config)
        self.assertIn("select -assert-none A:blackbox", config)
        self.assertNotIn("assume", config)


if __name__ == "__main__":
    unittest.main()
