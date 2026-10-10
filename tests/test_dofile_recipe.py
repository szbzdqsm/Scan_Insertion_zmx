"""Compiler fixtures use source-derived hints, never case answers."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "agent"))
from dofile_recipe import configure_shift_segments, normalize_unrequested_counts, tcl_chunks  # noqa: E402


class RecipeTests(unittest.TestCase):
    def setUp(self):
        self.groups = [{"root": "top", "start_template": "u/r[{i0}]", "end_template": "u/t[{i0}]", "index_tuples": [[0], [1]],
                        "length": 10, "scan_data_in_pin": "SCD", "scan_enable_pin": "SCE", "scan_data_out_pin": "Q"}]

    def test_all_coordinates_are_compiled_before_examination(self):
        script = "load_netlist input.v\npresent_design top\nset_scan_segment old -access {}\nexamine_scan_drc\ninsert_dft_logic\nexit\n"
        result, references = configure_shift_segments(script, self.groups)
        self.assertNotIn("set_scan_segment old", result)
        self.assertIn("{{0} {1}}", result)
        self.assertIn("[format {u/r[%d]/SCE} $agent_i0_0]", result)
        self.assertLess(result.index("set_scan_segment agent_shift"), result.index("examine_scan_drc"))
        self.assertEqual(len(references), 2)
        self.assertEqual(configure_shift_segments(result, self.groups)[0], result)

    def test_pure_old_loop_is_replaced_but_other_dft_operations_are_refused(self):
        script = "foreach i {0 1} {\n set_scan_segment old_$i -access {}\n}\nexamine_scan_drc\nexit\n"
        result, _ = configure_shift_segments(script, self.groups)
        self.assertNotIn("old_$i", result)
        with self.assertRaisesRegex(ValueError, "other operations"):
            configure_shift_segments(script.replace(" set_scan_segment", " set_scan_cfg -max_length 100\n set_scan_segment"), self.groups)

    def test_backslash_continuations_form_one_command(self):
        script = "set_scan_segment old \\\n -access {}\nexamine_scan_drc\nexit\n"
        self.assertEqual(len(tcl_chunks(script)), 3)
        result, _ = configure_shift_segments(script, self.groups)
        self.assertNotIn("-access {}", result)
        with self.assertRaisesRegex(ValueError, "Incomplete"):
            tcl_chunks("foreach i {0 1} {\n")

    def test_maximum_only_recipe_uses_automatic_count_and_caps_wrappers(self):
        spec = "链最大长度（含内部链与 wrapper 链）不超过 100"
        script = "set_scan_cfg -chain_count 92 -max_length 100\nexamine_scan_drc\nexit\n"
        result, _ = configure_shift_segments(script, self.groups, spec)
        self.assertNotIn("-chain_count", result)
        self.assertIn("set_wrapper_cfg -max_length 100", result)
        self.assertEqual(normalize_unrequested_counts(script, "扫描链数不得超过 5"), script)

    def test_maximum_only_count_removal_leaves_no_bare_configuration(self):
        spec = "链最大长度（含内部链与 wrapper 链）不超过 100"
        script = ("set_scan_cfg -chain_count 80\n"
                  "set_wrapper_cfg -chain_count 2\n"
                  "set_scan_cfg -chain_count 80 -max_length 100\n"
                  "set_wrapper_cfg enable -chain_count 2 -max_length 100 -style shared\n"
                  "examine_scan_drc\n")
        result = normalize_unrequested_counts(script, spec)
        self.assertNotIn("-chain_count", result)
        self.assertFalse(any(line.strip() in {"set_scan_cfg", "set_wrapper_cfg"} for line in result.splitlines()))
        self.assertIn("set_scan_cfg -max_length 100", result)
        self.assertIn("set_wrapper_cfg enable -max_length 100 -style shared", result)
        self.assertEqual(normalize_unrequested_counts(result, spec), result)

    def test_explicit_chain_count_requirements_preserve_scan_and_wrapper_counts(self):
        script = "set_scan_cfg -chain_count 70\nset_wrapper_cfg enable -chain_count 15\n"
        for spec in ["wrapper chain 数目要求为 15 条，unwrapper chain 数目要求为 55 条。",
                     "扫描链数量必须为 70", "number of chains must be 70", "chain_count 70"]:
            with self.subTest(spec=spec):
                self.assertEqual(normalize_unrequested_counts(script, spec), script)


if __name__ == "__main__":
    unittest.main()
