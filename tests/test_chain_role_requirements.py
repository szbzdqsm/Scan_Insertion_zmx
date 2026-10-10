from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "agent"))
from report_validation import chain_problems, chain_role_requirements, chain_rows, report_rows, wrapper_chain_configuration_problems
from scan_agent import literal_tcl_words
from dofile_recipe import normalize_unrequested_counts


def rows(internal, wrapper):
    return [{"Chain": f"{role} renamed_{i}", "Length": "10", "Input": f"{role.lower()}_si_{i}",
             "Output": f"{role.lower()}_so_{i}", "ScanEnable": "select_shift", "Clocks": "reference_clock",
             "Partition": "Default_Partition"}
            for role, count in [("I", internal), ("W", wrapper)] for i in range(count)]


def table(data):
    headers = ["Chain", "Length", "Input", "Output", "ScanEnable", "Clocks", "Partition"]
    return "Design: renamed_chip\n" + "".join(f"{key:<28}" for key in headers) + "\n" + \
        "".join("".join(f"{row[key]:<28}" for key in headers) + "\n" for row in data)


class ChainRoleRequirements(unittest.TestCase):
    def setUp(self):
        self.spec = "wrapper chain 数目要求为15条，unwrapper chain 数目要求为55条。"
        self.script = ("present_design renamed_chip\n"
                       "set_scan_cfg -max_length 100 -chain_count 70\n"
                       "set_wrapper_cfg enable -style dedicated -chain_count 15\n"
                       "examine_scan_drc\nexamine_scan_chain\ninsert_dft_logic\n")

    def test_each_explicit_role_is_parsed_without_overlap(self):
        self.assertEqual(chain_role_requirements(self.spec), {"W": 15, "I": 55})
        for spec in ["Wrapper chains count must be 7; non-wrapper chains count must be 11.",
                     "封装扫描链数量为7条，内部扫描链数量为11条。", "包装链数=7；非封装扫描链数=11。"]:
            with self.subTest(spec=spec):
                self.assertEqual(chain_role_requirements(spec), {"W": 7, "I": 11})

    def test_explicit_unwrapper_count_survives_script_normalization(self):
        self.assertEqual(normalize_unrequested_counts(self.script,self.spec),self.script)

    def test_actual_platform_and_old_local_wrong_internal_counts_fail(self):
        for count in (32, 40):
            with self.subTest(count=count):
                problems = chain_problems(rows(count, 15), self.spec)
                self.assertTrue(any("Internal/unwrapper" in problem and f"proves {count}" in problem for problem in problems))
        self.assertEqual(chain_problems(rows(55, 15), self.spec), [])

    def test_renamed_counts_and_swapped_categories_cannot_use_the_same_total(self):
        spec = "封装扫描链数为7条；内部扫描链数为11条。"
        self.assertEqual(chain_problems(rows(11, 7), spec), [])
        self.assertEqual(len(chain_problems(rows(7, 11), spec)), 2)
        self.assertTrue(chain_problems(rows(18, 0), spec))

    def test_default_partition_does_not_waive_an_extra_chain(self):
        spec = "wrapper chains count is 2; internal scan is unspecified; unwrapper chains count is 3."
        actual = rows(3, 2)
        actual.append({**actual[0], "Chain": "I default_extra", "Partition": "Default_Partition"})
        self.assertTrue(chain_problems(actual, spec))

    def test_duplicate_and_conflicting_identities_cannot_prove_a_count(self):
        actual = rows(55, 15)
        actual[-1] = dict(actual[-2])
        self.assertTrue(any("Duplicate" in problem for problem in chain_problems(actual, self.spec)))
        actual[-1]["Output"] = "other_output"
        self.assertTrue(chain_problems(actual, self.spec))

    def test_complete_report_streams_are_not_prefix_limited_and_copies_do_not_double_count(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "scan_chain.rpt"
            source.write_text(table(rows(55, 15)))
            copied = source.with_name("scan_chain_copy.rpt")
            copied.write_bytes(source.read_bytes())
            self.assertEqual(chain_problems(chain_rows([source, copied]), self.spec), [])
            copied.write_text(table(rows(55, 15)[:-1] + [{**rows(55, 15)[-1], "Length": "11"}]))
            self.assertTrue(chain_problems(chain_rows([source, copied]), self.spec))

    def test_duplicate_lines_inside_a_report_are_not_hidden_by_deduplication(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "scan_chain.rpt"
            actual = rows(55, 15)
            source.write_text(table(actual + [actual[0]]))
            self.assertTrue(chain_problems(chain_rows([source]), self.spec))

    def test_untyped_missing_or_empty_rows_do_not_prove_explicit_roles(self):
        self.assertTrue(chain_problems([], self.spec))
        actual = rows(55, 15)
        actual[0]["Chain"] = "0"
        self.assertTrue(chain_problems(actual, self.spec))

    def test_conflicting_task_values_are_reported_without_guessing(self):
        spec = "wrapper chains count is 2; wrapper chains count is 3."
        self.assertEqual(chain_role_requirements(spec), {})
        self.assertTrue(any("conflicting explicit" in problem for problem in chain_problems(rows(0, 5), spec)))

    def test_conditional_negated_scoped_and_nonexact_counts_abstain(self):
        for spec in ["不要求wrapper chain数目为15条。", "如果启用包装则wrapper chain数为15条。",
                     "每个分区内部扫描链数量为7条。", "wrapper chain数目不超过15条。",
                     "Wrapper chains count is not required to be 15.", "When enabled, wrapper chains count is 15."]:
            with self.subTest(spec=spec):
                self.assertEqual(chain_role_requirements(spec), {})

    def test_configuration_requires_the_correct_command_for_each_role(self):
        self.assertEqual(wrapper_chain_configuration_problems(self.script, self.spec, literal_tcl_words), [])
        missing = self.script.replace("-chain_count 70", "")
        problems = wrapper_chain_configuration_problems(missing, self.spec, literal_tcl_words)
        self.assertTrue(any("set_scan_cfg -chain_count 70" in problem for problem in problems))
        swapped = self.script.replace("-chain_count 70", "-chain_count 15").replace("dedicated -chain_count 15", "dedicated -chain_count 55")
        self.assertEqual(len(wrapper_chain_configuration_problems(swapped, self.spec, literal_tcl_words)), 2)

    def test_dynamic_and_multi_scope_tcl_does_not_guess_configuration(self):
        for script in [self.script.replace("-chain_count 70", "-chain_count $goal"),
                       self.script.replace("present_design renamed_chip", "present_design $top"),
                       self.script + "present_design second_chip\nset_scan_cfg -chain_count 55\n",
                       self.script.replace("set_scan_cfg", "set_current_scan_partition secondary\nset_scan_cfg", 1),
                       "if {$enabled} {\n" + self.script + "}\n", "source configuration.tcl\n" + self.script]:
            with self.subTest(script=script):
                self.assertEqual(wrapper_chain_configuration_problems(script, self.spec, literal_tcl_words), [])
        default = self.script.replace("set_scan_cfg", "set_current_scan_partition Default_Partition\nset_scan_cfg", 1)
        self.assertEqual(wrapper_chain_configuration_problems(default, self.spec, literal_tcl_words), [])

    def test_global_count_includes_wrapper_chains_with_arbitrary_counts(self):
        script='present_design another\nset_scan_cfg -chain_count 18\nset_wrapper_cfg enable -chain_count 7\n'
        spec='wrapper chains count is 7; unwrapper chains count is 11.'
        self.assertEqual(wrapper_chain_configuration_problems(script,spec,literal_tcl_words),[])
        self.assertTrue(wrapper_chain_configuration_problems(script.replace('count 18','count 11'),spec,literal_tcl_words))

    def test_unrequested_and_existing_partition_table_behaviors_are_preserved(self):
        self.assertEqual(wrapper_chain_configuration_problems(self.script, "Configure scan.", literal_tcl_words), [])
        spec = "| 分区 | chain_count |\n|---|---|\n| renamed_partition | 2 |"
        actual = rows(2, 0)
        for row in actual:
            row["Partition"] = "renamed_partition"
        self.assertEqual(chain_problems(actual, spec), [])

    def test_report_row_filter_default_preserves_all_data_exactly(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "scan_chain.rpt"
            source.write_text(table(rows(3, 2)))
            required = {"Chain", "Length", "Input", "Output", "Partition"}
            original = list(report_rows(source, required))
            self.assertEqual(list(report_rows(source, required, row_filter=None)), original)
            self.assertEqual(list(report_rows(source, required, row_filter=lambda line: True)), original)

    def test_report_row_filter_keeps_header_detection_and_actual_source_line(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "scan_chain.rpt"
            source.write_text(table(rows(3, 2)))
            required = {"Chain", "Length", "Input", "Output", "Partition"}
            original = list(report_rows(source, required))
            filtered = list(report_rows(source, required, row_filter=lambda line: "I renamed_1" in line))
            self.assertEqual(filtered, [original[1]])
            self.assertEqual(filtered[0]["line"], 4)
            self.assertEqual(filtered[0]["source"], str(source))


if __name__ == "__main__":
    unittest.main()
