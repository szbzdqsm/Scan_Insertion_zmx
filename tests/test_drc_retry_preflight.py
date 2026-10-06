"""Narrow retry rejection from actual DRC codes and explicit configurations only."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "agent"))
import scan_agent
from dofile_recipe import configure_floating_inputs
from drc_retry_preflight import unchanged_control_retry_problems


class DRCRetryPreflight(unittest.TestCase):
    def setUp(self):
        self.previous = (
            "load_lib {/input/cells.lib}\nload_netlist -top top {/input/top.v}\npresent_design top\n"
            "set_scan_signal -type clock -port clk -off_state 0\n"
            "set_scan_signal -type reset -port rst_n -off_state 1\n"
            "set_scan_signal -type constant -port mode -value 1\n"
            "set_scan_signal -type scan_enable -port se -off_state 0 -usage all\n"
            "set_scan_drc_cfg -clock_gating_init_cycles 1\n"
            "set_dft_clock_gating_cfg -test_enable_pin TE\n"
            "set_scan_cfg -si_port_format si%d -so_port_format so%d -max_length 100 -chain_count 4\n"
            "examine_scan_drc\ninsert_dft_logic\nrpt_scan_chain -file /output/R1/chain.rpt\n"
            "dump_netlist -file /output/R1/post.v\nexit\n")

    def problems(self, candidate, previous=None, codes=None, edits=None):
        return unchanged_control_retry_problems(previous or self.previous, candidate,
                                                {"DFTR9"} if codes is None else codes,
                                                netlist_edits=edits, words_for=scan_agent.literal_tcl_words)

    def test_reports_ports_count_and_length_alone_cannot_repair_clock_control(self):
        candidate = self.previous.replace("/output/R1", "/output/R2").replace("si%d", "new_si%d")
        candidate = candidate.replace("so%d", "new_so%d").replace("-max_length 100", "-max_length 50")
        candidate = candidate.replace("-chain_count 4", "-chain_count 20") + "# changed only comments\n"
        self.assertTrue(self.problems(candidate))

    def test_compiler_readded_identical_pseudo_clocks_do_not_count_as_a_repair(self):
        pins = {"top": ["u_gate/clk_out", "u_other/clk_out"]}
        previous, _ = configure_floating_inputs(self.previous, pins)
        candidate, _ = configure_floating_inputs(self.previous.replace("/output/R1", "/output/R2"), pins)
        self.assertTrue(self.problems(candidate, previous=previous))

    def test_real_control_changes_are_allowed(self):
        for old, new in (("-port clk", "-port other_clk"), ("-port rst_n -off_state 1", "-port rst_n -off_state 0"),
                         ("-port mode -value 1", "-port mode -value 0"), ("-usage all", "-usage scan"),
                         ("-clock_gating_init_cycles 1", "-clock_gating_init_cycles 4"), ("-test_enable_pin TE", "-test_enable_pin SE")):
            with self.subTest(new=new):
                self.assertEqual(self.problems(self.previous.replace(old, new)), [])

    def test_other_substantive_dft_or_input_changes_are_allowed(self):
        for candidate in (self.previous.replace("/input/top.v", "/input/other.v"),
                          self.previous.replace("present_design top", "present_design other"),
                          self.previous.replace("insert_dft_logic", "set_wrapper_cfg enable\ninsert_dft_logic"),
                          self.previous.replace("insert_dft_logic", "load_ctl -module ip /input/ip.ctl\ninsert_dft_logic"),
                          self.previous.replace("insert_dft_logic", "set_scan_element false {U1}\ninsert_dft_logic"),
                          self.previous.replace("insert_dft_logic", "set_scan_cell_mapping DFF SFF\ninsert_dft_logic"),
                          self.previous.replace("-chain_count 4", "-chain_count 4 -internal_clocks multi")):
            with self.subTest(candidate=candidate):
                self.assertEqual(self.problems(candidate), [])

    def test_proposed_netlist_edits_are_left_to_the_eqy_admission_gate(self):
        self.assertEqual(self.problems(self.previous, edits=[{"path": "netlist/top.v"}]), [])

    def test_connectivity_diagnostic_without_full_insertion_is_allowed(self):
        candidate = self.previous.replace("insert_dft_logic", "get_pins -of_objects {u_gate}\nget_property {u_gate/CK} net_name")
        self.assertEqual(self.problems(candidate), [])
        self.assertEqual(self.problems(self.previous.replace("insert_dft_logic", "insert_dft_logic -replace_only")), [])
        self.assertTrue(self.problems(self.previous.replace("insert_dft_logic", "get_pins -of_objects {u_gate}\ninsert_dft_logic")))

    def test_adding_full_insertion_after_an_unresolved_diagnostic_needs_a_real_change(self):
        diagnostic = self.previous.replace("insert_dft_logic", "get_pins -of_objects {u_gate}")
        self.assertTrue(self.problems(self.previous, previous=diagnostic))

    def test_dynamic_controls_and_unknown_tcl_are_not_guessed(self):
        for candidate in (self.previous.replace("-port clk", "-port $selected_clock"),
                          self.previous.replace("-port clk", "-port [get_ports clk*]"),
                          self.previous.replace("set_scan_signal -type clock -port clk -off_state 0",
                                                "if {$condition} {set_scan_signal -type clock -port clk -off_state 0}"),
                          self.previous.replace("insert_dft_logic", "source /input/extra.tcl\ninsert_dft_logic")):
            with self.subTest(candidate=candidate):
                self.assertEqual(self.problems(candidate), [])

    def test_only_actual_unpermitted_target_rules_trigger_the_guard(self):
        self.assertEqual(self.problems(self.previous, codes=set()), [])
        self.assertEqual(self.problems(self.previous, codes={"DFTR10", "DFTR2"}), [])
        for codes in ({"DFTR1"}, {"DFTR8"}, {"DFTR-9"}):
            with self.subTest(codes=codes):
                self.assertTrue(self.problems(self.previous, codes=codes))

    def test_literal_option_formatting_is_not_a_control_change(self):
        candidate = self.previous.replace("set_scan_signal -type clock -port clk -off_state 0",
                                           'set_scan_signal -off_state 0 -port {clk} -type "clock"')
        self.assertTrue(self.problems(candidate))

    def test_output_only_bindings_and_readonly_probe_bindings_are_irrelevant(self):
        previous = "set out_dir /output/R1\n" + self.previous.replace("/output/R1/post.v", "$out_dir/post.v")
        candidate = previous.replace("set out_dir /output/R1", "set out_dir /output/R2")
        candidate = candidate.replace("insert_dft_logic", "set observed [get_pins -of_objects {u_gate}]\nputs $observed\ninsert_dft_logic")
        self.assertTrue(self.problems(candidate, previous=previous))

    def test_report_argument_that_may_execute_a_control_is_not_ignored(self):
        candidate = self.previous.replace("rpt_scan_chain -file /output/R1/chain.rpt",
                                           "rpt_scan_chain -file [set_scan_signal -type clock -port new_clk]")
        self.assertEqual(self.problems(candidate), [])

    def test_unknown_dynamic_clock_gating_configuration_opts_out(self):
        candidate = self.previous.replace("-test_enable_pin TE", "-exclude_elements [get_cells -hier gated*]")
        self.assertEqual(self.problems(candidate), [])


if __name__ == "__main__":
    unittest.main()
