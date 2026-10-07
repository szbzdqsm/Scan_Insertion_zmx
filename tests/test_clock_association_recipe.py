from pathlib import Path
import sys
import unittest
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "agent"))
from clock_association_recipe import clock_association_problems, configure_clock_associations
from scan_agent import literal_tcl_words


class ClockAssociationRecipe(unittest.TestCase):
    def setUp(self):
        self.hint = {"root": "chip", "root_primary_clock_candidate": "main_clk",
                     "clock_output_candidates": ["clock_sub/gate/O", "clock_sub/local_clk"],
                     "enable_latch_q_pin": "clock_sub/gate/en_latch/Q"}
        self.spec = "CE latch 的时钟值传播正确"
        self.script = "present_design chip\nset_scan_signal -type clock -port main_clk -off_state 0\nexamine_scan_drc\nexit\n"

    def compile(self, script=None, spec=None, hint=None):
        return configure_clock_associations(script or self.script, [hint or self.hint],
                                             self.spec if spec is None else spec, literal_tcl_words)

    def test_source_relation_is_compiled_and_idempotent(self):
        result, refs = self.compile()
        self.assertIn("-associated_internal_clocks {clock_sub/local_clk}", result)
        self.assertEqual(len(refs), 1)
        self.assertEqual(self.compile(result)[0], result)
        self.assertNotIn("en_latch/Q", result)

    def test_unrequested_or_other_root_relation_is_not_injected(self):
        self.assertEqual(self.compile(spec="Generic insertion"), (self.script, []))
        self.assertEqual(self.compile(hint=dict(self.hint, root="another_root")), (self.script, []))

    def test_ambiguous_or_dynamic_declaration_stays_with_the_model(self):
        duplicate = self.script.replace("examine_scan_drc", "set_scan_signal -type clock -port main_clk -off_state 0\nexamine_scan_drc")
        self.assertEqual(self.compile(duplicate), (duplicate, []))
        dynamic = self.script.replace("main_clk", "$clock")
        self.assertEqual(self.compile(dynamic), (dynamic, []))
        shadow = self.script.replace("examine_scan_drc", "set_scan_signal -type constant -port main_clk -constant_value 0\nexamine_scan_drc")
        self.assertEqual(self.compile(shadow), (shadow, []))

    def test_literal_load_top_proves_the_design_without_present_design(self):
        base = self.script.replace("present_design chip", "load_netlist /input/netlist/chip.v -top {chip}")
        result, refs = self.compile(base)
        self.assertEqual(len(refs), 1)
        self.assertIn("-associated_internal_clocks {clock_sub/local_clk}", result)
        for header in ("load_netlist /input/chip.v -top $root", "present_design $root"):
            dynamic = self.script.replace("present_design chip", header)
            self.assertEqual(self.compile(dynamic), (dynamic, []))

    def test_output_guards_and_file_join_do_not_hide_literal_clocks(self):
        guard = ('set output_dir /output\n'
                 'if {![file exists [file join $output_dir reports]]} {\n'
                 '    file mkdir [file join $output_dir reports]\n'
                 '} else { puts "reports already exist" }\n')
        footer = 'rpt_scan_signal > [file join $output_dir reports signal.rpt]\n'
        base = guard + self.script.replace("exit\n", footer + "exit\n")
        result, refs = self.compile(base)
        self.assertEqual(len(refs), 1)
        self.assertTrue(result.startswith(guard))
        self.assertIn(footer, result)

    def test_runtime_input_and_segment_blocks_do_not_hide_literal_clocks(self):
        blocks = ('# Agent literal floating-clock inputs\n'
                  'add_pseudo_pi [list {gate/disconnected_clk}]\n'
                  'set_scan_signal -type clock -port {gate/disconnected_clk} -off_state 0\n'
                  '# End agent floating-clock inputs\n'
                  '# Agent recipe from actual input shift-register connections\n'
                  'foreach coordinates {{0 0} {1 1}} {\n'
                  '    set index [lindex $coordinates 0]\n'
                  '    set_scan_segment shift_$index -access [list scan_data_in [format {register_%d/SI} $index]] -lockup_exists false\n'
                  '}\n'
                  '# End agent shift-register recipe\n')
        base = self.script.replace("examine_scan_drc", blocks + "examine_scan_drc")
        result, refs = self.compile(base)
        self.assertEqual(len(refs), 1)
        self.assertIn(blocks, result)

    def test_known_scan_exclusion_and_partition_configuration_preserve_clock_adaptation(self):
        configuration = ('set targets [get_obj_insts -hier -filter {cell.is_latch == true}]\n'
                         'if {[sizeof_collection $targets] > 0} {\n'
                         '    set_scan_element false $targets\n'
                         '}\n'
                         'set_scan_element false [get_obj_insts -hier {clock_sub/gate/en_latch}]\n'
                         'add_scan_partition local_partition -clocks {main_clk}\n'
                         'set_current_scan_partition local_partition\n'
                         'set_scan_signal -type scan_enable -port shift_en -off_state 0 -usage all\n'
                         'set_dft_clock_gating_cfg -test_enable_pin TE\n'
                         'load_ctl /input/block.ctl\n'
                         'add_dedicated_wrapper_cell_type -design_name wrapper_cell -interface {}\n')
        base = self.script.replace("examine_scan_drc", configuration + "examine_scan_drc")
        for size_command in ("sizeof_collection", "cluster_length"):
            with self.subTest(size_command=size_command):
                candidate = base.replace("sizeof_collection", size_command)
                result, refs = self.compile(candidate)
                self.assertEqual(len(refs), 1)
                self.assertIn(configuration.replace("sizeof_collection", size_command), result)
                self.assertIn("-associated_internal_clocks {clock_sub/local_clk}", result)

    def test_exclusion_guard_cannot_redeclare_clocks_or_call_unknown_tcl(self):
        chunks = (
            'if {[sizeof_collection $targets] > 0} { set_scan_signal -type clock -port main_clk -off_state 1 }',
            'if {[sizeof_collection $targets] > 0} { set_scan_element false [eval $targets] }',
            'if {[sizeof_collection $targets] > 0} { unknown_command $targets }',
            'if {[sizeof_collection $targets] > 0} { add_scan_partition other -clocks {main_clk} }',
        )
        for chunk in chunks:
            with self.subTest(chunk=chunk):
                base = self.script + chunk + "\n"
                self.assertEqual(self.compile(base), (base, []))

    def test_multiline_declaration_is_compiled_without_reformatting_other_commands(self):
        base = self.script.replace("-port main_clk", "\\\n    -port {main_clk}")
        base += 'if {[file exists /output]} { rpt_scan_cfg > /output/cfg.rpt; puts "done; ok" }\n'
        result, refs = self.compile(base)
        self.assertEqual(len(refs), 1)
        self.assertIn("-associated_internal_clocks {clock_sub/local_clk}", result)
        self.assertIn('rpt_scan_cfg > /output/cfg.rpt; puts "done; ok"', result)

    def test_comments_and_literal_semicolons_are_not_dynamic_control(self):
        base = '# Comments may have a semicolon; it is not an executable command\n' + self.script
        base += 'puts "report; saved"\n'
        result, refs = self.compile(base)
        self.assertEqual(len(refs), 1)
        self.assertTrue(result.startswith("# Comments may have a semicolon;"))
        self.assertTrue(result.endswith('puts "report; saved"\n'))

    def test_control_mutations_in_structured_or_unknown_tcl_opt_out(self):
        unsafe_chunks = [
            'if {[file exists /input]} { present_design chip }',
            'if {1} { set_scan_signal -type clock -port main_clk -off_state 1 }',
            'if {[set_scan_signal -type clock -port main_clk -off_state 1]} { puts result }',
            'if $condition { puts result }',
            'foreach port {main_clk} { set_scan_signal -type clock -port $port -off_state 1 }',
            'rpt_scan_signal > [file join /output [eval $code]]',
            'rpt_scan_signal > [file join /output; present_design chip]',
            'source other.tcl',
            'proc other {} { present_design chip }',
            'unknown_command',
            'present_design another_chip',
            'load_netlist /input/other.v -top another_chip',
            # Runtime marker comments do not establish trust in a block body.
            '# Agent audit reports from actual tool state\nif {1} { present_design chip }\n# End agent audit reports',
        ]
        for chunk in unsafe_chunks:
            with self.subTest(chunk=chunk):
                base = self.script + chunk + "\n"
                self.assertEqual(self.compile(base), (base, []))

    def test_existing_actual_clock_association_is_preserved(self):
        base = self.script.replace("-off_state 0", "-off_state 0 -associated_internal_clocks {another_branch/clk}")
        result, _ = self.compile(base)
        self.assertIn("another_branch/clk clock_sub/local_clk", result)

    def test_enable_data_q_is_never_promoted_to_clock(self):
        base = self.script.replace("-off_state 0", "-off_state 0 -associated_internal_clocks {clock_sub/gate/en_latch/Q}")
        with self.assertRaises(ValueError):
            self.compile(base)
        with self.assertRaises(ValueError):
            self.compile(hint=dict(self.hint, clock_output_candidates=[self.hint["enable_latch_q_pin"]]))

    def test_actual_typed_signal_must_prove_the_clock_output(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "scan_signal.rpt"
            headers = ["Port", "SignalType", "AssociatedInternal"]
            def table(output):
                return ''.join(f'{value:<32}' for value in headers) + '\n' + ''.join(
                    f'{value:<32}' for value in ["main_clk", "clock", output]) + '\n'
            script, _ = self.compile()
            path.write_text(table("clock_sub/gate/en_latch/Q"))
            self.assertTrue(clock_association_problems([path], script, [self.hint], self.spec, literal_tcl_words))
            path.write_text(table("clock_sub/local_clk"))
            self.assertEqual(clock_association_problems([path], script, [self.hint], self.spec, literal_tcl_words), [])
            path.write_text(table("clock_sub/local_clk").replace("clock", "reset", 1))
            self.assertTrue(clock_association_problems([path], script, [self.hint], self.spec, literal_tcl_words))


if __name__ == "__main__":
    unittest.main()
