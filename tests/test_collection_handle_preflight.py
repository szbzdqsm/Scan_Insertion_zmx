"""Regress the observed exclusion failure; keep valid native collection use."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'agent'))
import scan_agent as agent


class CollectionHandlePreflightTests(unittest.TestCase):
    query = 'set selected [get_obj_insts -hier -filter {full_name =~ core/* && full_name !~ *keep*}]\n'
    bad = query + '''set excluded {}
cluster_foreach cell $selected {
    set name [get_property $cell full_name]
    if {![string match *keep* $name]} {
        lappend excluded $cell
    }
}
if {[llength $excluded] > 0} {
    set_scan_element false $excluded
}
'''

    def test_rejects_list_of_collection_handles(self):
        errors = agent.collection_handle_list_problems(self.bad)
        self.assertEqual(len(errors), 1)
        self.assertIn('COM-2003', errors[0])
        self.assertIn('requirement_mapping', errors[0])

    def test_rejects_alias_iteration_and_guarded_loop(self):
        script = self.bad.replace('cluster_foreach', 'foreach_in_collection')
        script = 'if {[cluster_length $selected] > 0} {\n' + script + '}\n'
        self.assertEqual(len(agent.collection_handle_list_problems(script)), 1)

    def test_direct_filtered_collection_is_valid(self):
        script = self.query + 'if {[cluster_length $selected] > 0} {\nset_scan_element false $selected\n}\n'
        self.assertEqual(agent.collection_handle_list_problems(script), [])

    def test_applying_command_to_iterator_inside_loop_is_valid(self):
        script = self.query + 'cluster_foreach cell $selected {\nset_scan_element false $cell\n}\n'
        self.assertEqual(agent.collection_handle_list_problems(script), [])

    def test_actual_instance_names_are_valid(self):
        script = self.bad.replace('lappend excluded $cell', 'lappend excluded $name')
        self.assertEqual(agent.collection_handle_list_problems(script), [])

    def test_rebinding_list_to_collection_is_valid(self):
        script = self.bad.replace('if {[llength $excluded]',
                                  'set excluded [get_cells -hier core/*]\nif {[llength $excluded]')
        self.assertEqual(agent.collection_handle_list_problems(script), [])

    def test_iterator_rebound_to_name_is_valid(self):
        script = self.bad.replace('lappend excluded $cell',
                                  'set cell [get_property $cell full_name]\n        lappend excluded $cell')
        self.assertEqual(agent.collection_handle_list_problems(script), [])

    def test_conditional_iterator_rebind_is_not_assumed_to_remain_handle(self):
        script = self.bad.replace('lappend excluded $cell',
                                  'if {1} {\nset cell [get_property $cell full_name]\n}\n        lappend excluded $cell')
        self.assertEqual(agent.collection_handle_list_problems(script), [])

    def test_unexecuted_constant_false_body_is_not_rejected(self):
        self.assertEqual(agent.collection_handle_list_problems('if {0} {\n' + self.bad + '}\n'), [])

    def test_constant_false_with_else_is_not_assumed_to_execute_bad_branch(self):
        script = self.query + 'if {0} {\n' + self.bad + '} else {\nset_scan_element false $selected\n}\n'
        self.assertEqual(agent.collection_handle_list_problems(script), [])

    def test_unknown_collection_source_is_not_guessed(self):
        script = self.bad.replace(self.query, 'set selected [custom_collection_source]\n')
        self.assertEqual(agent.collection_handle_list_problems(script), [])

    def test_comments_and_dynamic_scripts_are_not_guessed(self):
        self.assertEqual(agent.collection_handle_list_problems('# ' + self.bad.replace('\n', '\n# ')), [])
        self.assertEqual(agent.collection_handle_list_problems('source overrides.tcl\n' + self.bad), [])


if __name__ == '__main__':
    unittest.main()
