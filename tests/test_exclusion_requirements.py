"""Task-derived exclusion scope checks; no model, tool or answer inputs."""
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'agent'))
import scan_agent as agent
from exclusion_requirements import debug_domain_source_context, exclusion_configuration_problems, exclusion_report_problems, subtree_exclusion_requirements
from source_hierarchy import source_hierarchy_hints
import json


class ExclusionRequirementTests(unittest.TestCase):
    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root=Path(self.temporary.name)
        self.report=self.root/'rpt_scan_element.audit.rpt'
        self.spec='对 Hinstance：`outer/ctrl` 下的所有可扫描单元，除了 `outer/ctrl/keep*`，其余均不允许参与扫描链。'
        self.script='present_design renamed\nset_scan_signal -type clock -port cadence -off_state 0\n'

    def write(self, rows):
        headers=['Name','Type','Length','InstanceName','SiSoClocks','ClockEdge','ObjState']
        widths=[16,12,10,72,24,16,36]
        text=''.join(f'{x:<{w}}' for x,w in zip(headers,widths))+'\n'
        for name,state,clock in rows:
            values=[name.split('/')[-1],'dff','1',name,clock,'(+)',state]
            text+=''.join(f'{x:<{w}}' for x,w in zip(values,widths))+'\n'
        self.report.write_text(text)

    def check(self,spec=None):
        return exclusion_report_problems([self.report],self.spec if spec is None else spec,self.script,agent.literal_tcl_words)

    def test_task_paths_and_exceptions_are_derived_without_case_names(self):
        self.assertEqual(subtree_exclusion_requirements(self.spec),[{'prefix':'outer/ctrl','exceptions':['outer/ctrl/keep*']}])
        self.assertEqual(subtree_exclusion_requirements('例如：'+self.spec),[])

    def test_debug_source_context_accepts_actual_list_of_module_records(self):
        path=self.root/'arbitrary.v'
        path.write_text('module actual_jtag_sync(input cadence);\ncell unit0 (.CLK(cadence));\nendmodule\n')
        hints=source_hierarchy_hints([path],{'cell'})
        context=json.loads(debug_domain_source_context([path],'JTAG 域（TAP 状态机）不纳入扫描链',hints))
        self.assertTrue(context['source_excerpts'])
        self.assertTrue(any('.CLK(cadence)' in item['literal'] for item in context['source_excerpts']))
        self.assertFalse(context['roles_proved'])

    def test_parent_selector_cannot_preserve_descendant_exceptions(self):
        script=self.script+'set selected [get_obj_insts -hier -filter {full_name =~ *outer/ctrl* && full_name !~ *keep*}]\nif {[cluster_length $selected] > 0} {set_scan_element false $selected}\n'
        self.assertTrue(exclusion_configuration_problems(script,self.spec,agent.literal_tcl_words))

    def test_sequential_descendant_selector_avoids_recursive_parent_selection(self):
        script=self.script+'set_scan_element false [get_obj_insts -hier -filter {full_name =~ *outer/ctrl* && full_name !~ *keep* && is_sequential == true}]\n'
        self.assertEqual(exclusion_configuration_problems(script,self.spec,agent.literal_tcl_words),[])

    def test_actual_exception_must_not_be_user_excluded(self):
        self.write([('outer/ctrl/drop0','user_defined_nonscannable','cadence'),('outer/ctrl/keep0','user_defined_nonscannable','cadence')])
        self.assertTrue(any('exception' in item for item in self.check()))

    def test_keep_and_drop_states_prove_actual_scope(self):
        self.write([('outer/ctrl/drop0','user_defined_nonscannable','cadence'),('outer/ctrl/keep0','scannable','cadence')])
        self.assertEqual(self.check(),[])

    def test_other_subtree_does_not_satisfy_scope(self):
        self.write([('outer/ctrl_extra/keep0','scannable','cadence')])
        self.assertTrue(any('No actual' in item for item in self.check()))

    def test_explicit_design_prefix_is_handled_without_arbitrary_suffix_matching(self):
        self.write([('/renamed/outer/ctrl/drop0','user_defined_nonscannable','cadence'),('/renamed/outer/ctrl/keep0','scannable','cadence')])
        self.assertEqual(self.check(),[])

    def test_excluded_descendant_cannot_remain_scannable(self):
        self.write([('outer/ctrl/drop0','scannable','cadence'),('outer/ctrl/keep0','scannable','cadence')])
        self.assertTrue(any('lacks explicit exclusion' in item for item in self.check()))

    def test_debug_exclusion_must_not_disable_clocked_functional_synchronizer(self):
        self.write([('debug/i_tap/state0','user_defined_nonscannable','-'),('debug/core_sync/sync0','user_defined_nonscannable','cadence')])
        self.assertTrue(any('functional FF' in item for item in self.check('JTAG 域（TAP 状态机）不纳入扫描链')))

    def test_debug_exclusion_accepts_kept_functional_synchronizer(self):
        self.write([('debug/i_tap/state0','user_defined_nonscannable','-'),('debug/core_sync/sync0','scannable','cadence')])
        self.assertEqual(self.check('JTAG 域（TAP 状态机）不纳入扫描链'),[])

    def test_other_clock_topology_is_not_guessed(self):
        self.write([('debug/i_tap/state0','user_defined_nonscannable','-'),('debug/core_sync/sync0','user_defined_nonscannable','other_clock')])
        self.assertEqual(self.check('JTAG 域（TAP 状态机）不纳入扫描链'),[])

    def test_report_is_needed_for_explicit_task_scope(self):
        self.assertTrue(exclusion_report_problems([],self.spec,self.script,agent.literal_tcl_words))
        self.assertEqual(exclusion_report_problems([],'No exclusions requested.',self.script,agent.literal_tcl_words),[])


if __name__=='__main__':
    unittest.main()
