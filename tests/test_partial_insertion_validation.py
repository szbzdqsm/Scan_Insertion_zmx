from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "agent"))
from partial_insertion_validation import (partial_flow_artifact_paths,
                                         partial_insertion_problems,
                                         partial_insertion_requirements,
                                         partial_insertion_validation)


LIBRARY = '''library (demo) {
cell (Gate) { clock_gating_integrated_cell : "latch_posedge";
 pin(C) { direction : input; clock_gate_clock_pin : true; }
 pin(E) { direction : input; clock_gate_enable_pin : true; }
 pin(T) { direction : input; clock_gate_test_pin : true; }
 pin(O) { direction : output; clock_gate_out_pin : true; function : "C&E"; }
}
cell (Ordinary) { ff(IQ,IQ_N) { clocked_on : "C"; next_state : "D"; }
 pin(C) {direction:input;} pin(D) {direction:input;} pin(Q) {direction:output;function:"IQ";}
}
cell (Scan) { ff(IQ,IQ_N) {clocked_on:"C";next_state:"(D&!S)+(I&S)";}
 pin(C) {direction:input;} pin(D) {direction:input;} pin(Q) {direction:output;function:"IQ";}
 pin(I) {direction:input;} pin(S) {direction:input;}
 test_cell() {pin(I) {signal_type:test_scan_in;} pin(S) {signal_type:test_scan_enable;}
              pin(Q) {signal_type:test_scan_out;}}
}
cell (ScanVariant) { ff(IQ,IQ_N) {clocked_on:"C";next_state:"(D&!S)+(I&S)";}
 pin(C) {direction:input;} pin(D) {direction:input;} pin(Q) {direction:output;function:"IQ";}
 pin(QB) {direction:output;function:"IQ_N";} pin(I) {direction:input;signal_type:test_scan_in;}
 pin(S) {direction:input;signal_type:test_scan_enable;} test_cell() {pin(Q) {signal_type:test_scan_out;}}
}
cell (WrongScan) { ff(IQ,IQ_N) {clocked_on:"!C";next_state:"(D&!S)+(I&S)";}
 pin(C) {direction:input;} pin(D) {direction:input;} pin(Q) {direction:output;function:"IQ";}
 pin(I) {direction:input;signal_type:test_scan_in;} pin(S) {direction:input;signal_type:test_scan_enable;}
}
cell (Buffer) {pin(A) {direction:input;} pin(Z) {direction:output;function:"A";}}
cell (Inverter) {pin(A) {direction:input;} pin(Z) {direction:output;function:"!A";}}
cell (TieLow) {pin(Z) {direction:output;function:"0";}}
}'''

SPEC = '''# 任务
仅替换，不插链，不构建扫描链。
- Top 模块: Chip
- 原本 TE 绑定常数 0 且不在 `debug` 实例下的 ICG，由顶层端口 `gate_control` 驱动；其余 ICG 保持原连接
- 最终 `core/pll` 实例内部的所有触发器均为普通 DFF；其它实例在工具可替换时使用 SFF。
| DFF | SFF |
| `Ordinary` | `Scan` |
## 输出文件
| `stage_replace.v` | DFF→SFF 替换后 |
| `stage_final.v` | SFF→DFF 回替后（最终网表） |
'''


def netlist(stage="source", *, control="gate_control", excluded="1'b0", ordinary="Scan",
            extra="", output="gclk", scan_input="1'b0", ff_data="d"):
    is_source = stage == "source"
    ff_type = "Ordinary" if is_source else ordinary
    pll_type = "Ordinary" if stage == "final" else "Scan"
    pins = "" if ff_type == "Ordinary" else f", .I({scan_input}), .S(1'b0)"
    pll_pins = "" if pll_type == "Ordinary" else ", .I(1'b0), .S(1'b0)"
    return f'''module Chip(input c, input e, input gate_control, input wrong, input d, output q);
 wire gclk, other, zero_signal;
 Gate targeted (.C(c), .E(e), .T({"1'b0" if is_source else control}), .O({output}));
 TieLow zero_driver (.Z(zero_signal));
 Gate functional (.C(c), .E(e), .T(zero_signal), .O(other));
 {ff_type} f (.C(c), .D({ff_data}), .Q(q){pins});
 Ordinary not_replaced (.C(c), .D(d), .Q());
 Debug debug (.c(c), .e(e), .t({"1'b0" if is_source else excluded}));
 Core core (.c(c), .d(d));
 {extra}
endmodule
module Debug(input c, input e, input t);
 wire o; Gate original (.C(c), .E(e), .T(t), .O(o));
endmodule
module Core(input c, input d); Pll pll (.c(c), .d(d)); endmodule
module Pll(input c, input d);
 wire q; {pll_type} existing (.C(c), .D(d), .Q(q){pll_pins});
endmodule
'''


class PartialInsertionValidation(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.lib = self.root / "library.lib"
        self.source, self.middle, self.final = [self.root / name for name in ("source.v", "stage_replace.v", "stage_final.v")]
        self.lib.write_text(LIBRARY)
        self.source.write_text(netlist())
        self.middle.write_text(netlist("middle"))
        self.final.write_text(netlist("final"))

    def tearDown(self):
        self.temp.cleanup()

    def validate(self, spec=SPEC, **kwargs):
        return partial_insertion_validation([self.source], [self.final], [self.lib], spec,
                                            replacement_paths=[self.middle], **kwargs)

    def test_task_names_stages_and_scopes_are_extracted_without_case_constants(self):
        req = partial_insertion_requirements(SPEC)
        self.assertTrue(req["applicable"])
        self.assertEqual(req["top"], "Chip")
        self.assertEqual(req["control_port"], "gate_control")
        self.assertEqual(req["icg_excluded_scopes"], ["debug"])
        self.assertEqual(req["unscan_scopes"], ["core/pll"])
        self.assertEqual(req["ff_pairs"], {"Ordinary": "Scan"})
        self.assertEqual(req["final_netlist_names"], ["stage_final.v"])
        self.assertEqual(req["replacement_netlist_names"], ["stage_replace.v"])
        self.assertEqual(partial_insertion_requirements("Build scan chains")["applicable"], False)

    def test_good_partial_result_and_tool_skipped_ff_pass(self):
        result = self.validate()
        self.assertEqual(result["status"], "pass", result)
        self.assertEqual(result["counts"]["required_icg_reconnections"], 1)
        self.assertEqual(result["counts"]["preserved_icg"], 2)
        self.assertEqual(result["counts"]["source_ff"], 3)
        self.assertEqual(result["counts"]["final_scan_ff"], 1)

    def test_real_liberty_buffer_and_inverter_trace_the_required_input(self):
        for kind in ("Buffer", "Inverter"):
            self.final.write_text(netlist("final", control="buffered", extra=f"wire buffered; {kind} b (.A(gate_control), .Z(buffered));"))
            self.assertEqual(self.validate()["status"], "pass", kind)

    def test_declared_port_is_not_connection_proof(self):
        self.final.write_text(netlist("final", control="wrong"))
        self.assertIn("task-required", " ".join(self.validate()["problems"]))
        self.final.write_text(netlist("final", control="undriven", extra="wire undriven;"))
        self.assertEqual(self.validate()["status"], "unknown")

    def test_debug_exception_is_preserved_and_functional_tie_low_is_not_retargeted(self):
        self.final.write_text(netlist("final", excluded="gate_control"))
        self.assertIn("outside reconnect targets", " ".join(self.validate()["problems"]))
        self.final.write_text(netlist("final").replace(".T(zero_signal)", ".T(gate_control)"))
        self.assertIn("outside reconnect targets", " ".join(self.validate()["problems"]))

    def test_icg_clock_enable_type_count_and_output_are_checked(self):
        for before, after, expected in ((".C(c), .E(e)", ".C(wrong), .E(e)", "functional input"),
                                         (".C(c), .E(e)", ".C(c), .E(wrong)", "functional input"),
                                         ("Gate targeted", "Buffer targeted", "identities")):
            self.final.write_text(netlist("final").replace(before, after, 1))
            self.assertIn(expected, " ".join(self.validate()["problems"]))
        self.final.write_text(netlist("final", output="reconnected", extra="wire reconnected;"))
        self.assertIn("output connection", " ".join(self.validate()["problems"]))

    def test_global_back_replacement_cannot_pass_on_total_ff_count(self):
        self.final.write_text(netlist("final", ordinary="Ordinary"))
        result = self.validate()
        self.assertEqual(result["counts"]["source_ff"], result["counts"]["final_ff"])
        self.assertIn("remained ordinary", " ".join(result["problems"]))
        self.assertEqual(result["evidence"]["ff_violation_count"], 1)

    def test_non_scan_scope_must_contain_only_ordinary_ffs(self):
        self.final.write_text(netlist("middle"))
        self.assertIn("still contains a scan FF", " ".join(self.validate()["problems"]))

    def test_equivalent_library_variant_can_add_an_unused_inverted_output(self):
        self.final.write_text(netlist("final", ordinary="ScanVariant"))
        self.assertEqual(self.validate()["status"], "pass")
        self.final.write_text(netlist("final", ordinary="WrongScan"))
        self.assertIn("functional mapping", " ".join(self.validate()["problems"]))

    def test_ff_functional_data_connection_must_be_preserved(self):
        self.final.write_text(netlist("final", ff_data="wrong"))
        self.assertIn("functional input changed: D", " ".join(self.validate()["problems"]))

    def test_new_chain_edge_is_rejected_even_without_new_ports(self):
        self.final.write_text(netlist("final", scan_input="q"))
        result = self.validate()
        self.assertIn("chain connections", " ".join(result["problems"]))
        self.assertEqual(result["evidence"]["new_scan_chain_edges"], [("f", "f")])

    def test_unsupported_reachable_hdl_and_conflicting_drivers_abstain(self):
        self.final.write_text(netlist("final", extra="always @(posedge c) begin end"))
        self.assertEqual(self.validate()["status"], "unknown")
        self.final.write_text(netlist("final", control="both", extra="wire both; Buffer b1 (.A(gate_control), .Z(both)); Buffer b2 (.A(wrong), .Z(both));"))
        self.assertEqual(self.validate()["status"], "unknown")
        self.assertTrue(partial_insertion_problems([self.source], [self.final], [self.lib], SPEC, replacement_paths=[self.middle]))

    def test_missing_ambiguous_and_preferred_artifacts(self):
        run = self.root / "run"
        reports, delivered = run / "reports", run / "deliverables"
        reports.mkdir(parents=True); delivered.mkdir()
        self.assertEqual(partial_flow_artifact_paths(run, SPEC), ([], []))
        for folder in (reports, delivered):
            (folder / "stage_final.v").write_text("final")
            (folder / "stage_replace.v").write_text("middle")
        self.assertEqual(partial_flow_artifact_paths(run, SPEC), ([delivered / "stage_final.v"], [delivered / "stage_replace.v"]))
        nested = delivered / "nested"; nested.mkdir()
        (nested / "stage_final.v").write_text("different")
        self.assertEqual(partial_flow_artifact_paths(run, SPEC)[0], [])
        result = partial_insertion_validation([self.source], [self.final], [self.lib], SPEC, replacement_paths=[])
        self.assertIn("missing or ambiguous", " ".join(result["unknown"]))


if __name__ == "__main__":
    unittest.main()
