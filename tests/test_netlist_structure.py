"""Verify read-only structural hints against small actual Verilog connections."""
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "agent"))
from netlist_structure import reset_polarity_hints, shift_register_context  # noqa: E402


class StructureTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="scan-structure-")
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def test_chain_crosses_named_bus_hierarchy_with_correlated_indices(self):
        lib = self.root / "cells.lib"
        lib.write_text('cell ("sky130_fd_sc_hd__sdfxtp_1") {\npin ("SCD") {}\npin ("SCE") {}\n}\n')
        source = self.root / "input.v"
        text = "module child(input clk, input [1:0] d, output [1:0] q);\n"
        for bit in range(2):
            text += f"sky130_fd_sc_hd__dfxtp_1 \\middle_reg[{bit}] (.D(d[{bit}]), .CLK(clk), .Q(m[{bit}]));\n"
            text += f"sky130_fd_sc_hd__dfxtp_1 \\end_reg[{bit}] (.D(m[{bit}]), .CLK(clk), .Q(q[{bit}]));\n"
        text += "endmodule\nmodule top(input clk,se, input [1:0] d, output [1:0] q);\n"
        for bit in range(2):
            text += f"sky130_fd_sc_hd__sdfxtp_1 \\seed_reg[{bit}] (.D(d[{bit}]), .CLK(clk), .Q(start[{bit}]), .SCE(se));\n"
        text += "child u_blk (.clk(clk), .d(start), .q(q));\nendmodule\n"
        source.write_text(text)
        before = source.read_bytes()
        context = shift_register_context([source], minimum=3, libraries=[lib])
        rows = json.loads(context.split("\n", 1)[1])
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["root"], "top")
        self.assertEqual(rows[0]["start_template"], "seed_reg[{i0}]")
        self.assertEqual(rows[0]["end_template"], "u_blk/end_reg[{i0}]")
        self.assertEqual(rows[0]["index_tuples"], [[0], [1]])
        self.assertEqual(rows[0]["length"], 3)
        self.assertEqual(source.read_bytes(), before)

    def test_branch_or_different_clock_cannot_form_an_unbranched_segment(self):
        source = self.root / "input.v"
        prefix = ("module top(input clk,clk2,se,d, output q);\n"
                  "sky130_fd_sc_hd__sdfxtp_1 first (.D(d), .CLK(clk), .Q(start), .SCE(se), .SCD(d));\n")
        source.write_text(prefix +
                         "sky130_fd_sc_hd__dfxtp_1 second (.D(start), .CLK(clk2), .Q(q));\nendmodule\n")
        self.assertEqual(json.loads(shift_register_context([source], minimum=2).split("\n", 1)[1]), [])
        source.write_text(prefix +
                         "sky130_fd_sc_hd__dfxtp_1 second (.D(start), .CLK(clk), .Q(q));\n"
                         "sky130_fd_sc_hd__dfxtp_1 third (.D(start), .CLK(clk), .Q(other));\nendmodule\n")
        self.assertEqual(json.loads(shift_register_context([source], minimum=2).split("\n", 1)[1]), [])

    def test_reset_inactive_level_comes_from_function_and_inversion(self):
        library = self.root / "cells.lib"
        library.write_text('cell (sky130_fd_sc_hd__dfrtp_1) {\nclear : "(!RESET_B)";\n}\n')
        source = self.root / "input.v"
        common = ("module child(input clk,rb,d,output q);\n"
                  "sky130_fd_sc_hd__dfrtp_1 ff (.CLK(clk), .D(d), .RESET_B(rb), .Q(q));\nendmodule\n")
        source.write_text(common + "module top(input clk,rst,d,output q);\nchild u (.clk(clk),.rb(rst),.d(d),.q(q));\nendmodule\n")
        self.assertEqual(reset_polarity_hints([source], [library])["top"]["rst"]["inactive_level"], 1)
        source.write_text(common + "module top(input clk,rst,d,output q);\n"
                         "sky130_fd_sc_hd__clkinv_1 inv (.A(rst), .Y(rb));\n"
                         "child u (.clk(clk),.rb(rb),.d(d),.q(q));\nendmodule\n")
        self.assertEqual(reset_polarity_hints([source], [library])["top"]["rst"]["inactive_level"], 0)


if __name__ == "__main__":
    unittest.main()
