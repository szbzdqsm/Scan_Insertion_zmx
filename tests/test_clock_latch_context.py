"""Source-only clock-latch fixtures: no Tool, Public answers, or generated Tcl."""
import sys
import tempfile
import tracemalloc
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "agent"))
from clock_latch_context import (  # noqa: E402
    _library_shapes, _modules, _source_line, clock_latch_context, clock_latch_hints,
)


LIBRARY = '''library (fixture) {
cell (LAT) {
latch (IQ, IQ_N) {
data_in : "D";
enable : "!GATE_N";
}
pin (D) {
direction : "input";
}
pin (GATE_N) {
direction : "input";
}
pin (Q) {
direction : "output";
function : "IQ";
}
}
cell (AND2) {
pin (A) {
direction : "input";
}
pin (B) {
direction : "input";
}
pin (X) {
direction : "output";
function : "A&B";
}
}
cell (BUF) {
pin (A) {
direction : "input";
}
pin (X) {
direction : "output";
function : "A";
}
}
}
'''

SOURCE = '''module ClockBuffer(input I,CE,output O);
wire enable_latched;
LAT ce_latch(.D(CE),.GATE_N(I),.Q(enable_latched));
AND2 clock_and(.A(enable_latched),.B(I),.X(O));
endmodule
module manager(input source_clock,enable,output out_clock);
ClockBuffer gate_unit(.I(source_clock),.CE(enable),.O(out_clock));
endmodule
module top(input pll,enable,output out_clock);
manager controller(.source_clock(pll),.enable(enable),.out_clock(out_clock));
endmodule
'''


class ClockLatchContextTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="clock-latch-source-")
        self.root = Path(self.temp.name)
        self.source = self.root / "source.v"
        self.lib = self.root / "fixture.lib"
        self.source.write_text(SOURCE)
        self.lib.write_text(LIBRARY)

    def tearDown(self):
        self.temp.cleanup()

    def hints(self):
        return clock_latch_hints([self.source], [self.lib])

    def test_latch_enable_data_and_clock_output_have_distinct_actual_paths(self):
        hints = self.hints()
        self.assertEqual(len(hints), 1)
        hint = hints[0]
        self.assertEqual(hint["root_primary_clock_candidate"], "pll")
        self.assertEqual(hint["clock_input_pin"], "controller/gate_unit/I")
        self.assertEqual(hint["enable_data_pin"], "controller/gate_unit/ce_latch/D")
        self.assertEqual(hint["enable_latch_q_pin"], "controller/gate_unit/ce_latch/Q")
        self.assertEqual(hint["and_clock_output_pin"], "controller/gate_unit/clock_and/X")
        self.assertEqual(hint["clock_output_candidates"],
                         ["controller/gate_unit/O", "controller/out_clock", "out_clock"])
        self.assertEqual(hint["latch_transparent_clock_level"], 0)
        self.assertEqual(hint["module_instance_connections"]["pins"],
                         {"I": "source_clock", "CE": "enable", "O": "out_clock"})
        self.assertEqual(hint["literal_cells"][0]["pins"], {"D": "CE", "GATE_N": "I", "Q": "enable_latched"})

    def test_clock_source_is_taken_from_connections_not_port_names(self):
        self.source.write_text(SOURCE.replace("input pll,enable", "input real_source,enable").replace(".source_clock(pll)", ".source_clock(real_source)"))
        self.assertEqual(self.hints()[0]["root_primary_clock_candidate"], "real_source")

    def test_scalar_assign_and_library_buffer_can_trace_primary_source(self):
        self.source.write_text(SOURCE.replace("manager controller", "wire alias_clock;\nBUF pass_clock(.A(pll),.X(alias_clock));\nmanager controller")
                               .replace(".source_clock(pll)", ".source_clock(alias_clock)"))
        self.assertEqual(self.hints()[0]["root_primary_clock_candidate"], "pll")
        self.source.write_text(SOURCE.replace("manager controller", "wire alias_clock;\nassign alias_clock = pll;\nmanager controller")
                               .replace(".source_clock(pll)", ".source_clock(alias_clock)"))
        self.assertEqual(self.hints()[0]["root_primary_clock_candidate"], "pll")

    def test_unbound_complex_or_internal_clock_source_is_omitted(self):
        for value in ("", "pll & enable", "{pll,enable}", "pll[0]", "unknown_internal"):
            with self.subTest(value=value):
                self.source.write_text(SOURCE.replace(".source_clock(pll)", f".source_clock({value})"))
                self.assertEqual(self.hints(), [])

    def test_complex_latch_function_or_nonconjunction_is_omitted(self):
        for original, replacement in (('"!GATE_N"', '"GATE_N|D"'), ('"A&B"', '"A|B"'), ('"IQ"', '"!IQ"')):
            with self.subTest(replacement=replacement):
                self.lib.write_text(LIBRARY.replace(original, replacement))
                self.assertEqual(self.hints(), [])

    def test_other_clock_operand_or_multiple_matching_and_cells_are_omitted(self):
        self.source.write_text(SOURCE.replace(".B(I)", ".B(CE)"))
        self.assertEqual(self.hints(), [])
        self.source.write_text(SOURCE.replace("AND2 clock_and", "AND2 second_and(.A(enable_latched),.B(I),.X(O));\nAND2 clock_and"))
        self.assertEqual(self.hints(), [])

    def test_duplicate_latch_driver_or_named_binding_is_omitted(self):
        self.source.write_text(SOURCE.replace("LAT ce_latch", "LAT second_latch(.D(CE),.GATE_N(I),.Q(enable_latched));\nLAT ce_latch"))
        self.assertEqual(self.hints(), [])
        self.source.write_text(SOURCE.replace(".source_clock(pll)", ".source_clock(pll),.source_clock(enable)"))
        self.assertEqual(self.hints(), [])

    def test_large_clock_module_and_duplicate_module_definitions_are_omitted(self):
        extra = "".join(f"BUF extra_{index}(.A(I),.X(extra_net_{index}));\n" for index in range(33))
        self.source.write_text(SOURCE.replace("wire enable_latched;", "wire enable_latched;\n" + extra))
        self.assertEqual(self.hints(), [])
        self.source.write_text(SOURCE + "module top(input different);\nendmodule\n")
        self.assertEqual(self.hints(), [])

    def test_context_is_bounded_and_contains_candidates_without_tcl(self):
        context = clock_latch_context([self.source], [self.lib], limit=2000)
        self.assertTrue(context)
        self.assertLessEqual(len(context), 2000)
        self.assertIn("ENABLE DATA", context)
        self.assertIn("verify with actual tool reports", context)
        self.assertNotIn("set_scan_signal", context)
        self.assertEqual(clock_latch_context([self.source], [self.lib], limit=10), "")

    def test_block_comments_do_not_create_source_modules_or_bindings(self):
        self.source.write_text("/*\nmodule fakeClockBuffer(input I,CE,output O);\n" + SOURCE + "*/\n" +
                               SOURCE.replace(".source_clock(pll)", ".source_clock(/*comment*/ pll)"))
        hints = self.hints()
        self.assertEqual(len(hints), 1)
        self.assertEqual(hints[0]["root"], "top")

    def test_source_line_fast_path_preserves_comment_state(self):
        cases = [
            ("\tLAT cell(.D(clock));\n", False, ("\tLAT cell(.D(clock));\n", False)),
            ("  // module fake(); /*\n", False, ("  ", False)),
            ("module top(); /* unfinished\n", False, ("module top(); ", True)),
            ("module fake(); // still inside\n", True, ("", True)),
            ("*/ LAT cell(/* pin comment */ .D(clock)); // ignored\n", True,
             (" LAT cell( .D(clock)); ", False)),
            ("/* one */module top();/* two */endmodule\n", False,
             ("module top();endmodule\n", False)),
            ("*/ // /* not reopened\n", True, (" ", False)),
        ]
        for raw, blocked, expected in cases:
            with self.subTest(raw=raw, blocked=blocked):
                self.assertEqual(_source_line(raw, blocked), expected)

    def test_unselected_module_comments_keep_exact_source_line_numbers(self):
        prefix = '''module unrelated(input data,output result);
BUF pass_data(
  .A(data),
  .X(result));
/*
module hiddenClockBuffer(input I,CE,output O);
*/
endmodule
'''
        self.source.write_text(prefix + SOURCE)
        hints = self.hints()
        self.assertEqual(len(hints), 1)
        hint = hints[0]
        prefix_lines = len(prefix.splitlines())
        self.assertEqual(hint["literal_cells"][0]["line"], prefix_lines + 3)
        self.assertEqual(hint["literal_cells"][1]["line"], prefix_lines + 4)
        self.assertEqual(hint["module_instance_connections"]["line"], prefix_lines + 7)

    def test_selected_pass_still_rejects_duplicate_unselected_modules(self):
        self.source.write_text(SOURCE + "module unrelated();\nendmodule\n" * 2)
        modules = _modules([self.source], _library_shapes([self.lib]),
                           selected={"ClockBuffer", "manager", "top"})
        self.assertEqual(modules, {})

    def test_streams_more_than_64_mib_without_reading_whole_input(self):
        with self.source.open("a") as stream:
            padding = "//" + "x" * (1024 * 1024) + "\n"
            for _ in range(65):
                stream.write(padding)
        self.assertGreater(self.source.stat().st_size, 64 * 1024 * 1024)
        tracemalloc.start()
        try:
            with patch.object(Path, "read_text", side_effect=AssertionError("whole-file read")), \
                    patch.object(Path, "read_bytes", side_effect=AssertionError("whole-file read")):
                hints = self.hints()
            _, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
        self.assertEqual(len(hints), 1)
        self.assertLess(peak, 16 * 1024 * 1024)


if __name__ == "__main__":
    unittest.main()
