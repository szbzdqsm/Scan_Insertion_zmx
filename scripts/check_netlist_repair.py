"""Exercise actual private editing, EQY, admission and rejection on small fixtures."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "agent"))
from netlist_repair import RepairRejected, prepare_repair  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=ROOT / "outputs")
    parser.add_argument("--lib", type=Path, help="Optional actual sky130 Liberty library")
    args = parser.parse_args()
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    out = args.output.resolve() / f"netlist-repair-smoke-{stamp}"
    input_dir = out / "input"
    (input_dir / "netlist").mkdir(parents=True)
    source = input_dir / "netlist/top.v"
    span = ("sky130_fd_sc_hd__and2_1 u_and (.A(a), .B(b), .X(y));" if args.lib else "assign y = a & b;")
    source.write_text(f"module top(input a,b, output y);\n{span}\nendmodule\n")
    original = source.read_bytes()
    active = {source: source}
    libraries = [args.lib.resolve()] if args.lib else []
    equal, changes = prepare_repair("task2", "Top 模块: `top`", "present_design top\n", input_dir,
                                    [source], active, libraries,
                                    [{"file": "netlist/top.v", "old": span, "new": "assign y = ~(~a | ~b);",
                                      "reason": "equivalent localized fixture rewrite"}], out, "R2", time.monotonic() + 120)
    different_rejected = False
    try:
        prepare_repair("task2", "Top 模块: `top`", "present_design top\n", input_dir,
                       [source], active, libraries,
                       [{"file": "netlist/top.v", "old": span, "new": "assign y = a | b;",
                         "reason": "deliberately non-equivalent negative fixture"}], out, "R3", time.monotonic() + 120)
    except RepairRejected:
        different_rejected = True
    extra = input_dir / "netlist/extra.v"
    helper_span = "assign y = a & b; // helper logic"
    extra.write_text("module top(input a,b, output y);\nassign y = a & b;\nendmodule\n"
                     f"module helper(input a,b, output y);\n{helper_span}\nendmodule\n")
    unused_edit_rejected = False
    try:
        prepare_repair("task2", "Top 模块: `top`", "present_design top\n", input_dir,
                       [extra], {extra: extra}, libraries,
                       [{"file": "netlist/extra.v", "old": helper_span,
                         "new": "assign y = a | b; // helper logic",
                         "reason": "ensure modified unused module is independently proved"}], out, "R5", time.monotonic() + 120)
    except RepairRejected:
        unused_edit_rejected = True
    unsupported_rejected = None
    if args.lib:
        unknown = input_dir / "netlist/unsupported.v"
        cell = "sky130_fd_sc_hd__dlclkp_1 u_gate (.CLK(clk), .GATE(en), .GCLK(y));"
        unknown.write_text(f"module unsupported(input clk,en, output y);\n{cell}\nendmodule\n")
        unsupported_rejected = False
        try:
            prepare_repair("task2", "Top 模块: `unsupported`", "present_design unsupported\n", input_dir,
                           [unknown], {unknown: unknown}, libraries,
                           [{"file": "netlist/unsupported.v", "old": cell, "new": cell + " // comment only",
                             "reason": "verify unsupported used cells cannot be blackboxed"}], out, "R4", time.monotonic() + 120)
        except RepairRejected:
            unsupported_rejected = True
    passed = (equal[source] != source and bool(changes) and different_rejected
              and source.read_bytes() == original and active[source] == source
              and unsupported_rejected is not False and unused_edit_rejected)
    summary = {"passed": passed, "equivalent_candidate_admitted": equal[source] != source,
               "different_candidate_rejected": different_rejected,
               "unsupported_used_cell_rejected": unsupported_rejected,
               "unused_edited_module_rejected": unused_edit_rejected,
               "original_unchanged": source.read_bytes() == original,
               "library": str(args.lib) if args.lib else None, "changes": changes,
               "output_directory": str(out)}
    (out / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary, indent=2))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
