"""Extract command syntax from the installed official tool when building the image."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import subprocess
import tempfile

COMMANDS = (
    "load_lib load_netlist load_ctl present_design set_scan_signal set_scan_cfg "
    "set_scan_cell_mapping set_scan_element set_dft_clock_gating_cfg set_scan_drc_cfg "
    "set_scan_drc_rule_handling rpt_scan_drc_rule_handling add_scan_partition set_current_scan_partition "
    "set_wrapper_cfg examine_scan_drc examine_scan_chain insert_dft_logic "
    "dump_netlist dump_ctl dump_def rpt_scan_chain rpt_scan_chain_cell rpt_scan_element "
    "rpt_scan_cfg rpt_scan_signal rpt_scan_drc_violation rpt_scan_partition "
    "rpt_wrapper_cfg rpt_wrapper_implementation add_dedicated_wrapper_cell_type rpt_dedicated_wrapper_cell_type "
    "rpt_insertion_info set_scan_segment rpt_scan_segment "
    "add_pseudo_pi rpt_pseudo_pi get_cells get_pins get_ports get_nets get_obj_insts "
    "get_attribute get_property list_properties rpt_property "
    "sizeof_collection foreach_in_collection"
).split()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="scan-help-") as temp:
        script = Path(temp) / "help.dofile"
        script.write_text("\n".join(f'puts "=== SYNTAX {name} ==="\ncatch {{help -verbose {name}}}'
                                    for name in COMMANDS) +
                          '\nputs "=== SYNTAX __cell_properties ==="\nlist_properties -sys -obj_type cell -no_split\nexit\n')
        result = subprocess.run(["/opt/dftexp_scan/bin/dftexp_scan", "-f", str(script)],
                                capture_output=True, text=True, errors="replace", timeout=30, check=True)
    blocks = re.split(r"(?m)^=== SYNTAX ([A-Za-z_]+) ===\s*$", result.stdout)
    syntax = {}
    for index in range(1, len(blocks), 2):
        text = "\n".join(line for line in blocks[index + 1].splitlines()
                         if not line.startswith("[INFO]"))
        if "No commands matched" not in blocks[index + 1] and text.strip():
            syntax[blocks[index]] = text.strip()
    if not all(name in syntax for name in ("set_scan_signal", "set_scan_cfg", "insert_dft_logic")):
        raise RuntimeError("Official command syntax extraction was incomplete")
    args.output.write_text(json.dumps(syntax, ensure_ascii=False, indent=2))
    print(f"Extracted {len(syntax)} official command help entries")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
