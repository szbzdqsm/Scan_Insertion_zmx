"""Verify EQY's actual backend on small equal and unequal circuits; preserve logs."""
from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    missing = [name for name in ("eqy", "yosys", "make") if not shutil.which(name)]
    if missing:
        print(json.dumps({"missing": missing, "action": "Run this check in the configured Dev Container"}))
        return 1
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    out = ROOT / "outputs" / f"eqy-smoke-{stamp}"
    out.mkdir(parents=True, exist_ok=False)
    (out / "gold.v").write_text("module top(input a,b, output y); assign y = a & b; endmodule\n")
    expressions = {"equal": "~(~a | ~b)", "different": "a | b"}
    results = {}
    for name, expression in expressions.items():
        gate = out / f"{name}.v"
        gate.write_text(f"module top(input a,b, output y); assign y = {expression}; endmodule\n")
        config = out / f"{name}.eqy"
        config.write_text(
            f"[gold]\nread_verilog {json.dumps(str(out / 'gold.v'))}\nprep -top top\n"
            f"[gate]\nread_verilog {json.dumps(str(gate))}\nprep -top top\n"
            "[strategy sat]\nuse sat\ndepth 1\n"
        )
        proof_dir = out / name
        with (out / f"{name}.log").open("w") as log:
            result = subprocess.run(["eqy", "-d", str(proof_dir), str(config)],
                                    cwd=out, stdout=log, stderr=subprocess.STDOUT, timeout=60)
        marker = next((label for label in ("PASS", "FAIL", "UNPROVEN", "ERROR")
                       if (proof_dir / label).is_file()), "MISSING")
        results[name] = {"exit_code": result.returncode, "result": marker}
    passed = (results["equal"]["exit_code"] == 0 and results["equal"]["result"] == "PASS"
              and results["different"]["exit_code"] != 0
              and results["different"]["result"] in {"FAIL", "UNPROVEN"})
    summary = {"passed": passed, "results": results, "log_directory": str(out)}
    (out / "summary.json").write_text(json.dumps(summary, indent=2))
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
