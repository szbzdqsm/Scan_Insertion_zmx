"""Read-only selection of existing evidence for an existing issue's audit plan.

This module neither calls a model nor declares a repair successful. The caller
must freeze inputs/proofs/artifacts and run the existing semantic verifier again.
"""
from __future__ import annotations

import json
from pathlib import Path, PurePosixPath
import re
from typing import Any


def _eligible(issues: list[dict], runs: list[dict], current_run: str) -> dict[str, dict]:
    ids = [run.get("run_id", run.get("tool_call_id")) for run in runs]
    if (not ids or any(not isinstance(identity, str) or not re.fullmatch(r"R[1-9]\d*", identity) for identity in ids) or
            len(set(ids)) != len(ids) or ids[-1] != current_run):
        raise ValueError("Audit refresh requires the latest actual tool run")
    current = runs[-1]
    if current.get("status", current.get("exit_status")) != "completed" or current.get("returncode") != 0:
        raise ValueError("Audit refresh requires an actually completed successful tool process")
    result = {}
    seen = set()
    for issue in issues:
        identity = issue.get("issue_id")
        if not isinstance(identity, str) or identity in seen:
            raise ValueError("Existing issue identifiers must be unique strings")
        seen.add(identity)
        found = issue.get("found", {})
        attempts = issue.get("attempts", [])
        if (found.get("verified") is True and found.get("run_ref") in ids[:-1] and attempts and
                attempts[-1].get("fix", {}).get("artifact_ref") and
                not attempts[-1].get("verify", {}).get("resolved")):
            result[identity] = issue
    return result


def _catalog_entry(entry: Any, current_run: str) -> dict[str, str]:
    if not isinstance(entry, dict):
        raise ValueError("Evidence must be a catalog object")
    source, locator, excerpt = (entry.get(key) for key in ("source", "locator", "excerpt"))
    if not all(isinstance(value, str) and value for value in (source, locator, excerpt)):
        raise ValueError("Evidence needs an exact source, line locator and excerpt")
    path = PurePosixPath(source)
    if (path.is_absolute() or ".." in path.parts or path.parts[:2] != ("runs", current_run) or
            path.suffix.lower() not in {".log", ".rpt", ".report", ".txt"}):
        raise ValueError("Evidence must come from the current actual run's tool log/report")
    match = re.fullmatch(r"L([1-9]\d*)(?:-L([1-9]\d*))?", locator)
    if not match or int(match.group(2) or match.group(1)) < int(match.group(1)):
        raise ValueError("Invalid evidence line locator")
    return {"source": source, "locator": locator, "excerpt": excerpt}


def current_evidence_catalog(output_dir: Path, current_run: str, *, maximum: int = 32,
                             byte_budget: int = 16000) -> dict[str, dict[str, str]]:
    """Offer bounded real report lines/windows, without labelling them successful.

    The semantic verifier decides whether a selected candidate proves that issue.
    Full small reports allow aggregate/partition evidence without invented text.
    """
    root = output_dir / "runs" / current_run
    if not re.fullmatch(r"R[1-9]\d*", current_run):
        raise ValueError("Invalid current tool run identifier")
    if maximum <= 0 or byte_budget <= 0:
        return {}
    paths = sorted(path for path in (root / "reports").rglob("*") if path.is_file() and
                   path.suffix.lower() in {".rpt", ".report", ".txt"})
    paths += [root / f"{current_run}.log"]
    catalog = {}
    consumed = 0
    for path in paths:
        if not path.is_file() or not path.resolve().is_relative_to(root.resolve()):
            continue
        small = path.stat().st_size <= min(3000, byte_budget - consumed)
        with path.open(encoding="utf-8", errors="replace") as stream:
            if small:
                text = stream.read()
                exact = text.rstrip("\r\n")
                candidates = [(1, len(exact.splitlines()), exact)] if text.strip() else []
            else:
                candidates = []
                inspected = 0
                for number, line in enumerate(stream, 1):
                    inspected += len(line.encode("utf-8"))
                    if inspected > 131072:
                        break
                    text = line.rstrip("\r\n")
                    if len(text.encode("utf-8")) <= 1000 and re.search(
                            r"Total violations:|Design:|SignalType|ScanConfigurationParameter|"
                            r"WrapperConfigurationParameter|^\s*[IW]\s+\S+\s+\d+|"
                            r"\[INFO\].*(?:completed|successfully|passed)", text, re.I):
                        candidates.append((number, number, text))
                    if len(candidates) >= 8:
                        break
        for first, last, text in candidates:
            length = len(text.encode("utf-8"))
            if consumed + length > byte_budget or len(catalog) >= maximum:
                return catalog
            consumed += length
            catalog[f"V{len(catalog) + 1}"] = {
                "source": path.relative_to(output_dir).as_posix(),
                "locator": f"L{first}" if first == last else f"L{first}-L{last}", "excerpt": text}
    return catalog


def build_audit_refresh_request(issues: list[dict], run_records: list[dict], current_run: str,
                                catalog: dict[str, dict[str, str]]) -> list[dict[str, str]]:
    eligible = _eligible(issues, run_records, current_run)
    checked_catalog = {key: _catalog_entry(value, current_run) for key, value in catalog.items()}
    system = (
        "Select verification evidence for existing unresolved audit issues only. No tool will run. "
        "The listed current run already executed; only its actual catalog text may be selected. "
        "Return exactly one JSON object: {\"verification_updates\":[{\"issue_id\":\"I1\",\"evidence_id\":\"V1\"}]}. "
        "Return {\"verification_updates\":[]} if the supplied evidence cannot prove an issue's existing fix. "
        "Output only the JSON object, without markdown fences or other text. "
        "Do not change diagnoses, discoveries, fixes, Dofiles, netlists or run identifiers; do not "
        "withdraw issues or claim success/resolved. A runtime semantic verifier decides closure. "
        "Absence of an old diagnostic is not positive evidence."
    )
    return [{"role": "system", "content": system}, {"role": "user", "content": json.dumps(
        {"current_actual_run": current_run, "issues": list(eligible.values()),
         "current_actual_evidence_catalog": checked_catalog}, ensure_ascii=False)}]


def validate_audit_refresh(response: Any, issues: list[dict], run_records: list[dict], current_run: str,
                           catalog: dict[str, dict[str, str]]) -> dict[str, dict[str, str]]:
    """Return new verification plans; leave issues/found/fixes/run records intact."""
    eligible = _eligible(issues, run_records, current_run)
    if not isinstance(response, dict) or set(response) != {"verification_updates"}:
        raise ValueError("Only verification_updates are permitted in audit refresh")
    updates = response["verification_updates"]
    if not isinstance(updates, list) or len(updates) > len(eligible):
        raise ValueError("Invalid audit verification update list")
    plans = {}
    for update in updates:
        if not isinstance(update, dict) or set(update) != {"issue_id", "evidence_id"}:
            raise ValueError("An audit update may select only issue_id and evidence_id")
        identity, evidence_id = update["issue_id"], update["evidence_id"]
        if not isinstance(identity, str) or identity not in eligible or identity in plans:
            raise ValueError("Unknown, duplicate or ineligible existing issue_id")
        if not isinstance(evidence_id, str) or evidence_id not in catalog:
            raise ValueError("Unknown current actual evidence_id")
        evidence = _catalog_entry(catalog[evidence_id], current_run)
        plans[identity] = {"source": evidence["source"], "locator": evidence["locator"],
                           "expected_excerpt": evidence["excerpt"]}
    return plans
