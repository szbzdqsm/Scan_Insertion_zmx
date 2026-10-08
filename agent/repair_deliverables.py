"""Publish actual final adopted repair bytes and retained EQY evidence only."""
from __future__ import annotations

import json
import ctypes
import errno
import math
import os
from pathlib import Path, PurePosixPath
import re
import stat
import tempfile
import time
from typing import Any

from artifact_operations import independent_copy
from netlist_repair import RepairRejected, changed_paths, fingerprint_paths, run_proof


class _Directories:
    """Keep publication anchored to checked directory inodes, never symlink paths."""

    def __init__(self):
        self.bindings: dict[Path, tuple[int, tuple[int, int, int]]] = {}

    def open(self, path: Path, *, create: bool = False) -> int:
        path = Path(os.path.abspath(path))
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        if path in self.bindings:
            return self.bindings[path][0]
        if path == Path(path.anchor):
            descriptor = os.open(path, flags)
        else:
            parent = self.open(path.parent)
            if create:
                try:
                    os.mkdir(path.name, 0o755, dir_fd=parent)
                except FileExistsError:
                    pass
            try:
                descriptor = os.open(path.name, flags, dir_fd=parent)
            except OSError as exc:
                raise RepairRejected("Final publication directories must be real directories without symlink ancestors") from exc
        try:
            value = os.fstat(descriptor)
        except BaseException:
            os.close(descriptor)
            raise
        self.bindings[path] = descriptor, (value.st_dev, value.st_ino, value.st_mode)
        return descriptor

    def verify(self) -> None:
        for path, (descriptor, identity) in self.bindings.items():
            value = path.lstat()
            opened = os.fstat(descriptor)
            if (stat.S_ISLNK(value.st_mode) or
                    (value.st_dev, value.st_ino, value.st_mode) != identity or
                    (opened.st_dev, opened.st_ino, opened.st_mode) != identity):
                raise RepairRejected("Bound publication directory/ancestor changed: " + str(path))

    def close(self) -> None:
        for descriptor, _ in reversed(list(self.bindings.values())):
            os.close(descriptor)
        self.bindings.clear()


def _publish_new(source_fd: int, target_fd: int, name: str) -> None:
    """Linux atomic rename with RENAME_NOREPLACE; never replace an old target."""
    library = ctypes.CDLL(None, use_errno=True)
    rename = getattr(library, "renameat2", None)
    if rename is None:
        raise RepairRejected("Atomic no-overwrite publication requires Linux renameat2")
    rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    rename.restype = ctypes.c_int
    encoded = os.fsencode(name)
    if rename(source_fd, encoded, target_fd, encoded, 1):
        code = ctypes.get_errno()
        if code == errno.EEXIST:
            raise RepairRejected("Repair target already exists; refusing to replace retained evidence")
        raise OSError(code, os.strerror(code), name)


def _proof_files(root: Path) -> list[Path]:
    summary_path = root / "summary.json"
    paths = [summary_path, root / "eqy.log", root / "check.eqy", root / "proof" / "PASS"]
    if not all(path.is_file() for path in paths) or (root / "eqy.log").stat().st_size == 0:
        raise RepairRejected("Actual exported EQY proof files/PASS marker are missing")
    summary = json.loads(summary_path.read_text())
    if (summary.get("passed") is not True or summary.get("returncode") != 0 or summary.get("result") != "PASS" or
            any((root / "proof" / marker).exists() for marker in ("FAIL", "ERROR", "UNPROVEN"))):
        raise RepairRejected("Exported single-file EQY proof did not actually PASS")
    return paths


def _relative_file(output_dir: Path, reference: str) -> Path:
    relative = PurePosixPath(reference)
    if relative.is_absolute() or ".." in relative.parts:
        raise RepairRejected("Proof reference must stay inside the case output directory")
    path = output_dir / relative
    if not path.is_file() or not path.resolve().is_relative_to(output_dir.resolve()):
        raise RepairRejected("Proof reference is missing or resolves outside the case output")
    return path


def publish_repair_deliverables(output_dir: Path, *, task: str, final_run: str,
                                active_netlists: dict[Path, Path], repair_attempts: list[dict],
                                protected_fingerprints: dict[str, dict[str, str]],
                                libraries: list[Path] | None = None, deadline: float | None = None) -> dict[str, Any] | None:
    """Deliver only the exact candidate family proved and adopted by the caller.

    Single-file output is byte-identical. Multiple-file output concatenates the
    actual proof input order, inserting disclosed boundary newlines when needed.
    Multiple-file export additionally requires actual fixed EQY proofs of the
    persistent concatenation against the original family, including every prior
    affected-module proof top. No substituted top or interface is synthesized.
    """
    if task != "task2" or not active_netlists or all(
            Path(source).resolve() == Path(candidate).resolve() for source, candidate in active_netlists.items()):
        return None
    directories = _Directories()
    try:
        output_dir = Path(os.path.abspath(output_dir))
        directories.open(output_dir)
        return _publish_repair_deliverables(output_dir, final_run, active_netlists, repair_attempts,
                                             protected_fingerprints, libraries, deadline, directories)
    finally:
        directories.close()


def _publish_repair_deliverables(output_dir: Path, final_run: str, active_netlists: dict[Path, Path],
                                 repair_attempts: list[dict], protected_fingerprints: dict,
                                 libraries: list[Path] | None, deadline: float | None,
                                 directories: _Directories) -> dict[str, Any]:
    if not re.fullmatch(r"R[1-9]\d*", final_run):
        raise RepairRejected("Invalid final actual run identifier")
    active_paths = {str(Path(path).absolute()) for path in active_netlists.values()}
    original_paths = {str(Path(path).absolute()) for path in active_netlists}
    selected = None
    for attempt in reversed(repair_attempts):
        if attempt.get("admitted") is not True or attempt.get("adopted") is not True:
            continue
        aggregate = _relative_file(output_dir, str(attempt.get("lec_ref", "")))
        summary_path = aggregate.parent / "summary.json"
        if not summary_path.is_file():
            continue
        if not summary_path.resolve().is_relative_to(output_dir.resolve()):
            raise RepairRejected("EQY summary resolves outside the case output")
        summary = json.loads(summary_path.read_text())
        if {str(Path(path).absolute()) for path in summary.get("candidate_netlists", [])} == active_paths:
            selected = aggregate, summary
            break
    if selected is None:
        raise RepairRejected("Final active netlists have no matching actually adopted EQY proof")
    aggregate, primary_summary = selected
    proof_files = [aggregate]
    tops = [primary_summary.get("top")]
    if not isinstance(tops[0], str) or not re.fullmatch(r"[A-Za-z_][\w$]*", tops[0]):
        raise RepairRejected("Primary actual EQY proof top identifier is missing or invalid")
    summaries = sorted(aggregate.parent.rglob("summary.json"))
    if not summaries:
        raise RepairRejected("EQY proof summary is missing")
    for summary_path in summaries:
        if not summary_path.resolve().is_relative_to(output_dir.resolve()):
            raise RepairRejected("EQY summary resolves outside the case output")
        summary = json.loads(summary_path.read_text())
        if (summary.get("passed") is not True or summary.get("returncode") != 0 or summary.get("result") != "PASS" or
                {str(Path(path).absolute()) for path in summary.get("candidate_netlists", [])} != active_paths or
                {str(Path(path).absolute()) for path in summary.get("original_netlists", [])} != original_paths):
            raise RepairRejected("Every retained final-candidate EQY proof must actually PASS")
        directory = summary_path.parent
        required = [summary_path, directory / "eqy.log", directory / "check.eqy", directory / "proof" / "PASS"]
        if (not all(path.is_file() for path in required) or (directory / "eqy.log").stat().st_size == 0 or
                any((directory / "proof" / marker).exists() for marker in ("FAIL", "ERROR", "UNPROVEN"))):
            raise RepairRejected("Actual EQY log/config/PASS marker is missing or conflicting")
        proof_files.extend(required)
        if not isinstance(summary.get("top"), str) or not re.fullmatch(r"[A-Za-z_][\w$]*", summary["top"]):
            raise RepairRejected("Actual EQY proof top identifier is missing or invalid")
        if summary["top"] not in tops:
            tops.append(summary["top"])
    ordered = [Path(path) for path in primary_summary["candidate_netlists"]]
    if len(ordered) != len(active_paths):
        raise RepairRejected("Final proof candidate list contains duplicate paths")
    required_files = ordered + list(active_netlists) + proof_files
    for path in required_files:
        if str(path) not in protected_fingerprints:
            raise RepairRejected("Final candidate/proof file was not fingerprinted at actual execution: " + str(path))
    baseline = {name: value for name, value in protected_fingerprints.items()
                if name in {str(path) for path in required_files} or
                Path(name).absolute().is_relative_to(aggregate.parent.absolute())}
    if changed_paths(baseline):
        raise RepairRejected("Final candidate or proof changed after actual execution")
    export_candidate = None
    export_proof_files = []
    report_source = aggregate
    export_snapshot = {}
    if len(ordered) > 1:
        if libraries is None or deadline is None or not math.isfinite(deadline) or deadline <= time.monotonic() + 1:
            raise RepairRejected("Multi-file export requires libraries and time for an actual merged-candidate EQY proof")
        originals = [Path(path) for path in primary_summary["original_netlists"]]
        libraries = [Path(path) for path in libraries]
        directories.open(output_dir / "netlist_versions", create=True)
        directories.open(output_dir / "lec", create=True)
        export_root = output_dir / "netlist_versions" / f"export_{final_run}"
        export_proof_root = output_dir / "lec" / f"export_{final_run}"
        if export_root.exists() or export_root.is_symlink() or export_proof_root.exists() or export_proof_root.is_symlink():
            raise RepairRejected("Persistent exported candidate/proof already exists; refusing to overwrite")
        export_fd = directories.open(export_root, create=True)
        export_candidate = export_root / "pre_scan_final.v"
        descriptor = os.open(export_candidate.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                             0o600, dir_fd=export_fd)
        with os.fdopen(descriptor, "wb") as stream:
            for index, source in enumerate(ordered):
                if index and stream.tell():
                    stream.write(b"\n")
                with source.open("rb") as reader:
                    while chunk := reader.read(1024 * 1024):
                        stream.write(chunk)
        if changed_paths(baseline):
            raise RepairRejected("Original candidate/proof changed while preparing persistent export")
        export_snapshot = fingerprint_paths(originals + libraries + [export_candidate])
        for index, top in enumerate(tops):
            directories.verify()
            directory = export_proof_root if index == 0 else export_proof_root / f"affected_{index}"
            result = run_proof(originals, [export_candidate], libraries, top, directory, deadline)
            if result.get("passed") is not True or result.get("returncode") != 0 or result.get("result") != "PASS":
                raise RepairRejected("Exported single-file EQY did not prove module " + top + ": " + str(result.get("result")))
            actual_files = _proof_files(directory)
            summary = json.loads((directory / "summary.json").read_text())
            if (summary.get("top") != top or summary.get("candidate_netlists") != [str(export_candidate)] or
                    summary.get("original_netlists") != [str(path) for path in originals]):
                raise RepairRejected("Exported EQY summary does not bind the actual input family/top")
            if changed_paths(baseline) or changed_paths(export_snapshot):
                raise RepairRejected("Proof input/candidate changed while proving persistent export")
            export_proof_files.extend(actual_files)
            export_snapshot.update(fingerprint_paths(actual_files))
        report_source = export_proof_root / "aggregate.log"
        with report_source.open("xb") as stream:
            for path in export_proof_files:
                if path.name != "eqy.log":
                    continue
                stream.write(f"\n[agent] Actual EQY log for exported candidate: {path}\n".encode())
                with path.open("rb") as actual:
                    while chunk := actual.read(1024 * 1024):
                        stream.write(chunk)
        export_proof_files.append(report_source)
        export_snapshot.update(fingerprint_paths([report_source]))
    delivery = output_dir / "final_results" / "deliverables"
    reports = output_dir / "final_results" / "reports"
    directories.open(output_dir / "final_results", create=True)
    delivery_fd = directories.open(delivery, create=True)
    reports_fd = directories.open(reports, create=True)
    targets = [delivery / "pre_scan_final.v", reports / "lec_report.rpt", delivery / "pre_scan_final.manifest.json"]
    target_descriptors = [delivery_fd, reports_fd, delivery_fd]
    directories.verify()
    for target, descriptor in zip(targets, target_descriptors):
        try:
            os.stat(target.name, dir_fd=descriptor, follow_symlinks=False)
        except FileNotFoundError:
            continue
        raise RepairRejected("Repair delivery targets already exist; refusing to replace retained evidence")
    sources = []
    origin_for = {str(Path(candidate).absolute()): str(source) for source, candidate in active_netlists.items()}
    publication_intents = []
    with tempfile.TemporaryDirectory(prefix=".repair-delivery-", dir=output_dir) as temporary:
        staging = Path(temporary)
        staging_fd = directories.open(staging)
        netlist = staging / "pre_scan_final.v"
        independent_copy(export_candidate or ordered[0], netlist)
        offset = 0
        for index, source in enumerate(ordered):
            separator = 1 if index and offset else 0
            offset += separator
            size = source.stat().st_size
            sources.append({"original_path": origin_for[str(source.absolute())], "candidate_path": str(source),
                            "resolved_path": str(source.resolve()), "sha256": baseline[str(source)]["sha256"],
                            "original_sha256": baseline[origin_for[str(source.absolute())]]["sha256"],
                            "size_bytes": size, "start_byte": offset, "separator_bytes_before": separator})
            offset += size
        independent_copy(report_source, staging / "lec_report.rpt")
        delivered_hashes = fingerprint_paths([netlist, staging / "lec_report.rpt"])
        if len(ordered) == 1 and delivered_hashes[str(netlist)]["sha256"] != baseline[str(ordered[0])]["sha256"]:
            raise RepairRejected("Single-file final repair copy differs from its actual candidate")
        if changed_paths(baseline) or changed_paths(export_snapshot):
            raise RepairRejected("Final candidate or proof changed while copying delivery")
        manifest = {"final_run": final_run, "format": "byte_exact_single_file" if len(ordered) == 1 else "source_file_concatenation",
                    "sources": sources, "proof_scope": "EQY proved the listed candidate files against the original input family",
                    "proof_refs": [{"path": Path(name).relative_to(output_dir).as_posix(), **value}
                                   for name, value in sorted(baseline.items())
                                   if Path(name).absolute().is_relative_to(aggregate.parent.absolute())],
                    "pre_scan_final_sha256": delivered_hashes[str(netlist)]["sha256"],
                    "lec_report_sha256": delivered_hashes[str(staging / "lec_report.rpt")]["sha256"],
                    "lec_report_source": report_source.relative_to(output_dir).as_posix(),
                    "export_candidate": str(export_candidate) if export_candidate else None,
                    "exported_single_file_proved": True,
                    "additional_export_proof": bool(export_candidate),
                    "export_proof_refs": [{"path": path.relative_to(output_dir).as_posix(), **export_snapshot[str(path)]}
                                          for path in export_proof_files],
                    "export_proof_tops": tops if export_candidate else []}
        (staging / targets[2].name).write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n")
        try:
            for target, descriptor in zip(targets, target_descriptors):
                directories.verify()
                identity = os.stat(target.name, dir_fd=staging_fd, follow_symlinks=False)
                publication_intents.append((descriptor, target.name, identity.st_dev, identity.st_ino))
                _publish_new(staging_fd, descriptor, target.name)
            directories.verify()
            if changed_paths(baseline) or changed_paths(export_snapshot):
                raise RepairRejected("Final candidate/proof changed during publication")
        except BaseException:
            for descriptor, name, device, inode in reversed(publication_intents):
                try:
                    identity = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
                    if (identity.st_dev, identity.st_ino) == (device, inode):
                        os.unlink(name, dir_fd=descriptor)
                except OSError:
                    pass
            raise
    return manifest
