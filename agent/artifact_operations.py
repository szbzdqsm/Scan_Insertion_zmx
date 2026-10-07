"""Independent artifact copies and conservative reuse of completed-run checks.

The cache retains metadata and parameter digests, never report or input contents.
A hit still walks the artifact tree twice. SHA checks for repaired input/proof
files remain the responsibility of the caller and cannot be replaced by this cache.
"""
from __future__ import annotations

from collections import deque
from collections.abc import Callable, Mapping
import errno
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import sys
import tempfile
from typing import Any


def _clone_file(source: Path, destination: Path) -> bool:
    """Try Linux FICLONE; an unsupported filesystem needs an ordinary copy."""
    if sys.platform != "linux":
        return False
    import fcntl

    try:
        with source.open("rb") as reader, destination.open("wb") as writer:
            fcntl.ioctl(writer.fileno(), 0x40049409, reader.fileno())
    except OSError:
        return False
    return True


def independent_copy(source: str | os.PathLike[str], target: str | os.PathLike[str]) -> str:
    """Copy with copy2 metadata, an independent inode and atomic publication.

    Like copy2's defaults, source/destination symlinks are followed and a target
    directory receives source.name. A failed clone, copy or metadata operation
    never replaces an existing successful destination. No hard links are used.
    """
    original_source = Path(source)
    destination = Path(target)
    if destination.is_dir():
        destination = destination / original_source.name
    returned_destination = os.fspath(destination)
    source_path = original_source.resolve(strict=True)
    # Keep a destination symlink intact, following it as copy2 would.
    destination = destination.resolve(strict=False)
    source_stat = source_path.stat()
    if stat.S_ISFIFO(source_stat.st_mode):
        raise shutil.SpecialFileError(f"`{source}` is a named pipe")
    try:
        if os.path.samefile(source_path, destination):
            raise shutil.SameFileError(f"'{source}' and '{target}' are the same file")
    except FileNotFoundError:
        pass
    if not stat.S_ISREG(source_stat.st_mode):
        # Match copy2's error semantics for directories and other special files.
        with source_path.open("rb"):
            raise OSError(errno.EINVAL, "Source is not a regular file", os.fspath(source))
    temporary: Path | None = None
    try:
        descriptor, temporary_name = tempfile.mkstemp(prefix=".artifact-copy-", dir=destination.parent)
        os.close(descriptor)
        temporary = Path(temporary_name)
        if _clone_file(source_path, temporary):
            shutil.copystat(source_path, temporary)
        else:
            shutil.copy2(source_path, temporary)
        os.replace(temporary, destination)
        temporary = None
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    return returned_destination


def _stat_fields(value: os.stat_result) -> tuple[int, ...]:
    return (value.st_dev, value.st_ino, value.st_mode, value.st_size,
            value.st_mtime_ns, value.st_ctime_ns)


def _run_signature(run_dir: Path) -> tuple[tuple[Any, ...], ...] | None:
    """Snapshot all non-input artifacts plus symlink targets and ancestors.

    Directory symlinks outside input are deliberately uncacheable: checking only
    their directory inode would miss changes to an existing target child. Broken
    links, traversal races and inaccessible metadata also disable reuse.
    """
    records: dict[str, tuple[Any, ...]] = {}

    def remember(path: Path) -> os.stat_result:
        value = path.lstat()
        link = os.readlink(path) if stat.S_ISLNK(value.st_mode) else None
        records[os.fspath(path)] = (*_stat_fields(value), link)
        return value

    def resolve_recorded(path: Path) -> Path:
        # Record each link hop and each physical ancestor. Path.resolve alone
        # would conceal a changed intermediate link that still ends at the same file.
        remaining = deque(path.parts[1:])
        current = Path(path.anchor)
        remember(current)
        followed = 0
        while remaining:
            part = remaining.popleft()
            if part == "..":
                current = current.parent
                continue
            candidate = current / part
            value = remember(candidate)
            if stat.S_ISLNK(value.st_mode):
                followed += 1
                if followed > 40:
                    raise OSError("Too many symbolic links")
                target = Path(os.readlink(candidate))
                if target.is_absolute():
                    current = Path(target.anchor)
                    remember(current)
                    parts = target.parts[1:]
                else:
                    parts = target.parts
                remaining.extendleft(reversed(parts))
            else:
                current = candidate
        return current

    def visit(path: Path, relative: Path) -> None:
        value = remember(path)
        if stat.S_ISLNK(value.st_mode):
            resolved = resolve_recorded(path)
            target_value = remember(resolved)
            if stat.S_ISDIR(target_value.st_mode):
                raise OSError("Directory symlinks are not cacheable")
        elif stat.S_ISDIR(value.st_mode):
            with os.scandir(path) as entries:
                names = sorted(entry.name for entry in entries)
            for name in names:
                child_relative = relative / name
                if child_relative.parts[0] != "input":
                    visit(path / name, child_relative)

    try:
        root = Path(os.path.abspath(run_dir))
        resolve_recorded(root.parent)
        visit(root, Path())
        return tuple((path, *value) for path, value in sorted(records.items()))
    except (OSError, ValueError, RuntimeError):
        return None


def _parameter_digest(value: Any) -> str | None:
    """Type-sensitive digest; unknown mutable objects cannot become cache keys."""
    def encode(item: Any) -> Any:
        if item is None:
            return ["none"]
        if isinstance(item, bool):
            return ["bool", item]
        if isinstance(item, int):
            return ["int", str(item)]
        if isinstance(item, float):
            return ["float", item.hex()]
        if isinstance(item, str):
            return ["str", item]
        if isinstance(item, os.PathLike):
            return ["path", os.fspath(item)]
        if isinstance(item, Mapping):
            pairs = [[encode(key), encode(val)] for key, val in item.items()]
            pairs.sort(key=lambda pair: json.dumps(pair[0], sort_keys=True))
            return ["mapping", pairs]
        if isinstance(item, (tuple, list)):
            return [type(item).__name__, [encode(element) for element in item]]
        if isinstance(item, (set, frozenset)):
            elements = [encode(element) for element in item]
            elements.sort(key=lambda element: json.dumps(element, sort_keys=True))
            return [type(item).__name__, elements]
        raise TypeError("Unsupported validation parameter type")

    try:
        serialized = json.dumps(encode(value), ensure_ascii=True, separators=(",", ":"))
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()
    except (TypeError, ValueError, RecursionError):
        return None


class RunValidationCache:
    """Reuse one completed run's result only after two unchanged tree snapshots."""

    def __init__(self) -> None:
        self.stats = {"hits": 0, "full_validations": 0, "signature_scans": 0,
                      "invalidations": 0, "unstable_validations": 0}
        self._entry: tuple[str, str, tuple[tuple[Any, ...], ...], bool, tuple[str, ...]] | None = None

    def _snapshot(self, run_dir: Path) -> tuple[tuple[Any, ...], ...] | None:
        self.stats["signature_scans"] += 1
        return _run_signature(run_dir)

    def validate(self, run_dir: Path, validator: Callable[[], tuple[bool, list[str]]], *,
                 dofile: Any, task_spec: Any, status: Any, expected: Any,
                 tool_finished: bool = False) -> tuple[bool, list[str]]:
        """Check or reuse, returning a fresh problem list on every call.

        ``expected`` must contain every remaining checker argument, including task
        identity and source-derived structures. Only an explicitly ended tool can
        seed or use a cache entry. Changes while validation executes are rejected.
        """
        run_key = os.path.abspath(run_dir)
        parameters = _parameter_digest((dofile, task_spec, status, expected))
        before = self._snapshot(run_dir) if tool_finished else None
        if tool_finished and parameters is not None and before is not None and self._entry is not None:
            old_run, old_parameters, old_signature, old_ok, old_problems = self._entry
            if (run_key, parameters, before) == (old_run, old_parameters, old_signature):
                final_signature = self._snapshot(run_dir)
                final_parameters = _parameter_digest((dofile, task_spec, status, expected))
                if final_signature == before and final_parameters == parameters:
                    self.stats["hits"] += 1
                    return old_ok, list(old_problems)
                before, parameters = final_signature, final_parameters
        if self._entry is not None:
            self.stats["invalidations"] += 1
        self._entry = None
        self.stats["full_validations"] += 1
        ok, problems = validator()
        problems = list(problems)
        after = self._snapshot(run_dir) if tool_finished else None
        after_parameters = _parameter_digest((dofile, task_spec, status, expected))
        if before is not None and before != after:
            self.stats["unstable_validations"] += 1
            return False, problems + ["Run artifacts changed during validation; the result cannot be accepted"]
        if parameters != after_parameters:
            self.stats["unstable_validations"] += 1
            return False, problems + ["Validation parameters changed during validation; the result cannot be accepted"]
        if tool_finished and parameters is not None and before is not None and after == before:
            self._entry = (run_key, parameters, before, bool(ok), tuple(problems))
        return bool(ok), problems
