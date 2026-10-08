"""Read original scripts for context and copy their raw bytes for execution.

Decoded text may contain replacement characters and must never be used to
recreate the Task 2 original execution file. The caller owns the allowed output
directory checks; this module additionally protects the source and rejects
destination aliases before performing either copy.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import stat

from artifact_operations import independent_copy


def read_original_text(path: Path) -> str:
    """Read all context/diff text, retaining CRLF, LF, CR and a UTF-8 BOM.

    Invalid UTF-8 is replaced for presentation only. Execution and delivery must
    copy the original source bytes with ``copy_original_dofile``.
    """
    with Path(path).open("r", encoding="utf-8", errors="replace", newline="") as stream:
        return stream.read()


def _digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _identity(path: Path) -> tuple[int, ...]:
    value = path.stat()
    return value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns


def _same_file(left: Path, right: Path) -> bool:
    if left == right:
        return True
    try:
        return os.path.samefile(left, right)
    except FileNotFoundError:
        return False


def _destination(path: Path, source: Path) -> Path:
    if path.is_symlink():
        raise ValueError("Original Dofile destinations must not be symbolic links")
    resolved = path.resolve(strict=False)
    if _same_file(source, resolved):
        raise ValueError("Original Dofile destination aliases the protected source")
    if resolved.exists() and not stat.S_ISREG(resolved.stat().st_mode):
        raise ValueError("Original Dofile destinations must be regular files")
    if not resolved.parent.is_dir():
        raise FileNotFoundError(f"Original Dofile destination directory does not exist: {path.parent}")
    return resolved


def copy_original_dofile(source: Path, exec_path: Path, deliv_path: Path) -> tuple[Path, Path]:
    """Create independent execution/delivery copies, preserving every source byte.

    Validate both output paths before either write. The source cannot be any
    destination, including hard links and aliases through parent directories.
    Each atomic copy uses a distinct inode; output changes cannot affect input.
    SHA-256 checks are streamed and source mutations prevent a successful return.
    Output parents must already exist and must be checked by the caller against
    its allowed run/output roots. This helper does not create parent directories.
    """
    original = Path(source).resolve(strict=True)
    if not stat.S_ISREG(original.stat().st_mode):
        raise ValueError("Original Dofile source must be a regular file")
    execution_argument, delivery_argument = Path(exec_path), Path(deliv_path)
    execution = _destination(execution_argument, original)
    delivery = _destination(delivery_argument, original)
    if _same_file(execution, delivery):
        raise ValueError("Original execution and delivery Dofiles must be independent files")
    identity = _identity(original)
    expected = _digest(original)
    if _identity(original) != identity:
        raise RuntimeError("Original Dofile changed while preparing its copies")
    independent_copy(original, execution)
    independent_copy(original, delivery)
    if (_identity(original) != identity or _digest(original) != expected or
            _digest(execution) != expected or _digest(delivery) != expected):
        raise RuntimeError("Original Dofile bytes changed or its copies do not match")
    if _same_file(original, execution) or _same_file(original, delivery) or _same_file(execution, delivery):
        raise RuntimeError("Original Dofile copies are not independent")
    return execution_argument, delivery_argument
