"""Bounded byte/file loading for Run Contract v1."""

from __future__ import annotations

import errno
import json
import os
import stat
from pathlib import Path
from typing import Any

from ._contract_core import (
    ContractDocumentError,
    DuplicateKeyError,
    MAX_CONTRACT_BYTES,
    Violation,
)

def _no_duplicate_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateKeyError(key)
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON number {value!r} is forbidden")


def _document_error(code: str, message: str) -> ContractDocumentError:
    return ContractDocumentError((Violation(code, "$", message),))


def _read_regular_file(path: str | Path) -> bytes:
    contract_path = Path(path)
    try:
        initial = os.lstat(contract_path)
    except (FileNotFoundError, NotADirectoryError) as exc:
        raise _document_error(
            "document_not_file", f"{contract_path} is not a regular file"
        ) from exc
    except OSError as exc:
        raise _document_error("document_stat_failed", str(exc)) from exc

    if stat.S_ISLNK(initial.st_mode):
        raise _document_error(
            "document_symlink_refused",
            "contract files are read directly and may not be symlinks",
        )
    if not stat.S_ISREG(initial.st_mode):
        raise _document_error(
            "document_not_file", f"{contract_path} is not a regular file"
        )
    if initial.st_size > MAX_CONTRACT_BYTES:
        raise _document_error(
            "document_too_large",
            f"contract is {initial.st_size} bytes; maximum is {MAX_CONTRACT_BYTES}",
        )

    flags = os.O_RDONLY
    flags |= getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(contract_path, flags)
    except OSError as exc:
        if exc.errno in {errno.ELOOP, getattr(errno, "EMLINK", -1)}:
            raise _document_error(
                "document_symlink_refused",
                "contract files may not resolve through a symlink",
            ) from exc
        raise _document_error("document_open_failed", str(exc)) from exc

    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode):
            raise _document_error(
                "document_not_file", f"{contract_path} is not a regular file"
            )
        if opened.st_size > MAX_CONTRACT_BYTES:
            raise _document_error(
                "document_too_large",
                f"contract is {opened.st_size} bytes; maximum is {MAX_CONTRACT_BYTES}",
            )
        if (
            initial.st_dev != opened.st_dev
            or initial.st_ino != opened.st_ino
        ):
            raise _document_error(
                "document_changed_during_open",
                "contract path changed between metadata check and open",
            )

        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(65_536, MAX_CONTRACT_BYTES + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > MAX_CONTRACT_BYTES:
                raise _document_error(
                    "document_too_large",
                    f"contract exceeds maximum size {MAX_CONTRACT_BYTES}",
                )
        return b"".join(chunks)
    except ContractDocumentError:
        raise
    except OSError as exc:
        raise _document_error("document_read_failed", str(exc)) from exc
    finally:
        os.close(descriptor)


def load_contract(path: str | Path) -> dict[str, Any]:
    """Load and validate a regular UTF-8 JSON contract file without following links."""

    return load_contract_bytes(_read_regular_file(path))


def load_contract_bytes(raw: bytes, *, source: str = "<bytes>") -> dict[str, Any]:
    """Parse and validate contract bytes supplied by an embedding adapter."""

    if not isinstance(raw, bytes):
        raise TypeError("raw contract input must be bytes")
    if len(raw) > MAX_CONTRACT_BYTES:
        raise _document_error(
            "document_too_large",
            f"{source} is {len(raw)} bytes; maximum is {MAX_CONTRACT_BYTES}",
        )
    if raw.startswith(b"\xef\xbb\xbf"):
        raise _document_error(
            "document_bom_forbidden",
            "UTF-8 BOM is refused to keep byte handling explicit",
        )

    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise _document_error("document_not_utf8", f"invalid UTF-8: {exc}") from exc

    try:
        parsed = json.loads(
            text,
            object_pairs_hook=_no_duplicate_object,
            parse_constant=_reject_json_constant,
        )
    except DuplicateKeyError as exc:
        raise _document_error(
            "document_duplicate_key", f"duplicate object key {exc.args[0]!r}"
        ) from exc
    except (json.JSONDecodeError, ValueError) as exc:
        raise _document_error("document_invalid_json", str(exc)) from exc

    if not isinstance(parsed, dict):
        raise _document_error("document_root_not_object", "root must be a JSON object")

    from ._contract_validation import validate_run_contract

    validation = validate_run_contract(parsed)
    if validation:
        raise ContractDocumentError(validation)
    return parsed
