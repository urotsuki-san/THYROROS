"""Deterministic THYROROS Canonical JSON v1 encoding."""

from __future__ import annotations

import hashlib
import json
import unicodedata
from typing import Any

MAX_CANONICAL_DEPTH = 64
MAX_SAFE_INTEGER = (1 << 53) - 1


class CanonicalizationError(ValueError):
    """The value is outside the canonical data model."""


def _validate_value(value: Any, *, depth: int, active: set[int]) -> None:
    if depth > MAX_CANONICAL_DEPTH:
        raise CanonicalizationError(
            f"document exceeds maximum nesting depth {MAX_CANONICAL_DEPTH}"
        )

    if value is None or isinstance(value, bool):
        return
    if isinstance(value, int):
        if not -MAX_SAFE_INTEGER <= value <= MAX_SAFE_INTEGER:
            raise CanonicalizationError(
                f"integer {value} exceeds the interoperable JSON safe range"
            )
        return
    if isinstance(value, float):
        raise CanonicalizationError("floating-point numbers are not admitted")
    if isinstance(value, str):
        if unicodedata.normalize("NFC", value) != value:
            raise CanonicalizationError("strings must use NFC-normalized Unicode")
        if any(0xD800 <= ord(character) <= 0xDFFF for character in value):
            raise CanonicalizationError("unpaired Unicode surrogates are forbidden")
        return

    if isinstance(value, (list, tuple)):
        identity = id(value)
        if identity in active:
            raise CanonicalizationError("cyclic arrays are forbidden")
        active.add(identity)
        try:
            for item in value:
                _validate_value(item, depth=depth + 1, active=active)
        finally:
            active.remove(identity)
        return

    if isinstance(value, dict):
        identity = id(value)
        if identity in active:
            raise CanonicalizationError("cyclic objects are forbidden")
        active.add(identity)
        try:
            for key, item in value.items():
                if not isinstance(key, str):
                    raise CanonicalizationError("object keys must be strings")
                _validate_value(key, depth=depth + 1, active=active)
                _validate_value(item, depth=depth + 1, active=active)
        finally:
            active.remove(identity)
        return

    raise CanonicalizationError(
        f"unsupported canonical value type {type(value).__name__}"
    )


def canonical_json_bytes(value: Any) -> bytes:
    """Return THYROROS Canonical JSON v1.

    This deliberately restricted format is not advertised as a general RFC 8785
    implementation.  It admits NFC strings, booleans, null, arrays, objects with
    string keys, and integers in the interoperable IEEE-754 safe range.  Floats,
    duplicate keys (at parse time), cycles, and non-normalized Unicode are refused.
    """

    _validate_value(value, depth=0, active=set())
    try:
        encoded = json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        return encoded.encode("utf-8", errors="strict")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise CanonicalizationError(str(exc)) from exc


def canonical_digest(value: Any) -> str:
    """Return a lowercase ``sha256:`` digest of canonical JSON bytes."""

    return "sha256:" + hashlib.sha256(canonical_json_bytes(value)).hexdigest()
