"""Access to the Run Contract JSON Schema bundled with the Python package."""

from __future__ import annotations

import copy
import json
from importlib.resources import files
from typing import Any


def schema_bytes() -> bytes:
    """Return the exact bundled Run Contract v1 JSON Schema bytes."""

    return files("thyroros.data").joinpath("run-contract.schema.json").read_bytes()


def schema_document() -> dict[str, Any]:
    """Return a fresh object containing the bundled Run Contract v1 JSON Schema."""

    value = json.loads(schema_bytes())
    if not isinstance(value, dict):  # pragma: no cover - package integrity boundary
        raise RuntimeError("bundled Run Contract schema is not a JSON object")
    return copy.deepcopy(value)
