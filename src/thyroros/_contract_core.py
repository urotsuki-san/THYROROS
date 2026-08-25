"""Shared types, limits, and primitive validators for Run Contract v1."""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Callable, Iterable, Mapping, Sequence

from .scopes import MAX_SCOPE_RULES

MAX_CONTRACT_BYTES = 1_048_576

MAX_NETWORK_RULES = 64

MAX_PROCESS_IMAGES = 64

MAX_SECRET_REFS = 64

MAX_ACCEPTANCE_COMMANDS = 64

MAX_COMMAND_ARGUMENTS = 256

TOP_LEVEL_KEYS = {
    "schema",
    "version",
    "run",
    "subject",
    "authority",
    "budget",
    "acceptance",
}

RUN_KEYS = {"id", "task_digest", "created_at", "expires_at"}

SUBJECT_KEYS = {"repository", "base_revision", "workspace_digest"}

AUTHORITY_KEYS = {
    "read",
    "write",
    "deny",
    "network",
    "process",
    "secrets",
    "maximum_effect",
}

NETWORK_KEYS = {"default", "allow"}

NETWORK_RULE_KEYS = {"methods", "scheme", "host", "port", "path_prefix"}

PROCESS_KEYS = {"allowed_images", "max_children"}

BUDGET_KEYS = {"wall_seconds", "memory_mib", "network_requests"}

ACCEPTANCE_KEYS = {"commands", "forbidden_diff"}

COMMAND_KEYS = {"argv", "timeout_seconds"}

RUN_ID_RE = re.compile(r"^run_[a-z0-9][a-z0-9._-]{2,127}$")

DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")

REPOSITORY_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")

SECRET_RE = re.compile(r"^secret:[a-z0-9][a-z0-9._/-]{2,255}$")

HOST_RE = re.compile(r"^[a-z0-9.-]{1,253}$")

RFC3339_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})$"
)

PERCENT_ESCAPE_RE = re.compile(r"%[0-9A-Fa-f]{2}")

ALLOWED_METHODS = {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}


@dataclass(frozen=True, slots=True)
class Violation:
    """A stable machine-readable contract or comparison finding."""

    code: str
    path: str
    message: str

    def as_dict(self) -> dict[str, str]:
        return {"code": self.code, "path": self.path, "message": self.message}


@dataclass(frozen=True, slots=True)
class AuthorityComparison:
    """Result of verifying ``child authority ⊆ parent authority``."""

    allowed: bool
    violations: tuple[Violation, ...]

    @property
    def decision(self) -> str:
        return "ALLOW" if self.allowed else "HOLD"

    def as_dict(self) -> dict[str, Any]:
        return {
            "decision": self.decision,
            "allowed": self.allowed,
            "violations": [item.as_dict() for item in self.violations],
        }


class ContractDocumentError(ValueError):
    """A contract could not be loaded or did not satisfy the normative validator."""

    def __init__(self, violations: Sequence[Violation]):
        self.violations = tuple(violations)
        summary = "; ".join(
            f"{item.code} at {item.path}: {item.message}" for item in self.violations
        )
        super().__init__(summary)


class DuplicateKeyError(ValueError):
    pass


def validate_network_host(value: str) -> str | None:
    if not value or HOST_RE.fullmatch(value) is None or value != value.lower():
        return "host must be an exact lowercase ASCII DNS name"
    if value.startswith(".") or value.endswith(".") or ".." in value:
        return "host may not contain empty DNS labels or a trailing dot"
    labels = value.split(".")
    for label in labels:
        if len(label) > 63:
            return "DNS labels may contain at most 63 characters"
        if label.startswith("-") or label.endswith("-"):
            return "DNS labels may not start or end with a hyphen"
        if not all(character.isdigit() or "a" <= character <= "z" or character == "-" for character in label):
            return "host must contain only lowercase ASCII DNS characters"
    return None


def validate_url_path_prefix(value: str) -> str | None:
    if not value or len(value) > 2048 or not value.startswith("/"):
        return "path_prefix must be an absolute URL path of 1-2048 characters"
    if unicodedata.normalize("NFC", value) != value:
        return "path_prefix must use NFC-normalized Unicode"
    if "\\" in value or "?" in value or "#" in value:
        return "path_prefix may not contain backslash, query, or fragment syntax"
    if "//" in value:
        return "path_prefix may not contain empty path segments"
    if any(ord(character) < 0x20 or ord(character) == 0x7F for character in value):
        return "path_prefix may not contain control characters"
    if any(segment in {".", ".."} for segment in value.split("/")):
        return "path_prefix may not contain dot traversal segments"
    if "%" in value:
        escapes = PERCENT_ESCAPE_RE.findall(value)
        if sum(len(item) for item in escapes) != value.count("%") * 3:
            return "path_prefix contains malformed percent encoding"
        return "percent-encoded contract path prefixes are not admitted in v1"
    return None


def url_path_prefix_matches(prefix: str, path: str) -> bool:
    """Segment-aware URL path-prefix comparison used by contracts and requests."""

    if prefix == "/":
        return path.startswith("/")
    if prefix.endswith("/"):
        return path.startswith(prefix)
    return path == prefix or path.startswith(prefix + "/")


def _validate_image_name(value: str) -> str | None:
    if not value or len(value) > 260:
        return "image must be a basename of 1-260 characters"
    if unicodedata.normalize("NFC", value) != value:
        return "image must use NFC-normalized Unicode"
    if any(character in "/\\\x00:<>|\"" for character in value):
        return "image must be a portable basename without path or device syntax"
    if any(ord(character) < 0x20 or ord(character) == 0x7F for character in value):
        return "image may not contain control characters"
    if value.endswith((" ", ".")):
        return "image may not end with a space or dot"
    stem = value.split(".", 1)[0].upper()
    if stem in {"CON", "PRN", "AUX", "NUL"} or re.fullmatch(r"(?:COM|LPT)[1-9]", stem):
        return "Windows reserved device names are forbidden"
    return None


def _validate_secret_ref(value: str) -> str | None:
    if SECRET_RE.fullmatch(value) is None:
        return "secret references must match secret:<namespace>/<name>"
    return None


def _validate_string_list(
    value: Any,
    path: str,
    violations: list[Violation],
    item_validator: Callable[[str], str | None],
    *,
    maximum: int,
    minimum: int = 0,
    duplicate_key: Callable[[str], str] | None = None,
) -> list[str] | None:
    if not isinstance(value, list):
        violations.append(Violation("list_expected", path, "expected an array"))
        return None
    if len(value) < minimum or len(value) > maximum:
        violations.append(
            Violation(
                "list_size_out_of_range",
                path,
                f"expected {minimum} <= item count <= {maximum}",
            )
        )
    key_function = duplicate_key or (lambda item: item)
    seen: set[str] = set()
    result: list[str] = []
    for index, item in enumerate(value):
        item_path = f"{path}[{index}]"
        if not isinstance(item, str):
            violations.append(Violation("string_expected", item_path, "expected a string"))
            continue
        marker = key_function(item)
        if marker in seen:
            violations.append(
                Violation("duplicate_list_item", item_path, f"duplicate value {item!r}")
            )
        seen.add(marker)
        problem = item_validator(item)
        if problem is not None:
            violations.append(Violation("list_item_invalid", item_path, problem))
        result.append(item)
    return result


def parse_rfc3339(value: str) -> datetime:
    """Parse the strict RFC 3339 profile admitted by Run Contract v1."""

    if not isinstance(value, str) or RFC3339_RE.fullmatch(value) is None:
        raise ValueError("timestamp must be RFC 3339 with an explicit offset")
    if value.endswith("-00:00"):
        raise ValueError("unknown local offset -00:00 is forbidden")
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise ValueError(f"invalid calendar timestamp: {exc}") from exc
    offset = parsed.utcoffset()
    if offset is None:
        raise ValueError("timestamp must include an explicit UTC offset")
    if abs(offset) > timedelta(hours=14):
        raise ValueError("UTC offset must be within ±14:00")
    return parsed


def _parse_timestamp(value: Any, path: str, violations: list[Violation]) -> datetime | None:
    if not isinstance(value, str):
        violations.append(Violation("timestamp_not_string", path, "timestamp must be a string"))
        return None
    try:
        return parse_rfc3339(value)
    except ValueError as exc:
        violations.append(Violation("timestamp_invalid", path, str(exc)))
        return None


def _validate_digest(value: Any, path: str, violations: list[Violation]) -> None:
    if not isinstance(value, str) or DIGEST_RE.fullmatch(value) is None:
        violations.append(
            Violation(
                "digest_invalid",
                path,
                "expected lowercase sha256:<64 hexadecimal characters>",
            )
        )


def _validate_int(
    value: Any,
    path: str,
    violations: list[Violation],
    *,
    minimum: int,
    maximum: int,
) -> None:
    if isinstance(value, bool) or not isinstance(value, int):
        violations.append(Violation("integer_expected", path, "expected an integer"))
        return
    if value < minimum or value > maximum:
        violations.append(
            Violation(
                "integer_out_of_range",
                path,
                f"expected {minimum} <= value <= {maximum}",
            )
        )


def _object(value: Any, path: str, violations: list[Violation]) -> Mapping[str, Any] | None:
    if not isinstance(value, dict):
        violations.append(Violation("object_expected", path, "expected an object"))
        return None
    return value


def _reject_unknown(
    value: Mapping[str, Any], allowed: set[str], path: str, violations: list[Violation]
) -> None:
    for key in sorted(set(value) - allowed):
        violations.append(
            Violation(
                "unknown_member",
                f"{path}.{key}",
                "member is not admitted by this schema revision",
            )
        )


def _require_keys(
    value: Mapping[str, Any], required: set[str], path: str, violations: list[Violation]
) -> None:
    for key in sorted(required - set(value)):
        violations.append(
            Violation(
                "required_member_missing",
                f"{path}.{key}",
                "required member is missing",
            )
        )


def _expect_exact(
    value: Any, expected: Any, path: str, violations: list[Violation]
) -> None:
    if value != expected or type(value) is not type(expected):
        violations.append(
            Violation("constant_mismatch", path, f"expected exact value {expected!r}")
        )


def _require_equal(
    parent_value: Any,
    child_value: Any,
    path: str,
    code: str,
    violations: list[Violation],
) -> None:
    if parent_value != child_value:
        violations.append(Violation(code, path, "child value must equal parent value"))


def _require_exact_set_subset(
    parent_values: Iterable[str],
    child_values: Iterable[str],
    path: str,
    code: str,
    violations: list[Violation],
) -> None:
    for item in sorted(set(child_values) - set(parent_values)):
        violations.append(Violation(code, path, f"child adds value {item!r}"))
