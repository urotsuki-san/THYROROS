"""Reference authorization decisions over a validated THYROROS Run Contract.

This module is a policy engine, not an OS enforcement boundary.  A broker or launcher
must still ensure every real effect is routed through these decisions and must apply
platform-specific canonicalization before presenting a resource identity.
"""

from __future__ import annotations

import copy
import re
import unicodedata
from dataclasses import dataclass
from datetime import datetime, timezone
from types import MappingProxyType
from typing import Any, Mapping
from urllib.parse import SplitResult, urlsplit

from .canonical import canonical_digest
from .contracts import (
    ALLOWED_METHODS,
    ContractDocumentError,
    Violation,
    _validate_image_name,
    _validate_secret_ref,
    parse_rfc3339,
    url_path_prefix_matches,
    validate_network_host,
    validate_run_contract,
)
from .effects import EffectClass
from .scopes import ScopeAnalysisError, match_scope, validate_scope_target

_DANGEROUS_ESCAPE_RE = re.compile(r"%(?:25|2e|2f|5c)", re.IGNORECASE)
_VALID_ESCAPE_RE = re.compile(r"%[0-9A-Fa-f]{2}")
MAX_REQUEST_URL_CHARS = 8192


@dataclass(frozen=True, slots=True)
class PolicyDecision:
    """A stable allow/deny result bound to one canonical contract digest."""

    allowed: bool
    code: str
    message: str
    contract_digest: str
    matched_rule: str | None = None

    @property
    def decision(self) -> str:
        return "ALLOW" if self.allowed else "DENY"

    def as_dict(self) -> dict[str, Any]:
        return {
            "decision": self.decision,
            "allowed": self.allowed,
            "code": self.code,
            "message": self.message,
            "contract_digest": self.contract_digest,
            "matched_rule": self.matched_rule,
        }


class PolicyRequestError(ValueError):
    """The resource request itself was malformed or ambiguous."""

    def __init__(self, code: str, path: str, message: str):
        self.violation = Violation(code, path, message)
        super().__init__(f"{code} at {path}: {message}")

    def as_dict(self) -> dict[str, Any]:
        return {
            "decision": "DENY",
            "valid_request": False,
            "violations": [self.violation.as_dict()],
        }


def _freeze(value: Any) -> Any:
    if isinstance(value, dict):
        return MappingProxyType({key: _freeze(item) for key, item in value.items()})
    if isinstance(value, list):
        return tuple(_freeze(item) for item in value)
    return value


class PolicyEngine:
    """Immutable-in-practice reference engine compiled from one valid contract."""

    __slots__ = ("_contract", "contract_digest")

    def __init__(self, contract: Mapping[str, Any]):
        candidate = copy.deepcopy(dict(contract))
        violations = validate_run_contract(candidate)
        if violations:
            raise ContractDocumentError(violations)
        self.contract_digest = canonical_digest(candidate)
        self._contract = _freeze(candidate)

    def _decision(
        self,
        allowed: bool,
        code: str,
        message: str,
        matched_rule: str | None = None,
    ) -> PolicyDecision:
        return PolicyDecision(
            allowed=allowed,
            code=code,
            message=message,
            contract_digest=self.contract_digest,
            matched_rule=matched_rule,
        )

    def _active_decision(self, at: datetime | None) -> PolicyDecision | None:
        instant = at if at is not None else datetime.now(timezone.utc)
        if not isinstance(instant, datetime) or instant.tzinfo is None or instant.utcoffset() is None:
            raise PolicyRequestError(
                "request_time_invalid",
                "$.request.at",
                "authorization time must be a timezone-aware datetime",
            )
        created = parse_rfc3339(self._contract["run"]["created_at"])
        expires = parse_rfc3339(self._contract["run"]["expires_at"])
        if instant < created:
            return self._decision(
                False,
                "run_not_yet_active",
                "the Run Contract has not reached created_at",
            )
        if instant >= expires:
            return self._decision(
                False,
                "run_expired",
                "the Run Contract lease has expired",
            )
        return None

    def authorize_file(
        self, operation: str, target: str, *, at: datetime | None = None
    ) -> PolicyDecision:
        inactive = self._active_decision(at)
        if inactive is not None:
            return inactive
        if operation not in {"read", "write"}:
            raise PolicyRequestError(
                "file_operation_invalid",
                "$.request.operation",
                "operation must be exactly 'read' or 'write'",
            )
        if not isinstance(target, str):
            raise PolicyRequestError(
                "file_path_invalid", "$.request.path", "path must be a string"
            )
        problem = validate_scope_target(target)
        if problem is not None:
            raise PolicyRequestError("file_path_invalid", "$.request.path", problem)

        try:
            for rule in self._contract["authority"]["deny"]:
                if match_scope(rule, target):
                    return self._decision(
                        False,
                        "file_denied_by_rule",
                        "deny rules take precedence over granted file scopes",
                        rule,
                    )
            for rule in self._contract["authority"][operation]:
                if match_scope(rule, target):
                    return self._decision(
                        True,
                        "file_allowed",
                        f"{operation} is admitted by the matched scope",
                        rule,
                    )
        except ScopeAnalysisError as exc:  # valid contracts should make this unreachable
            return self._decision(False, "scope_analysis_failed", str(exc))

        return self._decision(
            False,
            "file_scope_not_granted",
            f"no {operation} scope admits the requested path",
        )

    def authorize_network(
        self,
        method: str,
        url: str,
        *,
        requests_used: int = 0,
        at: datetime | None = None,
    ) -> PolicyDecision:
        inactive = self._active_decision(at)
        if inactive is not None:
            return inactive
        normalized_method = _normalize_method(method)
        request = _parse_https_request(url)
        if isinstance(requests_used, bool) or not isinstance(requests_used, int) or requests_used < 0:
            raise PolicyRequestError(
                "network_request_count_invalid",
                "$.request.requests_used",
                "requests_used must be a non-negative integer",
            )
        if requests_used >= self._contract["budget"]["network_requests"]:
            return self._decision(
                False,
                "network_budget_exhausted",
                "the Run Contract network request budget is exhausted",
            )

        for index, rule in enumerate(self._contract["authority"]["network"]["allow"]):
            if (
                normalized_method in rule["methods"]
                and request.scheme == rule["scheme"]
                and request.hostname == rule["host"]
                and request.port == rule["port"]
                and url_path_prefix_matches(rule["path_prefix"], request.path)
            ):
                return self._decision(
                    True,
                    "network_allowed",
                    "HTTPS request is admitted by the matched network rule",
                    f"$.authority.network.allow[{index}]",
                )

        return self._decision(
            False,
            "network_scope_not_granted",
            "no network rule admits the normalized HTTPS request",
        )

    def authorize_process(
        self,
        image: str,
        *,
        current_children: int,
        at: datetime | None = None,
    ) -> PolicyDecision:
        inactive = self._active_decision(at)
        if inactive is not None:
            return inactive
        if not isinstance(image, str):
            raise PolicyRequestError(
                "process_image_invalid", "$.request.image", "image must be a string"
            )
        problem = _validate_image_name(image)
        if problem is not None:
            raise PolicyRequestError("process_image_invalid", "$.request.image", problem)
        if (
            isinstance(current_children, bool)
            or not isinstance(current_children, int)
            or current_children < 0
        ):
            raise PolicyRequestError(
                "process_count_invalid",
                "$.request.current_children",
                "current_children must be a non-negative integer",
            )

        process = self._contract["authority"]["process"]
        if current_children >= process["max_children"]:
            return self._decision(
                False,
                "process_budget_exhausted",
                "max_children would be exceeded",
            )
        for allowed in process["allowed_images"]:
            if image.casefold() == allowed.casefold():
                return self._decision(
                    True,
                    "process_allowed",
                    "executable basename is admitted and child capacity remains",
                    allowed,
                )
        return self._decision(
            False,
            "process_image_not_granted",
            "executable basename is not admitted by the contract",
        )

    def authorize_secret(
        self, secret_ref: str, *, at: datetime | None = None
    ) -> PolicyDecision:
        inactive = self._active_decision(at)
        if inactive is not None:
            return inactive
        if not isinstance(secret_ref, str):
            raise PolicyRequestError(
                "secret_ref_invalid",
                "$.request.secret",
                "secret reference must be a string",
            )
        problem = _validate_secret_ref(secret_ref)
        if problem is not None:
            raise PolicyRequestError("secret_ref_invalid", "$.request.secret", problem)
        if secret_ref in self._contract["authority"]["secrets"]:
            return self._decision(
                True,
                "secret_allowed",
                "opaque secret reference is admitted by the contract",
                secret_ref,
            )
        return self._decision(
            False,
            "secret_not_granted",
            "secret reference is not admitted by the contract",
        )

    def authorize_effect(
        self, effect: str | EffectClass, *, at: datetime | None = None
    ) -> PolicyDecision:
        inactive = self._active_decision(at)
        if inactive is not None:
            return inactive
        requested = effect if isinstance(effect, EffectClass) else EffectClass.parse(effect)
        if requested is None:
            raise PolicyRequestError(
                "effect_invalid",
                "$.request.effect",
                "effect must name a known EffectClass",
            )
        maximum = EffectClass[self._contract["authority"]["maximum_effect"]]
        if requested <= maximum:
            return self._decision(
                True,
                "effect_allowed",
                f"{requested.name} does not exceed {maximum.name}",
                maximum.name,
            )
        return self._decision(
            False,
            "effect_exceeds_contract",
            f"{requested.name} exceeds maximum effect {maximum.name}",
            maximum.name,
        )


@dataclass(frozen=True, slots=True)
class _NetworkRequest:
    scheme: str
    hostname: str
    port: int
    path: str


def _normalize_method(method: str) -> str:
    if not isinstance(method, str) or not method or method.strip() != method:
        raise PolicyRequestError(
            "network_method_invalid",
            "$.request.method",
            "method must be a non-empty HTTP token without surrounding whitespace",
        )
    normalized = method.upper()
    if normalized not in ALLOWED_METHODS:
        raise PolicyRequestError(
            "network_method_invalid",
            "$.request.method",
            f"unsupported HTTP method {method!r}",
        )
    return normalized


def _parse_https_request(url: str) -> _NetworkRequest:
    if not isinstance(url, str) or not url or len(url) > MAX_REQUEST_URL_CHARS:
        raise PolicyRequestError(
            "network_url_invalid",
            "$.request.url",
            f"URL must be a non-empty string of at most {MAX_REQUEST_URL_CHARS} characters",
        )
    if unicodedata.normalize("NFC", url) != url:
        raise PolicyRequestError(
            "network_url_invalid", "$.request.url", "URL must use NFC-normalized Unicode"
        )
    if "\\" in url or any(ord(character) < 0x20 or ord(character) == 0x7F for character in url):
        raise PolicyRequestError(
            "network_url_invalid",
            "$.request.url",
            "URL may not contain backslash or control characters",
        )

    try:
        split: SplitResult = urlsplit(url)
    except ValueError as exc:
        raise PolicyRequestError("network_url_invalid", "$.request.url", str(exc)) from exc
    if split.scheme.lower() != "https":
        raise PolicyRequestError(
            "network_url_not_https", "$.request.url", "only HTTPS requests are admitted"
        )
    if split.username is not None or split.password is not None:
        raise PolicyRequestError(
            "network_url_userinfo_forbidden",
            "$.request.url",
            "URL userinfo is forbidden",
        )
    if split.fragment:
        raise PolicyRequestError(
            "network_url_fragment_forbidden",
            "$.request.url",
            "URL fragments are not part of an HTTP request target and are forbidden",
        )

    hostname = split.hostname
    if hostname is None:
        raise PolicyRequestError(
            "network_host_invalid", "$.request.url", "URL must contain an exact hostname"
        )
    hostname = hostname.lower()
    host_problem = validate_network_host(hostname)
    if host_problem is not None:
        raise PolicyRequestError("network_host_invalid", "$.request.url", host_problem)
    try:
        explicit_port = split.port
        port = explicit_port if explicit_port is not None else 443
    except ValueError as exc:
        raise PolicyRequestError("network_port_invalid", "$.request.url", str(exc)) from exc

    path = split.path or "/"
    if not path.startswith("/"):
        raise PolicyRequestError(
            "network_path_invalid", "$.request.url", "request path must be absolute"
        )
    if "//" in path:
        raise PolicyRequestError(
            "network_path_ambiguous",
            "$.request.url",
            "request path may not contain empty path segments",
        )
    if any(segment in {".", ".."} for segment in path.split("/")):
        raise PolicyRequestError(
            "network_path_traversal",
            "$.request.url",
            "request path contains dot traversal segments",
        )
    if _DANGEROUS_ESCAPE_RE.search(path):
        raise PolicyRequestError(
            "network_path_ambiguous_encoding",
            "$.request.url",
            "encoded percent, dot, or path separators are refused",
        )
    escapes = _VALID_ESCAPE_RE.findall(path)
    if sum(len(item) for item in escapes) != path.count("%") * 3:
        raise PolicyRequestError(
            "network_path_invalid_encoding",
            "$.request.url",
            "request path contains malformed percent encoding",
        )

    return _NetworkRequest("https", hostname, port, path)


def authorize_file(
    contract: Mapping[str, Any],
    operation: str,
    target: str,
    *,
    at: datetime | None = None,
) -> PolicyDecision:
    return PolicyEngine(contract).authorize_file(operation, target, at=at)


def authorize_network(
    contract: Mapping[str, Any],
    method: str,
    url: str,
    *,
    requests_used: int = 0,
    at: datetime | None = None,
) -> PolicyDecision:
    return PolicyEngine(contract).authorize_network(
        method, url, requests_used=requests_used, at=at
    )


def authorize_process(
    contract: Mapping[str, Any],
    image: str,
    *,
    current_children: int,
    at: datetime | None = None,
) -> PolicyDecision:
    return PolicyEngine(contract).authorize_process(
        image, current_children=current_children, at=at
    )


def authorize_secret(
    contract: Mapping[str, Any], secret_ref: str, *, at: datetime | None = None
) -> PolicyDecision:
    return PolicyEngine(contract).authorize_secret(secret_ref, at=at)


def authorize_effect(
    contract: Mapping[str, Any],
    effect: str | EffectClass,
    *,
    at: datetime | None = None,
) -> PolicyDecision:
    return PolicyEngine(contract).authorize_effect(effect, at=at)
