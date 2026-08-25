"""Semantic child-authority conservation for Run Contract v1."""

from __future__ import annotations

from typing import Any, Mapping, Sequence

from .canonical import canonical_digest
from .effects import EffectClass
from .scopes import ScopeAnalysisError, scope_expansion_witness
from ._contract_core import (
    AuthorityComparison,
    ContractDocumentError,
    Violation,
    _require_equal,
    _require_exact_set_subset,
    parse_rfc3339,
    url_path_prefix_matches,
)
from ._contract_validation import validate_run_contract

def compare_child_authority(
    parent: Mapping[str, Any], child: Mapping[str, Any]
) -> AuthorityComparison:
    """Verify that a child contract only narrows the parent's effective authority."""

    parent_violations = validate_run_contract(parent)
    child_violations = validate_run_contract(child)
    if parent_violations or child_violations:
        prefixed: list[Violation] = []
        prefixed.extend(
            Violation(f"parent_{item.code}", item.path, item.message)
            for item in parent_violations
        )
        prefixed.extend(
            Violation(f"child_{item.code}", item.path, item.message)
            for item in child_violations
        )
        raise ContractDocumentError(prefixed)

    violations: list[Violation] = []
    _require_equal(
        parent["run"]["task_digest"],
        child["run"]["task_digest"],
        "$.run.task_digest",
        "child_task_changed",
        violations,
    )
    for key in ("repository", "base_revision", "workspace_digest"):
        _require_equal(
            parent["subject"][key],
            child["subject"][key],
            f"$.subject.{key}",
            f"child_subject_{key}_changed",
            violations,
        )

    parent_created = parse_rfc3339(parent["run"]["created_at"])
    child_created = parse_rfc3339(child["run"]["created_at"])
    parent_expires = parse_rfc3339(parent["run"]["expires_at"])
    child_expires = parse_rfc3339(child["run"]["expires_at"])
    if child_created < parent_created:
        violations.append(
            Violation(
                "child_time_starts_before_parent",
                "$.run.created_at",
                "child created_at may not predate parent created_at",
            )
        )
    if child_expires > parent_expires:
        violations.append(
            Violation(
                "child_time_exceeds_parent",
                "$.run.expires_at",
                "child expires_at may not exceed parent expires_at",
            )
        )

    parent_authority = parent["authority"]
    child_authority = child["authority"]
    _require_scope_subset(
        parent_authority["read"],
        child_authority["read"],
        "$.authority.read",
        "child_read_scope_expanded",
        violations,
    )
    _require_scope_subset(
        parent_authority["write"],
        child_authority["write"],
        "$.authority.write",
        "child_write_scope_expanded",
        violations,
    )
    _require_scope_subset(
        child_authority["deny"],
        parent_authority["deny"],
        "$.authority.deny",
        "child_deny_scope_removed",
        violations,
        inverse_message=True,
    )

    parent_images = {item.casefold() for item in parent_authority["process"]["allowed_images"]}
    child_images = {item.casefold() for item in child_authority["process"]["allowed_images"]}
    for extra in sorted(child_images - parent_images):
        violations.append(
            Violation(
                "child_process_image_expanded",
                "$.authority.process.allowed_images",
                f"child adds executable image {extra!r}",
            )
        )
    if (
        child_authority["process"]["max_children"]
        > parent_authority["process"]["max_children"]
    ):
        violations.append(
            Violation(
                "child_process_count_expanded",
                "$.authority.process.max_children",
                "child max_children exceeds parent",
            )
        )

    _require_exact_set_subset(
        parent_authority["secrets"],
        child_authority["secrets"],
        "$.authority.secrets",
        "child_secret_scope_expanded",
        violations,
    )

    parent_effect = EffectClass[parent_authority["maximum_effect"]]
    child_effect = EffectClass[child_authority["maximum_effect"]]
    if child_effect > parent_effect:
        violations.append(
            Violation(
                "child_effect_expanded",
                "$.authority.maximum_effect",
                f"child {child_effect.name} exceeds parent {parent_effect.name}",
            )
        )

    _compare_network_authority(
        parent_authority["network"]["allow"],
        child_authority["network"]["allow"],
        violations,
    )

    for key in ("wall_seconds", "memory_mib", "network_requests"):
        if child["budget"][key] > parent["budget"][key]:
            violations.append(
                Violation(
                    f"child_budget_{key}_expanded",
                    f"$.budget.{key}",
                    f"child {key} exceeds parent",
                )
            )

    _compare_acceptance_commands(
        parent["acceptance"]["commands"],
        child["acceptance"]["commands"],
        violations,
    )
    _require_scope_subset(
        child["acceptance"]["forbidden_diff"],
        parent["acceptance"]["forbidden_diff"],
        "$.acceptance.forbidden_diff",
        "child_forbidden_diff_removed",
        violations,
        inverse_message=True,
    )

    return AuthorityComparison(not violations, tuple(violations))


def _require_scope_subset(
    parent_patterns: Sequence[str],
    child_patterns: Sequence[str],
    path: str,
    code: str,
    violations: list[Violation],
    *,
    inverse_message: bool = False,
) -> None:
    try:
        witness = scope_expansion_witness(parent_patterns, child_patterns)
    except ScopeAnalysisError as exc:
        violations.append(Violation("scope_analysis_failed", path, str(exc)))
        return
    if witness is not None:
        if inverse_message:
            message = f"child removes a required restriction; witness path {witness!r}"
        else:
            message = f"child admits a witness path {witness!r} outside the parent scope"
        violations.append(Violation(code, path, message))


def _compare_network_authority(
    parent_rules: Sequence[Mapping[str, Any]],
    child_rules: Sequence[Mapping[str, Any]],
    violations: list[Violation],
) -> None:
    for index, child_rule in enumerate(child_rules):
        uncovered = [
            method
            for method in child_rule["methods"]
            if not any(
                _network_rule_covers_method(parent_rule, child_rule, method)
                for parent_rule in parent_rules
            )
        ]
        if uncovered:
            violations.append(
                Violation(
                    "child_network_scope_expanded",
                    f"$.authority.network.allow[{index}]",
                    "child adds uncovered network authority for methods "
                    + ", ".join(sorted(uncovered)),
                )
            )


def _network_rule_covers_method(
    parent: Mapping[str, Any], child: Mapping[str, Any], method: str
) -> bool:
    return (
        parent["scheme"] == child["scheme"]
        and parent["host"] == child["host"]
        and parent["port"] == child["port"]
        and method in parent["methods"]
        and url_path_prefix_matches(parent["path_prefix"], child["path_prefix"])
    )


def _compare_acceptance_commands(
    parent_commands: Sequence[Mapping[str, Any]],
    child_commands: Sequence[Mapping[str, Any]],
    violations: list[Violation],
) -> None:
    child_by_argv = {
        canonical_digest(command["argv"]): command for command in child_commands
    }
    for index, parent_command in enumerate(parent_commands):
        marker = canonical_digest(parent_command["argv"])
        child_command = child_by_argv.get(marker)
        if child_command is None:
            violations.append(
                Violation(
                    "child_acceptance_command_removed",
                    "$.acceptance.commands",
                    f"child removed parent acceptance argv at parent index {index}",
                )
            )
        elif child_command["timeout_seconds"] > parent_command["timeout_seconds"]:
            violations.append(
                Violation(
                    "child_acceptance_timeout_expanded",
                    "$.acceptance.commands",
                    f"child increased timeout for parent acceptance argv at index {index}",
                )
            )
