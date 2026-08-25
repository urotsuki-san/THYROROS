"""Normative Run Contract v1 semantic validation."""

from __future__ import annotations

import unicodedata
from typing import Any, Mapping

from .canonical import canonical_digest, canonical_json_bytes
from .effects import EffectClass
from .scopes import validate_scope_pattern
from ._contract_core import (
    ACCEPTANCE_KEYS,
    ALLOWED_METHODS,
    AUTHORITY_KEYS,
    BUDGET_KEYS,
    COMMAND_KEYS,
    MAX_ACCEPTANCE_COMMANDS,
    MAX_COMMAND_ARGUMENTS,
    MAX_NETWORK_RULES,
    MAX_PROCESS_IMAGES,
    MAX_SCOPE_RULES,
    MAX_SECRET_REFS,
    NETWORK_KEYS,
    NETWORK_RULE_KEYS,
    PROCESS_KEYS,
    REPOSITORY_RE,
    RUN_ID_RE,
    RUN_KEYS,
    SUBJECT_KEYS,
    TOP_LEVEL_KEYS,
    Violation,
    _expect_exact,
    _object,
    _parse_timestamp,
    _reject_unknown,
    _require_keys,
    _validate_digest,
    _validate_image_name,
    _validate_int,
    _validate_secret_ref,
    _validate_string_list,
    validate_network_host,
    validate_url_path_prefix,
)

def validate_run_contract(value: Any) -> tuple[Violation, ...]:
    """Validate the normative THYROROS Run Contract v1 semantics."""

    violations: list[Violation] = []
    if not isinstance(value, dict):
        return (Violation("contract_not_object", "$", "contract must be a JSON object"),)

    _reject_unknown(value, TOP_LEVEL_KEYS, "$", violations)
    _require_keys(value, TOP_LEVEL_KEYS, "$", violations)
    _expect_exact(value.get("schema"), "thyroros.run-contract", "$.schema", violations)
    _expect_exact(value.get("version"), 1, "$.version", violations)

    run = _object(value.get("run"), "$.run", violations)
    if run is not None:
        _reject_unknown(run, RUN_KEYS, "$.run", violations)
        _require_keys(run, RUN_KEYS, "$.run", violations)
        _validate_run(run, violations)

    subject = _object(value.get("subject"), "$.subject", violations)
    if subject is not None:
        _reject_unknown(subject, SUBJECT_KEYS, "$.subject", violations)
        _require_keys(subject, SUBJECT_KEYS, "$.subject", violations)
        _validate_subject(subject, violations)

    authority = _object(value.get("authority"), "$.authority", violations)
    if authority is not None:
        _reject_unknown(authority, AUTHORITY_KEYS, "$.authority", violations)
        _require_keys(authority, AUTHORITY_KEYS, "$.authority", violations)
        _validate_authority(authority, violations)

    budget = _object(value.get("budget"), "$.budget", violations)
    if budget is not None:
        _reject_unknown(budget, BUDGET_KEYS, "$.budget", violations)
        _require_keys(budget, BUDGET_KEYS, "$.budget", violations)
        _validate_budget(budget, violations)

    acceptance = _object(value.get("acceptance"), "$.acceptance", violations)
    if acceptance is not None:
        _reject_unknown(acceptance, ACCEPTANCE_KEYS, "$.acceptance", violations)
        _require_keys(acceptance, ACCEPTANCE_KEYS, "$.acceptance", violations)
        _validate_acceptance(acceptance, violations)

    try:
        canonical_json_bytes(value)
    except ValueError as exc:
        violations.append(Violation("contract_not_canonicalizable", "$", str(exc)))

    return tuple(violations)


def _validate_run(run: Mapping[str, Any], violations: list[Violation]) -> None:
    run_id = run.get("id")
    if not isinstance(run_id, str) or RUN_ID_RE.fullmatch(run_id) is None:
        violations.append(
            Violation(
                "run_id_invalid",
                "$.run.id",
                "expected run_<lowercase identifier>, 7-132 characters total",
            )
        )

    _validate_digest(run.get("task_digest"), "$.run.task_digest", violations)
    created = _parse_timestamp(run.get("created_at"), "$.run.created_at", violations)
    expires = _parse_timestamp(run.get("expires_at"), "$.run.expires_at", violations)
    if created is not None and expires is not None and expires <= created:
        violations.append(
            Violation(
                "run_expiry_not_after_creation",
                "$.run.expires_at",
                "expires_at must be later than created_at",
            )
        )


def _validate_subject(subject: Mapping[str, Any], violations: list[Violation]) -> None:
    repository = subject.get("repository")
    valid_repository = (
        isinstance(repository, str)
        and REPOSITORY_RE.fullmatch(repository) is not None
        and not repository.startswith(".")
        and "/." not in repository
        and unicodedata.normalize("NFC", repository) == repository
    )
    if not valid_repository:
        violations.append(
            Violation(
                "subject_repository_invalid",
                "$.subject.repository",
                "expected owner/repository using portable GitHub-safe characters",
            )
        )

    base = subject.get("base_revision")
    if (
        not isinstance(base, str)
        or not 1 <= len(base) <= 128
        or "\x00" in base
        or unicodedata.normalize("NFC", base) != base
    ):
        violations.append(
            Violation(
                "subject_base_revision_invalid",
                "$.subject.base_revision",
                "base_revision must be a non-empty bounded NFC string",
            )
        )

    _validate_digest(subject.get("workspace_digest"), "$.subject.workspace_digest", violations)


def _validate_authority(authority: Mapping[str, Any], violations: list[Violation]) -> None:
    _validate_string_list(
        authority.get("read"),
        "$.authority.read",
        violations,
        validate_scope_pattern,
        maximum=MAX_SCOPE_RULES,
    )
    _validate_string_list(
        authority.get("write"),
        "$.authority.write",
        violations,
        validate_scope_pattern,
        maximum=MAX_SCOPE_RULES,
    )
    _validate_string_list(
        authority.get("deny"),
        "$.authority.deny",
        violations,
        validate_scope_pattern,
        maximum=MAX_SCOPE_RULES,
    )

    network = _object(authority.get("network"), "$.authority.network", violations)
    if network is not None:
        _reject_unknown(network, NETWORK_KEYS, "$.authority.network", violations)
        _require_keys(network, NETWORK_KEYS, "$.authority.network", violations)
        if network.get("default") != "deny":
            violations.append(
                Violation(
                    "network_default_not_deny",
                    "$.authority.network.default",
                    "v1 requires default deny",
                )
            )
        rules = network.get("allow")
        if not isinstance(rules, list):
            violations.append(
                Violation(
                    "network_allow_not_array",
                    "$.authority.network.allow",
                    "allow must be an array",
                )
            )
        else:
            if len(rules) > MAX_NETWORK_RULES:
                violations.append(
                    Violation(
                        "network_allow_too_many_items",
                        "$.authority.network.allow",
                        f"allow may contain at most {MAX_NETWORK_RULES} rules",
                    )
                )
            seen: set[str] = set()
            for index, rule in enumerate(rules):
                path = f"$.authority.network.allow[{index}]"
                normalized = _validate_network_rule(rule, path, violations)
                if normalized is not None:
                    marker = canonical_digest(normalized)
                    if marker in seen:
                        violations.append(
                            Violation(
                                "network_rule_duplicate",
                                path,
                                "duplicate normalized network rule",
                            )
                        )
                    seen.add(marker)

    process = _object(authority.get("process"), "$.authority.process", violations)
    if process is not None:
        _reject_unknown(process, PROCESS_KEYS, "$.authority.process", violations)
        _require_keys(process, PROCESS_KEYS, "$.authority.process", violations)
        _validate_string_list(
            process.get("allowed_images"),
            "$.authority.process.allowed_images",
            violations,
            _validate_image_name,
            maximum=MAX_PROCESS_IMAGES,
            duplicate_key=str.casefold,
        )
        _validate_int(
            process.get("max_children"),
            "$.authority.process.max_children",
            violations,
            minimum=0,
            maximum=4096,
        )

    _validate_string_list(
        authority.get("secrets"),
        "$.authority.secrets",
        violations,
        _validate_secret_ref,
        maximum=MAX_SECRET_REFS,
    )

    if EffectClass.parse(authority.get("maximum_effect")) is None:
        violations.append(
            Violation(
                "maximum_effect_invalid",
                "$.authority.maximum_effect",
                "unknown effect class",
            )
        )


def _validate_budget(budget: Mapping[str, Any], violations: list[Violation]) -> None:
    _validate_int(
        budget.get("wall_seconds"),
        "$.budget.wall_seconds",
        violations,
        minimum=1,
        maximum=604800,
    )
    _validate_int(
        budget.get("memory_mib"),
        "$.budget.memory_mib",
        violations,
        minimum=16,
        maximum=1_048_576,
    )
    _validate_int(
        budget.get("network_requests"),
        "$.budget.network_requests",
        violations,
        minimum=0,
        maximum=1_000_000,
    )


def _validate_acceptance(acceptance: Mapping[str, Any], violations: list[Violation]) -> None:
    commands = acceptance.get("commands")
    if not isinstance(commands, list) or not commands:
        violations.append(
            Violation(
                "acceptance_commands_invalid",
                "$.acceptance.commands",
                "commands must be a non-empty array",
            )
        )
    else:
        if len(commands) > MAX_ACCEPTANCE_COMMANDS:
            violations.append(
                Violation(
                    "acceptance_commands_too_many_items",
                    "$.acceptance.commands",
                    f"commands may contain at most {MAX_ACCEPTANCE_COMMANDS} items",
                )
            )
        seen_argv: set[str] = set()
        for index, command in enumerate(commands):
            path = f"$.acceptance.commands[{index}]"
            if not isinstance(command, dict):
                violations.append(
                    Violation("acceptance_command_not_object", path, "command must be an object")
                )
                continue
            _reject_unknown(command, COMMAND_KEYS, path, violations)
            _require_keys(command, COMMAND_KEYS, path, violations)
            argv = command.get("argv")
            argv_valid = True
            if not isinstance(argv, list) or not argv:
                violations.append(
                    Violation(
                        "acceptance_argv_invalid",
                        f"{path}.argv",
                        "argv must be a non-empty array",
                    )
                )
                argv_valid = False
            else:
                if len(argv) > MAX_COMMAND_ARGUMENTS:
                    violations.append(
                        Violation(
                            "acceptance_argv_too_many_items",
                            f"{path}.argv",
                            f"argv may contain at most {MAX_COMMAND_ARGUMENTS} arguments",
                        )
                    )
                    argv_valid = False
                for arg_index, argument in enumerate(argv):
                    if (
                        not isinstance(argument, str)
                        or not argument
                        or len(argument) > 32768
                        or "\x00" in argument
                        or unicodedata.normalize("NFC", argument) != argument
                    ):
                        violations.append(
                            Violation(
                                "acceptance_argument_invalid",
                                f"{path}.argv[{arg_index}]",
                                "arguments must be non-empty bounded NFC strings without NUL",
                            )
                        )
                        argv_valid = False
                if argv_valid:
                    marker = canonical_digest(argv)
                    if marker in seen_argv:
                        violations.append(
                            Violation(
                                "acceptance_command_duplicate",
                                path,
                                "duplicate argv; timeout changes do not create a distinct command",
                            )
                        )
                    seen_argv.add(marker)
            _validate_int(
                command.get("timeout_seconds"),
                f"{path}.timeout_seconds",
                violations,
                minimum=1,
                maximum=86400,
            )

    _validate_string_list(
        acceptance.get("forbidden_diff"),
        "$.acceptance.forbidden_diff",
        violations,
        validate_scope_pattern,
        maximum=MAX_SCOPE_RULES,
    )


def _validate_network_rule(
    rule: Any, path: str, violations: list[Violation]
) -> dict[str, Any] | None:
    before = len(violations)
    if not isinstance(rule, dict):
        violations.append(
            Violation("network_rule_not_object", path, "network rule must be an object")
        )
        return None

    _reject_unknown(rule, NETWORK_RULE_KEYS, path, violations)
    _require_keys(rule, NETWORK_RULE_KEYS, path, violations)

    methods = rule.get("methods")
    normalized_methods: list[str] = []
    if not isinstance(methods, list) or not methods:
        violations.append(
            Violation(
                "network_methods_invalid",
                f"{path}.methods",
                "methods must be a non-empty array",
            )
        )
    else:
        if len(methods) > len(ALLOWED_METHODS):
            violations.append(
                Violation(
                    "network_methods_too_many_items",
                    f"{path}.methods",
                    f"methods may contain at most {len(ALLOWED_METHODS)} items",
                )
            )
        seen: set[str] = set()
        for index, method in enumerate(methods):
            if not isinstance(method, str) or method not in ALLOWED_METHODS:
                violations.append(
                    Violation(
                        "network_method_invalid",
                        f"{path}.methods[{index}]",
                        f"unsupported HTTP method {method!r}",
                    )
                )
                continue
            if method in seen:
                violations.append(
                    Violation(
                        "network_method_duplicate",
                        f"{path}.methods[{index}]",
                        f"duplicate method {method}",
                    )
                )
            seen.add(method)
            normalized_methods.append(method)

    scheme = rule.get("scheme")
    if scheme != "https":
        violations.append(
            Violation(
                "network_scheme_not_https",
                f"{path}.scheme",
                "v1 network rules require https",
            )
        )

    host = rule.get("host")
    host_problem = validate_network_host(host) if isinstance(host, str) else "host must be a string"
    if host_problem is not None:
        violations.append(Violation("network_host_invalid", f"{path}.host", host_problem))

    port = rule.get("port")
    _validate_int(port, f"{path}.port", violations, minimum=1, maximum=65535)

    prefix = rule.get("path_prefix")
    prefix_problem = validate_url_path_prefix(prefix) if isinstance(prefix, str) else "path_prefix must be a string"
    if prefix_problem is not None:
        violations.append(
            Violation("network_path_prefix_invalid", f"{path}.path_prefix", prefix_problem)
        )

    if len(violations) != before:
        return None
    return {
        "methods": sorted(normalized_methods),
        "scheme": scheme,
        "host": host,
        "port": port,
        "path_prefix": prefix,
    }
