"""Command-line interface for the THYROROS reference policy engine."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Mapping, Sequence

from . import __version__
from .canonical import canonical_digest, canonical_json_bytes
from .contracts import (
    MAX_CONTRACT_BYTES,
    ContractDocumentError,
    compare_child_authority,
    load_contract,
    load_contract_bytes,
    parse_rfc3339,
)
from .effects import EffectClass
from .policy import PolicyDecision, PolicyEngine, PolicyRequestError
from .schema import schema_bytes

EXIT_OK = 0
EXIT_INVALID = 2
EXIT_HELD = 3
EXIT_INTERNAL = 70


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="thyroros",
        description=(
            "Validate THYROROS Run Contracts and evaluate reference-policy requests. "
            "This CLI does not itself enforce an OS sandbox."
        ),
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    subcommands = parser.add_subparsers(dest="command", required=True)

    subcommands.add_parser("name", help="show the project pronunciation and meaning")

    contract = subcommands.add_parser(
        "contract", help="validate, digest, and canonicalize Run Contracts"
    )
    contract_commands = contract.add_subparsers(dest="contract_command", required=True)

    validate = contract_commands.add_parser("validate", help="validate a Run Contract")
    validate.add_argument("path", help="contract JSON path, or - for standard input")
    validate.add_argument("--json", action="store_true", dest="json_output")

    digest = contract_commands.add_parser(
        "digest", help="print the canonical SHA-256 contract digest"
    )
    digest.add_argument("path", help="contract JSON path, or - for standard input")

    canonicalize = contract_commands.add_parser(
        "canonicalize", help="emit validated THYROROS Canonical JSON v1"
    )
    canonicalize.add_argument("path", help="contract JSON path, or - for standard input")
    canonicalize.add_argument(
        "--output",
        "-o",
        type=Path,
        help="write to a new regular file instead of standard output",
    )

    schema = contract_commands.add_parser(
        "schema", help="emit the bundled Run Contract v1 JSON Schema"
    )
    schema.add_argument(
        "--output",
        "-o",
        type=Path,
        help="write to a new regular file instead of standard output",
    )

    authority = subcommands.add_parser("authority", help="compare contract authority")
    authority_commands = authority.add_subparsers(
        dest="authority_command", required=True
    )
    compare = authority_commands.add_parser(
        "compare",
        help="verify that child authority is no wider than parent authority",
    )
    compare.add_argument("--parent", required=True, help="parent contract path")
    compare.add_argument("--child", required=True, help="child contract path")
    compare.add_argument("--json", action="store_true", dest="json_output")

    authorize = subcommands.add_parser(
        "authorize",
        help="evaluate a request against a contract without performing the effect",
    )
    authorize_commands = authorize.add_subparsers(
        dest="authorize_command", required=True
    )

    file_command = authorize_commands.add_parser(
        "file", help="authorize a concrete relative file path"
    )
    _add_contract_and_common_decision_options(file_command)
    file_command.add_argument("--operation", choices=("read", "write"), required=True)
    file_command.add_argument("--path", dest="target_path", required=True)

    network = authorize_commands.add_parser(
        "network", help="authorize a normalized HTTPS request"
    )
    _add_contract_and_common_decision_options(network)
    network.add_argument("--method", required=True)
    network.add_argument("--url", required=True)
    network.add_argument("--requests-used", type=int, default=0)

    process = authorize_commands.add_parser(
        "process", help="authorize an executable basename and child count"
    )
    _add_contract_and_common_decision_options(process)
    process.add_argument("--image", required=True)
    process.add_argument("--current-children", type=int, required=True)

    secret = authorize_commands.add_parser(
        "secret", help="authorize an opaque secret reference"
    )
    _add_contract_and_common_decision_options(secret)
    secret.add_argument("--ref", dest="secret_ref", required=True)

    effect = authorize_commands.add_parser(
        "effect", help="authorize a requested effect class"
    )
    _add_contract_and_common_decision_options(effect)
    effect.add_argument("--effect", choices=tuple(item.name for item in EffectClass), required=True)

    return parser


def _add_contract_and_common_decision_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("contract", help="contract JSON path, or - for standard input")
    parser.add_argument(
        "--at",
        metavar="RFC3339",
        help="evaluate at an explicit timestamp; defaults to the current UTC time",
    )
    parser.add_argument("--json", action="store_true", dest="json_output")


def _load_contract_argument(value: str) -> dict[str, Any]:
    if value != "-":
        return load_contract(value)

    raw = sys.stdin.buffer.read(MAX_CONTRACT_BYTES + 1)
    return load_contract_bytes(raw, source="<stdin>")


def _parse_at(value: str | None) -> datetime | None:
    if value is None:
        return None
    try:
        return parse_rfc3339(value)
    except ValueError as exc:
        raise PolicyRequestError("request_time_invalid", "$.request.at", str(exc)) from exc


def _emit_json(value: Mapping[str, Any]) -> None:
    print(json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2))


def _write_stdout_bytes(content: bytes) -> None:
    stream = getattr(sys.stdout, "buffer", None)
    if stream is None:
        sys.stdout.write(content.decode("utf-8", errors="strict"))
        return
    stream.write(content)


def _emit_document_error(error: ContractDocumentError, json_output: bool) -> None:
    payload = {
        "decision": "DENY",
        "valid": False,
        "violations": [item.as_dict() for item in error.violations],
    }
    if json_output:
        _emit_json(payload)
        return
    print("DENY invalid contract", file=sys.stderr)
    for item in error.violations:
        print(f"- {item.code} {item.path}: {item.message}", file=sys.stderr)


def _emit_request_error(error: PolicyRequestError, json_output: bool) -> None:
    if json_output:
        _emit_json(error.as_dict())
        return
    item = error.violation
    print("DENY invalid authorization request", file=sys.stderr)
    print(f"- {item.code} {item.path}: {item.message}", file=sys.stderr)


def _emit_decision(decision: PolicyDecision, json_output: bool) -> None:
    if json_output:
        _emit_json(decision.as_dict())
        return
    destination = sys.stdout if decision.allowed else sys.stderr
    print(f"{decision.decision} {decision.code}: {decision.message}", file=destination)
    if decision.matched_rule is not None:
        print(f"matched {decision.matched_rule}", file=destination)
    print(f"contract {decision.contract_digest}", file=destination)


def _write_new_file(path: Path, content: bytes) -> None:
    try:
        with path.open("xb") as stream:
            stream.write(content)
            stream.write(b"\n")
    except FileExistsError as exc:
        raise PolicyRequestError(
            "output_exists",
            "$.request.output",
            f"refusing to overwrite existing path {path}",
        ) from exc
    except OSError as exc:
        raise PolicyRequestError("output_write_failed", "$.request.output", str(exc)) from exc


def _run_authorization(args: argparse.Namespace) -> PolicyDecision:
    document = _load_contract_argument(args.contract)
    engine = PolicyEngine(document)
    at = _parse_at(args.at)

    if args.authorize_command == "file":
        return engine.authorize_file(args.operation, args.target_path, at=at)
    if args.authorize_command == "network":
        return engine.authorize_network(
            args.method,
            args.url,
            requests_used=args.requests_used,
            at=at,
        )
    if args.authorize_command == "process":
        return engine.authorize_process(
            args.image,
            current_children=args.current_children,
            at=at,
        )
    if args.authorize_command == "secret":
        return engine.authorize_secret(args.secret_ref, at=at)
    if args.authorize_command == "effect":
        return engine.authorize_effect(args.effect, at=at)
    raise RuntimeError("unreachable authorization command state")


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)

    try:
        if args.command == "name":
            print("THYROROS /θi.roˈros/ — roughly 'thee-ro-ROSS'")
            print("Japanese project reading: シロロス")
            print("Greek θυρωρός: doorkeeper / gatekeeper")
            return EXIT_OK

        if args.command == "contract" and args.contract_command == "validate":
            try:
                document = _load_contract_argument(args.path)
            except ContractDocumentError as exc:
                _emit_document_error(exc, args.json_output)
                return EXIT_INVALID
            payload = {
                "decision": "ALLOW",
                "valid": True,
                "schema": document["schema"],
                "version": document["version"],
                "digest": canonical_digest(document),
            }
            if args.json_output:
                _emit_json(payload)
            else:
                print(f"PASS {document['schema']} v{document['version']}")
                print(f"digest {payload['digest']}")
            return EXIT_OK

        if args.command == "contract" and args.contract_command == "digest":
            document = _load_contract_argument(args.path)
            print(canonical_digest(document))
            return EXIT_OK

        if args.command == "contract" and args.contract_command == "canonicalize":
            document = _load_contract_argument(args.path)
            content = canonical_json_bytes(document)
            if args.output is None:
                _write_stdout_bytes(content + b"\n")
            else:
                _write_new_file(args.output, content)
            return EXIT_OK

        if args.command == "contract" and args.contract_command == "schema":
            content = schema_bytes().rstrip(b"\n")
            if args.output is None:
                _write_stdout_bytes(content + b"\n")
            else:
                _write_new_file(args.output, content)
            return EXIT_OK

        if args.command == "authority" and args.authority_command == "compare":
            if args.parent == "-" and args.child == "-":
                raise PolicyRequestError(
                    "stdin_reused",
                    "$.request",
                    "parent and child may not both read from standard input",
                )
            parent = _load_contract_argument(args.parent)
            child = _load_contract_argument(args.child)
            comparison = compare_child_authority(parent, child)
            if args.json_output:
                _emit_json(comparison.as_dict())
            elif comparison.allowed:
                print("PASS child authority is a semantic subset of parent authority")
            else:
                print(
                    "HOLD child requests authority outside the parent contract",
                    file=sys.stderr,
                )
                for item in comparison.violations:
                    print(f"- {item.code} {item.path}: {item.message}", file=sys.stderr)
            return EXIT_OK if comparison.allowed else EXIT_HELD

        if args.command == "authorize":
            decision = _run_authorization(args)
            _emit_decision(decision, args.json_output)
            return EXIT_OK if decision.allowed else EXIT_HELD

        raise RuntimeError("unreachable command state")
    except ContractDocumentError as exc:
        _emit_document_error(exc, bool(getattr(args, "json_output", False)))
        return EXIT_INVALID
    except PolicyRequestError as exc:
        _emit_request_error(exc, bool(getattr(args, "json_output", False)))
        return EXIT_INVALID
    except BrokenPipeError:
        return EXIT_OK
    except Exception as exc:  # pragma: no cover - last-resort CLI boundary
        print(f"INTERNAL {type(exc).__name__}: {exc}", file=sys.stderr)
        return EXIT_INTERNAL


if __name__ == "__main__":
    raise SystemExit(main())
