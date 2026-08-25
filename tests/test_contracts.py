from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path

from thyroros.canonical import canonical_digest
from thyroros.contracts import (
    ContractDocumentError,
    compare_child_authority,
    load_contract,
    load_contract_bytes,
    parse_rfc3339,
    validate_run_contract,
    url_path_prefix_matches,
)
from thyroros.effects import EffectClass

ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = ROOT / "examples" / "run-contract.json"


def example_contract() -> dict:
    value = json.loads(EXAMPLE.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


class ContractValidationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.contract = example_contract()

    def codes(self) -> set[str]:
        return {item.code for item in validate_run_contract(self.contract)}

    def test_example_is_valid(self) -> None:
        self.assertEqual(validate_run_contract(self.contract), ())

    def test_unknown_member_is_rejected(self) -> None:
        self.contract["authority"]["mystery_permission"] = True
        self.assertIn("unknown_member", self.codes())

    def test_embedded_glob_is_rejected(self) -> None:
        self.contract["authority"]["write"] = ["workspace/src/*.py"]
        self.assertIn("list_item_invalid", self.codes())

    def test_parent_traversal_is_rejected(self) -> None:
        self.contract["authority"]["write"] = ["workspace/../user-profile/**"]
        self.assertIn("list_item_invalid", self.codes())

    def test_network_must_be_default_deny(self) -> None:
        self.contract["authority"]["network"]["default"] = "allow"
        self.assertIn("network_default_not_deny", self.codes())

    def test_network_host_must_be_exact_lowercase_dns(self) -> None:
        self.contract["authority"]["network"]["allow"][0]["host"] = "*.GitHub.com"
        self.assertIn("network_host_invalid", self.codes())

    def test_network_path_prefix_refuses_percent_encoding(self) -> None:
        self.contract["authority"]["network"]["allow"][0]["path_prefix"] = "/repos/%2e%2e/"
        self.assertIn("network_path_prefix_invalid", self.codes())

    def test_network_path_prefix_refuses_empty_segments(self) -> None:
        self.contract["authority"]["network"]["allow"][0]["path_prefix"] = "/repos//private"
        self.assertIn("network_path_prefix_invalid", self.codes())

    def test_invalid_digest_is_rejected(self) -> None:
        self.contract["run"]["task_digest"] = "sha256:ABC"
        self.assertIn("digest_invalid", self.codes())

    def test_expiry_must_follow_creation(self) -> None:
        self.contract["run"]["expires_at"] = self.contract["run"]["created_at"]
        self.assertIn("run_expiry_not_after_creation", self.codes())

    def test_negative_zero_timezone_is_rejected(self) -> None:
        self.contract["run"]["created_at"] = "2026-08-24T09:20:00-00:00"
        self.assertIn("timestamp_invalid", self.codes())

    def test_boolean_is_not_an_integer(self) -> None:
        self.contract["budget"]["wall_seconds"] = True
        self.assertIn("integer_expected", self.codes())

    def test_casefold_duplicate_process_image_is_rejected(self) -> None:
        self.contract["authority"]["process"]["allowed_images"].append("PYTHON.EXE")
        self.assertIn("duplicate_list_item", self.codes())

    def test_duplicate_acceptance_argv_is_rejected_even_with_new_timeout(self) -> None:
        duplicate = copy.deepcopy(self.contract["acceptance"]["commands"][0])
        duplicate["timeout_seconds"] = 30
        self.contract["acceptance"]["commands"].append(duplicate)
        self.assertIn("acceptance_command_duplicate", self.codes())

    def test_canonical_digest_ignores_object_key_order(self) -> None:
        reordered = {key: self.contract[key] for key in reversed(self.contract)}
        self.assertEqual(canonical_digest(self.contract), canonical_digest(reordered))

    def test_duplicate_json_key_is_rejected(self) -> None:
        raw = b'{"schema":"thyroros.run-contract","schema":"other"}'
        with self.assertRaises(ContractDocumentError) as context:
            load_contract_bytes(raw)
        self.assertIn(
            "document_duplicate_key",
            {item.code for item in context.exception.violations},
        )

    def test_utf8_bom_is_rejected(self) -> None:
        raw = b"\xef\xbb\xbf" + EXAMPLE.read_bytes()
        with self.assertRaises(ContractDocumentError) as context:
            load_contract_bytes(raw)
        self.assertIn(
            "document_bom_forbidden",
            {item.code for item in context.exception.violations},
        )

    def test_contract_symlink_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "target.json"
            target.write_bytes(EXAMPLE.read_bytes())
            link = Path(directory) / "link.json"
            try:
                link.symlink_to(target)
            except (OSError, NotImplementedError):
                self.skipTest("symlink creation is unavailable")
            with self.assertRaises(ContractDocumentError) as context:
                load_contract(link)
        self.assertIn(
            "document_symlink_refused",
            {item.code for item in context.exception.violations},
        )

    def test_directory_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ContractDocumentError) as context:
                load_contract(directory)
        self.assertIn(
            "document_not_file",
            {item.code for item in context.exception.violations},
        )

    def test_timestamp_parser_normalizes_offsets(self) -> None:
        self.assertEqual(
            parse_rfc3339("2026-08-24T18:20:00+09:00"),
            parse_rfc3339("2026-08-24T09:20:00Z"),
        )

    def test_url_prefix_matching_is_segment_aware(self) -> None:
        self.assertTrue(url_path_prefix_matches("/repos/example", "/repos/example/issues"))
        self.assertFalse(url_path_prefix_matches("/repos/example", "/repos/example-evil"))


class AuthorityComparisonTests(unittest.TestCase):
    def setUp(self) -> None:
        self.parent = example_contract()

    def child(self) -> dict:
        child = copy.deepcopy(self.parent)
        child["run"]["id"] = "run_bootstrap_child"
        child["run"]["created_at"] = "2026-08-24T09:30:00Z"
        child["run"]["expires_at"] = "2026-08-24T10:00:00Z"
        return child

    def test_valid_semantic_narrowing_passes(self) -> None:
        child = self.child()
        child["authority"]["read"] = ["workspace/src/thyroros/**"]
        child["authority"]["write"] = ["workspace/src/thyroros/**"]
        child["authority"]["process"]["allowed_images"] = ["PYTHON.EXE"]
        child["authority"]["process"]["max_children"] = 4
        child["authority"]["maximum_effect"] = "READ_IDEMPOTENT"
        child["budget"]["wall_seconds"] = 600
        child["authority"]["network"]["allow"][0]["path_prefix"] = (
            "/repos/urotsuki-san/THYROROS/issues"
        )
        child["acceptance"]["commands"][0]["timeout_seconds"] = 300
        child["acceptance"]["forbidden_diff"].append("docs/**")
        comparison = compare_child_authority(self.parent, child)
        self.assertTrue(comparison.allowed, comparison.violations)

    def test_write_expansion_is_held_with_witness(self) -> None:
        child = self.child()
        child["authority"]["write"].append("workspace/docs/**")
        comparison = compare_child_authority(self.parent, child)
        self.assertFalse(comparison.allowed)
        violations = [
            item for item in comparison.violations if item.code == "child_write_scope_expanded"
        ]
        self.assertEqual(len(violations), 1)
        self.assertIn("witness", violations[0].message)

    def test_removed_deny_is_held(self) -> None:
        child = self.child()
        child["authority"]["deny"].remove("user-profile/**")
        comparison = compare_child_authority(self.parent, child)
        self.assertIn(
            "child_deny_scope_removed",
            {item.code for item in comparison.violations},
        )

    def test_broader_child_deny_passes(self) -> None:
        child = self.child()
        child["authority"]["deny"] = ["**"]
        comparison = compare_child_authority(self.parent, child)
        self.assertTrue(comparison.allowed, comparison.violations)

    def test_narrower_network_methods_and_path_pass(self) -> None:
        parent_rule = self.parent["authority"]["network"]["allow"][0]
        parent_rule["methods"] = ["GET", "HEAD"]
        child = self.child()
        child["authority"]["network"]["allow"][0]["methods"] = ["HEAD"]
        child["authority"]["network"]["allow"][0]["path_prefix"] = (
            "/repos/urotsuki-san/THYROROS/actions"
        )
        comparison = compare_child_authority(self.parent, child)
        self.assertTrue(comparison.allowed, comparison.violations)

    def test_added_network_method_is_held(self) -> None:
        child = self.child()
        child["authority"]["network"]["allow"][0]["methods"] = ["GET", "POST"]
        comparison = compare_child_authority(self.parent, child)
        self.assertIn(
            "child_network_scope_expanded",
            {item.code for item in comparison.violations},
        )

    def test_effect_expansion_is_held(self) -> None:
        child = self.child()
        child["authority"]["maximum_effect"] = "IRREVERSIBLE"
        comparison = compare_child_authority(self.parent, child)
        self.assertIn("child_effect_expanded", {item.code for item in comparison.violations})

    def test_removed_acceptance_command_is_held(self) -> None:
        child = self.child()
        child["acceptance"]["commands"] = [
            {"argv": ["python", "-m", "compileall", "src"], "timeout_seconds": 120}
        ]
        comparison = compare_child_authority(self.parent, child)
        self.assertIn(
            "child_acceptance_command_removed",
            {item.code for item in comparison.violations},
        )

    def test_longer_acceptance_timeout_is_held(self) -> None:
        child = self.child()
        child["acceptance"]["commands"][0]["timeout_seconds"] = 601
        comparison = compare_child_authority(self.parent, child)
        self.assertIn(
            "child_acceptance_timeout_expanded",
            {item.code for item in comparison.violations},
        )

    def test_effect_retry_semantics(self) -> None:
        self.assertTrue(EffectClass.PURE.may_retry_after_ambiguous_failure)
        self.assertTrue(EffectClass.WRITE_IDEMPOTENT.may_retry_after_ambiguous_failure)
        self.assertFalse(EffectClass.AT_MOST_ONCE.may_retry_after_ambiguous_failure)
        self.assertTrue(EffectClass.RECONCILE_REQUIRED.requires_reconciliation_after_ambiguous_failure)
        self.assertTrue(EffectClass.IRREVERSIBLE.requires_confirmation)


if __name__ == "__main__":
    unittest.main()
