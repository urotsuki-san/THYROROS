from __future__ import annotations

import json
import unittest
from datetime import datetime, timezone
from pathlib import Path

from thyroros.effects import EffectClass
from thyroros.policy import PolicyEngine, PolicyRequestError

ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = ROOT / "examples" / "run-contract.json"
ACTIVE = datetime(2026, 8, 24, 9, 30, tzinfo=timezone.utc)


def example_contract() -> dict:
    value = json.loads(EXAMPLE.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


class FilePolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.engine = PolicyEngine(example_contract())

    def test_read_is_allowed(self) -> None:
        result = self.engine.authorize_file(
            "read", "workspace/src/thyroros/cli.py", at=ACTIVE
        )
        self.assertTrue(result.allowed)
        self.assertEqual(result.code, "file_allowed")
        self.assertEqual(result.matched_rule, "workspace/**")

    def test_write_outside_scope_is_denied(self) -> None:
        result = self.engine.authorize_file("write", "workspace/docs/guide.md", at=ACTIVE)
        self.assertFalse(result.allowed)
        self.assertEqual(result.code, "file_scope_not_granted")

    def test_deny_rule_wins(self) -> None:
        result = self.engine.authorize_file("read", "user-profile/token.txt", at=ACTIVE)
        self.assertFalse(result.allowed)
        self.assertEqual(result.code, "file_denied_by_rule")

    def test_invalid_concrete_path_is_a_request_error(self) -> None:
        with self.assertRaises(PolicyRequestError):
            self.engine.authorize_file("read", "workspace/../secret", at=ACTIVE)

    def test_contract_copy_is_immutable_from_caller(self) -> None:
        contract = example_contract()
        engine = PolicyEngine(contract)
        contract["authority"]["read"] = ["**"]
        result = engine.authorize_file("read", "other/file", at=ACTIVE)
        self.assertFalse(result.allowed)

    def test_compiled_contract_is_recursively_frozen(self) -> None:
        engine = PolicyEngine(example_contract())
        with self.assertRaises(TypeError):
            engine._contract["authority"]["network"]["allow"][0]["host"] = (
                "example.com"
            )


class LeasePolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.engine = PolicyEngine(example_contract())

    def test_before_creation_is_denied(self) -> None:
        at = datetime(2026, 8, 24, 9, 19, tzinfo=timezone.utc)
        self.assertEqual(
            self.engine.authorize_effect("PURE", at=at).code,
            "run_not_yet_active",
        )

    def test_at_expiry_is_denied(self) -> None:
        at = datetime(2026, 8, 24, 10, 20, tzinfo=timezone.utc)
        self.assertEqual(self.engine.authorize_effect("PURE", at=at).code, "run_expired")

    def test_naive_datetime_is_rejected(self) -> None:
        with self.assertRaises(PolicyRequestError):
            self.engine.authorize_effect("PURE", at=datetime(2026, 8, 24, 9, 30))


class NetworkPolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.engine = PolicyEngine(example_contract())

    def test_allowed_request_and_query(self) -> None:
        result = self.engine.authorize_network(
            "get",
            "https://api.github.com/repos/urotsuki-san/THYROROS/issues?state=open",
            at=ACTIVE,
        )
        self.assertTrue(result.allowed)

    def test_path_prefix_is_segment_aware(self) -> None:
        result = self.engine.authorize_network(
            "GET",
            "https://api.github.com/repos/urotsuki-san/THYROROS-evil/issues",
            at=ACTIVE,
        )
        self.assertFalse(result.allowed)

    def test_http_is_rejected_as_malformed_request(self) -> None:
        with self.assertRaises(PolicyRequestError):
            self.engine.authorize_network(
                "GET", "http://api.github.com/repos/urotsuki-san/THYROROS/", at=ACTIVE
            )

    def test_userinfo_is_rejected(self) -> None:
        with self.assertRaises(PolicyRequestError):
            self.engine.authorize_network(
                "GET",
                "https://user:pass@api.github.com/repos/urotsuki-san/THYROROS/",
                at=ACTIVE,
            )

    def test_ambiguous_percent_encoding_is_rejected(self) -> None:
        with self.assertRaises(PolicyRequestError):
            self.engine.authorize_network(
                "GET",
                "https://api.github.com/repos/urotsuki-san/THYROROS/%2e%2e/private",
                at=ACTIVE,
            )

    def test_repeated_slash_is_rejected(self) -> None:
        with self.assertRaises(PolicyRequestError):
            self.engine.authorize_network(
                "GET",
                "https://api.github.com/repos//urotsuki-san/THYROROS/",
                at=ACTIVE,
            )

    def test_request_budget_is_enforced(self) -> None:
        result = self.engine.authorize_network(
            "GET",
            "https://api.github.com/repos/urotsuki-san/THYROROS/",
            requests_used=20,
            at=ACTIVE,
        )
        self.assertEqual(result.code, "network_budget_exhausted")


class ProcessSecretAndEffectPolicyTests(unittest.TestCase):
    def test_process_image_is_case_insensitive(self) -> None:
        engine = PolicyEngine(example_contract())
        result = engine.authorize_process("PYTHON.EXE", current_children=0, at=ACTIVE)
        self.assertTrue(result.allowed)

    def test_process_limit_is_enforced(self) -> None:
        engine = PolicyEngine(example_contract())
        result = engine.authorize_process("python.exe", current_children=16, at=ACTIVE)
        self.assertEqual(result.code, "process_budget_exhausted")

    def test_secret_reference_is_exact(self) -> None:
        contract = example_contract()
        contract["authority"]["secrets"] = ["secret:github/read-token"]
        engine = PolicyEngine(contract)
        self.assertTrue(
            engine.authorize_secret("secret:github/read-token", at=ACTIVE).allowed
        )
        self.assertFalse(
            engine.authorize_secret("secret:github/write-token", at=ACTIVE).allowed
        )

    def test_effect_ceiling_is_enforced(self) -> None:
        engine = PolicyEngine(example_contract())
        self.assertTrue(engine.authorize_effect(EffectClass.READ_IDEMPOTENT, at=ACTIVE).allowed)
        denied = engine.authorize_effect(EffectClass.IRREVERSIBLE, at=ACTIVE)
        self.assertEqual(denied.code, "effect_exceeds_contract")


if __name__ == "__main__":
    unittest.main()
