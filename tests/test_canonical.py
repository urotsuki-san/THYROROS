from __future__ import annotations

import unittest

from thyroros.canonical import (
    CanonicalizationError,
    canonical_digest,
    canonical_json_bytes,
)


class CanonicalJsonTests(unittest.TestCase):
    def test_object_order_does_not_change_digest(self) -> None:
        first = {"b": [True, None, "x"], "a": 7}
        second = {"a": 7, "b": [True, None, "x"]}
        self.assertEqual(canonical_digest(first), canonical_digest(second))
        self.assertEqual(canonical_json_bytes(first), b'{"a":7,"b":[true,null,"x"]}')

    def test_float_is_rejected(self) -> None:
        with self.assertRaises(CanonicalizationError):
            canonical_json_bytes({"value": 1.0})

    def test_unsafe_integer_is_rejected(self) -> None:
        with self.assertRaises(CanonicalizationError):
            canonical_json_bytes({"value": 2**53})

    def test_non_nfc_string_is_rejected(self) -> None:
        with self.assertRaises(CanonicalizationError):
            canonical_json_bytes({"value": "e\u0301"})

    def test_surrogate_is_rejected(self) -> None:
        with self.assertRaises(CanonicalizationError):
            canonical_json_bytes({"value": "\ud800"})

    def test_cycles_are_rejected(self) -> None:
        value: list[object] = []
        value.append(value)
        with self.assertRaises(CanonicalizationError):
            canonical_json_bytes(value)

    def test_non_string_object_key_is_rejected(self) -> None:
        with self.assertRaises(CanonicalizationError):
            canonical_json_bytes({1: "not admitted"})


if __name__ == "__main__":
    unittest.main()
