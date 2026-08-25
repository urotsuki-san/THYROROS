from __future__ import annotations

import json
import unittest
from pathlib import Path

from thyroros.schema import schema_bytes, schema_document

ROOT = Path(__file__).resolve().parents[1]


class PackagedSchemaTests(unittest.TestCase):
    def test_packaged_schema_matches_repository_schema(self) -> None:
        self.assertEqual(
            schema_bytes(),
            (ROOT / "schemas" / "run-contract.schema.json").read_bytes(),
        )

    def test_schema_is_a_fresh_json_object(self) -> None:
        first = schema_document()
        second = schema_document()
        self.assertIsInstance(first, dict)
        self.assertEqual(first["$schema"], "https://json-schema.org/draft/2020-12/schema")
        first["title"] = "mutated"
        self.assertNotEqual(first["title"], second["title"])

    def test_schema_bytes_are_valid_json(self) -> None:
        self.assertIsInstance(json.loads(schema_bytes()), dict)


if __name__ == "__main__":
    unittest.main()
