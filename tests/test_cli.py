from __future__ import annotations

import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from thyroros.cli import EXIT_HELD, EXIT_INVALID, EXIT_OK, main

ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = ROOT / "examples" / "run-contract.json"
ACTIVE = "2026-08-24T09:30:00Z"


class CliTests(unittest.TestCase):
    def test_name(self) -> None:
        output = io.StringIO()
        with redirect_stdout(output):
            code = main(["name"])
        self.assertEqual(code, EXIT_OK)
        self.assertIn("シロロス", output.getvalue())

    def test_validate_example_json(self) -> None:
        output = io.StringIO()
        with redirect_stdout(output):
            code = main(["contract", "validate", str(EXAMPLE), "--json"])
        self.assertEqual(code, EXIT_OK)
        payload = json.loads(output.getvalue())
        self.assertTrue(payload["valid"])
        self.assertTrue(payload["digest"].startswith("sha256:"))

    def test_invalid_file_returns_invalid_exit(self) -> None:
        error = io.StringIO()
        with redirect_stderr(error):
            code = main(["contract", "validate", str(ROOT / "missing.json")])
        self.assertEqual(code, EXIT_INVALID)
        self.assertIn("document_not_file", error.getvalue())

    def test_authorize_file_allow(self) -> None:
        output = io.StringIO()
        with redirect_stdout(output):
            code = main(
                [
                    "authorize",
                    "file",
                    str(EXAMPLE),
                    "--operation",
                    "read",
                    "--path",
                    "workspace/src/thyroros/cli.py",
                    "--at",
                    ACTIVE,
                    "--json",
                ]
            )
        self.assertEqual(code, EXIT_OK)
        self.assertEqual(json.loads(output.getvalue())["decision"], "ALLOW")

    def test_authorize_file_denial_uses_held_exit(self) -> None:
        error = io.StringIO()
        with redirect_stderr(error):
            code = main(
                [
                    "authorize",
                    "file",
                    str(EXAMPLE),
                    "--operation",
                    "write",
                    "--path",
                    "workspace/docs/guide.md",
                    "--at",
                    ACTIVE,
                ]
            )
        self.assertEqual(code, EXIT_HELD)
        self.assertIn("DENY file_scope_not_granted", error.getvalue())

    def test_invalid_request_uses_invalid_exit(self) -> None:
        error = io.StringIO()
        with redirect_stderr(error):
            code = main(
                [
                    "authorize",
                    "network",
                    str(EXAMPLE),
                    "--method",
                    "GET",
                    "--url",
                    "http://api.github.com/",
                    "--at",
                    ACTIVE,
                ]
            )
        self.assertEqual(code, EXIT_INVALID)
        self.assertIn("network_url_not_https", error.getvalue())

    def test_canonicalize_to_text_stdout(self) -> None:
        output = io.StringIO()
        with redirect_stdout(output):
            code = main(["contract", "canonicalize", str(EXAMPLE)])
        self.assertEqual(code, EXIT_OK)
        payload = json.loads(output.getvalue())
        self.assertEqual(payload["schema"], "thyroros.run-contract")

    def test_canonicalize_refuses_to_overwrite(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "contract.json"
            target.write_text("existing", encoding="utf-8")
            error = io.StringIO()
            with redirect_stderr(error):
                code = main(
                    [
                        "contract",
                        "canonicalize",
                        str(EXAMPLE),
                        "--output",
                        str(target),
                    ]
                )
        self.assertEqual(code, EXIT_INVALID)
        self.assertIn("output_exists", error.getvalue())

    def test_schema_writes_new_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "schema.json"
            code = main(["contract", "schema", "--output", str(target)])
            self.assertEqual(code, EXIT_OK)
            self.assertEqual(
                json.loads(target.read_text(encoding="utf-8"))["title"],
                "THYROROS Run Contract",
            )


if __name__ == "__main__":
    unittest.main()
