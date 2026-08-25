from __future__ import annotations

import unittest

from thyroros.scopes import (
    match_scope,
    scope_expansion_witness,
    scope_set_covers,
    validate_scope_pattern,
    validate_scope_target,
)


class ScopeValidationTests(unittest.TestCase):
    def test_portable_pattern_is_valid(self) -> None:
        self.assertIsNone(validate_scope_pattern("workspace/src/**"))
        self.assertIsNone(validate_scope_pattern("workspace/*/file.txt"))

    def test_embedded_glob_is_rejected(self) -> None:
        self.assertIsNotNone(validate_scope_pattern("workspace/*.py"))

    def test_windows_reserved_name_is_rejected(self) -> None:
        self.assertIsNotNone(validate_scope_pattern("workspace/CON/file"))
        self.assertIsNotNone(validate_scope_target("workspace/lpt1.txt"))

    def test_traversal_and_absolute_paths_are_rejected(self) -> None:
        self.assertIsNotNone(validate_scope_pattern("workspace/../profile/**"))
        self.assertIsNotNone(validate_scope_target("/workspace/file"))


class ScopeMatchingTests(unittest.TestCase):
    def test_literal_and_single_segment_wildcard(self) -> None:
        self.assertTrue(match_scope("workspace/*/file.txt", "workspace/src/file.txt"))
        self.assertFalse(match_scope("workspace/*/file.txt", "workspace/a/b/file.txt"))

    def test_globstar_matches_zero_or_more_segments(self) -> None:
        self.assertTrue(match_scope("workspace/**", "workspace/file.txt"))
        self.assertTrue(match_scope("workspace/**", "workspace/a/b/file.txt"))
        self.assertTrue(match_scope("workspace/**/file.txt", "workspace/file.txt"))
        self.assertTrue(match_scope("workspace/**/file.txt", "workspace/a/b/file.txt"))

    def test_literal_is_case_sensitive(self) -> None:
        self.assertFalse(match_scope("workspace/src/**", "workspace/SRC/file.py"))


class ScopeInclusionTests(unittest.TestCase):
    def test_narrower_child_scope_is_covered_semantically(self) -> None:
        self.assertTrue(scope_set_covers(["workspace/**"], ["workspace/src/**"]))
        self.assertIsNone(
            scope_expansion_witness(["workspace/**"], ["workspace/src/**"])
        )

    def test_broader_child_scope_returns_a_witness(self) -> None:
        witness = scope_expansion_witness(
            ["workspace/src/**"],
            ["workspace/**"],
        )
        self.assertIsNotNone(witness)
        assert witness is not None
        self.assertTrue(match_scope("workspace/**", witness))
        self.assertFalse(match_scope("workspace/src/**", witness))

    def test_union_of_parent_rules_covers_child(self) -> None:
        self.assertTrue(
            scope_set_covers(
                ["workspace/src/**", "workspace/tests/**"],
                ["workspace/src/thyroros/**", "workspace/tests/unit/**"],
            )
        )

    def test_single_segment_scope_does_not_cover_recursive_scope(self) -> None:
        self.assertFalse(scope_set_covers(["workspace/*"], ["workspace/**"]))

    def test_empty_child_grants_nothing(self) -> None:
        self.assertTrue(scope_set_covers(["workspace/**"], []))

    def test_maximum_rule_set_narrowing_stays_analyzable(self) -> None:
        parent = [f"workspace/component-{index}/**" for index in range(64)]
        child = [f"workspace/component-{index}/src/**" for index in range(64)]
        self.assertTrue(scope_set_covers(parent, child))


if __name__ == "__main__":
    unittest.main()
