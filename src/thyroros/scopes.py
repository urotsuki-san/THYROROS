"""Portable, analyzable path-scope semantics for THYROROS contracts.

The v1 language is intentionally smaller than shell globs:

* a literal segment matches itself;
* ``*`` matches exactly one path segment;
* ``**`` matches zero or more path segments.

Wildcards embedded inside literal segments are refused.  The restricted language lets
THYROROS decide scope-language inclusion exactly rather than relying on fragile string
prefix checks.
"""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Iterable, Sequence
import unicodedata

MAX_SCOPE_PATH_CHARS = 1024
MAX_SCOPE_SEGMENTS = 64
MAX_SCOPE_RULES = 64
MAX_ANALYSIS_STATES = 100_000

_FORBIDDEN_LITERAL_CHARS = frozenset("*?[]<>|\"")
_WINDOWS_RESERVED = {
    "CON",
    "PRN",
    "AUX",
    "NUL",
    *(f"COM{index}" for index in range(1, 10)),
    *(f"LPT{index}" for index in range(1, 10)),
}


class ScopeAnalysisError(ValueError):
    """Raised when a scope expression is invalid or exceeds analysis limits."""


def _common_path_problem(value: str) -> str | None:
    if not value or len(value) > MAX_SCOPE_PATH_CHARS:
        return f"path must be 1-{MAX_SCOPE_PATH_CHARS} characters"
    if unicodedata.normalize("NFC", value) != value:
        return "path must use NFC-normalized Unicode"
    if value.startswith(("/", "//")):
        return "path must be relative"
    if "\\" in value:
        return "use forward slashes only"
    if ":" in value:
        return "colon is forbidden in portable v1 paths"
    if any(ord(character) < 0x20 or ord(character) == 0x7F for character in value):
        return "control characters are forbidden"

    segments = value.split("/")
    if len(segments) > MAX_SCOPE_SEGMENTS:
        return f"path may contain at most {MAX_SCOPE_SEGMENTS} segments"
    if any(not segment for segment in segments):
        return "empty path segments are forbidden"
    if any(segment in {".", ".."} for segment in segments):
        return "dot and parent traversal segments are forbidden"
    return None


def _portable_literal_problem(segment: str) -> str | None:
    if any(character in _FORBIDDEN_LITERAL_CHARS for character in segment):
        return "literal segments may not contain glob or Windows-special characters"
    if segment.endswith((" ", ".")):
        return "segments may not end with a space or dot"
    stem = segment.split(".", 1)[0].upper()
    if stem in _WINDOWS_RESERVED:
        return f"Windows reserved device name {stem!r} is forbidden"
    return None


def validate_scope_pattern(value: str) -> str | None:
    """Return a human-readable validation problem, or ``None`` when valid."""

    problem = _common_path_problem(value)
    if problem is not None:
        return problem

    for segment in value.split("/"):
        if segment in {"*", "**"}:
            continue
        problem = _portable_literal_problem(segment)
        if problem is not None:
            return problem
    return None


def validate_scope_target(value: str) -> str | None:
    """Validate a concrete path presented to the reference policy engine."""

    problem = _common_path_problem(value)
    if problem is not None:
        return problem

    for segment in value.split("/"):
        if segment in {"*", "**"}:
            return "concrete paths may not contain wildcard segments"
        problem = _portable_literal_problem(segment)
        if problem is not None:
            return problem
    return None


@dataclass(frozen=True, slots=True)
class _Automaton:
    start: int
    accepting: frozenset[int]
    epsilon: dict[int, frozenset[int]]
    literal: dict[tuple[int, str], frozenset[int]]
    wildcard: dict[int, frozenset[int]]
    symbols_by_state: dict[int, frozenset[str]]
    literals: frozenset[str]

    def closure(self, states: Iterable[int]) -> frozenset[int]:
        result = set(states)
        pending = list(result)
        while pending:
            state = pending.pop()
            for target in self.epsilon.get(state, ()):  # pragma: no branch - tiny loop
                if target not in result:
                    result.add(target)
                    pending.append(target)
        return frozenset(result)

    def move(self, states: frozenset[int], symbol: str) -> frozenset[int]:
        targets: set[int] = set()
        for state in states:
            targets.update(self.literal.get((state, symbol), ()))
            targets.update(self.wildcard.get(state, ()))
        if not targets:
            return frozenset()
        return self.closure(targets)

    def active_literals(self, states: frozenset[int]) -> set[str]:
        symbols: set[str] = set()
        for state in states:
            symbols.update(self.symbols_by_state.get(state, ()))
        return symbols

    def accepts(self, states: frozenset[int]) -> bool:
        return not self.accepting.isdisjoint(states)


def _compile(patterns: Sequence[str]) -> _Automaton:
    if len(patterns) > MAX_SCOPE_RULES:
        raise ScopeAnalysisError(
            f"at most {MAX_SCOPE_RULES} scope rules may be analyzed together"
        )

    epsilon_sets: dict[int, set[int]] = defaultdict(set)
    literal_sets: dict[tuple[int, str], set[int]] = defaultdict(set)
    wildcard_sets: dict[int, set[int]] = defaultdict(set)
    symbols_by_state: dict[int, set[str]] = defaultdict(set)
    literals: set[str] = set()
    accepting: set[int] = set()

    start = 0
    next_state = 1
    for pattern in patterns:
        problem = validate_scope_pattern(pattern)
        if problem is not None:
            raise ScopeAnalysisError(f"invalid scope pattern {pattern!r}: {problem}")
        tokens = pattern.split("/")
        base = next_state
        next_state += len(tokens) + 1
        epsilon_sets[start].add(base)

        for index, token in enumerate(tokens):
            state = base + index
            following = state + 1
            if token == "**":
                epsilon_sets[state].add(following)
                wildcard_sets[state].add(state)
            elif token == "*":
                wildcard_sets[state].add(following)
            else:
                literal_sets[(state, token)].add(following)
                symbols_by_state[state].add(token)
                literals.add(token)
        accepting.add(base + len(tokens))

    return _Automaton(
        start=start,
        accepting=frozenset(accepting),
        epsilon={key: frozenset(value) for key, value in epsilon_sets.items()},
        literal={key: frozenset(value) for key, value in literal_sets.items()},
        wildcard={key: frozenset(value) for key, value in wildcard_sets.items()},
        symbols_by_state={
            key: frozenset(value) for key, value in symbols_by_state.items()
        },
        literals=frozenset(literals),
    )


def match_scope(pattern: str, target: str) -> bool:
    """Return whether a concrete portable path is admitted by ``pattern``."""

    problem = validate_scope_target(target)
    if problem is not None:
        raise ScopeAnalysisError(f"invalid concrete path {target!r}: {problem}")
    automaton = _compile((pattern,))
    states = automaton.closure((automaton.start,))
    for segment in target.split("/"):
        states = automaton.move(states, segment)
        if not states:
            return False
    return automaton.accepts(states)


def _other_symbol(literals: set[str]) -> str:
    candidate = "_"
    index = 0
    while candidate in literals or validate_scope_target(candidate) is not None:
        index += 1
        candidate = f"__other_{index}"
    return candidate


def scope_expansion_witness(
    parent_patterns: Sequence[str], child_patterns: Sequence[str]
) -> str | None:
    """Return one child-admitted path not covered by the parent, if one exists.

    The check is exact for the v1 segment language.  It constructs epsilon NFAs for
    the two unions and performs a deterministic symbolic product search over active
    literal transitions plus one representative "other" segment.
    """

    if not child_patterns:
        return None

    parent = _compile(tuple(parent_patterns))
    child = _compile(tuple(child_patterns))
    literals = set(parent.literals | child.literals)
    other = _other_symbol(literals)

    child_start = child.closure((child.start,))
    parent_start = parent.closure((parent.start,))
    start = (child_start, parent_start, False)
    pending = deque([start])
    seen = {start}
    predecessor: dict[
        tuple[frozenset[int], frozenset[int], bool],
        tuple[tuple[frozenset[int], frozenset[int], bool], str],
    ] = {}

    while pending:
        current = pending.popleft()
        child_states, parent_states, consumed = current
        if (
            consumed
            and child.accepts(child_states)
            and not parent.accepts(parent_states)
        ):
            segments: list[str] = []
            cursor = current
            while cursor != start:
                previous, symbol = predecessor[cursor]
                segments.append(symbol)
                cursor = previous
            return "/".join(reversed(segments))

        active = child.active_literals(child_states)
        active.update(parent.active_literals(parent_states))
        alphabet = tuple(sorted(active)) + (other,)
        for symbol in alphabet:
            next_child = child.move(child_states, symbol)
            if not next_child:
                continue
            next_parent = parent.move(parent_states, symbol)
            following = (next_child, next_parent, True)
            if following in seen:
                continue
            seen.add(following)
            if len(seen) > MAX_ANALYSIS_STATES:
                raise ScopeAnalysisError(
                    "scope inclusion exceeded the deterministic analysis limit"
                )
            predecessor[following] = (current, symbol)
            pending.append(following)

    return None


def scope_set_covers(
    parent_patterns: Sequence[str], child_patterns: Sequence[str]
) -> bool:
    """Return whether every child-admitted path is admitted by the parent union."""

    return scope_expansion_witness(parent_patterns, child_patterns) is None
