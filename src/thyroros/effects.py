from __future__ import annotations

from enum import IntEnum


class EffectClass(IntEnum):
    """Ordered side-effect and recovery semantics."""

    PURE = 0
    READ_IDEMPOTENT = 1
    WRITE_IDEMPOTENT = 2
    AT_MOST_ONCE = 3
    RECONCILE_REQUIRED = 4
    IRREVERSIBLE = 5

    @classmethod
    def parse(cls, value: object) -> "EffectClass | None":
        if not isinstance(value, str):
            return None
        try:
            return cls[value]
        except KeyError:
            return None

    @property
    def requires_confirmation(self) -> bool:
        return self is EffectClass.IRREVERSIBLE

    @property
    def may_retry_after_ambiguous_failure(self) -> bool:
        return self <= EffectClass.WRITE_IDEMPOTENT

    @property
    def requires_reconciliation_after_ambiguous_failure(self) -> bool:
        return not self.may_retry_after_ambiguous_failure
