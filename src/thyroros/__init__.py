"""THYROROS authority-contract and reference policy engine."""

from .canonical import CanonicalizationError, canonical_digest, canonical_json_bytes
from .contracts import (
    AuthorityComparison,
    ContractDocumentError,
    Violation,
    compare_child_authority,
    load_contract,
    load_contract_bytes,
    parse_rfc3339,
    validate_run_contract,
)
from .effects import EffectClass
from .policy import (
    PolicyDecision,
    PolicyEngine,
    PolicyRequestError,
    authorize_effect,
    authorize_file,
    authorize_network,
    authorize_process,
    authorize_secret,
)
from .schema import schema_bytes, schema_document
from .scopes import (
    ScopeAnalysisError,
    match_scope,
    scope_expansion_witness,
    scope_set_covers,
    validate_scope_pattern,
    validate_scope_target,
)

__all__ = [
    "AuthorityComparison",
    "CanonicalizationError",
    "ContractDocumentError",
    "EffectClass",
    "PolicyDecision",
    "PolicyEngine",
    "PolicyRequestError",
    "ScopeAnalysisError",
    "Violation",
    "authorize_effect",
    "authorize_file",
    "authorize_network",
    "authorize_process",
    "authorize_secret",
    "canonical_digest",
    "canonical_json_bytes",
    "compare_child_authority",
    "load_contract",
    "load_contract_bytes",
    "match_scope",
    "parse_rfc3339",
    "schema_bytes",
    "schema_document",
    "scope_expansion_witness",
    "scope_set_covers",
    "validate_run_contract",
    "validate_scope_pattern",
    "validate_scope_target",
]

__version__ = "0.2.0"
