# Security invariants

These are requirements for the enforcement architecture. The 0.2.0 Python package implements only
the contract and policy portions described at the end of this document.

## I-01 — No ambient authority

A supervised worker must not inherit unrestricted user files, credentials, network access, handles,
or authentication state.

## I-02 — Complete mediation

Operations covered by a Run Contract must pass through an enforcement point: file mutation, process
creation, network requests, Git changes, MCP calls, secret use, approvals, and persistent-memory
updates.

Observation alone does not satisfy this requirement.

## I-03 — Child authority is a subset

```text
child authority ⊆ parent authority
```

Delegation may reduce authority but may not expand it. This applies to file scopes, deny rules,
processes, network access, secrets, time/resource budgets, effect class, acceptance checks, and
policy revision.

## I-04 — Policy input does not grant authority

Repository text, web content, tool output, model output, memory, and other untrusted data can request
an operation. They cannot add permissions to the current contract.

## I-05 — Invalid or missing state fails closed

Missing, malformed, expired, contradictory, or incomplete policy state is not treated as permission.
The caller must deny, hold, or use a stronger isolation mode.

## I-06 — Learned state cannot increase privilege

Learned or behavioral data may affect warnings, ranking, verification, or denial. It may not expand
the Run Contract.

## I-07 — Verification is independent

The worker that changes an artifact must not be the only component that marks the result as verified.
Verification should bind the command, configuration, artifact digest, and policy revision.

## I-08 — Decision input is stable

A decision and its explanation must be based on the same policy/request snapshot. Re-reading mutable
state after the decision must not change the recorded reason.

## I-09 — No silent isolation downgrade

If a requested sandbox backend is unavailable, THYROROS must not continue with unrestricted host
execution unless the contract explicitly permits that mode.

## I-10 — Detection is advisory

Prompt-injection detectors, anomaly models, and LLM reviewers may warn, hold, or deny. They do not
create authority.

## I-11 — Retry follows effect semantics

Idempotent operations may be retried according to their effect class. Ambiguous non-idempotent
operations require reconciliation before retry.

## I-12 — Receipt coverage is explicit

A receipt must state what was monitored and whether events were lost or truncated. Incomplete
coverage must not be reported as complete.

## 0.2.0 implementation note

The current package implements contract-level parts of I-03, I-05, I-08, and I-11:

- strict parsing and unknown-field rejection;
- parent/child scope comparison;
- policy decisions tied to a contract digest;
- stable invalid/deny reason codes;
- effect-class ordering and retry properties.

It does not isolate a worker or force operations through a broker, so I-01 and I-02 are not yet
provided by the package itself.
