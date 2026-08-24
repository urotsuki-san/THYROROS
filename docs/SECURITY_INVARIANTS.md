# Security Invariants

These invariants are policy and architecture rules, not anomaly signatures.

## I-01 — No ambient authority

The agent does not inherit the user's full filesystem, credentials, environment, network, handles,
or authentication identity.

## I-02 — Complete mediation

Every file mutation, process launch, network request, Git effect, MCP call, secret use, approval,
and persistent-memory update crosses a named enforcement point.

An observe-only sensor does not satisfy this invariant.

## I-03 — Child authority is a subset

```text
child authority ⊆ parent authority
```

The relation applies independently and transitively to:

- readable and writable paths;
- deny rules;
- process images and child count;
- network destinations and methods;
- secret references and token audience;
- device access;
- time and resource budgets;
- effect class;
- policy revision.

A profile merge cannot expand the parent.

## I-04 — Data cannot mint authority

Text from a user task, repository, website, tool, model, memory, or another agent can request
authority. It cannot grant it.

## I-05 — Unknown is not safe

Missing, malformed, stale, contradictory, lossy, or unmeasured evidence becomes `HOLD`, `DENY`, or
a stronger sandbox. It never becomes an implicit allow.

## I-06 — Memory cannot elevate privilege

Experience and learned claims may rank, warn, require verification, require confirmation, or avoid.
Only human-owned policy may create a hard authority expansion.

## I-07 — Independent verification

The worker that changed an artifact cannot be the only component that declares it correct.
Verification runs under a separate identity and binds result, command, configuration, artifact
digest, and policy revision.

## I-08 — One observation, one decision

The decision and its human explanation are projections of the same immutable observation snapshot.
A second read cannot rewrite the reason after the decision.

## I-09 — No silent downgrade

A backend fallback is automatic only when it proves an equivalent-or-stronger Run Contract.
Unavailable isolation never falls back to an unrestricted local shell.

## I-10 — Detection cannot grant

Behavioral models, prompt-injection classifiers, and LLM judges may increase risk, require
verification, hold, or deny. They cannot create permission.

## I-11 — Effect-aware retry

Retry behavior follows the action's effect class. Ambiguous non-idempotent completion requires
reconciliation, not blind replay.

## I-12 — Evidence completeness is explicit

A receipt states sensor coverage, event loss, monitor type, truncation, and unresolved ambiguity.
An incomplete trace is not labeled complete.

## R0 implementation note

The current validator implements a conservative subset of I-03, I-05, I-08, and I-11 at the
contract level. It does not enforce effects on the operating system.
