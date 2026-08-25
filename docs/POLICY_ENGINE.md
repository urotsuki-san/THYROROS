# Reference policy engine

THYROROS 0.2.0 checks requests against a validated Run Contract. The engine does not perform the
requested operation.

## Decision contract

A `PolicyDecision` contains:

- `decision`: `ALLOW` or `DENY`;
- `allowed`: boolean form of the decision;
- `code`: machine-readable reason code;
- `message`: short explanation;
- `contract_digest`: SHA-256 digest of the validated contract;
- `matched_rule`: matching allow/deny rule, when applicable.

Malformed requests raise `PolicyRequestError` and return CLI exit code `2`. A well-formed request
that is outside the contract returns `DENY` and exit code `3`.

## Lease evaluation

A run is active during:

```text
created_at <= evaluation_time < expires_at
```

Timestamps use the RFC 3339 profile accepted by the contract validator. Missing offsets, `-00:00`,
offsets outside ±14:00, and more than six fractional digits are rejected.

The Python API uses the current UTC time unless `at` is supplied. Tests and replay tools should pass
an explicit timezone-aware `datetime`.

## File authority

### Identity language

File requests use logical relative paths, not host-native paths. They are NFC-normalized,
case-sensitive, separated by `/`, and reject drive syntax, backslashes, control characters, empty
segments, `.`/`..`, Windows device names, and trailing spaces or dots.

Patterns accept whole-segment wildcards only:

- a literal segment matches itself;
- `*` matches one segment;
- `**` matches zero or more segments.

Patterns such as `*.py` are not part of Run Contract v1. The smaller grammar allows exact inclusion
checks for parent and child scopes.

### Decision order

1. Check the run lease.
2. Validate the requested logical path.
3. Apply `deny` rules.
4. Apply the requested `read` or `write` rules.
5. Deny when no rule grants the path.

### Adapter obligation

A filesystem adapter still has to map the logical path to the same real object that will be used by
the operation. On Windows this includes handling case rules, symlinks, junctions, reparse points,
alternate data streams, hard links, mount points, and TOCTOU races.

## Network authority

A network rule contains:

```text
HTTP method + https + exact lowercase DNS host + port + path prefix
```

Path-prefix comparison is segment-aware. `/repos/example` matches `/repos/example` and
`/repos/example/issues`, but not `/repos/example-evil`.

Request normalization:

- methods are uppercased and checked against the supported method set;
- only HTTPS is accepted;
- URL userinfo, fragments, controls, and backslashes are rejected;
- hosts are lowercased and validated as ASCII DNS names;
- an omitted port becomes `443`;
- an empty path becomes `/`;
- repeated slashes, dot traversal, malformed escapes, and encoded dot/path separators are rejected;
- query text is not part of Run Contract v1 authority.

`requests_used` is checked against `budget.network_requests`. The engine does not maintain that
counter. An enforcing broker must own it and must keep DNS resolution, redirects, proxying, and raw
socket access inside the same policy boundary.

## Process authority

`authorize_process` checks an executable basename and the caller's current child-process count.
Basename comparison is case-insensitive for the Windows-first contract model.

The process supervisor is responsible for resolving that name to an approved executable, controlling
the environment and inherited handles, maintaining the child count, and terminating descendants when
the lease closes.

## Secret authority

Contracts contain opaque references of the form:

```text
secret:<namespace>/<name>
```

Matching is exact. The policy engine does not resolve the reference and should not receive the secret
value. Credential storage and issuance belong in the integrating broker.

## Effect authority

Effect classes are ordered:

```text
PURE
READ_IDEMPOTENT
WRITE_IDEMPOTENT
AT_MOST_ONCE
RECONCILE_REQUIRED
IRREVERSIBLE
```

A request is allowed when its class does not exceed `maximum_effect`. Ambiguous completion of
non-idempotent work should be reconciled against external state before retrying. `IRREVERSIBLE` is
marked as requiring confirmation by the reference model.

## Child authority conservation

`compare_child_authority(parent, child)` checks that:

- task and subject identity are unchanged;
- the child lease stays within the parent lease;
- read/write scopes do not widen;
- the child retains all parent deny coverage;
- executable, child-process, secret, effect, and budget limits do not widen;
- child network rules are covered by parent rules with the same scheme, host, and port;
- parent acceptance commands remain with equal or shorter timeouts;
- `forbidden_diff` coverage is not reduced.

If a file scope widens, the comparison includes an example path admitted by the child but not by the
parent. Analysis fails closed if its state limit is exceeded.

## Immutability and concurrency

`PolicyEngine` validates, copies, and freezes the supplied contract. It does not maintain request or
process counters, so read-only policy checks do not mutate shared engine state.

An adapter still has to keep the resource identity and counter state stable between the policy check
and the actual operation.

## Non-goals of 0.2.x

The policy engine does not:

- intercept operations;
- provide an OS sandbox;
- resolve host filesystem objects;
- resolve DNS or follow redirects;
- supervise processes;
- store credentials;
- verify worker output;
- sign execution receipts.
