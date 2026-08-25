# Roadmap

Milestones are capability-based rather than date-based. Each milestone lists the work that must be
implemented and tested before it is considered complete.

## R0 — Contract core: complete

Implemented:

- Run Contract v1 schema and semantic validation;
- rejection of duplicate keys, unknown fields, path traversal, malformed digests, and non-deny
  network defaults;
- canonical JSON and SHA-256 digests;
- effect classes and stable reason codes;
- parent/child scope comparison for paths and network rules;
- bounded contract loading, packaged schema, examples, and repository checks.

Completion checks:

- valid child narrowing passes;
- widening is rejected, with an example path for path-scope expansion;
- canonical output does not depend on object key order;
- rejection tests have matching valid-use tests where appropriate.

## R0.5 — Reference policy engine: complete in 0.2.0

Implemented:

- `PolicyEngine` bound to a validated contract digest;
- file read/write checks with deny precedence;
- HTTPS method/host/port/path checks;
- executable basename and child-count checks;
- secret-reference and effect-class checks;
- lease and network-budget checks;
- CLI and Python API;
- wheel/sdist build and installation checks;
- CI across supported Python versions and desktop platforms.

The 0.2.0 engine evaluates requests. It does not enforce them at the operating-system level.

## R1 — Windows constrained launcher

Planned work:

- host capability detection;
- `CreateProcessInSandbox` evaluation where supported;
- AppContainer and Job Object backend;
- restricted-token compatibility backend;
- isolated staging workspace and resource resolution;
- reduced environment and controlled inherited handles;
- process counting and cleanup.

Completion checks:

- test fixtures cannot read outside granted paths, use ambient credentials, access ungranted network
  destinations, or leave child processes after shutdown;
- missing isolation support fails closed instead of starting an unrestricted process.

## R2 — Mediated effects

Planned work:

- action identifiers and effect-state tracking;
- file/Git broker;
- network broker with DNS and redirect handling;
- MCP gateway with server/schema identity;
- secret and identity broker;
- one-shot leases and atomic counters.

Completion checks:

- each allowed effect is tied to a contract and action identifier;
- ambiguous `AT_MOST_ONCE` completion is reconciled before retry;
- tool schema changes invalidate prior approval;
- raw long-lived credentials stay outside the sandbox.

## R3 — Independent verification and receipts

Planned work:

- verifier separate from the worker;
- fixed acceptance commands;
- Change Capsule and controlled apply;
- chained event records;
- signed receipt;
- in-toto export.

Completion checks:

- worker stdout alone cannot produce a verified PASS;
- modified tests, missing coverage, or worker-authored receipt data are detected.

## R4 — Stronger Windows enforcement

Planned work:

- WFP enforcement evaluation;
- optional filesystem minifilter research;
- tests for reparse points, alternate data streams, hard links, memory-mapped I/O, raw sockets, and
  TOCTOU races;
- tamper and recovery tests.

Completion checks:

- bypass tests fail for the advertised protection grade;
- unsupported operations are refused or reported at a lower grade.

## R5 — Behavioral evidence

Planned work:

- adapter interface for behavioral signals;
- agent/repository/task baselines;
- uncertainty calibration;
- drift handling and rollback;
- sensor-health tracking.

Completion checks:

- behavioral models cannot grant authority;
- policy checks remain usable when behavioral signals are unavailable;
- evaluation reports utility and false-action rates separately.

## R6 — Additional platforms and adapters

- Linux namespaces, Landlock, seccomp, and cgroups;
- macOS sandbox and Endpoint Security evaluation;
- additional agent adapters;
- cross-platform replay and attestation.

## Commit policy

Keep commits focused and verified. Avoid WIP/checkpoint commits, merge noise, and formatting-only
history when a change can be included with the work it belongs to.
