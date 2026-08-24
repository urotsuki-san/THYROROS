# Roadmap

Progress is gated by measured evidence rather than dates.

## R0 — Contract core

Current milestone.

Deliverables:

- strict Run Contract schema;
- canonical digest;
- effect classes;
- authority subset comparison;
- typed reason codes;
- inert examples;
- repository verification.

Exit gate:

- duplicate keys, unknown fields, path traversal, malformed digests, unsafe network defaults, and
  authority widening are rejected;
- reverse tests demonstrate that valid narrowing still passes;
- output is deterministic across JSON key order.

## R1 — Windows constrained launcher

Deliverables:

- host capability probe;
- `CreateProcessInSandbox` API spike;
- AppContainer / Job Object fallback adapter;
- restricted-token compatibility adapter;
- staging workspace;
- sanitized environment and handle list;
- process absence proof.

Exit gate:

- an inert malicious fixture cannot read the user profile, escape the staging root, use ambient
  credentials, access the network, or leave a child process after lease closure;
- backend unavailability never starts unrestricted execution.

## R2 — Mediated effects

Deliverables:

- action identity;
- effect-aware state machine;
- file / Git broker;
- network broker;
- MCP gateway;
- secret and identity broker;
- one-shot authority leases.

Exit gate:

- every allowed side effect has a contract reference and action identity;
- ambiguous `AT_MOST_ONCE` completion reconciles rather than replays;
- tool schema drift invalidates prior approval;
- raw credentials never enter the sandbox.

## R3 — Independent verification and receipts

Deliverables:

- verifier identity separate from worker;
- immutable acceptance commands;
- Change Capsule;
- controlled apply;
- chained event segments;
- signed receipt;
- in-toto export.

Exit gate:

- fake stdout, modified tests, missing sensor coverage, or a worker-authored receipt cannot create a
  verified PASS.

## R4 — Stronger Windows enforcement

Deliverables:

- WFP enforcement evaluation;
- optional minifilter research;
- reparse-point, alternate-data-stream, memory-mapped-I/O, raw-socket, and TOCTOU fixtures;
- anti-tamper and recovery drills.

Exit gate:

- broker-bypass attempts fail in the supported protection grade;
- unsupported paths are explicitly downgraded or refused.

## R5 — Behavioral evidence

Deliverables:

- behavior-evidence adapter interface;
- agent / repository / task baselines;
- calibrated uncertainty;
- drift and rollback;
- sensor-health-aware learning.

Exit gate:

- a failed or missing model cannot grant authority;
- deterministic policy remains safe when behavioral evidence is unavailable;
- utility, false actions per device-day, and subgroup worst cases are reported separately.

## R6 — Additional platforms and adapters

- Linux namespace / Landlock / seccomp / cgroup backend;
- macOS sandbox / Endpoint Security evaluation;
- additional native agent adapters;
- cross-platform replay and attestation.

## Commit policy

Repository history should remain intentionally compact. Owner-directed work may land directly on the requested branch. Each commit must be a complete, verified logical change; checkpoint, merge-noise, and formatting-only history should not be created.
