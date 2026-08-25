# Security policy

## Supported versions

| Version | Security fixes |
|---|---|
| `0.2.x` | Supported while it is the current contract/policy line |
| `0.1.x` and earlier | Not supported |

THYROROS is pre-1.0. Security-sensitive behavior and public APIs may change between minor releases.
See `CHANGELOG.md` for changes.

## Current scope

THYROROS 0.2.0 validates Run Contracts, compares delegated authority, and evaluates policy requests.
It does not provide OS isolation or mandatory mediation on its own.

Do not use the Python package by itself as an EDR, malware sandbox, credential store, or compliance
control. An integrating launcher or broker must resolve real resources, maintain counters and process
state, intercept the relevant operations, and enforce denials.

## Reporting a vulnerability

Do not report suspected vulnerabilities in public issues, discussions, pull requests, commits, or
paste services.

Use GitHub private vulnerability reporting / Security Advisories when available. If that channel is
not available, contact the repository owner through GitHub and ask for a private reporting method
without including sensitive details in the initial message.

Do not attach live credentials, private customer/user data, production logs containing secrets, or
weaponized malware. Use a disposable repository and an inert reproduction when possible.

A useful report includes:

- affected version or commit;
- operating system and Python version;
- smallest reproduction;
- expected and observed behavior;
- security impact;
- whether the issue depends on timing or adapter-specific normalization.

This volunteer project does not publish a response-time SLA.

## High-priority areas

Reports are especially useful for:

- duplicate-key or parser inconsistencies;
- canonical-digest ambiguity;
- schema/implementation drift;
- parent/child authority bypass;
- path matching or scope-inclusion errors;
- Unicode, path traversal, link/reparse-point, or TOCTOU confusion in an adapter;
- network host, port, method, path-prefix, or percent-encoding confusion;
- effect-class downgrade or unsafe retry behavior;
- lease, counter, or budget bypass;
- mutable policy state changing a decision after it has been tied to a contract digest;
- future sandbox/receipt code reporting stronger coverage than it actually provides.

## Not provided by the 0.2.x package

The current package does not guarantee:

- prevention of operations that bypass the integrating broker;
- resistance to an administrator or kernel-level attacker;
- host filesystem or network canonicalization;
- secure storage or delivery of raw credentials;
- signed or tamper-resistant execution receipts;
- detection of malicious intent or prompt injection.

A documentation or API issue that encourages an unsafe integration is still in scope for a security
report.

## Disclosure

Please allow time for private investigation and a coordinated fix before public disclosure. Passing
unit tests is not a security certification of a future OS enforcement backend.
