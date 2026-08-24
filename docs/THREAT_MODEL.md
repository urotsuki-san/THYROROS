# Threat Model

## Protected assets

- source code and build artifacts;
- user files and private documents;
- API keys, OAuth tokens, SSH keys, browser/session credentials, and Git credentials;
- repository integrity and release configuration;
- endpoint availability and resource budget;
- agent memory, skill, lesson, and policy state;
- approval authority;
- event evidence, verification records, and signing keys.

## Adversaries

### Manipulated agent

A normally benign model follows instructions embedded in a README, source comment, issue, web page,
email, PDF, tool result, or memory entry.

### Malicious or compromised tool

An MCP server, CLI tool, package script, browser helper, or integration lies about its effect,
changes schema after approval, returns malicious instructions, or attempts credential theft.

### Supply-chain adversary

A dependency, installer, compiler plugin, generated executable, or release asset performs behavior
outside the task.

### Local unprivileged adversary

Another process attempts to inject, race, replace, observe, or tamper with the agent workspace,
broker channel, or evidence store.

### Privileged adversary

An administrator or kernel-level attacker disables monitoring or replaces trusted components.
Complete resistance to this adversary is not an early-project claim.

## In-scope attack classes

- direct and indirect prompt injection;
- agent goal hijacking;
- tool misuse and confused-deputy behavior;
- identity and privilege abuse;
- credential exfiltration;
- network destination substitution;
- MCP tool-name collision and schema drift;
- unsafe token passthrough;
- symlink, junction, path traversal, and alternate-stream escapes;
- child-process and handle inheritance escapes;
- replay or duplicate execution of non-idempotent actions;
- lost-response retry ambiguity;
- fake test output and self-certification;
- memory poisoning and provenance laundering;
- denial of wallet and resource exhaustion;
- sensor impairment and evidence truncation;
- silent fallback to a weaker sandbox.

## Out of scope or partial coverage

- firmware or hardware compromise;
- full kernel compromise at the same trust level as enforcement;
- all covert channels;
- malicious action explicitly and knowingly performed by the authorized human;
- model-provider internals;
- social engineering that never reaches an executable agent path;
- guaranteed detection or attribution of every attack.

## Trust boundaries

Trusted in R0:

- the local Python interpreter used to run the validator;
- the checked source revision;
- the operator-supplied contract file, only after strict validation.

Untrusted in the product architecture:

- all models and planners;
- repository contents;
- external data;
- MCP server descriptions and annotations;
- tool stdout and exit text;
- learned memory;
- sandboxed processes;
- derived UI projections.

Future enforcement components join the trusted computing base only after a platform-specific release
gate.

## Required security posture

THYROROS does not need to prove that an agent's internal reasoning is benign. It must mediate the
effect so that reasoning cannot exceed the contract.
