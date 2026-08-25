# Threat model

## Protected assets

- source code and build artifacts;
- user files and private documents;
- API keys, OAuth tokens, SSH keys, browser/session credentials, and Git credentials;
- repository and release configuration;
- host availability and resource limits;
- agent memory and policy state;
- approval state;
- audit records and future signing keys.

## Adversaries

### Manipulated agent

An otherwise normal agent follows hostile instructions from repository content, a web page, email,
PDF, tool result, issue, or stored memory.

### Malicious or compromised tool

An MCP server, CLI program, package script, browser helper, or other integration lies about its
effect, changes its schema, or attempts to steal credentials.

### Supply-chain adversary

A dependency, build action, installer, compiler plugin, generated executable, or release asset runs
behavior outside the intended task.

### Local unprivileged adversary

Another local process attempts to read or modify the workspace, broker channel, counters, policy
input, or audit data.

### Privileged adversary

An administrator or kernel-level attacker can disable or replace enforcement components. Full
protection against this attacker is outside the early project scope.

## In-scope attack classes

- direct and indirect prompt injection;
- tool misuse and confused-deputy behavior;
- credential exfiltration and token misuse;
- network destination, redirect, DNS, proxy, or normalization bypass;
- MCP tool-name collision and schema drift;
- symlink, junction, reparse-point, hard-link, traversal, case, Unicode, and alternate-stream issues;
- child-process and handle-inheritance escape;
- duplicate execution or unsafe retry of non-idempotent actions;
- fake verification output;
- memory poisoning;
- resource exhaustion;
- counter races and missing/truncated audit data;
- fallback to a weaker sandbox without an explicit policy decision.

## Out of scope or partial coverage

- firmware or hardware compromise;
- full kernel compromise at the same trust level as enforcement;
- all covert channels;
- actions explicitly authorized by the user despite a known risk;
- model-provider internals;
- social engineering that never reaches an executable agent path;
- guaranteed detection or attribution of every attack.

## Trust boundaries in 0.2.0

The policy result depends on:

- the Python interpreter;
- the installed THYROROS package and schema;
- the parsed Run Contract;
- request identity, time, and counter values supplied by the caller.

The 0.2.0 library does not establish that:

- the logical request names the same OS object later used by the operation;
- every operation passes through the policy engine;
- caller-supplied counters are accurate and atomic;
- DNS, redirects, process lookup, and filesystem resolution remain within policy;
- a denied result cannot be bypassed.

These are responsibilities of later enforcement components.

## Target product trust boundaries

The agent, repository contents, external data, MCP descriptions, tool output, learned memory, and
sandboxed processes are treated as untrusted input. Supervisors, brokers, verifiers, audit storage,
and signing components become part of the trusted computing base only when their corresponding
milestones are implemented and tested.

## Required security posture

The intended end state is effect control rather than intent classification: the system should limit
what an agent can do even when the agent follows hostile input. Until mandatory mediation exists,
THYROROS documentation must not imply that the Python package alone provides containment.
