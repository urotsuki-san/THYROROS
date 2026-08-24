# Project Charter

## Mission

THYROROS is an external runtime reference monitor for autonomous AI agents. It translates a human
task and policy into an immutable Run Contract, places the agent inside a bounded execution
environment, mediates side effects, independently verifies results, and emits evidence describing
what actually happened.

## Product statement

> An agent runtime gate that controls authority at the point of effect and records a verifiable
> flight receipt.

## Why this is a separate project

THYROROS is not a subsystem of any single agent. It must be capable of supervising heterogeneous
coding agents, tool runners, MCP clients, and future autonomous systems without owning their planner,
memory, provider routing, or product identity.

This separation prevents the monitored agent from becoming its own final policy authority.

## Goals

1. Make authority explicit, typed, finite, revocable, and digest-bound.
2. Remove ambient credentials and user permissions from agent workspaces.
3. Enforce child-authority subset semantics across processes, tools, network, files, secrets, time,
   and effect class.
4. Separate observation, decision, enforcement, verification, learning, and UI.
5. Preserve enough evidence to reconstruct the decision and execution path.
6. Support safe degradation without silently weakening protection.
7. Evaluate both security and benign utility.

## Non-goals

- perfect classification of malicious prompts;
- general malware-family naming;
- guaranteed protection after administrator or kernel compromise;
- replacing a full enterprise EDR in early releases;
- making a behavioral model or an LLM the policy authority;
- treating logs as proof when the monitor can miss the relevant event;
- forcing every agent implementation into one framework.

## Initial platform

Windows is first because it provides the isolation, process-control, telemetry, and network-policy
primitives needed to measure a realistic desktop-agent protection boundary: AppContainer, Job
Objects, restricted tokens, process mitigations, ETW, and WFP.

The initial implementation deliberately starts with contracts and a staging workspace before a
driver.

## Success criteria

R0 succeeds when:

- a Run Contract is strict, deterministic, and digestible;
- malformed or ambiguous input is refused;
- child authority cannot widen a parent contract;
- every refusal has a stable reason code;
- tests prove both fail-closed behavior and recovery from over-restriction.

Later phases must define separate release gates. No phase inherits a security claim merely because
the previous phase passed.
