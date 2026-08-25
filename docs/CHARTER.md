# Project Charter

## Mission

THYROROS is intended to put a policy boundary around autonomous agents. A Run Contract describes the
files, network destinations, executables, secrets, time limits, and effect classes available to a
run. Later components will use the same contract to launch, supervise, verify, and record the run.

## Product statement

THYROROS is an agent runtime gate with an execution record.

## Why this is a separate project

The runtime is kept separate from any particular agent or model. Coding agents, tool runners, and
MCP clients should be able to use the same contract format without sharing planner, memory, or model
provider code.

## Goals

1. Define run authority in a machine-readable contract.
2. Prevent delegated runs from gaining authority that the parent did not have.
3. Keep long-lived credentials out of agent workspaces.
4. Mediate filesystem, process, network, tool, and secret use through explicit interfaces.
5. Verify results outside the worker that produced them.
6. Record enough information to reconstruct what was allowed and what happened.
7. Refuse unsupported enforcement modes instead of silently falling back to unrestricted execution.

## Non-goals

- classifying every malicious prompt;
- identifying malware families;
- protecting a host after administrator or kernel compromise;
- replacing an enterprise EDR in early releases;
- using an LLM or anomaly model as the final authorization decision;
- forcing all agents into one framework.

## Initial platform

Windows is the first enforcement target. The planned backend work evaluates AppContainer, Job
Objects, restricted tokens, process mitigations, ETW, WFP, and the newer `CreateProcessInSandbox`
APIs where available.

Contract validation and policy checks come first; OS enforcement is a later milestone.

## Success criteria

For the contract core:

- malformed or ambiguous contracts are rejected;
- canonical digests are stable;
- a child contract cannot widen its parent;
- denials use stable reason codes;
- tests cover both rejection and valid narrowing.

Later milestones define their own enforcement tests before adding stronger security claims.
