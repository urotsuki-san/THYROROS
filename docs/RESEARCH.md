# Research and Standards Basis

Accessed: **2026-08-24**.

THYROROS translates mechanisms into its own authority and evidence model. It does not claim that
citing a paper or standard proves the implementation secure.

## Primary sources

### OWASP Top 10 for Agentic Applications for 2026

Source:
<https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/>

Adopted concern set:

- agent goal hijacking;
- tool misuse;
- identity and privilege abuse;
- memory poisoning;
- insecure inter-agent communication;
- cascading failure and trust exploitation.

Translation into THYROROS: the protection boundary includes authority, tools, identity, memory,
delegation, effects, and evidence—not prompt filtering alone.

### CaMeL — Defeating Prompt Injections by Design

Paper:
<https://arxiv.org/abs/2503.18813>

Adopted principle: separate trusted control/data-flow policy from untrusted retrieved content and
use capability restrictions to prevent unauthorized data flow.

Not adopted as a claim: THYROROS does not assert CaMeL's proof applies to arbitrary coding agents or
to the current R0 validator.

### Fides — Securing AI Agents with Information-Flow Control

Microsoft Research:
<https://www.microsoft.com/en-us/research/publication/securing-ai-agents-with-information-flow-control/>

Adopted principle: deterministic confidentiality/integrity labels and policy enforcement are more
appropriate as authority controls than a probabilistic model judge.

Translation into THYROROS: origin labels can restrict sinks; labels do not grant capabilities.

### Model Context Protocol specification 2026-07-28

Specification:
<https://modelcontextprotocol.io/specification/2026-07-28>

Tools:
<https://modelcontextprotocol.io/specification/2026-07-28/server/tools>

Authorization:
<https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization>

Relevant requirements and guidance:

- tool inputs, outputs, timeouts, audit, and sensitive-operation confirmation need host/client
  controls;
- tool annotations are untrusted unless supplied by a trusted server;
- tool names are scoped to a server and can collide;
- protected HTTP resources use least privilege and audience/resource-bound authorization;
- a server must not accept or transit tokens intended for another resource.

Translation into THYROROS: server namespace and schema digest are part of tool identity; token
passthrough is not an implementation shortcut.

### Windows Create Process In Sandbox APIs

Microsoft Learn:
<https://learn.microsoft.com/en-us/windows/win32/secauthz/createprocessinsandbox>

The June 2026 documentation describes a versioned FlatBuffer sandbox specification, AppContainer
isolation, filesystem grants, network proxy policy, integrity settings, Win32k restrictions, and
Job Object UI limits. It explicitly rejects unsupported capability resolution instead of silently
degrading.

Research decision: treat this API as the first Windows backend candidate, not as an assumed
universal dependency. Availability, minimum OS build, compatibility, nesting, and real enforcement
must be probed and attested.

### Windows Job Objects and restricted tokens

Job Objects:
<https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects>

Restricted Tokens:
<https://learn.microsoft.com/en-us/windows/win32/secauthz/restricted-tokens>

Adopted principles:

- own a process group as one lifetime and accounting unit;
- avoid breakaway settings that lose the process tree;
- kill the full owned tree on lease loss;
- remove privileges and use restricting SIDs;
- do not treat token reduction alone as filesystem/network isolation.

### in-toto Runtime Trace attestation

Specification:
<https://in-toto.io/attestation/runtime-trace/v0.1>

Adopted principle: identify the monitor, monitored process, trace policy, and observed process,
network, and file-access evidence.

Important limitation retained: asynchronous monitoring cannot make the same file-digest guarantee
as a synchronous monitor that can pause use. THYROROS receipts must state monitor strength and
coverage.

### SLSA Build Provenance

Specification:
<https://slsa.dev/spec/v1.2/build-provenance>

Adopted principle: the untrusted worker does not author the final trusted provenance or hold the
signing key.

## Design provenance policy

This repository is intended to be self-contained when published. Unpublished notes, private
repositories, local deployment details, and inaccessible internal documents are not normative
references for THYROROS.

Ideas may originate from prior experiments or internal design review, but any principle required to
understand, implement, review, or verify THYROROS must be restated here and supported by public
primary sources where an external source is relevant.

The reusable principles currently captured by the public design are:

- child authority can only narrow relative to its parent;
- observation, decision, enforcement, verification, learning, and UI are separate trust boundaries;
- learned evidence can restrict or rank behavior but cannot mint authority;
- unknown or incomplete evidence is not silently converted to PASS;
- retries and reconciliation follow explicit effect semantics;
- fallback never silently weakens the promised isolation contract;
- verification and final provenance are produced outside the untrusted worker.
