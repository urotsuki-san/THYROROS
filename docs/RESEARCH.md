# Research and standards

Last reviewed: **2026-08-24**.

This file records the public sources used for the design. A citation explains where a design choice
came from; it is not a security certification of THYROROS.

## Primary sources

### OWASP Top 10 for Agentic Applications for 2026

<https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/>

Relevant topics include agent goal hijacking, tool misuse, identity/privilege abuse, memory
poisoning, insecure inter-agent communication, and cascading failures. THYROROS treats these as
runtime authority problems in addition to prompt-handling problems.

### CaMeL — Defeating Prompt Injections by Design

<https://arxiv.org/abs/2503.18813>

CaMeL separates control policy from untrusted retrieved data and uses capability restrictions to
limit data flow. THYROROS follows the same broad separation of trusted policy from untrusted content;
it does not claim that CaMeL's formal results apply directly to arbitrary coding agents.

### Fides — Securing AI Agents with Information-Flow Control

<https://www.microsoft.com/en-us/research/publication/securing-ai-agents-with-information-flow-control/>

Fides is relevant to future origin/confidentiality labels. Those labels may restrict where data can
flow, but they are not a source of new permissions in THYROROS.

### Model Context Protocol specification 2026-07-28

Specification:
<https://modelcontextprotocol.io/specification/2026-07-28>

Tools:
<https://modelcontextprotocol.io/specification/2026-07-28/server/tools>

Authorization:
<https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization>

Relevant MCP requirements include host-side controls for sensitive tools, server-scoped tool
identity, untrusted annotations, and audience/resource-bound authorization. The planned THYROROS MCP
gateway therefore includes the server and schema digest in tool identity and avoids raw token
passthrough.

### Windows Create Process In Sandbox APIs

<https://learn.microsoft.com/en-us/windows/win32/secauthz/createprocessinsandbox>

Microsoft documents a sandbox specification covering AppContainer isolation, filesystem grants,
network proxy policy, integrity settings, Win32k restrictions, and Job Object UI limits. THYROROS
will evaluate this API as the first Windows backend where the required capabilities are available.
Actual OS/build support and enforcement behavior still need platform tests.

### Windows Job Objects and restricted tokens

Job Objects:
<https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects>

Restricted Tokens:
<https://learn.microsoft.com/en-us/windows/win32/secauthz/restricted-tokens>

These APIs are candidates for process lifetime control and privilege reduction. Token reduction by
itself is not treated as filesystem or network isolation.

### in-toto Runtime Trace attestation

<https://in-toto.io/attestation/runtime-trace/v0.1>

The runtime-trace format informs the planned receipt fields for monitor identity, process, policy,
and file/network observations. Its distinction between synchronous and asynchronous monitoring is
also relevant to what integrity claims a receipt can make.

### SLSA Build Provenance

<https://slsa.dev/spec/v1.2/build-provenance>

SLSA provenance reinforces the separation between an untrusted worker and the component that emits
final provenance. THYROROS follows the same separation for future verification and receipt signing.

## Repository policy

Public documentation should be sufficient to understand and review the design. Private notes or
unpublished repositories are not normative references. If an external result is important to the
implementation, link the public primary source here and describe the specific dependency on it.
