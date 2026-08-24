# Architecture

## Architectural rule

Observation, decision, enforcement, verification, learning, and UI must not be collapsed into one
process or one model call.

```text
Operator / owner policy
          |
          v
Run Contract Compiler
          |
          v
+------------------------------------------------------+
| THYROROS trusted control plane                       |
| policy | leases | supervisor | brokers | ledger      |
+--------+-------------------+-------------------------+
         |                   |
         v                   v
Agent sandbox          Independent verifier
         |
         +--> File broker / staging workspace
         +--> Process supervisor
         +--> Network broker
         +--> MCP gateway
         +--> Secret and identity broker
         +--> Git apply broker
```

## Control plane

The control plane owns:

- contract compilation and digest;
- policy revision;
- capability leases;
- effect-class decisions;
- broker authorization;
- sandbox lifecycle;
- approval state;
- evidence sequencing;
- verification admission;
- receipt signing.

It does not ask the monitored agent to decide these facts.

## Agent sandbox

The sandbox receives:

- a bounded staging workspace;
- sanitized environment;
- no raw provider or service credentials;
- only the broker channels named by the contract;
- an enforceable process lifetime;
- explicit resource ceilings.

The real repository is not the normal write target.

```text
real repository
      |
      | immutable snapshot
      v
staging workspace
      |
      | agent edits
      v
Change Capsule
      |
      | independent verification
      v
controlled apply
```

## Brokers

### File and Git broker

The broker resolves paths against a known root, rejects traversal and reparse-point escapes, and
applies only a verified Change Capsule to the real repository.

### Network broker

Network is default deny. A permitted request is bound to method, scheme, host, port, path scope,
run, action identity, and lease. Raw credentials do not enter the sandbox.

### MCP gateway

The gateway namespaces servers, pins transport and schema digests, treats annotations as untrusted,
and invalidates approval when a tool definition changes.

### Secret and identity broker

The broker performs an action or returns a short-lived audience-bound lease. It does not copy a
long-lived token into a prompt, environment variable, workspace, or untrusted MCP server.

## Windows backend direction

The preferred order for evaluation is:

1. Microsoft `CreateProcessInSandbox` APIs where platform availability and behavior are proven;
2. explicit AppContainer + Job Object composition;
3. restricted token + isolated ACL staging workspace for compatibility;
4. stronger VM/container backend for hostile or incompatible workloads.

A backend is a candidate only if its actual attestations satisfy the Run Contract.

## Evidence plane

The eventual event ledger contains:

```text
sequence
run identity
actor
action identity
effect class
resource identity
policy digest
origin/information-flow labels
sensor health
previous event digest
event digest
```

A searchable database is a projection, not the only source of truth.

## Protection grades

- Grade A: semantic mediation of every effect;
- Grade B: OS-enforced sandbox with partial semantic mediation;
- Grade C: observe only.

The grade is evidence, not branding. Missing coverage lowers the displayed grade.
