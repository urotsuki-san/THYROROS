# Architecture

## Architectural rule

Policy, enforcement, and verification are separate components. The worker being supervised is not
trusted to enforce its own Run Contract or verify its own output.

## Implemented boundary in 0.2.0

```text
validated Run Contract
          |
          v
+-------------------------------------------+
| dependency-free policy engine             |
| validation | scopes | leases | decisions  |
+----------------------+--------------------+
                       |
                       | ALLOW / DENY / HOLD
                       | reason + contract digest
                       v
              external adapter / broker
                       |
                       | enforce decision
                       v
                 requested effect
```

Implemented modules:

- `canonical.py`: canonical JSON encoding and digest;
- `scopes.py`: path matching and scope inclusion;
- `contracts.py`: parsing, validation, and parent/child comparison;
- `policy.py`: policy checks for concrete requests;
- `schema.py`: packaged Run Contract v1 schema;
- `cli.py`: command-line interface and exit codes.

The 0.2.0 package returns policy decisions only. It does not force an agent to use them.

## Target product architecture

```text
Operator / owner policy
          |
          v
Run Contract Compiler
          |
          v
+------------------------------------------------------+
| THYROROS control plane                               |
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

Planned control-plane responsibilities include:

- contract validation and digesting;
- policy revisions and leases;
- broker authorization and counters;
- sandbox and process lifecycle;
- approval state;
- event ordering;
- verifier admission;
- receipt signing.

## Agent sandbox

The planned Windows launcher provides a staging workspace, a reduced environment, controlled handle
inheritance, and an enforceable process lifetime. Raw service credentials are kept outside the
worker.

The real repository is not the normal write target:

```text
real repository
      |
      | snapshot
      v
staging workspace
      |
      | agent edits
      v
Change Capsule
      |
      | verification
      v
controlled apply
```

## Brokers

### File and Git broker

The file broker maps contract paths to objects under an owned root and must reject traversal,
reparse-point, link, and race escapes. Git changes are staged and applied after verification.

### Network broker

The network broker applies the contract's method, scheme, host, port, and path rules. Redirects and
DNS resolution must remain subject to the same policy. Credentials stay outside the sandbox.

### MCP gateway

The MCP gateway identifies tools by server and schema, rather than by tool name alone. A schema
change invalidates earlier approval.

### Secret and identity broker

Contracts refer to secrets by name. The broker either performs the authenticated operation or issues
a short-lived credential for the intended service; long-lived tokens are not copied into the worker.

## Windows backend direction

The current evaluation order is:

1. `CreateProcessInSandbox` where the installed Windows version supports the required capabilities;
2. AppContainer with Job Objects;
3. restricted token plus an isolated ACL-controlled staging directory for compatibility;
4. a stronger VM/container backend where the desktop mechanisms are insufficient.

An unavailable backend is an error, not permission to run unrestricted.

## Evidence plane

A later receipt format is expected to include the run and action identifiers, effect class, resource
identity, contract digest, counter/sensor state, and a hash chain over events. The exact format is not
implemented in 0.2.0.

## Protection grades

- Grade A: all relevant effects are mediated by typed brokers;
- Grade B: OS sandboxing is enforced but some effects lack typed mediation;
- Grade C: observation only.

THYROROS 0.2.0 does not claim an enforcement grade.
