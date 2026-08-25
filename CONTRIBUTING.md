# Contributing to THYROROS

Small, focused changes are easiest to review. Security-sensitive changes should preserve the existing
contract semantics unless the schema/version is intentionally being changed.

## Before changing code

Read `docs/CHARTER.md`, `docs/THREAT_MODEL.md`, `docs/SECURITY_INVARIANTS.md`, and `AGENTS.md`.

For a new rejection rule, add a test for the rejected case and a nearby valid case so the check does
not become broader than intended.

## Local verification

Python 3.11 or newer is required. The runtime package has no third-party dependencies.

```bash
python -m venv .venv
# Activate the environment for your shell, then:
python -m pip install -e .
python scripts/check_repo.py
```

`check_repo.py` compiles the package, validates schemas/examples, runs the tests, builds wheel and
source distributions, installs the wheel into an isolated target, checks local Markdown links, and
scans for common secret-file mistakes.

## Change rules

- Keep reason codes stable when possible.
- Reject unknown contract fields until a schema revision adds them.
- Do not use an LLM judgement as an authorization grant.
- The policy engine only returns decisions; an adapter is responsible for enforcement.
- Do not commit production credentials, private data, live malware, or exploit payloads.
- Do not advertise a sandbox or protection grade before the corresponding backend is tested.
- Keep commits focused and avoid checkpoint/formatting-only history.

## Reporting vulnerabilities

Follow `SECURITY.md`. Suspected vulnerabilities should not be opened as public issues.
