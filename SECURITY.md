# Security policy

## Current status

THYROROS is a research scaffold and does not yet provide protection. Do not deploy it as an EDR,
sandbox, credential boundary, or compliance control.

## Reporting

Please do not disclose suspected security vulnerabilities in a public issue. Use GitHub's private
vulnerability reporting / Security Advisory channel when it is enabled for this repository. If that
channel is unavailable, contact the maintainer through the repository owner's GitHub profile.

Do not attach live credentials, private user data, production logs, or weaponized malware samples.

When demonstrating a defect:

- use a disposable repository and inert fixture;
- provide the smallest reproduction;
- state the expected security invariant;
- state the observed behavior;
- include platform and revision information;
- remove secrets and personal paths.

## Scope of early security review

High-priority findings include:

- contract parser differential or duplicate-key acceptance;
- unknown-field acceptance;
- authority-subset bypass;
- path normalization escape;
- effect-class downgrade;
- canonical-digest ambiguity;
- approval replay;
- silent sandbox downgrade;
- verification performed by the untrusted worker;
- evidence truncation reported as complete.

Passing repository tests is engineering evidence, not a security certification.
