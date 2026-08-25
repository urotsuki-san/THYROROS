# Changelog

All notable changes are documented here. The project follows semantic versioning while the public
Python API remains pre-1.0.

## [Unreleased]

No unreleased changes.

## [0.2.0] - 2026-08-24

### Added

- dependency-free reference policy decisions for file, HTTPS, process, secret, and effect requests;
- exact semantic inclusion analysis for the restricted portable path-scope language;
- narrower child network rules and shorter acceptance timeouts;
- strict canonical JSON data-model checks, packaged JSON Schema access, stdin support, and
  canonicalization CLI output;
- cross-platform CI, packaging verification, security hygiene checks, contribution guidance, and
  machine-readable issue templates.

### Changed

- child authority comparison now evaluates scope meaning instead of requiring exact pattern text;
- contract loading applies bounded regular-file reads and refuses symlinks;
- package status advances from an R0 scaffold to a usable alpha contract and reference-policy core.

### Security

- deny rules take precedence over granted file scopes;
- ambiguous URL encodings, userinfo, non-HTTPS URLs, traversal segments, and malformed requests fail
  closed;
- all authorization results bind to the canonical contract digest.

## [0.1.0.dev0] - 2026-08-24

- Initial Run Contract validator, canonical digest, effect ordering, authority comparison, and
  research documentation.

[Unreleased]: https://github.com/urotsuki-san/THYROROS/commits/main
[0.2.0]: https://github.com/urotsuki-san/THYROROS/compare/480667ca29f80bc0ec67c73cae47b3c0bddf7668...main
[0.1.0.dev0]: https://github.com/urotsuki-san/THYROROS/commit/2aff096320863d0c17126b8607009a393f73afea
