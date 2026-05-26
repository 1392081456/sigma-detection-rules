# Changelog

All notable changes to this ruleset follow [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- Initial public release with 30 Sigma rules and 24 Suricata signatures.
- Coverage of 23 published CVEs reproduced in `ctf-notes/labs`, covering
  the parsing-boundary categories described in
  [the methodology blog post](https://1392081456.github.io/2026/05/26/cve-to-sigma-30min/):
  cookie deserialization, OGNL evaluation, JNDI logging chain, non-HTTP
  deserialization, auth bypass, arbitrary file read, traversal,
  unauthenticated services.
- `scripts/extract_rules.py` — deterministic extractor that pulls
  rules from the upstream `ctf-notes/labs/*/writeup_en.md` files.
- `scripts/lint_sigma.py` and `scripts/lint_suricata.py` — structural
  lint, no heavy dependencies.
- GitHub Actions CI: lint on push / PR, with a job-summary table of
  the current ruleset stats.

## [0.1.0] — 2026-05-26

Initial scaffold.
