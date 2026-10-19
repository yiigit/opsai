# Changelog

All notable changes to OpsAI CLI are documented here. Versioning follows Semantic Versioning and Conventional Commits.

## Unreleased

### Added

- Add a dedicated GitHub Actions workflow for Bandit source scanning and
  `pip-audit` dependency checks.

## v0.9.0 (2026-10-18)

First public release of OpsAI CLI.

### Added

- Read-only Linux, Nginx, Laravel, SSH, and Docker diagnostics and security
  audits, with JSON output and GitHub Actions reporting.
- Optional AI-assisted log analysis and incident investigation with explicit
  approval gates.
- Laravel configuration and Composer dependency assessment with OWASP Top
  10:2025 classifications and JSON or standalone HTML reports.
- Explicit OSV.dev refresh for lockfile package versions; assessments continue
  to use the local snapshot offline.
- macOS-inspired and Ubuntu terminal themes.

### Documentation

- Document Debian/Ubuntu amd64 package installation, update, and removal,
  including Python-version requirements and private-repository access.
- Add usage examples, troubleshooting, privacy, CI, development, and release
  guidance, plus illustrative terminal screenshots.

Earlier internal milestones (0.1.0 through 0.3.0) were development history and
were not public releases.
