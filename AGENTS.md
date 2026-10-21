# OpsAI CLI — Agent Development Instructions

## Project mission
OpsAI CLI is a Python 3.10+ command-line application focused on advanced read-only Linux and network diagnostics, with Nginx/Laravel log analysis, SSH monitoring, Linux/Docker security auditing, offline Laravel and Composer application security assessment, GitHub reporting, and optional AI-assisted troubleshooting. Keep diagnostics safe, understandable, and testable.

## Release baseline
- **v0.9.0 is the first public release.**
- Do not describe earlier internal milestones as published releases.
- The version in `pyproject.toml` is authoritative. Use Commitizen with Conventional Commits for subsequent bumps, changelog updates, and tags (`vX.Y.Z`).
- Never bump a version just to satisfy an unrelated code task unless explicitly requested.

## Architecture and code standards
- `src/opsai/domain/`: models, interfaces, pure validation and classification, including OWASP Top 10 taxonomy; no network, filesystem or subprocess side effects.
- `src/opsai/application/`: use cases and orchestration; depend on protocols rather than infrastructure implementations.
- `src/opsai/infrastructure/`: adapters for files, journalctl, SSH/OpenSSH, Docker, and OpenAI.
- `src/opsai/security/`: read-only audit checks, offline Laravel/Composer assessment, and structured findings/reports.
- `src/opsai/cli.py`: Typer commands, Rich formatting, input validation and confirmation; keep business logic out of CLI handlers.
- Favor small, typed functions, descriptive names, explicit error handling, dependency injection and predictable JSON output. Preserve backwards-compatible commands where practical.
- Avoid broad `except Exception` unless errors are reported clearly and failure is contained at a well-defined boundary.

## Safety rules
- Default to read-only collection. Never silently mutate servers, services, containers or configuration.
- Do not execute arbitrary shell commands suggested by an AI model. Remediation must be allowlisted, scoped and explicitly approved by a human.
- SSH must use key-based authentication, batch mode, strict host-key checking, bounded timeouts and bounded output.
- Treat logs, incident evidence and AI output as untrusted data. Limit collection size, redact sensitive content on a best-effort basis, and request explicit consent before sending anything to an external AI provider.
- Keep application-security assessment offline by default; consume explicitly supplied local project files and advisory snapshots, escape untrusted report content, and do not claim complete OWASP coverage. Any OSV refresh must be a separate, explicitly approved network operation that sends only lockfile package names and versions.
- Keep system diagnostics read-only and bounded. Security update checks must not refresh package indexes; active network probes require an explicit host and port; AI troubleshooting must obtain consent before sending system evidence externally.
- Do not hardcode secrets or include credentials, tokens, private keys, real inventories, or production logs in commits/tests.
- Never claim that AI output is a verified root cause; distinguish observations, hypotheses and recommended checks.

## Development workflow
1. Read the affected modules and existing tests before editing.
2. Keep changes scoped; add or update tests for both success and failure paths.
3. Run `python -m pytest -q` and `python -m compileall -q src`.
4. For packaging changes run `python -m build` and verify `opsai --help` after installation.
5. Update README and changelog as appropriate; avoid stale version numbers in headings and examples.
6. Describe exactly what was tested; never claim production SSH, Docker or live OpenAI validation when only mocks ran.

## Conventional Commits
Use `type(scope): summary`, e.g.:
- `feat(logs): support multiline Laravel exceptions`
- `fix(ssh): handle connection timeout`
- `test(security): cover privileged containers`
- `docs: clarify incident approvals`
- `refactor(application): extract collector interface`

Use `feat!:` or a `BREAKING CHANGE:` footer for intentional incompatible changes. Commitizen determines the next version; while on `0.x`, breaking-change handling follows the configured `major_version_zero` policy.

## Local commands
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'
python -m pytest -q
python -m compileall -q src
opsai --help
cz check --rev-range HEAD~1..HEAD  # when a previous commit exists
cz bump --dry-run                  # after conventional commits exist
```

## Testing expectations
- Unit tests must not require root, running Docker, remote hosts, production log files, or network/API access.
- Mock subprocesses, OpenAI calls and filesystem inputs at boundaries.
- Cover invalid configuration, denied approvals, command failures, redaction, JSON schemas and deterministic output.
- Any new remote or remediation capability needs explicit negative security tests.

## Pull request checklist
- [ ] Feature is backwards compatible or breaking change is documented.
- [ ] No credentials or sensitive production data are introduced.
- [ ] Human approval gates remain intact for write actions.
- [ ] Tests and compile checks pass.
- [ ] README, changelog and release metadata are consistent.
