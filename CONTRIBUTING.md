# Contributing to OpsAI CLI

Thanks for helping improve OpsAI CLI. For substantial changes, open an issue
first to discuss the scope and intended behavior.

## Development setup

OpsAI CLI supports Python 3.10 and newer. Create an environment and install the
development dependencies:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev]'
```

Before submitting changes, run:

```bash
python -m pytest -q
python -m compileall -q src
opsai --help
```

Tests should be deterministic and must not require root, Docker, remote hosts,
production logs, or network/API access. Mock external boundaries such as
subprocesses, OpenAI calls, SSH, and filesystem inputs where appropriate.

## Code and safety expectations

- Keep domain logic pure and put I/O behind application or infrastructure
  boundaries.
- Use small, typed functions, explicit errors, and predictable JSON output.
- Preserve read-only behavior by default. Any write or remediation action must
  be narrowly scoped and require explicit human approval.
- Do not run arbitrary shell commands suggested by an AI model.
- Treat logs, inventories, reports, and AI output as untrusted data. Do not
  commit credentials, private keys, production logs, or real inventories.
- Keep application-security assessment offline by default. Any advisory-data
  refresh must be explicit and disclose what data is sent externally.
- Do not present AI-generated hypotheses as verified root causes.

## Commits and pull requests

Use Conventional Commit messages, for example:

```text
feat(logs): support multiline Laravel exceptions
fix(ssh): handle connection timeout
test(security): cover privileged containers
docs: clarify incident approval requirements
```

Keep changes focused, add tests for success and failure paths, and update
related user documentation and the changelog. Pull requests should describe
user-visible behavior, safety implications, and the validation performed.
Never claim production SSH, Docker, or live AI validation when only mocks were
used.

See [RELEASING.md](docs/RELEASING.md) for release procedures.
