# OpsAI CLI — Advanced Linux & Network Diagnostics

Advanced, read-only Linux and network diagnostics, alongside Nginx/Laravel log
analysis, SSH monitoring, Docker and application-security audits, and optional
AI-assisted troubleshooting.

OpsAI is designed for operators who need a quick terminal view or deterministic
JSON for automation. Collection and audits do not change system configuration.
AI-assisted analysis is optional and requires consent before evidence is sent to
OpenAI.

**Current release: v1.0.0.** The first public release was v0.9.0.

## Contents

- [Install](#install)
- [Terminal themes](#terminal-themes)
- [Command guide](#command-guide)
- [Log analysis](#log-analysis)
- [SSH monitoring](#ssh-monitoring)
- [Security audits](#security-audits)
- [Application security assessment](#application-security-assessment)
- [Incident investigation](#incident-investigation)
- [GitHub Actions](#github-actions)
- [Architecture and development](#architecture-and-development)
- [Contributing](#contributing)
- [Semantic versioning and releases](#semantic-versioning-and-releases)

## Install

### Ubuntu and Debian package

The release workflow publishes amd64 `.deb` packages for Python 3.10, 3.11,
3.12 and 3.13. The package installer targets Ubuntu/Debian and requires `curl`,
`dpkg`, `apt-get`, and Python 3.10–3.13. For a private GitHub repository,
provide a token with read access to repository releases:

```bash
read -rsp "GitHub token: " GH_TOKEN
export GH_TOKEN
echo
./install.sh
opsai --version
```

To check for and install a newer stable release:

```bash
./update.sh
```

To remove the package and its package-managed files:

```bash
./uninstall.sh
```

`install.sh` and `update.sh` download the latest stable release package matching
the system Python version and amd64 architecture, then install it with `apt-get`.
`update.sh` skips installation when the current version is already at least as
new as the latest stable release. `uninstall.sh` purges the `opsai-cli` Debian
package. Installation, update, and removal require root privileges; the scripts
use `sudo` when needed. The package bundles Python dependencies and requires no
network access during package configuration. Do not put access tokens directly
in shell commands or commit them to files.

Set `OPSAI_REPOSITORY=OWNER/REPOSITORY` to use a different GitHub repository.

### Install from source

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
pytest -q
```

`opsai --version` prints the installed package version. Source installation is
useful for development; the diagnostics themselves are designed primarily for
Linux hosts. The macOS terminal theme is a color palette, not an installer or a
claim that Linux-specific collection features work on macOS.

## Terminal themes

Choose a Rich color palette with the global `--theme` option. It must appear
before the command. Ubuntu styling is the default; macOS selects a blue/purple
palette and Ubuntu selects an orange/plum palette.

```bash
opsai --theme ubuntu status
opsai --theme macos security all
```

![OpsAI system status in the Ubuntu terminal theme](docs/images/status-ubuntu.svg)

*Sample `status` output with fixed example metrics (not a live host reading).*

![OpsAI system status in the macOS terminal theme](docs/images/status-macos.svg)

*The same command output using the macOS-inspired palette.*

The themes change terminal styling only; they do not indicate that a command is
specific to either operating system. `--json` output is intended for scripts
and has no theme styling.

## Command guide

### Linux and network diagnostics

`opsai system` groups detailed host diagnostics under a single command:

| Command | Function |
| --- | --- |
| `opsai system health` | Complete system health assessment with partial-result errors |
| `opsai system cpu` | CPU utilization, per-core sampling, frequency, and load averages |
| `opsai system memory` | RAM, swap, and Linux memory-pressure data |
| `opsai system disk` | Filesystem capacity and cumulative disk I/O |
| `opsai system processes` | Top resource-intensive processes (no command-line arguments collected) |
| `opsai system services` | Failed systemd units |
| `opsai system boot` | Boot duration and slow-starting systemd units |
| `opsai system journal` | Recent error-level journal entries with best-effort redaction |
| `opsai system updates` | Cached Debian/Ubuntu or DNF security-update checks |
| `opsai system network` | Interfaces, addresses, default routes, and DNS configuration |
| `opsai system troubleshoot` | Collect diagnostics and optionally request AI suggestions |

Use `--json` with any system command for machine-readable output. Update checks
do not refresh repository metadata; results may reflect stale local caches.
Systemd commands require systemd and suitable journal permissions. Network
inspection is local by default. An active TCP probe only runs when both an
explicit `--host` and `--port` are provided:

```bash
opsai system health --json
opsai system network --host example.com --port 443
opsai system troubleshoot --ai
```

`--ai` requires consent before sending diagnostics to OpenAI unless `--yes` is
provided. The payload can include process names, local network addresses, and
redacted journal messages. AI suggestions are advisory; OpsAI does not execute
them.

The earlier `opsai status` command remains available for a quick CPU, memory,
and root-filesystem summary.

```bash
opsai --help                         # list commands and options
opsai --version                      # print the installed version
opsai --theme macos status           # select a theme globally
opsai system health --json           # detailed Linux system report
opsai status                         # CPU, memory, and disk summary
opsai status --json                  # machine-readable local metrics
opsai docker                         # list running containers
opsai docker --json
opsai analyze                        # ask AI about local system metrics
opsai logs linux --unit nginx        # read a systemd journal unit
opsai logs nginx --path /var/log/nginx/error.log
opsai logs laravel --path storage/logs/laravel.log
opsai ssh --inventory inventory.json # read-only remote health checks
opsai security all --json            # local Linux and Docker checks
opsai appsec --project ./laravel --osv-db ./osv-packagist.json --format html --output appsec.html
opsai incident --evidence incident.example.json
opsai github-report --report security.json
```

Commands that use system services or Docker require their local tools and
permissions. Remote SSH checks require OpenSSH, configured key-based access,
and host keys already trusted in `~/.ssh/known_hosts`.

## Log analysis

`opsai logs` supports three sources:

| Source | Default input | Example |
| --- | --- | --- |
| `linux` | systemd journal for the selected unit (default `nginx`) | `opsai logs linux --unit nginx --lines 100` |
| `nginx` | `/var/log/nginx/error.log` | `opsai logs nginx --path ./error.log` |
| `laravel` | Laravel application log | `opsai logs laravel --path storage/logs/laravel.log` |

`--path` overrides the file path for Nginx and Laravel. Laravel also recognizes
daily `laravel-YYYY-MM-DD.log` logs. `--lines` is bounded to 1–300 and limits
collected input. Repeated errors are grouped across varying timestamps and
numeric identifiers.

Add `--json` for machine-readable summaries or `--ai` for optional OpenAI
analysis. AI analysis sends a bounded, best-effort redacted summary only after
interactive confirmation; `--yes` acknowledges the transfer without prompting.
Redaction cannot guarantee removal of every secret, so review logs before
approving transfer. `OPENAI_API_KEY` must be configured for AI use. Tests mock
the API and do not require a network connection.

## SSH monitoring

SSH monitoring reads a JSON inventory and runs a fixed set of read-only
commands (`uptime`, `free`, `df`, and `/proc/loadavg`) through OpenSSH. It uses
key-based authentication, batch mode, strict host-key checking, bounded
timeouts/output, and deterministic result ordering.

```bash
cp inventory.example.json inventory.json
# Edit inventory.json with your hosts and SSH user.
opsai ssh --inventory inventory.json
opsai ssh --inventory inventory.json --workers 4 --timeout 12 --json
opsai ssh --inventory inventory.json --ai
```

Workers are limited to 1–16 and the per-host timeout to 1–120 seconds. Exit
code `1` indicates invalid inventory/configuration; `2` indicates one or more
hosts failed. With `--ai`, summarized remote output is sent only after consent
(or `--yes`); review data and redact sensitive details first.

## Security audits

The local security audit checks selected Linux configuration permissions and
SSH directives, and running Docker containers for risky configuration. It is
read-only and does not remediate findings.

```bash
opsai security linux
opsai security docker
opsai security all --json
opsai security docker --fail-on critical --json
```

Linux checks inspect `/etc/shadow` and `/etc/ssh/sshd_config` permissions and
explicit SSH root/password-login directives. This is a **limited configuration
audit**, not a complete hardening assessment: SSH `Include` files and effective
`sshd -T` settings are not evaluated. Missing or inaccessible files are skipped.

Docker checks running containers for privileged mode, host networking, host
PID namespace, writable root filesystems, root users, and host-root or
Docker-socket mounts. This is **not a CVE image scanner**; use Trivy or Grype
for image vulnerability scanning. Docker daemon access is privileged, so grant
it only to trusted operators.

Choose `linux`, `docker`, or `all` as the target. `--fail-on` accepts
`critical`, `high`, `medium`, `low`, or `none` (default `high`). Exit codes are
`0` no findings meet the selected threshold, `1` invalid arguments, `2`
collection errors/partial report, and `3` threshold reached. JSON includes
structured findings and recommendations for CI pipelines.

The audit may require Linux file access and Docker daemon access. Unit tests
mock Docker calls and do not require root or a running daemon.

## Application security assessment

`opsai appsec` performs a local, offline assessment of a Laravel project and,
when provided a local advisory snapshot, its Composer dependencies:

```bash
opsai appsec --project ./my-laravel-app \
  --osv-db ./osv-packagist.json \
  --format json --output appsec-report.json --fail-on high

opsai appsec --project ./my-laravel-app \
  --osv-db ./osv-packagist.json \
  --format html --output appsec-report.html --fail-on none
```

The Laravel checks inspect selected `.env` settings and file permissions:
production debug mode, a missing or placeholder production `APP_KEY`, insecure
session-cookie settings, and group/other-readable `.env` permissions. The
assessment never includes `.env` values in its findings. These static checks
do not evaluate the effective Laravel configuration, runtime middleware,
authorization policies, or application source code.

When `composer.lock` exists, provide `--osv-db` to match locked `Packagist`
package versions against a **local JSON OSV snapshot**. No snapshot is bundled;
create or refresh a project-specific snapshot explicitly with:

```bash
opsai osv-refresh \
  --composer-lock ./my-laravel-app/composer.lock \
  --output ./osv-packagist.json
```

The command asks for confirmation before sending package names and exact locked
versions to `api.osv.dev`. Add `--yes` only when that data transfer and replacing
an existing output file are approved. The refresh only queries the package
versions in the supplied lockfile; it is not a full Packagist vulnerability
database. Once saved, `opsai appsec` reads the snapshot locally and does not
make network requests. The snapshot has the OSV `vulns` array shape; it can
also be produced or updated by another trusted source. For a Laravel-only
check, explicitly pass `--skip-dependencies`; dependency matching requires
both `composer.lock` and `--osv-db`. Unsupported version syntax or range types
(including OSV ecosystem-specific ranges not supported by the current SemVer
comparator) are reported as incomplete checks rather than treated as a clean
scan. Exact affected-version entries and OSV `SEMVER` ranges are supported.
A refresh reporting zero advisories means OSV.dev returned no matches for the
queried package versions; the resulting empty snapshot is not a complete
Packagist database and does not prove those dependencies are vulnerability-free.

For example, a local snapshot can contain a Packagist advisory like:

```json
{
  "vulns": [{
    "id": "OSV-EXAMPLE",
    "database_specific": {"severity": "HIGH"},
    "affected": [{
      "package": {"ecosystem": "Packagist", "name": "vendor/package"},
      "ranges": [{
        "type": "SEMVER",
        "events": [{"introduced": "1.2.0"}, {"fixed": "1.2.5"}]
      }]
    }]
  }]
}
```

Findings are classified against the [OWASP Top 10:2025](https://top10.owasp.org/2025/)
taxonomy, with deterministic checks currently covering security
misconfiguration, cryptographic failures, and software supply-chain failures.
Severity comes from the local advisory data when available; unknown severity
makes a threshold-gated result incomplete.
JSON is the default output; `--format html --output FILE` writes a standalone,
escaped HTML report. Exit code `0` means the selected threshold was not
reached, `1` indicates invalid input or an assessment error, `2` indicates
incomplete checks or unknown severity under a threshold, and `3` indicates a
finding at or above the selected threshold.

This is a focused static assessment, not an OWASP certification, complete
Laravel review, or substitute for dynamic testing and human security review.

## Troubleshooting

- **Docker reports a connection error:** confirm Docker is installed and the
  current user can access the daemon. OpsAI does not start or modify Docker.
- **Linux log collection is empty or unavailable:** `logs linux` reads the
  systemd journal. Check that `journalctl` is installed and the user can read
  the requested unit's journal.
- **SSH hosts fail:** verify the inventory, SSH key permissions, network reachability,
  and trusted host keys. OpsAI deliberately uses strict host-key checking; it
  does not bypass an unknown or changed host key.
- **AI analysis fails:** configure `OPENAI_API_KEY` in the environment and check
  the provider/network separately. AI use remains optional.
- **Debian install cannot find a release:** use a stable published tag, check
  the host Python version and amd64 architecture, and ensure the token has
  repository read access. The installer does not install from a development
  branch or create a GitHub release.

## Security and privacy notes

OpsAI is a diagnostic assistant, not a complete security scanner or compliance
certification tool. Review findings in the context of your operating-system
baseline. Treat logs, inventories, audit reports, and AI responses as sensitive
input: do not commit real host inventories, production logs, generated audit
reports, or credentials. AI suggestions are hypotheses for operator review,
not verified root causes. Audit and collection commands are read-only; the
incident command's optional local action is a separate, explicitly approved
exception.

## Incident investigation

Provide an evidence JSON file containing a `source` and `logs` list:

```json
{
  "source": "nginx",
  "logs": ["nginx failed to start"]
}
```

Then run the deterministic investigation:

```bash
opsai incident --evidence incident.example.json
opsai incident --evidence incident.example.json --json
opsai incident --evidence incident.example.json --ai
```

The rule engine may recommend a narrowly allowlisted local service action when
evidence matches. AI output is advisory and cannot create executable actions.
An action runs only when the operator supplies `--action`, `--execute`, and
types the exact interactive approval phrase. This is a demonstration approval
gate, not a production authorization system; use change control and appropriate
access controls. The optional action changes the **local** host and may require
elevated privileges. `--yes` confirms AI data transfer only; it never approves
an action.

## GitHub Actions

The CI workflow tests supported Python versions, runs local audits, publishes
annotations and a job summary, builds Python distributions and Debian packages,
and uploads artifacts. A separate weekly security workflow scans source with
Bandit and checks installed dependencies with `pip-audit`. These workflows do
not need OpenAI credentials or SSH secrets.

Run locally:

```bash
python -m pip install -e '.[dev]'
pytest -q
opsai security all --json --fail-on none > security.json
opsai github-report --report security.json --fail-on high --no-summary
python -m build
```

`github-report` exit codes are `0` pass, `1` invalid input, `2` incomplete
audit, and `3` severity threshold reached. The CI runner's audit output reflects
that ephemeral runner, not your production infrastructure; the Docker checks
are not image CVE scanning. Use trusted pull requests and avoid exposing secrets
to untrusted workflow code.

## Architecture and development

- `src/opsai/domain/`: models, interfaces, and pure validation/classification.
- `src/opsai/application/`: use cases and orchestration through protocols.
- `src/opsai/infrastructure/`: local collectors, OpenSSH, Docker, and OpenAI.
- `src/opsai/security/`: read-only audit checks and structured findings.
- `src/opsai/cli.py`: Typer commands, Rich presentation, and consent handling.

Install a development environment and run the test suite:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev]'
python -m pytest -q
python -m compileall -q src
opsai --help
```

Tests mock subprocess, OpenAI, and filesystem boundaries; they do not require
root, Docker, remote hosts, production logs, or a live API key.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, tests, safety
expectations, and pull request guidance.

## Semantic versioning and releases

The package version is the single source of truth in `pyproject.toml` (PEP 621).
Commitizen uses Conventional Commits and writes `CHANGELOG.md`.

```bash
pip install -e '.[dev]'
git init                         # only for a new checkout; omit in an existing repository

git add -i                        # review and select project files; exclude local evidence and secrets
git commit -m 'chore: initialize opsai 0.9.0'
git tag v0.9.0                  # first public release
# On future changes:
git commit -m 'feat: add Docker log collector'
git commit -m 'fix: handle missing log file'
cz bump --dry-run
cz bump                         # updates pyproject, changelog, commit and tag
git push origin main --follow-tags
```

`feat:` increments MINOR, `fix:` increments PATCH, and `BREAKING CHANGE:` marks a breaking change. With `major_version_zero = true`, breaking changes before 1.0 follow Commitizen's 0.x behavior; review each bump before release. Use `cz commit` for an interactive commit wizard, or `cz check --rev-range BASE..HEAD` to validate a range.

`.github/workflows/commitlint.yml` checks PR commit messages. The existing `ci.yml` runs tests and audits. `.github/workflows/release.yml` runs on version tags, validates tag-to-package consistency, runs tests, builds distributions, and publishes GitHub Release assets. The release workflow requires repository Actions write permissions and a tag pushed after the version bump. Avoid automatic release of unreviewed code; use protected main branch and controlled tag creation.

## AI coding agent instructions

See [`AGENT.md`](AGENT.md) (also available as [`AGENTS.md`](AGENTS.md) for tools that recognize that convention). Version `0.9.0` was the first public release; earlier internal milestones were not public releases.
