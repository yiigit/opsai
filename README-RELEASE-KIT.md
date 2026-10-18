# OpsAI GitHub Release Kit v0.9.0

This is an **overlay** for the existing OpsAI repository, not a complete OpsAI source distribution. It contains GitHub Actions, Dependabot, security and contribution policies, and release documentation. It has not been tested against the user's actual repository.

Copy the kit files into your repository, review all changes, and follow `docs/RELEASING.md`. **Do not overwrite existing customized files without merging them.** No `pyproject.toml` is included because the existing package configuration must be preserved.

Requirements: Python package with static `[project].version`, `src/` package, pytest tests, and an existing build backend. If your project uses dynamic versions or a different layout, adapt the workflows before tagging.
