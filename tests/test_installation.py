import subprocess
from importlib.metadata import version
from pathlib import Path

import pytest
from typer.testing import CliRunner

from opsai import cli
from opsai.cli import app

ROOT = Path(__file__).resolve().parents[1]


def test_version_option_displays_installed_version():
    result = CliRunner().invoke(app, ["--version"])

    assert result.exit_code == 0
    assert result.stdout.strip() == f"OpsAI CLI {version('opsai-cli')}"


def test_installation_scripts_have_valid_bash_syntax():
    scripts = [
        ROOT / "install.sh",
        ROOT / "update.sh",
        ROOT / "uninstall.sh",
        ROOT / "scripts" / "build_deb.sh",
        ROOT / "scripts" / "lib" / "release.sh",
    ]

    for script in scripts:
        subprocess.run(["bash", "-n", str(script)], check=True)


@pytest.mark.parametrize("theme", ["macos", "ubuntu"])
def test_status_supports_terminal_themes(monkeypatch, theme):
    monkeypatch.setattr(cli, "health", lambda: {"cpu_percent": 12.5})

    result = CliRunner().invoke(app, ["--theme", theme, "status"])

    assert result.exit_code == 0
    assert "System health" in result.stdout
    assert "cpu_percent" in result.stdout


def test_theme_option_rejects_unknown_theme():
    result = CliRunner().invoke(app, ["--theme", "windows", "status"])

    assert result.exit_code == 2
