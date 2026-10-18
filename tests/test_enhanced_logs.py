import json
from pathlib import Path
from typer.testing import CliRunner
from opsai.cli import app
from opsai.domain.triage import summarize
from opsai.infrastructure.logs import collect


def test_laravel_daily_log_fallback(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    logs = tmp_path / "storage" / "logs"
    logs.mkdir(parents=True)
    (logs / "laravel-2026-10-10.log").write_text("old\n")
    (logs / "laravel-2026-10-12.log").write_text("new\n")
    assert collect("laravel") == ["new"]


def test_laravel_single_file_preferred(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    logs = tmp_path / "storage" / "logs"
    logs.mkdir(parents=True)
    (logs / "laravel.log").write_text("single\n")
    (logs / "laravel-2026-10-12.log").write_text("daily\n")
    assert collect("laravel") == ["single"]


def test_timestamp_grouping():
    summary = summarize("laravel", [
        "[2026-10-12 12:00:00] production.ERROR: Connection failed for 123",
        "[2026-10-12 12:01:00] production.ERROR: Connection failed for 456",
    ])
    assert summary["top_errors"][0]["count"] == 2


def test_cli_nginx_json_redacts(tmp_path):
    log = tmp_path / "error.log"
    log.write_text("[error] upstream failed token=supersecret\n")
    result = CliRunner().invoke(app, ["logs", "nginx", "--path", str(log), "--json"])
    assert result.exit_code == 0, result.output
    assert json.loads(result.output)["error_lines"] == 1
    assert "supersecret" not in result.output
