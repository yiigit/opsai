import json
from pathlib import Path
from unittest.mock import patch

import pytest
from typer.testing import CliRunner
from opsai.cli import app
from opsai.logs import collect, redact, summarize

runner = CliRunner()


def test_redaction():
    s = redact('Authorization: Bearer abc123 password=secret token=abc email=a@b.com ip=192.168.1.1')
    for secret in ('abc123', 'password=secret', 'token=abc', 'a@b.com', '192.168.1.1'):
        assert secret not in s


def test_nginx_collection_and_summary(tmp_path):
    p = tmp_path / 'error.log'
    p.write_text('notice started\n[error] upstream timed out\n[error] upstream timed out\n')
    summary = summarize('nginx', collect('nginx', path=p, lines=2))
    assert summary['total_lines'] == 2
    assert summary['error_lines'] == 2
    assert summary['top_errors'][0]['count'] == 2


def test_laravel_json_cli(tmp_path):
    p = tmp_path / 'laravel.log'
    p.write_text('[2026-10-12] production.ERROR: QueryException password=hunter2\n')
    result = runner.invoke(app, ['logs', 'laravel', '--path', str(p), '--json'])
    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    assert data['error_lines'] == 1
    assert 'hunter2' not in result.output


def test_linux_journal(monkeypatch):
    class Result:
        stdout = 'first\nsecond\n'
    monkeypatch.setattr('opsai.logs.shutil.which', lambda _: '/usr/bin/journalctl')
    def fake_run(args, **kwargs):
        assert args[:3] == ['journalctl', '--no-pager', '--output=short-iso']
        return Result()
    monkeypatch.setattr('opsai.logs.subprocess.run', fake_run)
    assert collect('linux', lines=2, unit='ssh') == ['first', 'second']


def test_invalid_unit():
    with pytest.raises(ValueError):
        collect('linux', unit='ssh;rm -rf /')


def test_ai_requires_confirmation(tmp_path):
    p = tmp_path / 'nginx.log'
    p.write_text('error test\n')
    result = runner.invoke(app, ['logs', 'nginx', '--path', str(p), '--ai'], input='n\n')
    assert result.exit_code == 0
    assert 'Continue?' in result.output


def test_ai_mocked(tmp_path, monkeypatch):
    p = tmp_path / 'nginx.log'
    p.write_text('error upstream timeout\n')
    monkeypatch.setattr('opsai.infrastructure.adapters.analyze_logs', lambda data: 'Investigate upstream')
    result = runner.invoke(app, ['logs', 'nginx', '--path', str(p), '--ai', '--yes', '--json'])
    assert result.exit_code == 0, result.output
    assert json.loads(result.output)['ai_analysis'] == 'Investigate upstream'
