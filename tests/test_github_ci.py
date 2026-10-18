import json
from pathlib import Path
from typer.testing import CliRunner
from opsai.cli import app
from opsai.ci.github import annotations, gate_exit_code, markdown_summary, publish_report, validate_report

runner = CliRunner()


def sample(severity='high'):
    return {'findings': [{'severity': severity, 'id': 'TEST', 'title': 'Issue', 'recommendation': 'Fix'}], 'errors': [], 'status': 'completed'}


def test_gate_high():
    assert gate_exit_code(sample(), 'high') == 3
    assert gate_exit_code(sample('medium'), 'high') == 0
    assert gate_exit_code(sample(), 'none') == 0


def test_gate_partial_always_fails():
    r = sample(); r['errors'] = ['docker unavailable']
    assert gate_exit_code(r, 'none') == 2


def test_annotation_escape():
    r = sample(); r['findings'][0]['title'] = 'bad\n::warning::injected%'
    output = annotations(r)
    assert len(output) == 1
    assert '%0A' in output[0] and '%25' in output[0]
    assert '\n' not in output[0]


def test_invalid_report():
    import pytest
    with pytest.raises(ValueError):
        validate_report({'findings': [{'severity': 'unknown'}]})


def test_summary():
    assert '| High | 1 |' in markdown_summary(sample())


def test_publish(tmp_path):
    report = tmp_path / 'audit.json'; summary = tmp_path / 'summary.md'
    report.write_text(json.dumps(sample()))
    lines, code = publish_report(report, summary, 'high')
    assert code == 3 and lines[0].startswith('::error')
    assert 'OpsAI security audit' in summary.read_text()


def test_cli_report(tmp_path):
    report = tmp_path / 'audit.json'; report.write_text(json.dumps(sample('low')))
    result = runner.invoke(app, ['github-report', '--report', str(report), '--fail-on', 'high', '--no-summary'])
    assert result.exit_code == 0
    assert '::warning' in result.output


def test_cli_bad_report(tmp_path):
    report = tmp_path / 'audit.json'; report.write_text('not json')
    result = runner.invoke(app, ['github-report', '--report', str(report), '--no-summary'])
    assert result.exit_code == 1
