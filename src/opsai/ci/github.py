"""Safe, offline GitHub Actions report formatting."""
from __future__ import annotations

import json
from pathlib import Path

SEVERITIES = ('critical', 'high', 'medium', 'low')


def validate_report(payload: object) -> dict:
    if not isinstance(payload, dict) or not isinstance(payload.get('findings'), list):
        raise ValueError('Expected an OpsAI security JSON report with findings array')
    if not isinstance(payload.get('errors', []), list):
        raise ValueError('Report errors must be an array')
    for item in payload['findings']:
        if not isinstance(item, dict) or item.get('severity') not in SEVERITIES:
            raise ValueError('Invalid finding severity or structure')
        for key in ('id', 'title', 'recommendation'):
            if not isinstance(item.get(key), str):
                raise ValueError(f'Finding {key} must be a string')
    return payload


def escape_command(value: str) -> str:
    """Prevent workflow-command and annotation injection."""
    return value.replace('%', '%25').replace('\r', '%0D').replace('\n', '%0A')


def annotations(report: dict) -> list[str]:
    lines = []
    for item in report['findings']:
        level = 'error' if item['severity'] in ('critical', 'high') else 'warning'
        title = escape_command(f"{item['severity'].upper()} {item['id']}")
        message = escape_command(f"{item['title']}: {item['recommendation']}")
        lines.append(f'::{level} title={title}::{message}')
    for err in report.get('errors', []):
        lines.append(f'::error title=OpsAI audit incomplete::{escape_command(str(err))}')
    return lines


def markdown_summary(report: dict) -> str:
    counts = {level: sum(f['severity'] == level for f in report['findings']) for level in SEVERITIES}
    status = 'Partial / failed' if report.get('errors') else 'Completed'
    rows = ['## OpsAI security audit', '', f'**Status:** {status}', '',
            '| Severity | Count |', '|---|---:|']
    rows.extend(f'| {level.capitalize()} | {counts[level]} |' for level in SEVERITIES)
    rows.extend(['', 'Findings are available in the uploaded JSON artifact.'])
    if report.get('errors'):
        rows.append('**Audit incomplete:** check workflow logs before trusting results.')
    return '\n'.join(rows) + '\n'


def gate_exit_code(report: dict, threshold: str) -> int:
    if threshold not in (*SEVERITIES, 'none'):
        raise ValueError('Invalid threshold')
    if report.get('errors') or report.get('status') == 'partial':
        return 2
    if threshold != 'none' and any(SEVERITIES.index(f['severity']) <= SEVERITIES.index(threshold)
                                   for f in report['findings']):
        return 3
    return 0


def publish_report(report_file: Path, summary_file: Path | None, threshold: str) -> tuple[list[str], int]:
    report = validate_report(json.loads(report_file.read_text(encoding='utf-8')))
    if summary_file is not None:
        # GitHub-provided path should be trusted only when supplied by the runner.
        with summary_file.open('a', encoding='utf-8') as stream:
            stream.write(markdown_summary(report))
    return annotations(report), gate_exit_code(report, threshold)
