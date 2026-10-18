"""Deterministic JSON and escaped standalone HTML reports for appsec findings."""
from __future__ import annotations

import html
import json
from typing import Any


def render_json(report: dict[str, Any]) -> str:
    return json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False)


def render_html(report: dict[str, Any]) -> str:
    findings = report.get('findings', [])
    if not isinstance(findings, list):
        raise ValueError('Assessment findings must be an array')

    rows: list[str] = []
    for finding in findings:
        if not isinstance(finding, dict):
            raise ValueError('Assessment findings must contain objects')
        owasp = finding.get('owasp', {})
        if not isinstance(owasp, dict):
            raise ValueError('Finding OWASP classification must be an object')
        severity = str(finding.get('severity', 'unknown')).lower()
        rows.append(
            '<tr>'
            f'<td><span class="severity {html.escape(severity, quote=True)}">{html.escape(severity)}</span></td>'
            f'<td>{html.escape(str(finding.get("id", "")))}</td>'
            f'<td><strong>{html.escape(str(finding.get("title", "")))}</strong>'
            f'<p>{html.escape(str(finding.get("evidence", "")))}</p></td>'
            f'<td>{html.escape(str(owasp.get("id", "")))} '
            f'{html.escape(str(owasp.get("title", "")))}</td>'
            f'<td>{html.escape(str(finding.get("recommendation", "")))}</td>'
            '</tr>'
        )
    if not rows:
        rows.append('<tr><td colspan="5">No findings were reported by the selected checks.</td></tr>')

    counts = report.get('counts', {})
    if not isinstance(counts, dict):
        raise ValueError('Assessment counts must be an object')
    count_text = ' · '.join(
        f'{html.escape(str(level).capitalize())}: {html.escape(str(counts.get(level, 0)))}'
        for level in ('critical', 'high', 'medium', 'low', 'unknown')
    )
    errors = report.get('errors', [])
    if not isinstance(errors, list):
        raise ValueError('Assessment errors must be an array')
    error_section = ''
    if errors:
        rendered_errors = ''.join(f'<li>{html.escape(str(error))}</li>' for error in errors)
        error_section = f'<section class="errors"><h2>Incomplete checks</h2><ul>{rendered_errors}</ul></section>'

    project_name = html.escape(str(report.get('project', 'Laravel project')))
    status = html.escape(str(report.get('status', 'unknown')).capitalize())
    owasp_version = html.escape(str(report.get('owasp_version', '2025')))
    return f'''<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>OpsAI application security assessment</title>
  <style>
    :root {{ color-scheme: light; font-family: system-ui, sans-serif; color: #172033; background: #f3f5f8; }}
    body {{ margin: 0; padding: 2rem; }}
    main {{ max-width: 1200px; margin: auto; background: white; padding: 2rem; border-radius: 14px; box-shadow: 0 8px 30px #18253a16; }}
    h1 {{ margin-bottom: .25rem; }} .meta, .counts {{ color: #586579; }}
    .counts {{ padding: 1rem; background: #f3f5f8; border-radius: 8px; }}
    table {{ width: 100%; border-collapse: collapse; margin-top: 1.5rem; }}
    th, td {{ padding: .8rem; border-bottom: 1px solid #dce1e8; text-align: left; vertical-align: top; }}
    th {{ background: #202837; color: white; }} td p {{ margin: .5rem 0 0; color: #586579; }}
    .severity {{ display: inline-block; padding: .2rem .5rem; border-radius: 5px; font-weight: 700; text-transform: uppercase; }}
    .critical {{ color: #8b1020; background: #ffe1e5; }} .high {{ color: #963b00; background: #ffeadb; }}
    .medium {{ color: #765300; background: #fff2c2; }} .low {{ color: #155c3e; background: #dff6e9; }}
    .unknown {{ color: #39465a; background: #e6eaf0; }} .errors {{ margin-top: 1.5rem; color: #8b1020; }}
    footer {{ margin-top: 2rem; font-size: .9rem; color: #586579; }}
    @media print {{ body {{ padding: 0; background: white; }} main {{ box-shadow: none; }} }}
  </style>
</head>
<body>
<main>
  <h1>OpsAI application security assessment</h1>
  <p class="meta">Project: {project_name} · Status: {status} · OWASP Top 10:{owasp_version}</p>
  <p class="counts">{count_text}</p>
  <table>
    <thead><tr><th>Severity</th><th>Finding</th><th>Evidence</th><th>OWASP category</th><th>Recommendation</th></tr></thead>
    <tbody>{''.join(rows)}</tbody>
  </table>
  {error_section}
  <footer>Static, offline assessment. Findings are indicators for review, not proof of exploitability or a complete security audit.</footer>
</main>
</body>
</html>
'''
