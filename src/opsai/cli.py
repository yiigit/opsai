import json
from enum import Enum
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console, Theme
from rich.table import Table

from opsai.collectors import docker_status, health

app = typer.Typer(help='OpsAI: read-only DevOps diagnostics', no_args_is_help=True)


class OutputTheme(str, Enum):
    MACOS = 'macos'
    UBUNTU = 'ubuntu'


THEMES = {
    OutputTheme.MACOS: Theme({
        'accent': 'bold #0A84FF',
        'table.header': 'bold #0A84FF',
        'table.border': '#5E5CE6',
        'error': 'bold #FF453A',
        'warning': '#FF9F0A',
        'success': '#30D158',
        'json.key': '#64D2FF',
        'json.str': '#30D158',
    }),
    OutputTheme.UBUNTU: Theme({
        'accent': 'bold #E95420',
        'table.header': 'bold #E95420',
        'table.border': '#77216F',
        'error': 'bold #C01C28',
        'warning': '#C47F00',
        'success': '#4E9A06',
        'json.key': '#77216F',
        'json.str': '#4E9A06',
    }),
}
console = Console(theme=THEMES[OutputTheme.UBUNTU])


def _show_version(value: bool) -> None:
    if not value:
        return
    try:
        installed_version = version('opsai-cli')
    except PackageNotFoundError:
        from opsai import __version__

        installed_version = __version__
    typer.echo(f'OpsAI CLI {installed_version}')
    raise typer.Exit()


@app.callback()
def main(
    theme: OutputTheme = typer.Option(
        OutputTheme.UBUNTU,
        '--theme',
        help='Terminal color theme: macos or ubuntu.',
    ),
    version_option: bool = typer.Option(
        False,
        '--version',
        callback=_show_version,
        is_eager=True,
        help='Show the installed version and exit.',
    ),
):
    """OpsAI: read-only DevOps diagnostics."""
    global console
    console = Console(theme=THEMES[theme])


@app.command()
def status(json_output: bool = typer.Option(False, '--json', help='Machine-readable output')):
    """Show current CPU, RAM and disk utilization."""
    metrics = health()
    if json_output:
        typer.echo(json.dumps(metrics, indent=2))
        return
    table = Table(
        title='System health',
        title_style='accent',
        style='accent',
        border_style='table.border',
        header_style='table.header',
    )
    table.add_column('Metric')
    table.add_column('Value', justify='right')
    for key, value in metrics.items():
        table.add_row(key, str(value))
    console.print(table)


@app.command('docker')
def docker_command(json_output: bool = typer.Option(False, '--json')):
    """List running Docker containers (read-only)."""
    try:
        containers = docker_status()
    except RuntimeError as exc:
        console.print(f'[error]Error:[/error] {exc}')
        raise typer.Exit(code=1)
    if json_output:
        typer.echo(json.dumps(containers, indent=2))
        return
    table = Table(
        title='Running containers',
        title_style='accent',
        style='accent',
        border_style='table.border',
        header_style='table.header',
    )
    for field in ('Names', 'Image', 'Status', 'Ports'):
        table.add_column(field)
    for item in containers:
        table.add_row(*(str(item.get(field, '')) for field in ('Names', 'Image', 'Status', 'Ports')))
    console.print(table)


@app.command()
def analyze(
    input_file: Optional[Path] = typer.Option(None, '--input', help='JSON metrics file'),
    yes: bool = typer.Option(False, '--yes', help='Confirm sending metrics to AI'),
):
    """Ask AI to interpret sanitized metrics (requires API key)."""
    try:
        metrics = json.loads(input_file.read_text()) if input_file else health()
        if not isinstance(metrics, dict):
            raise ValueError('Input JSON must be an object')
        if not yes:
            console.print('[warning]Metrics will be sent to the OpenAI API. Remove sensitive data first.[/warning]')
            if not typer.confirm('Continue?'):
                raise typer.Exit(code=0)
        from opsai.ai import analyze as run_analysis
        console.print(run_analysis(metrics))
    except (OSError, ValueError, RuntimeError) as exc:
        console.print(f'[error]Error:[/error] {exc}')
        raise typer.Exit(code=1)


@app.command('logs')
def logs_command(
    source: str = typer.Argument(..., help='linux, nginx or laravel'),
    path: Optional[Path] = typer.Option(None, '--path', help='Override log path'),
    unit: str = typer.Option('nginx', '--unit', help='Linux systemd unit'),
    lines: int = typer.Option(100, '--lines', min=1, max=300),
    json_output: bool = typer.Option(False, '--json'),
    ai: bool = typer.Option(False, '--ai', help='Send redacted summary to OpenAI'),
    yes: bool = typer.Option(False, '--yes', help='Confirm AI data transfer'),
):
    """Inspect Linux, Nginx or Laravel logs, optionally using AI."""
    from opsai.application.log_analysis import LogAnalysisService
    from opsai.infrastructure.adapters import LocalLogCollector, OpenAILogAnalyzer
    try:
        service = LogAnalysisService(LocalLogCollector(), OpenAILogAnalyzer() if ai else None)
        result = service.run(source, lines=lines, path=path, unit=unit, ai=False)
        summary = result
        if ai:
            if not yes:
                typer.echo('A best-effort redacted log summary will be sent to OpenAI. Review for secrets first.')
                if not typer.confirm('Continue?'):
                    return
            result = service.analyze_summary(summary)
            if json_output:
                typer.echo(json.dumps({'summary': summary, 'ai_analysis': result}, indent=2))
            else:
                console.print_json(data=summary)
                console.print('\n[accent]AI assessment[/accent]')
                console.print(result)
        elif json_output:
            typer.echo(json.dumps(summary, indent=2))
        else:
            console.print_json(data={k: v for k, v in summary.items() if k != 'sample'})
            console.print('\n[accent]Recent log lines (redacted)[/accent]')
            for line in summary['sample'][-10:]:
                console.print(line, markup=False, highlight=False)
    except (OSError, ValueError, RuntimeError) as exc:
        typer.echo(f'Error: {exc}', err=True)
        raise typer.Exit(code=1)



@app.command('ssh')
def ssh_command(
    inventory: Path = typer.Option(..., '--inventory', '-i', help='JSON server inventory'),
    workers: int = typer.Option(4, '--workers', min=1, max=16),
    timeout: int = typer.Option(12, '--timeout', min=1, max=120),
    json_output: bool = typer.Option(False, '--json'),
    ai: bool = typer.Option(False, '--ai', help='AI assessment of redacted monitoring output'),
    yes: bool = typer.Option(False, '--yes', help='Confirm sending monitoring data to OpenAI'),
):
    """Read-only SSH health checks across inventory servers."""
    from opsai.infrastructure.ssh import load_inventory, SSHRunner
    from opsai.application.remote_monitoring import RemoteMonitoringService
    from opsai.domain.triage import summarize
    try:
        servers = load_inventory(inventory)
        results = RemoteMonitoringService(SSHRunner(timeout)).check(servers, workers)
        payload = {'servers': results, 'total': len(results),
                   'healthy': sum(r['status'] == 'ok' for r in results)}
        if ai:
            if not yes:
                typer.echo('Redacted remote system output will be sent to OpenAI. Review for sensitive data.')
                if not typer.confirm('Continue?'):
                    return
            from opsai.infrastructure.openai import analyze_logs
            # Only bounded, redacted monitoring data is passed to the existing AI adapter.
            payload['ai_analysis'] = analyze_logs(summarize('remote-ssh', [
                r['name'] + ': ' + (r.get('output') or r.get('error', '')) for r in results
            ]))
        if json_output:
            typer.echo(json.dumps(payload, indent=2))
        else:
            table = Table(
                title='Remote SSH monitoring',
                title_style='accent',
                style='accent',
                border_style='table.border',
                header_style='table.header',
            )
            for column in ('Server', 'Status', 'Result'):
                table.add_column(column)
            for result in results:
                table.add_row(result['name'], result['status'],
                              (result.get('output') or result.get('error', ''))[:500])
            console.print(table)
            if ai:
                console.print('\n[accent]AI assessment[/accent]')
                console.print(payload['ai_analysis'])
        if payload['healthy'] != payload['total']:
            raise typer.Exit(code=2)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        typer.echo(f'Error: {exc}', err=True)
        raise typer.Exit(code=1)


@app.command('security')
def security_command(
    target: str = typer.Argument('all', help='linux, docker or all'),
    json_output: bool = typer.Option(False, '--json'),
    fail_on: str = typer.Option('high', '--fail-on', help='critical, high, medium, low or none'),
):
    """Perform read-only local Docker and Linux security checks."""
    from opsai.security.audit import audit_docker, audit_linux, report
    if target not in ('linux', 'docker', 'all'):
        typer.echo('Target must be linux, docker or all', err=True)
        raise typer.Exit(code=1)
    if fail_on not in ('critical', 'high', 'medium', 'low', 'none'):
        typer.echo('Invalid --fail-on severity', err=True)
        raise typer.Exit(code=1)
    findings = []
    errors = []
    if target in ('linux', 'all'):
        try:
            findings.extend(audit_linux())
        except (OSError, RuntimeError, ValueError) as exc:
            errors.append(f'Linux audit: {exc}')
    if target in ('docker', 'all'):
        try:
            findings.extend(audit_docker())
        except (OSError, RuntimeError, ValueError) as exc:
            errors.append(f'Docker audit: {exc}')
    payload = report(target, findings, errors)
    if json_output:
        typer.echo(json.dumps(payload, indent=2))
    else:
        table = Table(
            title=f'DevSecOps security audit: {target}',
            title_style='accent',
            style='accent',
            border_style='table.border',
            header_style='table.header',
        )
        for column in ('Severity', 'Check', 'Finding', 'Recommendation'):
            table.add_column(column)
        for finding in findings:
            table.add_row(finding.severity, finding.id, finding.title, finding.recommendation)
        console.print(table)
        for error in errors:
            typer.echo(f'Warning: {error}', err=True)
    levels = ('critical', 'high', 'medium', 'low')
    if errors:
        raise typer.Exit(code=2)
    if fail_on != 'none' and any(levels.index(f.severity) <= levels.index(fail_on) for f in findings):
        raise typer.Exit(code=3)


@app.command('appsec')
def appsec_command(
    project: Path = typer.Option(
        ...,
        '--project',
        file_okay=False,
        dir_okay=True,
        resolve_path=True,
        help='Laravel project directory.',
    ),
    osv_database: Optional[Path] = typer.Option(
        None,
        '--osv-db',
        file_okay=True,
        dir_okay=False,
        resolve_path=True,
        help='Local OSV JSON snapshot for Composer dependency scanning.',
    ),
    skip_dependencies: bool = typer.Option(
        False,
        '--skip-dependencies',
        help='Explicitly skip Composer dependency vulnerability matching.',
    ),
    report_format: str = typer.Option('json', '--format', help='Report format: json or html.'),
    output: Optional[Path] = typer.Option(None, '--output', '-o', help='Write the report to this file.'),
    fail_on: str = typer.Option(
        'high',
        '--fail-on',
        help='Exit 3 for findings at or above critical, high, medium, low, or none.',
    ),
):
    """Assess Laravel configuration and Composer dependencies using local data only."""
    from opsai.security.appsec import assess_project, gate_exit_code
    from opsai.security.appsec_report import render_html, render_json

    if report_format.lower() not in ('json', 'html'):
        typer.echo('Report format must be json or html', err=True)
        raise typer.Exit(code=1)
    if fail_on not in ('critical', 'high', 'medium', 'low', 'none'):
        typer.echo('Invalid --fail-on severity', err=True)
        raise typer.Exit(code=1)
    try:
        payload = assess_project(
            project,
            osv_database=osv_database,
            skip_dependencies=skip_dependencies,
        )
        rendered = render_html(payload) if report_format.lower() == 'html' else render_json(payload)
        if output is not None:
            protected_inputs = {
                (project / name).resolve()
                for name in ('.env', 'composer.json', 'composer.lock', 'artisan')
            }
            if osv_database is not None:
                protected_inputs.add(osv_database.resolve())
            if output.resolve() in protected_inputs:
                raise ValueError('Report output must not overwrite a project or advisory input file')
            output.write_text(rendered + '\n', encoding='utf-8')
        else:
            typer.echo(rendered)
        exit_code = gate_exit_code(payload, fail_on)
        if exit_code:
            raise typer.Exit(code=exit_code)
    except (OSError, ValueError) as exc:
        typer.echo(f'Application security assessment error: {exc}', err=True)
        raise typer.Exit(code=1)


@app.command('osv-refresh')
def osv_refresh_command(
    composer_lock: Path = typer.Option(
        ...,
        '--composer-lock',
        exists=True,
        file_okay=True,
        dir_okay=False,
        resolve_path=True,
        help='Composer lockfile whose package names and versions will be queried.',
    ),
    output: Path = typer.Option(
        ...,
        '--output',
        '-o',
        file_okay=True,
        dir_okay=False,
        help='Destination for the project-specific OSV JSON snapshot.',
    ),
    yes: bool = typer.Option(
        False,
        '--yes',
        help='Confirm sending package names and locked versions to OSV.dev and replacing output.',
    ),
):
    """Fetch OSV.dev advisories for a Composer lockfile into a local snapshot."""
    from opsai.infrastructure.osv import refresh_osv_snapshot
    from opsai.security.appsec import load_composer_lock_packages

    try:
        packages = load_composer_lock_packages(composer_lock)
        protected_inputs = {
            (composer_lock.parent / name).resolve()
            for name in ('.env', 'composer.json', 'composer.lock', 'artisan')
        }
        if output.resolve() in protected_inputs:
            raise ValueError('OSV snapshot output must not overwrite a project input file')
        consent_message = (
            f'Output {output} already exists and will be replaced. '
            if output.exists() else ''
        )
        if not yes and not typer.confirm(
            f'{consent_message}Send {len(packages)} package names and locked versions '
            'to api.osv.dev and write the returned advisory snapshot?'
        ):
            typer.echo('OSV snapshot refresh cancelled; no request was made.')
            raise typer.Exit(code=1)
        advisory_count = refresh_osv_snapshot(packages, output)
        typer.echo(
            f'Wrote {advisory_count} advisories for {len(packages)} locked packages to {output}.'
        )
        if advisory_count == 0:
            typer.echo(
                'OSV.dev returned no advisories matching these package versions. '
                'This is not a full Packagist database and does not prove the dependencies are vulnerability-free.',
                err=True,
            )
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        typer.echo(f'OSV snapshot refresh error: {exc}', err=True)
        raise typer.Exit(code=1)



@app.command('github-report')
def github_report_command(
    report_file: Path = typer.Option(..., '--report', help='JSON output from opsai security'),
    fail_on: str = typer.Option('high', '--fail-on', help='critical, high, medium, low, none'),
    summary: bool = typer.Option(True, '--summary/--no-summary', help='Append to GITHUB_STEP_SUMMARY'),
):
    """Publish audit findings as GitHub Actions annotations and a job summary."""
    import os
    from opsai.ci.github import publish_report
    if fail_on not in ('critical', 'high', 'medium', 'low', 'none'):
        typer.echo('Invalid --fail-on severity', err=True)
        raise typer.Exit(code=1)
    summary_path = Path(os.environ['GITHUB_STEP_SUMMARY']) if summary and os.environ.get('GITHUB_STEP_SUMMARY') else None
    try:
        annotations, code = publish_report(report_file, summary_path, fail_on)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        typer.echo(f'Cannot publish audit report: {exc}', err=True)
        raise typer.Exit(code=1)
    for annotation in annotations:
        typer.echo(annotation)
    raise typer.Exit(code=code)



@app.command('incident')
def incident_command(
    evidence: Path = typer.Option(..., '--evidence', help='JSON file with source and logs'),
    json_output: bool = typer.Option(False, '--json'),
    ai: bool = typer.Option(False, '--ai', help='Optional AI advice, never executable'),
    yes: bool = typer.Option(False, '--yes', help='Confirm redacted data transfer only'),
    action: Optional[str] = typer.Option(None, '--action', help='Approved action ID to execute'),
    execute: bool = typer.Option(False, '--execute', help='Allow an explicitly approved local action'),
):
    """Investigate incident evidence and optionally approve a local allowlisted action."""
    from opsai.incident.agent import (load_evidence, investigate, ai_assessment,
                                      execute_approved, SystemctlExecutor)
    try:
        report = investigate(load_evidence(evidence))
        if ai:
            if not yes:
                typer.echo('A best-effort redacted summary will be sent to OpenAI. Review sensitive data first.')
                if not typer.confirm('Continue?'):
                    return
            report['ai_assessment'] = ai_assessment(report)
        if action:
            if not execute:
                raise ValueError('Action requires --execute and explicit approval')
            typer.echo('CAUTION: This changes the LOCAL host, not a remote SSH target.')
            approval = typer.prompt(f'Type APPROVE {action} to authorize execution')
            report['execution_result'] = execute_approved(report, action, approval, SystemctlExecutor())
        elif execute:
            raise ValueError('--execute requires --action')
        if json_output:
            typer.echo(json.dumps(report, indent=2))
        else:
            console.print_json(data=report)
    except (OSError, ValueError, PermissionError, RuntimeError, json.JSONDecodeError) as exc:
        typer.echo(f'Incident error: {exc}', err=True)
        raise typer.Exit(code=1)

if __name__ == '__main__':
    app()
