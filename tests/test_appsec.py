import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from opsai.cli import app
from opsai.domain.owasp import OWASP_TOP_10_2025, get_owasp_category
from opsai.security.appsec import (
    AppSecFinding,
    assess_project,
    audit_laravel_project,
    gate_exit_code,
    scan_composer_dependencies,
)
from opsai.security.appsec_report import render_html, render_json


def make_laravel_project(root: Path, env: str = '') -> Path:
    root.mkdir(parents=True, exist_ok=True)
    (root / 'artisan').write_text('# Laravel artisan marker\n', encoding='utf-8')
    (root / 'composer.json').write_text(json.dumps({
        'require': {'laravel/framework': '^11.0'},
    }), encoding='utf-8')
    env_path = root / '.env'
    env_path.write_text(env, encoding='utf-8')
    env_path.chmod(0o600)
    return root


def make_lock_and_osv(root: Path, version: str = '1.3.2', severity: str = 'HIGH') -> tuple[Path, Path]:
    lock_path = root / 'composer.lock'
    lock_path.write_text(json.dumps({
        'packages': [{'name': 'vendor/vulnerable', 'version': version}],
        'packages-dev': [{'name': 'vendor/dev-tool', 'version': '2.0.0'}],
    }), encoding='utf-8')
    osv_path = root / 'osv.json'
    osv_path.write_text(json.dumps({
        'vulns': [{
            'id': 'OSV-2025-123',
            'summary': 'Example vulnerable package',
            'aliases': ['CVE-2025-0123'],
            'database_specific': {'severity': severity},
            'affected': [{
                'package': {'ecosystem': 'Packagist', 'name': 'vendor/vulnerable'},
                'ranges': [{
                    'type': 'SEMVER',
                    'events': [{'introduced': '1.0.0'}, {'fixed': '1.4.0'}],
                }],
            }],
        }],
    }), encoding='utf-8')
    return lock_path, osv_path


def test_owasp_2025_categories_are_complete_and_known():
    assert [item.id for item in OWASP_TOP_10_2025] == [
        f'A{i:02d}:2025' for i in range(1, 11)
    ]
    assert get_owasp_category('A03:2025').title == 'Software Supply Chain Failures'
    with pytest.raises(ValueError, match='Unknown OWASP'):
        get_owasp_category('A11:2025')


def test_laravel_production_findings_never_include_environment_values(tmp_path):
    project = make_laravel_project(
        tmp_path / 'laravel',
        'APP_ENV=production\nAPP_DEBUG=true\nAPP_KEY=\n'
        'SESSION_SECURE_COOKIE=false\nSESSION_HTTP_ONLY=false\nSESSION_SAME_SITE=none\n'
        'SECRET_TOKEN=do-not-print-this\n',
    )
    findings = audit_laravel_project(project)
    identifiers = {item.id for item in findings}
    assert identifiers == {
        'LARAVEL_DEBUG_PRODUCTION',
        'LARAVEL_APP_KEY_MISSING',
        'LARAVEL_SESSION_COOKIE_SECURE',
        'LARAVEL_SESSION_HTTP_ONLY',
        'LARAVEL_SESSION_SAMESITE',
    }
    assert all(item.owasp['id'] in ('A02:2025', 'A04:2025') for item in findings)
    assert 'APP_KEY is empty' in str([item.as_dict() for item in findings])
    assert 'do-not-print-this' not in str([item.as_dict() for item in findings])


def test_laravel_env_permission_finding_and_nonproduction_scope(tmp_path):
    project = make_laravel_project(tmp_path / 'laravel', 'APP_ENV=local\nAPP_DEBUG=true\nAPP_KEY=sample-secret\n')
    (project / '.env').chmod(0o644)
    findings = audit_laravel_project(project)
    assert [item.id for item in findings] == ['LARAVEL_ENV_PERMISSIONS']
    assert 'sample-secret' not in str([item.as_dict() for item in findings])


def test_laravel_missing_env_is_not_assumed_insecure(tmp_path):
    project = make_laravel_project(tmp_path / 'laravel')
    (project / '.env').unlink()
    assert audit_laravel_project(project) == []


@pytest.mark.parametrize('missing', ['artisan', 'composer.json'])
def test_laravel_requires_project_markers(tmp_path, missing):
    project = make_laravel_project(tmp_path / 'project')
    (project / missing).unlink()
    with pytest.raises(ValueError, match='Laravel'):
        audit_laravel_project(project)


def test_laravel_rejects_non_laravel_composer_project(tmp_path):
    project = make_laravel_project(tmp_path / 'project')
    (project / 'composer.json').write_text('{"require": {"symfony/console": "^7"}}', encoding='utf-8')
    with pytest.raises(ValueError, match='laravel/framework'):
        audit_laravel_project(project)


def test_laravel_duplicate_env_keys_are_rejected_without_values(tmp_path):
    project = make_laravel_project(tmp_path / 'project', 'APP_KEY=secret-one\nAPP_KEY=secret-two\n')
    with pytest.raises(ValueError, match='duplicate key'):
        audit_laravel_project(project)


def test_laravel_env_symlink_is_rejected(tmp_path):
    project = make_laravel_project(tmp_path / 'project')
    outside = tmp_path / 'external-env'
    outside.write_text('APP_ENV=production\nAPP_DEBUG=true\n', encoding='utf-8')
    (project / '.env').unlink()
    (project / '.env').symlink_to(outside)
    with pytest.raises(ValueError, match='symbolic link'):
        audit_laravel_project(project)


def test_composer_lock_matches_local_osv_fixed_range_and_classifies_top10(tmp_path):
    lock_path, osv_path = make_lock_and_osv(tmp_path)
    findings, errors = scan_composer_dependencies(lock_path, osv_path)
    assert not errors
    assert len(findings) == 1
    finding = findings[0]
    assert finding.id == 'OSV-OSV-2025-123'
    assert finding.severity == 'high'
    assert finding.owasp == {
        'id': 'A03:2025',
        'title': 'Software Supply Chain Failures',
    }
    assert 'vendor/vulnerable 1.3.2' in finding.title
    assert 'vendor/dev-tool' not in finding.title


@pytest.mark.parametrize(('version', 'expected'), [
    ('1.0.0', True),
    ('1.3.2', True),
    ('1.4.0', False),
    ('2.0.0', False),
])
def test_composer_osv_range_boundaries(tmp_path, version, expected):
    lock_path, osv_path = make_lock_and_osv(tmp_path, version=version)
    findings, errors = scan_composer_dependencies(lock_path, osv_path)
    assert not errors
    assert bool(findings) is expected


def test_osv_semver_prerelease_comparison_is_case_sensitive(tmp_path):
    lock_path, osv_path = make_lock_and_osv(tmp_path, version='1.4.0-Alpha')
    payload = json.loads(osv_path.read_text())
    payload['vulns'][0]['affected'][0]['ranges'][0]['events'][1]['fixed'] = '1.4.0-alpha'
    osv_path.write_text(json.dumps(payload), encoding='utf-8')
    findings, errors = scan_composer_dependencies(lock_path, osv_path)
    assert not errors
    assert len(findings) == 1


def test_osv_exact_versions_support_non_semver_composer_dev_versions(tmp_path):
    lock_path, osv_path = make_lock_and_osv(tmp_path, version='dev-main')
    payload = json.loads(osv_path.read_text())
    affected = payload['vulns'][0]['affected'][0]
    affected.pop('ranges')
    affected['versions'] = ['dev-main']
    osv_path.write_text(json.dumps(payload), encoding='utf-8')
    findings, errors = scan_composer_dependencies(lock_path, osv_path)
    assert not errors
    assert len(findings) == 1


def test_osv_empty_introduced_boundary_means_all_prior_versions(tmp_path):
    lock_path, osv_path = make_lock_and_osv(tmp_path, version='0.1.0')
    payload = json.loads(osv_path.read_text())
    payload['vulns'][0]['affected'][0]['ranges'][0]['events'][0]['introduced'] = ''
    osv_path.write_text(json.dumps(payload), encoding='utf-8')
    findings, errors = scan_composer_dependencies(lock_path, osv_path)
    assert not errors
    assert len(findings) == 1


@pytest.mark.parametrize('version', ['dev-main', '1.3.2-alpha..1', '1.3.2-01'])
def test_unsupported_composer_range_version_marks_assessment_partial(tmp_path, version):
    lock_path, osv_path = make_lock_and_osv(tmp_path, version=version)
    findings, errors = scan_composer_dependencies(lock_path, osv_path)
    assert findings == []
    assert len(errors) == 1
    assert 'Unsupported Composer/OSV version syntax' in errors[0]


def test_unsupported_osv_ecosystem_range_marks_assessment_partial(tmp_path):
    lock_path, osv_path = make_lock_and_osv(tmp_path)
    payload = json.loads(osv_path.read_text())
    payload['vulns'][0]['affected'][0]['ranges'][0]['type'] = 'ECOSYSTEM'
    osv_path.write_text(json.dumps(payload), encoding='utf-8')
    findings, errors = scan_composer_dependencies(lock_path, osv_path)
    assert findings == []
    assert len(errors) == 1
    assert "Unsupported OSV range type: 'ECOSYSTEM'" in errors[0]


def test_unsupported_osv_version_boundary_marks_assessment_partial(tmp_path):
    lock_path, osv_path = make_lock_and_osv(tmp_path)
    payload = json.loads(osv_path.read_text())
    payload['vulns'][0]['affected'][0]['ranges'][0]['events'][1]['fixed'] = 'dev-main'
    osv_path.write_text(json.dumps(payload), encoding='utf-8')
    findings, errors = scan_composer_dependencies(lock_path, osv_path)
    assert findings == []
    assert len(errors) == 1
    assert 'Unsupported Composer/OSV version syntax' in errors[0]


def test_malformed_osv_ranges_are_not_treated_as_no_vulnerability(tmp_path):
    lock_path, osv_path = make_lock_and_osv(tmp_path)
    payload = json.loads(osv_path.read_text())
    payload['vulns'][0]['affected'][0]['ranges'] = {}
    osv_path.write_text(json.dumps(payload), encoding='utf-8')
    with pytest.raises(ValueError, match='affected ranges must be an array'):
        scan_composer_dependencies(lock_path, osv_path)


def test_osv_range_close_event_requires_an_introduced_boundary(tmp_path):
    lock_path, osv_path = make_lock_and_osv(tmp_path)
    payload = json.loads(osv_path.read_text())
    payload['vulns'][0]['affected'][0]['ranges'][0]['events'] = [{'fixed': '1.4.0'}]
    osv_path.write_text(json.dumps(payload), encoding='utf-8')
    with pytest.raises(ValueError, match='has no introduced boundary'):
        scan_composer_dependencies(lock_path, osv_path)


def test_osv_non_packagist_advisories_are_ignored(tmp_path):
    lock_path, osv_path = make_lock_and_osv(tmp_path)
    payload = json.loads(osv_path.read_text())
    payload['vulns'][0]['affected'][0]['package']['ecosystem'] = 'npm'
    osv_path.write_text(json.dumps(payload), encoding='utf-8')
    findings, errors = scan_composer_dependencies(lock_path, osv_path)
    assert not findings
    assert not errors


def test_empty_local_osv_snapshot_is_valid(tmp_path):
    lock_path, osv_path = make_lock_and_osv(tmp_path)
    osv_path.write_text('{"vulns": []}', encoding='utf-8')
    findings, errors = scan_composer_dependencies(lock_path, osv_path)
    assert findings == []
    assert errors == []


@pytest.mark.parametrize('payload', [
    {'vulns': 'not-an-array'},
    {'vulns': ['not-an-object']},
    {'vulns': [{'affected': []}]},
])
def test_invalid_osv_snapshot_is_rejected(tmp_path, payload):
    lock_path, osv_path = make_lock_and_osv(tmp_path)
    osv_path.write_text(json.dumps(payload), encoding='utf-8')
    with pytest.raises(ValueError):
        scan_composer_dependencies(lock_path, osv_path)


def test_large_osv_snapshot_is_rejected_before_parsing(tmp_path):
    lock_path, osv_path = make_lock_and_osv(tmp_path)
    from opsai.security.appsec import MAX_OSV_DATABASE_BYTES

    osv_path.write_bytes(b' ' * (MAX_OSV_DATABASE_BYTES + 1))
    with pytest.raises(ValueError, match='size limit'):
        scan_composer_dependencies(lock_path, osv_path)


def test_assessment_requires_explicit_osv_db_when_composer_lock_exists(tmp_path):
    project = make_laravel_project(tmp_path / 'laravel')
    (project / 'composer.lock').write_text('{"packages": []}', encoding='utf-8')
    with pytest.raises(ValueError, match='--osv-db or explicitly use --skip-dependencies'):
        assess_project(project)
    report = assess_project(project, skip_dependencies=True)
    assert report['checks'] == ['laravel_configuration']


def test_assessment_offline_report_shape_and_partial_errors(tmp_path):
    project = make_laravel_project(tmp_path / 'laravel', 'APP_ENV=production\nAPP_DEBUG=true\n')
    lock_path, osv_path = make_lock_and_osv(tmp_path)
    (project / 'composer.lock').write_bytes(lock_path.read_bytes())
    report = assess_project(project, osv_database=osv_path)
    assert report['status'] == 'completed'
    assert report['checks'] == ['laravel_configuration', 'composer_dependencies']
    assert report['owasp_version'] == '2025'
    assert report['counts']['high'] == 3
    assert report['counts']['medium'] == 0
    assert report['counts']['unknown'] == 0


def test_gate_threshold_and_unknown_severity_behavior():
    report = {
        'status': 'completed',
        'errors': [],
        'counts': {'critical': 0, 'high': 1, 'medium': 0, 'low': 0, 'unknown': 0},
        'findings': [{'severity': 'high'}],
    }
    assert gate_exit_code(report, 'high') == 3
    assert gate_exit_code(report, 'critical') == 0
    report['counts']['unknown'] = 1
    assert gate_exit_code(report, 'high') == 2
    assert gate_exit_code(report, 'none') == 0
    report['errors'] = ['version cannot be assessed']
    assert gate_exit_code(report, 'none') == 2


def test_html_report_escapes_untrusted_advisory_text():
    report = {
        'project': '<script>alert(1)</script>',
        'status': 'completed',
        'owasp_version': '2025',
        'counts': {'critical': 0, 'high': 1, 'medium': 0, 'low': 0, 'unknown': 0},
        'errors': [],
        'findings': [AppSecFinding(
            'OSV-1', 'high', '<img src=x onerror=alert(1)>',
            '<script>untrusted</script>', 'Upgrade & verify',
            'composer.lock', {'id': 'A03:2025', 'title': 'Software Supply Chain Failures'},
        ).as_dict()],
    }
    html_output = render_html(report)
    assert '<script>alert(1)</script>' not in html_output
    assert '<img src=x onerror=alert(1)>' not in html_output
    assert '&lt;script&gt;' in html_output
    assert '&lt;img src=x onerror=alert(1)&gt;' in html_output
    assert 'Upgrade &amp; verify' in html_output


def test_json_report_is_deterministic():
    payload = {'tool': 'opsai-appsec', 'findings': [], 'status': 'completed'}
    assert render_json(payload) == render_json(payload)
    assert json.loads(render_json(payload)) == payload


def test_appsec_cli_writes_json_and_returns_threshold_exit(tmp_path):
    project = make_laravel_project(tmp_path / 'laravel', 'APP_ENV=production\nAPP_DEBUG=true\n')
    output = tmp_path / 'assessment.json'
    result = CliRunner().invoke(app, [
        'appsec', '--project', str(project), '--skip-dependencies',
        '--format', 'json', '--output', str(output), '--fail-on', 'high',
    ])
    assert result.exit_code == 3
    report = json.loads(output.read_text())
    assert report['findings'][0]['owasp']['id'] == 'A02:2025'


def test_appsec_cli_html_output_is_standalone(tmp_path):
    project = make_laravel_project(tmp_path / 'laravel')
    output = tmp_path / 'assessment.html'
    result = CliRunner().invoke(app, [
        'appsec', '--project', str(project), '--skip-dependencies',
        '--format', 'html', '--output', str(output),
    ])
    assert result.exit_code == 0, result.output
    html_output = output.read_text()
    assert '<!doctype html>' in html_output
    assert 'OWASP Top 10:2025' in html_output
    assert 'No findings were reported' in html_output


def test_appsec_cli_will_not_overwrite_project_inputs(tmp_path):
    env_contents = 'APP_ENV=production\nAPP_DEBUG=true\nAPP_KEY=private-example-key\n'
    project = make_laravel_project(tmp_path / 'laravel', env_contents)
    result = CliRunner().invoke(app, [
        'appsec', '--project', str(project), '--skip-dependencies',
        '--output', str(project / '.env'),
    ])
    assert result.exit_code == 1
    assert 'must not overwrite' in result.output
    assert (project / '.env').read_text() == env_contents


def test_appsec_cli_rejects_unknown_format_and_threshold(tmp_path):
    project = make_laravel_project(tmp_path / 'laravel')
    runner = CliRunner()
    bad_format = runner.invoke(app, ['appsec', '--project', str(project), '--format', 'xml'])
    assert bad_format.exit_code == 1
    assert 'must be json or html' in bad_format.output
    bad_threshold = runner.invoke(app, [
        'appsec', '--project', str(project), '--fail-on', 'blocker',
    ])
    assert bad_threshold.exit_code == 1


def test_appsec_cli_requires_advisory_snapshot_for_composer_lock(tmp_path):
    project = make_laravel_project(tmp_path / 'laravel')
    (project / 'composer.lock').write_text('{"packages": []}', encoding='utf-8')
    result = CliRunner().invoke(app, ['appsec', '--project', str(project)])
    assert result.exit_code == 1
    assert '--osv-db' in result.output


def test_osv_refresh_cli_requires_consent_before_network(tmp_path, monkeypatch):
    project = make_laravel_project(tmp_path / 'laravel')
    lock_path = project / 'composer.lock'
    lock_path.write_text(json.dumps({
        'packages': [{'name': 'vendor/package', 'version': '1.2.3'}],
    }), encoding='utf-8')
    monkeypatch.setattr(
        'opsai.infrastructure.osv.refresh_osv_snapshot',
        lambda *_args: pytest.fail('Declined consent must not make a request'),
    )
    result = CliRunner().invoke(app, [
        'osv-refresh',
        '--composer-lock', str(lock_path),
        '--output', str(tmp_path / 'osv-packagist.json'),
    ], input='n\n')
    assert result.exit_code == 1
    assert 'no request was made' in result.output


def test_osv_refresh_cli_writes_snapshot_after_explicit_yes(tmp_path, monkeypatch):
    project = make_laravel_project(tmp_path / 'laravel')
    lock_path = project / 'composer.lock'
    lock_path.write_text(json.dumps({
        'packages': [{'name': 'vendor/package', 'version': '1.2.3'}],
        'packages-dev': [{'name': 'vendor/dev-tool', 'version': '2.0.0'}],
    }), encoding='utf-8')
    output = tmp_path / 'osv-packagist.json'
    calls = []

    def refresh(packages, destination):
        calls.append((packages, destination))
        destination.write_text('{"vulns":[]}', encoding='utf-8')
        return 0

    monkeypatch.setattr('opsai.infrastructure.osv.refresh_osv_snapshot', refresh)
    result = CliRunner().invoke(app, [
        'osv-refresh',
        '--composer-lock', str(lock_path),
        '--output', str(output),
        '--yes',
    ])
    assert result.exit_code == 0, result.output
    assert calls == [(
        [('vendor/package', '1.2.3'), ('vendor/dev-tool', '2.0.0')],
        output,
    )]
    assert output.read_text() == '{"vulns":[]}'
    assert 'does not prove the dependencies are vulnerability-free' in result.output


def test_osv_refresh_cli_will_not_overwrite_project_inputs(tmp_path, monkeypatch):
    project = make_laravel_project(tmp_path / 'laravel')
    lock_path = project / 'composer.lock'
    lock_path.write_text('{"packages": []}', encoding='utf-8')
    original = lock_path.read_text()
    monkeypatch.setattr(
        'opsai.infrastructure.osv.refresh_osv_snapshot',
        lambda *_args: pytest.fail('Protected output must be rejected before network'),
    )
    result = CliRunner().invoke(app, [
        'osv-refresh',
        '--composer-lock', str(lock_path),
        '--output', str(lock_path),
        '--yes',
    ])
    assert result.exit_code == 1
    assert 'must not overwrite' in result.output
    assert lock_path.read_text() == original
