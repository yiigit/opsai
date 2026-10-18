import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from opsai.cli import app
from opsai.security.audit import audit_docker, audit_linux, report


def test_linux_insecure_permissions_and_ssh(tmp_path):
    etc = tmp_path / 'etc'
    (etc / 'ssh').mkdir(parents=True)
    shadow = etc / 'shadow'
    shadow.write_text('fake')
    shadow.chmod(0o644)
    sshd = etc / 'ssh' / 'sshd_config'
    sshd.write_text('# PermitRootLogin yes\nPermitRootLogin yes\nPasswordAuthentication yes\n')
    sshd.chmod(0o666)
    findings = audit_linux(tmp_path)
    ids = {f.id for f in findings}
    assert ids == {'LINUX_SHADOW', 'LINUX_SSH_CONFIG', 'LINUX_ROOT_SSH', 'LINUX_SSH_PASSWORD'}


def test_linux_safe_or_missing_files(tmp_path):
    assert audit_linux(tmp_path) == []
    (tmp_path / 'etc' / 'ssh').mkdir(parents=True)
    conf = tmp_path / 'etc' / 'ssh' / 'sshd_config'
    conf.write_text('#PasswordAuthentication yes\nPermitRootLogin no\n')
    conf.chmod(0o600)
    assert audit_linux(tmp_path) == []


def test_docker_detects_unsafe_configurations():
    calls = []
    def runner(args):
        calls.append(args)
        if args[:3] == ['docker', 'ps', '-q']:
            return 'abc\n'
        return json.dumps([{'Name': '/web', 'HostConfig': {
            'Privileged': True, 'NetworkMode': 'host', 'PidMode': 'host',
            'ReadonlyRootfs': False, 'Binds': ['/var/run/docker.sock:/var/run/docker.sock']},
            'Config': {'User': ''}}])
    findings = audit_docker(runner)
    assert {f.id for f in findings} == {
        'DOCKER_PRIVILEGED', 'DOCKER_HOST_NETWORK', 'DOCKER_HOST_PID',
        'DOCKER_WRITABLE_ROOT', 'DOCKER_ROOT_USER', 'DOCKER_HOST_MOUNT'}
    assert calls[1] == ['docker', 'inspect', 'abc']


def test_docker_no_containers():
    assert audit_docker(lambda args: '') == []


def test_docker_invalid_json():
    with pytest.raises(ValueError):
        audit_docker(lambda args: 'a' if args[1] == 'ps' else '{bad')


def test_docker_inspection_bounded():
    with pytest.raises(ValueError):
        audit_docker(lambda args: '\n'.join(str(i) for i in range(201)))


def test_report_counts():
    payload = report('linux', audit_linux(Path('/nonexistent-test-root')))
    assert payload['status'] == 'completed'
    assert payload['counts']['high'] == 0


def test_cli_linux_json(monkeypatch):
    monkeypatch.setattr('opsai.security.audit.audit_linux', lambda: [])
    result = CliRunner().invoke(app, ['security', 'linux', '--json'])
    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout)['target'] == 'linux'


def test_cli_fail_on(monkeypatch):
    from opsai.security.audit import Finding
    monkeypatch.setattr('opsai.security.audit.audit_linux', lambda: [
        Finding('CHECK', 'high', 'bad', 'evidence', 'fix')])
    runner = CliRunner()
    assert runner.invoke(app, ['security', 'linux', '--json']).exit_code == 3
    assert runner.invoke(app, ['security', 'linux', '--fail-on', 'critical']).exit_code == 0


def test_cli_docker_failure_partial(monkeypatch):
    def unavailable():
        raise RuntimeError('daemon unavailable')
    monkeypatch.setattr('opsai.security.audit.audit_docker', unavailable)
    result = CliRunner().invoke(app, ['security', 'docker', '--json'])
    assert result.exit_code == 2
    assert json.loads(result.stdout)['status'] == 'partial'
