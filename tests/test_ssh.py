import json
import subprocess
from pathlib import Path
from typer.testing import CliRunner
import pytest
from opsai.cli import app
from opsai.domain.servers import Server
from opsai.infrastructure.ssh import load_inventory, SSHRunner
from opsai.application.remote_monitoring import RemoteMonitoringService


def test_inventory(tmp_path):
    path = tmp_path / 'inventory.json'
    path.write_text(json.dumps({'servers': [{'name': 'web', 'host': '10.0.0.5', 'user': 'deploy'}]}))
    assert load_inventory(path)[0].port == 22

@pytest.mark.parametrize('host', ['-oProxyCommand=evil', 'host name', 'host\ncmd'])
def test_reject_unsafe_host(host):
    with pytest.raises(ValueError):
        Server('web', host, 'deploy')

def test_duplicate_names(tmp_path):
    p = tmp_path / 'inv.json'
    p.write_text(json.dumps({'servers': [{'name': 'a', 'host': 'one', 'user': 'me'}, {'name': 'a', 'host': 'two', 'user': 'me'}]}))
    with pytest.raises(ValueError, match='Duplicate'):
        load_inventory(p)

def test_runner_uses_safe_ssh_options(monkeypatch):
    seen = {}
    def fake_run(args, **kwargs):
        seen['args'] = args
        return subprocess.CompletedProcess(args, 0, 'ok', '')
    monkeypatch.setattr(subprocess, 'run', fake_run)
    assert SSHRunner().run(Server('web', 'example.org', 'deploy')) == 'ok'
    assert 'StrictHostKeyChecking=yes' in seen['args']
    assert 'BatchMode=yes' in seen['args']
    assert '--' in seen['args']

def test_runner_failure(monkeypatch):
    monkeypatch.setattr(subprocess, 'run', lambda *a, **k: subprocess.CompletedProcess(a, 255, '', 'private error'))
    with pytest.raises(RuntimeError, match='255'):
        SSHRunner().run(Server('web', 'example.org', 'deploy'))

def test_monitoring_order_and_failures():
    class Fake:
        def run(self, server):
            if server.name == 'bad':
                raise RuntimeError('unreachable')
            return 'CPU ok; token=secret123'
    result = RemoteMonitoringService(Fake()).check([Server('good', 'a', 'u'), Server('bad', 'b', 'u')])
    assert [r['name'] for r in result] == ['good', 'bad']
    assert result[0]['status'] == 'ok'
    assert 'secret123' not in result[0]['output']
    assert result[1]['status'] == 'error'

def test_cli_json(tmp_path, monkeypatch):
    p = tmp_path / 'inventory.json'
    p.write_text(json.dumps({'servers': [{'name': 'web', 'host': 'example.org', 'user': 'deploy'}]}))
    monkeypatch.setattr(SSHRunner, 'run', lambda self, server: 'uptime 1 day')
    result = CliRunner().invoke(app, ['ssh', '--inventory', str(p), '--json'])
    assert result.exit_code == 0, result.output
    assert json.loads(result.output)['healthy'] == 1

def test_cli_partial_failure(tmp_path, monkeypatch):
    p = tmp_path / 'inventory.json'
    p.write_text(json.dumps({'servers': [{'name': 'web', 'host': 'example.org', 'user': 'deploy'}]}))
    def fail(self, server):
        raise RuntimeError('unreachable')
    monkeypatch.setattr(SSHRunner, 'run', fail)
    result = CliRunner().invoke(app, ['ssh', '--inventory', str(p), '--json'])
    assert result.exit_code == 2
    assert json.loads(result.output)['healthy'] == 0
