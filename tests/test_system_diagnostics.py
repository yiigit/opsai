import json
from types import SimpleNamespace

import pytest
from typer.testing import CliRunner

from opsai.cli import app
from opsai.infrastructure import system_diagnostics as diagnostics

runner = CliRunner()


def test_cpu_diagnostics_reports_load_and_core_data(monkeypatch):
    monkeypatch.setattr(diagnostics.psutil, 'cpu_freq', lambda: None)
    monkeypatch.setattr(diagnostics.psutil, 'cpu_count', lambda logical: 8 if logical else 4)
    samples = iter((37.5, [10.0, 20.0]))
    monkeypatch.setattr(diagnostics.psutil, 'cpu_percent', lambda **_kwargs: next(samples))
    monkeypatch.setattr(diagnostics.os, 'getloadavg', lambda: (1.0, 0.8, 0.4))

    result = diagnostics.cpu_diagnostics()

    assert result['logical_cores'] == 8
    assert result['physical_cores'] == 4
    assert result['utilization_percent'] == 37.5
    assert result['per_core_percent'] == [10.0, 20.0]
    assert result['load_average'] == [1.0, 0.8, 0.4]


def test_process_diagnostics_sorts_by_memory_and_omits_command_lines(monkeypatch):
    processes = [
        SimpleNamespace(info={
            'pid': 10, 'name': 'small', 'username': 'user', 'status': 'running',
            'memory_percent': 1.0, 'cpu_percent': 80.0,
        }),
        SimpleNamespace(info={
            'pid': 11, 'name': 'large', 'username': 'root', 'status': 'sleeping',
            'memory_percent': 20.0, 'cpu_percent': 1.0,
        }),
    ]
    monkeypatch.setattr(diagnostics.psutil, 'process_iter', lambda **_kwargs: processes)
    result = diagnostics.process_diagnostics(limit=1)
    assert result['processes'][0]['name'] == 'large'
    assert 'cmdline' not in result['processes'][0]
    with pytest.raises(ValueError, match='Process limit'):
        diagnostics.process_diagnostics(limit=0)


def test_journal_diagnostics_redacts_sensitive_message(monkeypatch):
    monkeypatch.setattr(
        diagnostics,
        '_run_command',
        lambda args: json.dumps({
            'MESSAGE': 'service failed token=private-value',
            'PRIORITY': '3',
            '_SYSTEMD_UNIT': 'example.service',
        }),
    )
    result = diagnostics.journal_diagnostics(lines=1)
    assert result['entries'][0]['message'] == 'service failed token=[REDACTED]'
    assert 'private-value' not in json.dumps(result)


def test_apt_security_updates_use_simulation_and_filter_by_repo(monkeypatch):
    calls = []
    monkeypatch.setattr(diagnostics.shutil, 'which', lambda _name: '/usr/bin/apt-get')

    def fake_run(args, timeout=20):
        calls.append((args, timeout))
        return '\n'.join([
            'Inst ordinary [1.0] (2.0 Ubuntu:24.04/noble-updates [amd64])',
            'Inst openssl [1.0] (2.0 Ubuntu:24.04/noble-security [amd64])',
            'Inst security-tool [1.0] (2.0 Ubuntu:24.04/noble-updates [amd64])',
        ])

    monkeypatch.setattr(diagnostics, '_run_command', fake_run)
    result = diagnostics._apt_security_updates()
    assert calls[0][0][:3] == ['apt-get', '-s', '-o']
    assert calls[0][0][-1] == 'upgrade'
    assert [item['package'] for item in result['security_updates']] == ['openssl']
    assert 'no index refresh' in result['source']


def test_dnf_security_update_check_is_cache_only(monkeypatch):
    calls = []
    monkeypatch.setattr(diagnostics.shutil, 'which', lambda name: '/usr/bin/dnf' if name == 'dnf' else None)

    def fake_run(args, **kwargs):
        calls.append(args)
        return SimpleNamespace(
            returncode=100,
            stdout='openssl.x86_64 1:3.0.0-1 updates\n',
            stderr='',
        )

    monkeypatch.setattr(diagnostics.subprocess, 'run', fake_run)
    result = diagnostics._dnf_security_updates()
    assert '--cacheonly' in calls[0]
    assert result['count'] == 1
    assert result['security_updates'][0]['package'] == 'openssl.x86_64'


def test_network_diagnostics_requires_host_and_port_together():
    with pytest.raises(ValueError, match='both --host and --port'):
        diagnostics.network_diagnostics(host='example.com')


def test_ipv6_default_route_parsing(monkeypatch):
    monkeypatch.setattr(
        diagnostics.Path,
        'read_text',
        lambda *_args, **_kwargs: (
            '00000000000000000000000000000000 00 00000000000000000000000000000000 '
            '00 fe800000000000000000000000000001 00000000 00000000 00000000 00000001 eth0\n'
        ),
    )
    assert diagnostics._default_ipv6_routes() == [{
        'family': 'ipv6',
        'interface': 'eth0',
        'gateway': 'fe80::1',
    }]


def test_network_diagnostics_includes_local_info_and_explicit_probe(monkeypatch):
    monkeypatch.setattr(diagnostics.psutil, 'net_if_stats', lambda: {
        'eth0': SimpleNamespace(isup=True, speed=1000, mtu=1500),
    })
    monkeypatch.setattr(diagnostics.psutil, 'net_if_addrs', lambda: {'eth0': []})
    monkeypatch.setattr(diagnostics.psutil, 'net_io_counters', lambda pernic: {
        'eth0': SimpleNamespace(
            bytes_sent=10, bytes_recv=20, packets_sent=1, packets_recv=2,
        ),
    })
    monkeypatch.setattr(diagnostics, '_default_routes', lambda: [{'interface': 'eth0', 'gateway': '192.0.2.1'}])
    monkeypatch.setattr(diagnostics, '_default_ipv6_routes', lambda: [])
    monkeypatch.setattr(diagnostics, '_dns_configuration', lambda: ['192.0.2.53'])

    class Connection:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def getpeername(self):
            return ('203.0.113.10', 443)

    monkeypatch.setattr(diagnostics.socket, 'create_connection', lambda *_args, **_kwargs: Connection())
    result = diagnostics.network_diagnostics('example.com', 443)
    assert result['interfaces'][0]['name'] == 'eth0'
    assert result['default_routes'][0]['gateway'] == '192.0.2.1'
    assert result['connectivity_probe']['reachable'] is True
    assert result['connectivity_probe']['peer'] == '203.0.113.10'


def test_network_probe_failure_is_reported_without_false_success(monkeypatch):
    monkeypatch.setattr(diagnostics.psutil, 'net_if_stats', lambda: {})
    monkeypatch.setattr(diagnostics.psutil, 'net_if_addrs', lambda: {})
    monkeypatch.setattr(diagnostics.psutil, 'net_io_counters', lambda pernic: {})
    monkeypatch.setattr(diagnostics, '_default_routes', lambda: [])
    monkeypatch.setattr(diagnostics, '_default_ipv6_routes', lambda: [])
    monkeypatch.setattr(diagnostics, '_dns_configuration', lambda: [])

    def fail_connect(*_args, **_kwargs):
        raise TimeoutError('connection timed out')

    monkeypatch.setattr(diagnostics.socket, 'create_connection', fail_connect)
    result = diagnostics.network_diagnostics('example.com', 443)
    assert result['connectivity_probe']['reachable'] is False
    assert 'timed out' in result['connectivity_probe']['error']


def test_system_health_reports_partial_results(monkeypatch):
    for collector_name in (
        'cpu_diagnostics', 'memory_diagnostics', 'disk_diagnostics',
        'process_diagnostics', 'service_diagnostics', 'boot_diagnostics',
        'journal_diagnostics', 'update_diagnostics', 'network_diagnostics',
    ):
        monkeypatch.setattr(
            diagnostics,
            collector_name,
            lambda: {'ok': True},
        )
    monkeypatch.setattr(
        diagnostics,
        'service_diagnostics',
        lambda: (_ for _ in ()).throw(RuntimeError('systemctl unavailable')),
    )
    result = diagnostics.system_health()
    assert result['status'] == 'partial'
    assert result['diagnostics']['cpu'] == {'ok': True}
    assert result['errors']['services'] == 'systemctl unavailable'


def test_system_subcommands_are_available():
    result = runner.invoke(app, ['system', '--help'])
    assert result.exit_code == 0, result.output
    for command in (
        'health', 'cpu', 'memory', 'disk', 'processes', 'services',
        'boot', 'journal', 'updates', 'network', 'troubleshoot',
    ):
        assert command in result.output


def test_system_network_cli_rejects_host_without_port():
    result = runner.invoke(app, ['system', 'network', '--host', 'example.com', '--json'])
    assert result.exit_code == 1
    assert 'both --host and --port' in result.output


def test_system_cpu_json_cli(monkeypatch):
    monkeypatch.setattr(
        'opsai.infrastructure.system_diagnostics.cpu_diagnostics',
        lambda: {'utilization_percent': 12.5},
    )
    result = runner.invoke(app, ['system', 'cpu', '--json'])
    assert result.exit_code == 0, result.output
    assert json.loads(result.output) == {'utilization_percent': 12.5}


def test_system_troubleshoot_ai_requires_consent(monkeypatch):
    monkeypatch.setattr(
        diagnostics,
        'system_health',
        lambda: {'status': 'completed', 'diagnostics': {}, 'errors': {}},
    )
    monkeypatch.setattr(
        'opsai.infrastructure.openai.analyze',
        lambda _payload: pytest.fail('Declined consent must not call the AI provider'),
    )
    result = runner.invoke(app, ['system', 'troubleshoot', '--ai'], input='n\n')
    assert result.exit_code == 0, result.output
    assert 'will be sent to OpenAI' in result.output
    assert 'Continue?' in result.output


def test_system_troubleshoot_ai_adds_result_after_explicit_yes(monkeypatch):
    monkeypatch.setattr(
        diagnostics,
        'system_health',
        lambda: {'status': 'completed', 'diagnostics': {}, 'errors': {}},
    )
    monkeypatch.setattr('opsai.infrastructure.openai.analyze', lambda _payload: 'Check disk pressure.')
    result = runner.invoke(
        app,
        ['system', 'troubleshoot', '--ai', '--yes', '--json'],
    )
    assert result.exit_code == 0, result.output
    assert json.loads(result.output)['ai_analysis'] == 'Check disk pressure.'
