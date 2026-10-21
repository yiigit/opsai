"""Bounded, read-only Linux and network diagnostics."""
from __future__ import annotations

import ipaddress
import json
import os
import shutil
import socket
import struct
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import psutil

from opsai.domain.triage import redact

MAX_COMMAND_OUTPUT_BYTES = 2 * 1024 * 1024
MAX_PROCESSES = 100
MAX_PARTITIONS = 40
MAX_JOURNAL_LINES = 100
COMMAND_TIMEOUT_SECONDS = 20
NETWORK_TIMEOUT_SECONDS = 4
SECURITY_REPOSITORY_PATTERN = ('security', 'security.debian.org', 'security.ubuntu.com')


def _run_command(arguments: list[str], timeout: int = COMMAND_TIMEOUT_SECONDS) -> str:
    executable = shutil.which(arguments[0])
    if executable is None:
        raise RuntimeError(f'Required command is unavailable: {arguments[0]}')
    try:
        result = subprocess.run(
            [executable, *arguments[1:]],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f'{arguments[0]} timed out after {timeout} seconds') from exc
    except OSError as exc:
        raise RuntimeError(f'Unable to run {arguments[0]}: {exc}') from exc
    if len(result.stdout.encode('utf-8', errors='replace')) > MAX_COMMAND_OUTPUT_BYTES:
        raise RuntimeError(f'{arguments[0]} output exceeded the size limit')
    if result.returncode:
        raise RuntimeError(f'{arguments[0]} failed with exit code {result.returncode}')
    return result.stdout


def cpu_diagnostics() -> dict[str, Any]:
    frequencies = psutil.cpu_freq()
    return {
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'logical_cores': psutil.cpu_count(logical=True),
        'physical_cores': psutil.cpu_count(logical=False),
        'utilization_percent': psutil.cpu_percent(interval=0.2),
        'per_core_percent': psutil.cpu_percent(interval=None, percpu=True),
        'load_average': list(os.getloadavg()),
        'frequency_mhz': (
            {
                'current': round(frequencies.current, 1),
                'minimum': round(frequencies.min, 1),
                'maximum': round(frequencies.max, 1),
            }
            if frequencies is not None else None
        ),
    }


def _read_pressure(name: str) -> str | None:
    path = Path('/proc/pressure') / name
    try:
        return path.read_text(encoding='ascii')[:512].strip()
    except FileNotFoundError:
        return None


def memory_diagnostics() -> dict[str, Any]:
    memory = psutil.virtual_memory()
    swap = psutil.swap_memory()
    return {
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'virtual_memory': {
            'total_bytes': memory.total,
            'available_bytes': memory.available,
            'used_bytes': memory.used,
            'percent': memory.percent,
        },
        'swap': {
            'total_bytes': swap.total,
            'used_bytes': swap.used,
            'free_bytes': swap.free,
            'percent': swap.percent,
        },
        'pressure': {
            name: _read_pressure(name) for name in ('cpu', 'memory', 'io')
        },
    }


def disk_diagnostics() -> dict[str, Any]:
    partitions: list[dict[str, Any]] = []
    for partition in psutil.disk_partitions(all=False)[:MAX_PARTITIONS]:
        usage = psutil.disk_usage(partition.mountpoint)
        partitions.append({
            'device': partition.device,
            'mountpoint': partition.mountpoint,
            'filesystem': partition.fstype,
            'total_bytes': usage.total,
            'used_bytes': usage.used,
            'free_bytes': usage.free,
            'percent': usage.percent,
        })
    io_counters = psutil.disk_io_counters()
    io = None
    if io_counters is not None:
        io = {
            'read_bytes': io_counters.read_bytes,
            'write_bytes': io_counters.write_bytes,
            'read_count': io_counters.read_count,
            'write_count': io_counters.write_count,
        }
    return {'timestamp': datetime.now(timezone.utc).isoformat(), 'partitions': partitions, 'io': io}


def process_diagnostics(limit: int = 10) -> dict[str, Any]:
    if not 1 <= limit <= MAX_PROCESSES:
        raise ValueError(f'Process limit must be between 1 and {MAX_PROCESSES}')
    processes: list[dict[str, Any]] = []
    for process in psutil.process_iter(
        attrs=('pid', 'name', 'username', 'status', 'memory_percent', 'cpu_percent'),
        ad_value=None,
    ):
        info = process.info
        processes.append({
            'pid': info['pid'],
            'name': info['name'],
            'user': info['username'],
            'status': info['status'],
            'memory_percent': round(info['memory_percent'], 2) if info['memory_percent'] is not None else None,
            'cpu_percent': round(info['cpu_percent'], 2) if info['cpu_percent'] is not None else None,
        })
    processes.sort(
        key=lambda item: (item['memory_percent'] or 0, item['cpu_percent'] or 0),
        reverse=True,
    )
    return {
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'limit': limit,
        'processes': processes[:limit],
        'note': 'CPU percentages are per-process samples and may be zero on the first observation.',
    }


def service_diagnostics() -> dict[str, Any]:
    output = _run_command([
        'systemctl', 'list-units', '--failed', '--no-legend', '--plain', '--no-pager',
    ])
    failures = []
    for line in output.splitlines()[:100]:
        fields = line.split(None, 4)
        if fields:
            failures.append({
                'unit': fields[0],
                'load': fields[1] if len(fields) > 1 else '',
                'active': fields[2] if len(fields) > 2 else '',
                'sub': fields[3] if len(fields) > 3 else '',
                'description': fields[4] if len(fields) > 4 else '',
            })
    return {'timestamp': datetime.now(timezone.utc).isoformat(), 'failed_units': failures}


def boot_diagnostics() -> dict[str, Any]:
    boot_time = _run_command(['systemd-analyze', 'time']).strip()
    blame_output = _run_command(['systemd-analyze', 'blame', '--no-pager'])
    return {
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'boot_time': boot_time[:1000],
        'slowest_units': [line[:500] for line in blame_output.splitlines()[:20]],
    }


def journal_diagnostics(lines: int = 50) -> dict[str, Any]:
    if not 1 <= lines <= MAX_JOURNAL_LINES:
        raise ValueError(f'Journal line count must be between 1 and {MAX_JOURNAL_LINES}')
    output = _run_command([
        'journalctl', '--no-pager', '--output=json', '--priority=err', '--lines', str(lines),
    ])
    entries: list[dict[str, Any]] = []
    for line in output.splitlines()[-lines:]:
        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError('journalctl returned invalid JSON output') from exc
        if not isinstance(record, dict):
            raise ValueError('journalctl entries must be JSON objects')
        entries.append({
            'timestamp': record.get('__REALTIME_TIMESTAMP'),
            'priority': record.get('PRIORITY'),
            'unit': record.get('_SYSTEMD_UNIT'),
            'identifier': record.get('SYSLOG_IDENTIFIER'),
            'message': redact(str(record.get('MESSAGE', ''))),
        })
    return {
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'priority_filter': 'err and more severe',
        'entries': entries,
    }


def _apt_security_updates() -> dict[str, Any]:
    output = _run_command(['apt-get', '-s', '-o', 'Debug::NoLocking=1', 'upgrade'])
    updates: list[dict[str, str]] = []
    for line in output.splitlines():
        if not line.startswith('Inst '):
            continue
        fields = line.split()
        if len(fields) < 2:
            continue
        repository_text = line.partition('(')[2].lower()
        if any(marker in repository_text for marker in SECURITY_REPOSITORY_PATTERN):
            updates.append({'package': fields[1], 'simulation': line[:1000]})
    lists_path = Path('/var/lib/apt/lists')
    cache_age_seconds: float | None = None
    try:
        cache_age_seconds = max(0.0, time.time() - lists_path.stat().st_mtime)
    except OSError:
        pass
    return {
        'package_manager': 'apt',
        'source': 'local package cache; no index refresh performed',
        'cache_age_seconds': round(cache_age_seconds) if cache_age_seconds is not None else None,
        'security_updates': updates,
        'count': len(updates),
    }


def _dnf_security_updates() -> dict[str, Any]:
    executable = shutil.which('dnf')
    if executable is None:
        raise RuntimeError('Neither apt-get nor dnf is available for security update checks')
    try:
        result = subprocess.run(
            [executable, '-q', 'check-update', '--security', '--cacheonly'],
            capture_output=True,
            text=True,
            timeout=COMMAND_TIMEOUT_SECONDS,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError('dnf security update check timed out') from exc
    except OSError as exc:
        raise RuntimeError(f'Unable to run dnf: {exc}') from exc
    if result.returncode not in (0, 100):
        raise RuntimeError(f'dnf security update check failed with exit code {result.returncode}')
    if len(result.stdout.encode('utf-8', errors='replace')) > MAX_COMMAND_OUTPUT_BYTES:
        raise RuntimeError('dnf output exceeded the size limit')
    updates = []
    for line in result.stdout.splitlines():
        fields = line.split()
        if len(fields) >= 3 and '.' in fields[0]:
            updates.append({
                'package': fields[0],
                'version': fields[1],
                'repository': fields[2],
            })
    return {
        'package_manager': 'dnf',
        'source': 'local package cache; --cacheonly prevents repository access',
        'security_updates': updates,
        'count': len(updates),
    }


def update_diagnostics() -> dict[str, Any]:
    if shutil.which('apt-get') is not None:
        return _apt_security_updates()
    return _dnf_security_updates()


def _default_routes() -> list[dict[str, str]]:
    path = Path('/proc/net/route')
    try:
        lines = path.read_text(encoding='ascii').splitlines()[1:]
    except OSError as exc:
        raise RuntimeError(f'Cannot read local IPv4 routes from {path}') from exc
    routes = []
    for line in lines:
        fields = line.split()
        if len(fields) < 8 or fields[1] != '00000000':
            continue
        try:
            gateway = socket.inet_ntoa(struct.pack('<I', int(fields[2], 16)))
        except (ValueError, OSError) as exc:
            raise ValueError('Invalid gateway entry in /proc/net/route') from exc
        routes.append({'family': 'ipv4', 'interface': fields[0], 'gateway': gateway})
    return routes


def _default_ipv6_routes() -> list[dict[str, str | None]]:
    path = Path('/proc/net/ipv6_route')
    try:
        lines = path.read_text(encoding='ascii').splitlines()
    except FileNotFoundError:
        return []
    except OSError as exc:
        raise RuntimeError(f'Cannot read local IPv6 routes from {path}') from exc
    routes: list[dict[str, str | None]] = []
    for line in lines:
        fields = line.split()
        if len(fields) < 10 or fields[1] != '00':
            continue
        try:
            gateway_address = ipaddress.IPv6Address(int(fields[4], 16))
        except ValueError as exc:
            raise ValueError('Invalid gateway entry in /proc/net/ipv6_route') from exc
        routes.append({
            'family': 'ipv6',
            'interface': fields[9],
            'gateway': str(gateway_address) if not gateway_address.is_unspecified else None,
        })
    return routes


def _dns_configuration() -> list[str]:
    resolv_conf = Path('/etc/resolv.conf')
    try:
        lines = resolv_conf.read_text(encoding='utf-8', errors='replace').splitlines()
    except OSError as exc:
        raise RuntimeError(f'Cannot read DNS configuration at {resolv_conf}') from exc
    servers = [
        fields[1] for line in lines
        if len(fields := line.split()) >= 2 and fields[0] == 'nameserver'
    ]
    return servers[:16]


def network_diagnostics(host: str | None = None, port: int | None = None) -> dict[str, Any]:
    if (host is None) != (port is None):
        raise ValueError('Provide both --host and --port for an active connectivity probe')
    if host is not None and (
        not host.strip()
        or len(host) > 253
        or any(character.isspace() for character in host)
    ):
        raise ValueError('Host must be 1 to 253 non-whitespace characters')
    if port is not None and not 1 <= port <= 65535:
        raise ValueError('Port must be between 1 and 65535')

    interfaces: list[dict[str, Any]] = []
    stats = psutil.net_if_stats()
    counters = psutil.net_io_counters(pernic=True)
    addresses = psutil.net_if_addrs()
    for name in sorted(set(stats) | set(addresses)):
        interface_stats = stats.get(name)
        interface_addresses = []
        for address in addresses.get(name, []):
            interface_addresses.append({
                'family': str(address.family),
                'address': address.address,
                'netmask': address.netmask,
                'broadcast': address.broadcast,
            })
        interface_counters = counters.get(name) if counters else None
        interfaces.append({
            'name': name,
            'is_up': interface_stats.isup if interface_stats else None,
            'speed_mbps': interface_stats.speed if interface_stats else None,
            'mtu': interface_stats.mtu if interface_stats else None,
            'addresses': interface_addresses,
            'io': ({
                'bytes_sent': interface_counters.bytes_sent,
                'bytes_received': interface_counters.bytes_recv,
                'packets_sent': interface_counters.packets_sent,
                'packets_received': interface_counters.packets_recv,
            } if interface_counters else None),
        })
    payload: dict[str, Any] = {
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'interfaces': interfaces,
        'default_routes': _default_routes() + _default_ipv6_routes(),
        'dns_nameservers': _dns_configuration(),
    }
    if host is not None and port is not None:
        started = time.monotonic()
        try:
            with socket.create_connection((host, port), timeout=NETWORK_TIMEOUT_SECONDS) as connection:
                peer = connection.getpeername()
        except OSError as exc:
            payload['connectivity_probe'] = {
                'host': host,
                'port': port,
                'reachable': False,
                'error': str(exc)[:300],
                'duration_ms': round((time.monotonic() - started) * 1000),
            }
        else:
            payload['connectivity_probe'] = {
                'host': host,
                'port': port,
                'reachable': True,
                'peer': str(peer[0]),
                'duration_ms': round((time.monotonic() - started) * 1000),
            }
    return payload


def system_health() -> dict[str, Any]:
    diagnostics = {
        'cpu': cpu_diagnostics,
        'memory': memory_diagnostics,
        'disk': disk_diagnostics,
        'processes': process_diagnostics,
        'services': service_diagnostics,
        'boot': boot_diagnostics,
        'journal': journal_diagnostics,
        'updates': update_diagnostics,
        'network': network_diagnostics,
    }
    results: dict[str, Any] = {}
    errors: dict[str, str] = {}
    for name, collect in diagnostics.items():
        try:
            results[name] = collect()
        except (OSError, RuntimeError, ValueError, psutil.Error) as exc:
            errors[name] = str(exc)
    return {
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'status': 'partial' if errors else 'completed',
        'diagnostics': results,
        'errors': errors,
    }
