"""Read-only, local Linux and Docker security checks."""
from __future__ import annotations

import json
import os
import re
import stat
import subprocess
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Callable


@dataclass(frozen=True)
class Finding:
    id: str
    severity: str
    title: str
    evidence: str
    recommendation: str

    def as_dict(self) -> dict:
        return asdict(self)


Runner = Callable[[list[str]], str]


def run_readonly(args: list[str]) -> str:
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=12, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError(f'Command unavailable or timed out: {args[0]}') from exc
    if result.returncode:
        raise RuntimeError(f'{args[0]} returned status {result.returncode}: {result.stderr[:160]}')
    return result.stdout


def audit_linux(root: Path = Path('/'), *, uid: int | None = None) -> list[Finding]:
    """Inspect selected local file permissions without changing anything.

    `root` enables isolated tests and offline root-filesystem inspection.
    """
    findings: list[Finding] = []
    checks = [
        ('etc/shadow', 0o077, 'LINUX_SHADOW', 'Sensitive shadow file is accessible to group/others'),
        ('etc/ssh/sshd_config', 0o022, 'LINUX_SSH_CONFIG', 'SSH server configuration is writable by group/others'),
    ]
    for relative, forbidden, identifier, title in checks:
        path = root / relative
        try:
            mode = stat.S_IMODE(path.stat().st_mode)
        except (FileNotFoundError, PermissionError):
            continue
        if mode & forbidden:
            findings.append(Finding(identifier, 'high', title,
                                    f'/{relative}: permissions {mode:04o}',
                                    'Review ownership and permissions using your distribution security baseline.'))

    sshd = root / 'etc/ssh/sshd_config'
    try:
        content = sshd.read_text(encoding='utf-8', errors='replace')
    except (FileNotFoundError, PermissionError):
        content = ''
    # Explicit active directives only; include snippets in the real SSH configuration separately.
    if re.search(r'^\s*PermitRootLogin\s+yes\s*(?:#.*)?$', content, re.I | re.M):
        findings.append(Finding('LINUX_ROOT_SSH', 'high', 'Root SSH login explicitly enabled',
                                'PermitRootLogin yes', 'Prefer a non-root administrative account and disable direct root login.'))
    if re.search(r'^\s*PasswordAuthentication\s+yes\s*(?:#.*)?$', content, re.I | re.M):
        findings.append(Finding('LINUX_SSH_PASSWORD', 'medium', 'SSH password authentication explicitly enabled',
                                'PasswordAuthentication yes', 'Consider key-based authentication and restrict password access.'))
    return findings


def audit_docker(runner: Runner = run_readonly) -> list[Finding]:
    """Use Docker inspection APIs via the CLI; no privileged changes."""
    output = runner(['docker', 'ps', '-q', '--no-trunc'])
    ids = [x.strip() for x in output.splitlines() if x.strip()]
    if not ids:
        return []
    if len(ids) > 200:
        raise ValueError('Refusing to inspect more than 200 containers in one audit')
    raw = runner(['docker', 'inspect', *ids])
    try:
        containers = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError('Docker inspect returned invalid JSON') from exc
    if not isinstance(containers, list):
        raise ValueError('Docker inspect must return an array')
    findings: list[Finding] = []
    for container in containers:
        if not isinstance(container, dict):
            continue
        name = str(container.get('Name') or container.get('Id') or 'unknown').lstrip('/')[:100]
        host = container.get('HostConfig') or {}
        config = container.get('Config') or {}
        if host.get('Privileged') is True:
            findings.append(Finding('DOCKER_PRIVILEGED', 'critical', f'{name}: privileged container',
                                    'HostConfig.Privileged=true', 'Remove privileged mode and grant only required capabilities.'))
        if host.get('NetworkMode') == 'host':
            findings.append(Finding('DOCKER_HOST_NETWORK', 'medium', f'{name}: host networking',
                                    'HostConfig.NetworkMode=host', 'Prefer an isolated bridge network where feasible.'))
        if host.get('PidMode') == 'host':
            findings.append(Finding('DOCKER_HOST_PID', 'high', f'{name}: host PID namespace',
                                    'HostConfig.PidMode=host', 'Avoid sharing the host PID namespace.'))
        if host.get('ReadonlyRootfs') is False:
            findings.append(Finding('DOCKER_WRITABLE_ROOT', 'low', f'{name}: writable root filesystem',
                                    'HostConfig.ReadonlyRootfs=false', 'Consider a read-only root filesystem with dedicated writable mounts.'))
        user = str(config.get('User') or '')
        if user in ('', '0', 'root', '0:0'):
            findings.append(Finding('DOCKER_ROOT_USER', 'medium', f'{name}: root user configured',
                                    'Config.User is root or unspecified', 'Configure a non-root container user where supported.'))
        binds = host.get('Binds') or []
        for bind in binds:
            if isinstance(bind, str) and bind.split(':', 1)[0] in ('/', '/var/run/docker.sock'):
                findings.append(Finding('DOCKER_HOST_MOUNT', 'high', f'{name}: sensitive host mount',
                                        'Host root or Docker socket bind mount detected', 'Avoid mounting host root and the Docker socket.'))
        mounts = container.get('Mounts') or []
        for mount in mounts:
            if isinstance(mount, dict) and mount.get('Source') in ('/', '/var/run/docker.sock'):
                if not any(f.id == 'DOCKER_HOST_MOUNT' and f.title.startswith(name + ':') for f in findings):
                    findings.append(Finding('DOCKER_HOST_MOUNT', 'high', f'{name}: sensitive host mount',
                                            'Host root or Docker socket mount detected', 'Avoid mounting host root and the Docker socket.'))
    return findings


def report(target: str, findings: list[Finding], errors: list[str] | None = None) -> dict:
    return {'target': target, 'findings': [f.as_dict() for f in findings],
            'counts': {severity: sum(f.severity == severity for f in findings)
                       for severity in ('critical', 'high', 'medium', 'low')},
            'errors': errors or [], 'status': 'partial' if errors else 'completed'}
