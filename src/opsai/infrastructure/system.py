import json
import shutil
import subprocess
from datetime import datetime, timezone

import psutil


def health():
    disk = psutil.disk_usage('/')
    memory = psutil.virtual_memory()
    return {
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'cpu_percent': psutil.cpu_percent(interval=0.3),
        'memory_percent': memory.percent,
        'disk_percent': disk.percent,
        'disk_free_gb': round(disk.free / (1024 ** 3), 2),
    }


def docker_status():
    if not shutil.which('docker'):
        raise RuntimeError('Docker CLI not installed')
    try:
        result = subprocess.run(
            ['docker', 'ps', '--format', '{{json .}}'],
            capture_output=True, text=True, timeout=10, check=True,
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError('Unable to query Docker. Check daemon and permissions.') from exc
    return [json.loads(line) for line in result.stdout.splitlines() if line.strip()]
