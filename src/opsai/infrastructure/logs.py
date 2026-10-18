"""Read-only, bounded log collection, redaction and deterministic triage."""
import re
import shutil
import subprocess
from pathlib import Path

MAX_LINES = 300
MAX_LINE_CHARS = 1200
MAX_BYTES = 2_000_000

def tail_file(path: Path, lines: int) -> list[str]:
    """Read up to MAX_BYTES from the end, without loading a large file."""
    if not path.is_file():
        raise ValueError(f'Log file not found: {path}')
    with path.open('rb') as stream:
        stream.seek(0, 2)
        size = stream.tell()
        stream.seek(max(0, size - MAX_BYTES))
        data = stream.read(MAX_BYTES)
    if size > MAX_BYTES:
        data = data.split(b'\n', 1)[-1]
    return data.decode('utf-8', errors='replace').splitlines()[-lines:]


def collect(source: str, lines: int = 100, path: Path | None = None,
            unit: str = 'nginx') -> list[str]:
    if not 1 <= lines <= MAX_LINES:
        raise ValueError(f'--lines must be between 1 and {MAX_LINES}')
    if source == 'linux':
        if path is not None:
            return tail_file(path, lines)
        if not shutil.which('journalctl'):
            raise RuntimeError('journalctl unavailable; use --path for a log file')
        if not re.fullmatch(r'[A-Za-z0-9_.@-]{1,100}', unit):
            raise ValueError('Invalid systemd unit name')
        try:
            result = subprocess.run(
                ['journalctl', '--no-pager', '--output=short-iso', '-u', unit,
                 '-n', str(lines)], capture_output=True, text=True, timeout=15,
                check=True)
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
            raise RuntimeError('journalctl failed; check unit and permissions') from exc
        return result.stdout.splitlines()[-lines:]
    if source == 'nginx':
        return tail_file(path or Path('/var/log/nginx/error.log'), lines)
    if source == 'laravel':
        if path is not None:
            return tail_file(path, lines)
        log_dir = Path('storage/logs')
        default = log_dir / 'laravel.log'
        if default.is_file():
            return tail_file(default, lines)
        # Laravel daily logging produces laravel-YYYY-MM-DD.log files.
        candidates = sorted(log_dir.glob('laravel-????-??-??.log'), reverse=True) if log_dir.is_dir() else []
        if candidates:
            return tail_file(candidates[0], lines)
        raise ValueError(f'Laravel log not found in {log_dir}; use --path')
    raise ValueError('Source must be linux, nginx or laravel')



# Backwards-compatible exports for existing integrations.
from opsai.domain.triage import redact, summarize
