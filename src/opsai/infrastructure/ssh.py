"""OpenSSH transport: read-only commands and strict host-key verification."""
import json
from pathlib import Path
import subprocess
from opsai.domain.servers import Server

REMOTE_SCRIPT = """LC_ALL=C; export LC_ALL; printf '--- uptime ---\\n' 2>/dev/null || true; uptime; printf '%s\\n' '--- memory ---'; free -m; printf '%s\\n' '--- disk ---'; df -hP /; printf '%s\\n' '--- load ---'; cat /proc/loadavg"""
# No user-supplied command is ever executed remotely.


def load_inventory(path: Path) -> list[Server]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or not isinstance(data.get("servers"), list):
        raise ValueError("Inventory must contain a 'servers' array")
    servers = []
    names = set()
    for entry in data["servers"]:
        if not isinstance(entry, dict) or set(entry) - {"name", "host", "user", "port", "identity_file"}:
            raise ValueError("Invalid inventory server entry")
        server = Server(**entry)
        if server.name in names:
            raise ValueError(f"Duplicate server name: {server.name}")
        names.add(server.name)
        servers.append(server)
    if not servers:
        raise ValueError("Inventory has no servers")
    return servers


class SSHRunner:
    def __init__(self, timeout: int = 12):
        if not 1 <= timeout <= 120:
            raise ValueError("timeout must be 1..120 seconds")
        self.timeout = timeout

    def run(self, server: Server) -> str:
        args = ["ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
                "-o", "ConnectTimeout=5", "-o", "LogLevel=ERROR",
                "-p", str(server.port)]
        if server.identity_file:
            args.extend(["-i", str(Path(server.identity_file).expanduser())])
        args.extend(["--", f"{server.user}@{server.host}", "sh", "-c", REMOTE_SCRIPT])
        try:
            result = subprocess.run(args, capture_output=True, text=True, timeout=self.timeout, check=False)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise RuntimeError(f"SSH connection failed: {type(exc).__name__}") from exc
        if result.returncode:
            raise RuntimeError(f"SSH exited with status {result.returncode}; check host key, access and permissions")
        return result.stdout[:20000]
