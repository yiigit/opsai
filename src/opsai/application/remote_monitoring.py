"""Concurrent SSH monitoring use case; transport injected for testing."""
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Protocol
from opsai.domain.servers import Server
from opsai.domain.triage import redact

class RemoteRunner(Protocol):
    def run(self, server: Server) -> str: ...

@dataclass
class RemoteMonitoringService:
    runner: RemoteRunner

    def check(self, servers: list[Server], workers: int = 4) -> list[dict]:
        if not 1 <= workers <= 16:
            raise ValueError("workers must be 1..16")
        def check_one(server: Server) -> dict:
            try:
                output = self.runner.run(server)
                return {"name": server.name, "status": "ok", "output": redact(output)[:20000]}
            except (RuntimeError, OSError, ValueError) as exc:
                return {"name": server.name, "status": "error", "error": str(exc)}
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {pool.submit(check_one, server): index for index, server in enumerate(servers)}
            results = [None] * len(servers)
            for future in as_completed(futures):
                results[futures[future]] = future.result()
        return results
