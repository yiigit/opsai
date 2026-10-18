"""Ports used by the application layer."""
from typing import Protocol

class LogCollector(Protocol):
    def collect(self, source: str, *, lines: int, path: object, unit: str) -> list[str]: ...

class LogAnalyzer(Protocol):
    def analyze(self, summary: dict) -> str: ...
