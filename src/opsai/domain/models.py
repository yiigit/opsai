"""Immutable inputs and outputs shared across application boundaries."""
from dataclasses import dataclass
from pathlib import Path

@dataclass(frozen=True)
class LogRequest:
    source: str
    lines: int = 100
    path: Path | None = None
    unit: str = "nginx"

    def __post_init__(self) -> None:
        if self.source not in {"linux", "nginx", "laravel"}:
            raise ValueError("Source must be linux, nginx or laravel")
        if not 1 <= self.lines <= 300:
            raise ValueError("--lines must be between 1 and 300")
