"""Validated remote inventory models."""
from dataclasses import dataclass
import re

_SAFE = re.compile(r"^[A-Za-z0-9_.@:-]+$")

@dataclass(frozen=True)
class Server:
    name: str
    host: str
    user: str
    port: int = 22
    identity_file: str | None = None

    def __post_init__(self):
        for key in ("name", "host", "user"):
            value = getattr(self, key)
            if not value or not _SAFE.fullmatch(value) or value.startswith("-"):
                raise ValueError(f"Invalid {key}: {value!r}")
        if not 1 <= self.port <= 65535:
            raise ValueError("port must be between 1 and 65535")
        if self.identity_file is not None and (not self.identity_file.strip() or "\n" in self.identity_file):
            raise ValueError("Invalid identity_file")
