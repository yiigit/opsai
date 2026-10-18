"""Infrastructure adapters implementing application ports."""
from pathlib import Path
from opsai.infrastructure.logs import collect
from opsai.infrastructure.openai import analyze_logs

class LocalLogCollector:
    """Read-only collector for supported local sources."""
    def collect(self, source: str, *, lines: int, path: Path | None, unit: str) -> list[str]:
        return collect(source, lines=lines, path=path, unit=unit)

class OpenAILogAnalyzer:
    """AI adapter; the application does not import the OpenAI SDK."""
    def analyze(self, summary: dict) -> str:
        return analyze_logs(summary)
