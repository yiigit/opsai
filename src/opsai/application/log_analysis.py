"""Log analysis use case; depends only on domain ports and pure triage."""
from dataclasses import dataclass
from pathlib import Path
from opsai.domain.interfaces import LogCollector, LogAnalyzer
from opsai.domain.models import LogRequest
from opsai.domain.triage import summarize

@dataclass(frozen=True)
class LogAnalysisService:
    collector: LogCollector
    analyzer: LogAnalyzer | None = None

    def run(self, source: str, *, lines: int = 100, path: Path | None = None,
            unit: str = "nginx", ai: bool = False) -> dict:
        request = LogRequest(source=source, lines=lines, path=path, unit=unit)
        summary = summarize(request.source, self.collector.collect(
            request.source, lines=request.lines, path=request.path, unit=request.unit))
        if not ai:
            return summary
        if self.analyzer is None:
            raise RuntimeError("AI analyzer not configured")
        return {"summary": summary, "ai_analysis": self.analyze_summary(summary)}

    def analyze_summary(self, summary: dict) -> str:
        if self.analyzer is None:
            raise RuntimeError("AI analyzer not configured")
        return self.analyzer.analyze(summary)
