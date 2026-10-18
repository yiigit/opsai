from pathlib import Path
import pytest
from opsai.domain.models import LogRequest
from opsai.domain.triage import redact, summarize
from opsai.application.log_analysis import LogAnalysisService

class Collector:
    def __init__(self):
        self.calls = 0
    def collect(self, source, *, lines, path, unit):
        self.calls += 1
        return ["ERROR password=topsecret", "WARN retry"]

class Analyzer:
    def analyze(self, summary):
        assert "topsecret" not in str(summary)
        return "Check service configuration"

def test_request_validation():
    with pytest.raises(ValueError):
        LogRequest("unknown")
    with pytest.raises(ValueError):
        LogRequest("linux", lines=999)

def test_redaction_before_ai_and_single_collection():
    collector = Collector()
    service = LogAnalysisService(collector, Analyzer())
    summary = service.run("linux")
    assert "topsecret" not in str(summary)
    assert service.analyze_summary(summary) == "Check service configuration"
    assert collector.calls == 1

def test_domain_is_independent_of_infrastructure():
    domain = Path(__file__).resolve().parents[1] / "src/opsai/domain"
    for path in domain.glob("*.py"):
        assert "opsai.infrastructure" not in path.read_text()
