from opsai.application.log_analysis import LogAnalysisService

class FakeCollector:
    def collect(self, source, *, lines, path, unit):
        return ["ERROR failed to connect", "WARN retrying"]

class FakeAnalyzer:
    def analyze(self, summary):
        return "Investigate connectivity"

def test_offline_use_case():
    result = LogAnalysisService(FakeCollector()).run("linux")
    assert result["error_lines"] == 1
    assert result["warning_lines"] == 1

def test_injected_ai():
    result = LogAnalysisService(FakeCollector(), FakeAnalyzer()).run("linux", ai=True)
    assert result["ai_analysis"] == "Investigate connectivity"

def test_ai_requires_adapter():
    import pytest
    with pytest.raises(RuntimeError, match="not configured"):
        LogAnalysisService(FakeCollector()).run("linux", ai=True)
