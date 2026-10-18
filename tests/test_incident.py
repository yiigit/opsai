import json
import pytest
from typer.testing import CliRunner
from opsai.cli import app
from opsai.incident.agent import (load_evidence, investigate, execute_approved, ai_assessment)


class FakeExecutor:
    def __init__(self): self.calls = []
    def restart(self, service):
        self.calls.append(service)
        return "mocked"


def evidence():
    return {"source": "nginx", "logs": ["nginx failed to start", "nginx: [error] bad gateway"]}


def test_investigation_suggests_bounded_action():
    result = investigate(evidence())
    assert result["status"] == "needs_attention"
    assert result["suggested_actions"][0]["id"] == "restart-nginx"


def test_no_restart_for_unrelated_error():
    assert investigate({"source": "laravel", "logs": ["Laravel ERROR database timeout"]})["suggested_actions"] == []


def test_action_requires_exact_approval():
    fake = FakeExecutor()
    report = investigate(evidence())
    with pytest.raises(PermissionError): execute_approved(report, "restart-nginx", "yes", fake)
    assert fake.calls == []
    assert execute_approved(report, "restart-nginx", "APPROVE restart-nginx", fake) == "mocked"
    assert fake.calls == ["nginx"]


def test_unknown_action_rejected():
    with pytest.raises(ValueError): execute_approved(investigate(evidence()), "rm-everything", "APPROVE rm-everything", FakeExecutor())


def test_load_evidence_validation(tmp_path):
    path = tmp_path / "evidence.json"
    path.write_text(json.dumps(evidence()))
    assert load_evidence(path) == evidence()
    path.write_text(json.dumps({"logs": [123]}))
    with pytest.raises(ValueError): load_evidence(path)


def test_cli_json(tmp_path):
    path = tmp_path / "evidence.json"
    path.write_text(json.dumps(evidence()))
    result = CliRunner().invoke(app, ["incident", "--evidence", str(path), "--json"])
    assert result.exit_code == 0, result.output
    assert json.loads(result.output)["suggested_actions"]


def test_cli_refuses_execution_without_action(tmp_path):
    path = tmp_path / "evidence.json"
    path.write_text(json.dumps(evidence()))
    result = CliRunner().invoke(app, ["incident", "--evidence", str(path), "--execute"])
    assert result.exit_code == 1


def test_ai_uses_existing_adapter(monkeypatch):
    import opsai.infrastructure.openai as adapter
    seen = []
    monkeypatch.setattr(adapter, "analyze_logs", lambda payload: seen.append(payload) or "diagnostics")
    assert ai_assessment(investigate(evidence())) == "diagnostics"
    assert seen[0]["source"] == "nginx"
