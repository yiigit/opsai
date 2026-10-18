"""Deterministic incident investigation. AI is advisory, never an action planner."""
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Protocol
import json
import re
import subprocess

from opsai.domain.triage import redact, summarize

MAX_BYTES = 200_000
ALLOWED_SERVICES = frozenset({"nginx", "php8.2-fpm", "php8.3-fpm", "php8.4-fpm"})


@dataclass(frozen=True)
class Action:
    id: str
    title: str
    service: str
    risk: str = "medium"
    requires_approval: bool = True


class Executor(Protocol):
    def restart(self, service: str) -> str: ...


class SystemctlExecutor:
    def restart(self, service: str) -> str:
        if service not in ALLOWED_SERVICES:
            raise ValueError("Service is not allowlisted")
        result = subprocess.run(["systemctl", "restart", service], capture_output=True,
                                text=True, timeout=30, check=False)
        if result.returncode:
            raise RuntimeError(f"systemctl failed with exit code {result.returncode}")
        return f"Restart requested for {service}"


def load_evidence(path: Path) -> dict:
    if not path.is_file() or path.stat().st_size > MAX_BYTES:
        raise ValueError("Evidence file must exist and be <= 200 KB")
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict) or not isinstance(payload.get("logs"), list):
        raise ValueError("Evidence JSON must be an object with a logs array")
    logs = payload["logs"]
    if len(logs) > 500 or any(not isinstance(x, str) for x in logs):
        raise ValueError("Evidence must contain at most 500 string log lines")
    return {"source": str(payload.get("source", "incident"))[:80], "logs": logs}


def investigate(evidence: dict) -> dict:
    summary = summarize(evidence["source"], evidence["logs"])
    signals = " ".join(evidence["logs"]).lower()
    actions = []
    # Restart is only offered as a possible operator decision, not an AI instruction.
    if re.search(r"nginx.*(failed|inactive|emergency)|failed to start nginx", signals):
        actions.append(asdict(Action("restart-nginx", "Restart local Nginx service", "nginx")))
    return {
        "status": "needs_attention" if summary["error_lines"] else "no_errors_detected",
        "summary": summary,
        "suggested_actions": actions,
        "disclaimer": "Heuristic findings are not confirmed root causes. No action has been executed.",
    }


def execute_approved(report: dict, action_id: str, approval: str, executor: Executor) -> str:
    candidates = [a for a in report["suggested_actions"] if a["id"] == action_id]
    if len(candidates) != 1:
        raise ValueError("Action not present in this investigation")
    action = candidates[0]
    if action["service"] not in ALLOWED_SERVICES:
        raise ValueError("Service is not allowlisted")
    expected = f"APPROVE {action_id}"
    if approval != expected:
        raise PermissionError(f"Approval must match: {expected}")
    return executor.restart(action["service"])


def ai_assessment(report: dict) -> str:
    """Send only bounded, redacted evidence; AI output is never executable."""
    from opsai.infrastructure.openai import analyze_logs
    sanitized = report["summary"].copy()
    sanitized["sample"] = [redact(line) for line in sanitized["sample"]]
    return analyze_logs(sanitized)
