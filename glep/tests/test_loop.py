import logging

from glep.loop import ReactLoop
from glep.policy.deterministic import DeterministicPolicy
from glep.state import EngagementState, Phase
from glep.tools import TOOL_REGISTRY
from glep.tools.base import Tool, ToolResult


class FakeTool(Tool):
    def __init__(self, name: str, parsed: dict | None = None, available: bool = True):
        self.name = name
        self._parsed = parsed or {}
        self._available = available

    def available(self) -> bool:
        return self._available

    def build_command(self, args: dict) -> list[str]:
        return ["true"]

    def run(self, args: dict, timeout_seconds: int = 60) -> ToolResult:
        return ToolResult(
            tool=self.name, returncode=0, stdout="", stderr="", args=args
        )

    def parse(self, result: ToolResult) -> dict:
        return dict(self._parsed)


class FakeCurlTool(FakeTool):
    def parse(self, result: ToolResult) -> dict:
        base = result.args.get("url", "")
        if result.args.get("probe") == "sqli":
            return {
                "findings": [
                    {
                        "type": "sql_injection_candidate",
                        "severity": "high",
                        "url": base,
                        "evidence": "SQL syntax error",
                        "source": "curl",
                    }
                ]
            }
        return {
            "urls": [base, "http://127.0.0.1:18080/product?id=1"],
            "forms": [{"action": base, "method": "POST", "inputs": ["username"]}],
        }


def _install_fakes(monkeypatch, available: bool = True) -> None:
    fakes = {
        "nmap": FakeTool(
            "nmap",
            {
                "open_ports": [18080, 12222],
                "services": {18080: "http", 12222: "ssh OpenSSH 7.4"},
            },
            available,
        ),
        "dig": FakeTool("dig", {"dns_records": ["127.0.0.1"]}, available),
        "curl": FakeCurlTool("curl", available=available),
        "nikto": FakeTool(
            "nikto",
            {
                "findings": [
                    {
                        "type": "nikto",
                        "severity": "medium",
                        "port": 18080,
                        "evidence": "backup file found",
                        "source": "nikto",
                    }
                ]
            },
            available,
        ),
        "sqlmap": FakeTool(
            "sqlmap",
            {
                "findings": [
                    {
                        "type": "sql_injection",
                        "severity": "critical",
                        "url": "http://127.0.0.1:18080/product?id=1%27",
                        "evidence": "parameter=id",
                        "source": "sqlmap",
                    }
                ]
            },
            available,
        ),
        "hydra": FakeTool("hydra", {}, available),
    }
    for name, fake in fakes.items():
        monkeypatch.setitem(TOOL_REGISTRY, name, fake)


def test_loop_reaches_done_with_observation_flow(monkeypatch):
    _install_fakes(monkeypatch)
    logger = logging.getLogger("test")
    logger.addHandler(logging.NullHandler())

    loop = ReactLoop(policy=DeterministicPolicy(), logger=logger, max_iterations=30)
    state = EngagementState(target_host="127.0.0.1", target_port_range="1-1024")
    final_state = loop.run(state)

    assert final_state.phase == Phase.DONE
    assert 18080 in final_state.open_ports
    assert final_state.services[18080] == "http"
    types = {finding["type"] for finding in final_state.findings}
    assert "sql_injection_candidate" in types
    assert "sql_injection" in types

    tools = [action["tool"] for action in final_state.executed_actions]
    assert tools[:2] == ["nmap", "dig"]
    assert "curl" in tools
    assert "sqlmap" in tools


def test_loop_skips_missing_binaries_and_still_finishes(monkeypatch):
    _install_fakes(monkeypatch, available=False)
    logger = logging.getLogger("test-missing")

    state = EngagementState(target_host="127.0.0.1", target_port_range="1-1024")
    final_state = ReactLoop(
        policy=DeterministicPolicy(), logger=logger, max_iterations=20
    ).run(state)

    assert final_state.phase == Phase.DONE
    skipped = [a for a in final_state.executed_actions if a.get("skipped")]
    assert len(skipped) >= 2
    assert any("binario no encontrado" in error for error in final_state.errors)


def test_deterministic_policy_recon_order():
    policy = DeterministicPolicy()
    state = EngagementState(target_host="127.0.0.1")

    first_action = policy.decide(state)
    assert first_action["tool"] == "nmap"
    assert first_action["args"]["port_range"] == "1-1024"

    state.record_action(first_action)
    second_action = policy.decide(state)
    assert second_action["tool"] == "dig"
