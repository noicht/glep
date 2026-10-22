from glep.policy.llm import LLMPolicy
from glep.state import EngagementState
from glep.tools import TOOL_REGISTRY
from glep.tools.base import Tool, ToolResult


class FakeTool(Tool):
    def __init__(self, name: str, requires: tuple[str, ...] = ()):
        self.name = name
        self.requires_args = requires

    def available(self) -> bool:
        return True

    def build_command(self, args: dict) -> list[str]:
        return ["true"]

    def parse(self, result: ToolResult) -> dict:
        return {}


def _policy() -> LLMPolicy:
    return object.__new__(LLMPolicy)


def _state() -> EngagementState:
    return EngagementState(
        target_host="127.0.0.1",
        target_port_range="12000-19999",
        open_ports=[18080],
        web_port_hints=[18080],
    )


def test_llm_accepts_valid_action(monkeypatch):
    monkeypatch.setitem(TOOL_REGISTRY, "nmap", FakeTool("nmap", ("host",)))
    state = _state()
    assert _policy()._is_valid(
        {"tool": "nmap", "args": {"host": "127.0.0.1", "port_range": "12000-19999"}},
        state,
    )


def test_llm_rejects_wrong_host(monkeypatch):
    monkeypatch.setitem(TOOL_REGISTRY, "nmap", FakeTool("nmap", ("host",)))
    state = _state()
    assert not _policy()._is_valid(
        {"tool": "nmap", "args": {"host": "10.0.0.1"}}, state
    )


def test_llm_rejects_tool_outside_phase(monkeypatch):
    monkeypatch.setitem(TOOL_REGISTRY, "sqlmap", FakeTool("sqlmap", ("url",)))
    state = _state()  # RECON
    assert not _policy()._is_valid(
        {"tool": "sqlmap", "args": {"url": "http://127.0.0.1:18080/?id=1"}}, state
    )


def test_llm_rejects_external_url(monkeypatch):
    monkeypatch.setitem(TOOL_REGISTRY, "curl", FakeTool("curl"))
    state = _state()
    state.phase = state.phase.VULN_SCAN
    assert not _policy()._is_valid(
        {"tool": "curl", "args": {"url": "http://example.com/"}}, state
    )
    assert _policy()._is_valid(
        {"tool": "curl", "args": {"url": "http://127.0.0.1:18080/"}}, state
    )


def test_llm_rejects_already_ran(monkeypatch):
    monkeypatch.setitem(TOOL_REGISTRY, "nmap", FakeTool("nmap", ("host",)))
    state = _state()
    action = {"tool": "nmap", "args": {"host": "127.0.0.1", "port_range": "12000-19999"}}
    state.record_action(action)
    assert not _policy()._is_valid(action, state)
