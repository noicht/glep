import json

from glep.report import build_report, write_report
from glep.state import EngagementState, Phase


def _state() -> EngagementState:
    state = EngagementState(target_host="127.0.0.1", target_port_range="12000-19999")
    state.add_ports([18080], {18080: "http Apache httpd 2.4.49"})
    state.add_findings(
        [
            {
                "type": "sql_injection_candidate",
                "severity": "high",
                "url": "http://127.0.0.1:18080/product?id=1%27",
                "evidence": "SQL syntax error",
                "source": "curl",
            }
        ]
    )
    state.record_action({"tool": "nmap", "args": {"host": "127.0.0.1"}, "returncode": 0})
    state.phase = Phase.DONE
    return state


def test_build_report_contains_meta_and_state():
    report = build_report(_state(), scope={"kind": "loopback"}, policy_mode="deterministic")
    assert report["meta"]["tool"] == "glep"
    assert report["target_host"] == "127.0.0.1"
    assert report["severity_counts"] == {"high": 1}
    assert report["findings"][0]["type"] == "sql_injection_candidate"


def test_write_report_creates_json_and_markdown(tmp_path):
    json_path, md_path = write_report(
        _state(), tmp_path, scope={"kind": "loopback"}, policy_mode="deterministic"
    )
    assert json_path.exists() and md_path.exists()

    payload = json.loads(json_path.read_text())
    assert payload["open_ports"] == [18080]

    markdown = md_path.read_text()
    assert "# GLEP report" in markdown
    assert "sql_injection_candidate" in markdown
    assert "18080" in markdown
