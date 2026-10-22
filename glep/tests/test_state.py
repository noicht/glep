from glep.state import EngagementState, Phase


def test_findings_are_deduplicated():
    state = EngagementState(target_host="127.0.0.1")
    finding = {
        "type": "sql_injection_candidate",
        "severity": "high",
        "url": "http://x/?id=1",
        "evidence": "syntax error",
    }
    state.add_findings([finding, dict(finding), {**finding, "evidence": "other"}])
    assert len(state.findings) == 2


def test_complete_args_fills_target_values():
    state = EngagementState(
        target_host="10.0.0.5",
        target_port_range="1-1000",
        services={8080: "http"},
    )
    assert state.complete_args("nmap", {}) == {
        "host": "10.0.0.5",
        "port_range": "1-1000",
    }
    assert state.complete_args("nikto", {"port": 8080}) == {
        "host": "10.0.0.5",
        "port": 8080,
        "scheme": "http",
    }


def test_web_ports_uses_services_and_hints():
    state = EngagementState(
        target_host="127.0.0.1",
        web_port_hints=[18080],
        open_ports=[18080, 2222, 443],
        services={18080: "http", 2222: "ssh", 443: "ssl/https"},
    )
    assert state.web_ports() == [443, 18080]
    assert state.scheme_for(443) == "https"
    assert state.scheme_for(18080) == "http"


def test_summary_counts_severities():
    state = EngagementState(target_host="127.0.0.1", phase=Phase.DONE)
    state.add_findings(
        [
            {"type": "a", "severity": "high", "evidence": "x"},
            {"type": "b", "severity": "high", "evidence": "y"},
            {"type": "c", "severity": "low", "evidence": "z"},
        ]
    )
    summary = state.summary()
    assert summary["severity_counts"] == {"high": 2, "low": 1}
    assert summary["phase"] == "DONE"
