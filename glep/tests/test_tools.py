import pytest

from glep.tools.base import Tool, ToolResult, validate_host, validate_port_range
from glep.tools.curl_tool import CurlTool, sqli_probe_url
from glep.tools.dig_tool import DigTool
from glep.tools.hydra_tool import HydraTool
from glep.tools.nikto_tool import NiktoTool
from glep.tools.nmap_tool import NmapTool
from glep.tools.sqlmap_tool import SqlmapTool

NMAP_XML = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap">
  <host>
    <ports>
      <port protocol="tcp" portid="18080">
        <state state="open"/>
        <service name="http" product="Apache httpd" version="2.4.49"/>
      </port>
      <port protocol="tcp" portid="12222">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="7.4"/>
      </port>
      <port protocol="tcp" portid="22">
        <state state="closed"/>
        <service name="ssh"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""


def result(tool: str, stdout: str = "", stderr: str = "", rc: int = 0, args=None):
    return ToolResult(
        tool=tool,
        returncode=rc,
        stdout=stdout,
        stderr=stderr,
        args=args or {},
    )


def test_nmap_xml_parser():
    parsed = NmapTool().parse(result("nmap", NMAP_XML))
    assert parsed["open_ports"] == [12222, 18080]
    assert "http" in parsed["services"][18080]
    assert "OpenSSH" in parsed["services"][12222]


def test_nmap_text_fallback():
    stdout = "18080/tcp open  http    Apache httpd 2.4.49\n22/tcp closed ssh\n"
    parsed = NmapTool()._parse_text(stdout)
    assert parsed["open_ports"] == [18080]
    assert "Apache" in parsed["services"][18080]


def test_curl_parser_extracts_links_form_and_sqli():
    body = (
        'HTTP/1.0 200 OK\r\nServer: Apache/2.4.49\r\n\r\n'
        '<html><head><title>Lab</title></head><body>'
        '<a href="/product?id=1">p</a>'
        '<form action="/login" method="post"><input name="username"></form>'
        "You have an error in your SQL syntax near '1'''"
        "</body></html>"
    )
    parsed = CurlTool().parse(
        result(
            "curl",
            body,
            args={"url": "http://127.0.0.1:18080/product?id=1'", "probe": "sqli"},
        )
    )

    assert parsed["findings"][0]["type"] == "sql_injection_candidate"
    assert "http://127.0.0.1:18080/product?id=1" in parsed["urls"]
    assert parsed["forms"][0]["method"] == "POST"
    assert parsed["forms"][0]["inputs"] == ["username"]


def test_curl_parser_directory_listing():
    body = "HTTP/1.0 200 OK\r\n\r\n<html><title>Index of /</title></html>"
    parsed = CurlTool().parse(
        result("curl", body, args={"url": "http://127.0.0.1:18080/"})
    )
    assert any(f["type"] == "directory_listing" for f in parsed["findings"])


def test_sqli_probe_url_only_with_query():
    assert sqli_probe_url("http://h/") is None
    probe = sqli_probe_url("http://h/product?id=1&q=x")
    assert probe == "http://h/product?id=1%27&q=x%27"


def test_nikto_parser():
    stdout = (
        "+ Target IP: 127.0.0.1\n"
        "+ /admin/: Admin login page/section found.\n"
        "+ /backup.zip: Backup file found.\n"
        "+ OSVDB-1234: /x: vulnerable thing\n"
    )
    parsed = NiktoTool().parse(
        result("nikto", stdout, args={"host": "127.0.0.1", "port": 18080})
    )
    types = {finding["type"] for finding in parsed["findings"]}
    assert types == {"nikto"}
    assert len(parsed["findings"]) == 3
    severities = {finding["severity"] for finding in parsed["findings"]}
    assert "high" in severities
    assert "medium" in severities


def test_hydra_parser():
    stdout = "[22][ssh] host: 192.168.0.10   login: root   password: toor\n"
    parsed = HydraTool().parse(result("hydra", stdout))
    finding = parsed["findings"][0]
    assert finding["type"] == "valid_credentials"
    assert finding["severity"] == "critical"
    assert finding["username"] == "root"
    assert finding["password"] == "toor"


def test_sqlmap_parser_vulnerable():
    stdout = (
        "sqlmap identified the following injection point(s):\n"
        "Parameter: id (GET)\n"
        "    Type: boolean-based blind\n"
        "back-end DBMS: MySQL >= 5.0\n"
    )
    parsed = SqlmapTool().parse(
        result("sqlmap", stdout, args={"url": "http://h/product?id=1"})
    )
    finding = parsed["findings"][0]
    assert finding["type"] == "sql_injection"
    assert finding["parameter"] == "id"
    assert "MySQL" in finding["dbms"]


def test_sqlmap_parser_not_vulnerable():
    stdout = "all tested parameters do not appear to be injectable\n"
    parsed = SqlmapTool().parse(
        result("sqlmap", stdout, args={"url": "http://h/product?id=1"})
    )
    assert parsed["findings"] == []


def test_dig_parser():
    parsed = DigTool().parse(result("dig", "1.2.3.4\n5.6.7.8\n"))
    assert parsed["dns_records"] == ["1.2.3.4", "5.6.7.8"]


def test_argument_validation_blocks_flag_injection():
    with pytest.raises(ValueError):
        validate_host("-oN")
    with pytest.raises(ValueError):
        validate_port_range("1-1024; rm -rf /")
    with pytest.raises(ValueError):
        NmapTool().build_command({"host": "127.0.0.1", "port_range": "--script"})


class MissingBinaryTool(Tool):
    name = "missing"
    binary = "definitely-not-a-real-binary-glep"

    def build_command(self, args: dict) -> list[str]:
        return [self.binary]

    def parse(self, result: ToolResult) -> dict:
        return {}


def test_missing_binary_is_reported_not_raised():
    tool_result = MissingBinaryTool().run({})
    assert tool_result.returncode == -1
    assert "binario no encontrado" in tool_result.stderr
