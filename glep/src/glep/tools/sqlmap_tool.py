import re

from glep.tools.base import Tool, ToolResult, validate_url


class SqlmapTool(Tool):
    name = "sqlmap"
    binary = "sqlmap"
    requires_args = ("url",)

    def build_command(self, args: dict) -> list[str]:
        url = validate_url(args["url"])
        return [
            "sqlmap",
            "-u",
            url,
            "--batch",
            "--level=1",
            "--risk=1",       # detección, no explotación agresiva
            "--threads=1",
            "--timeout=10",
            "--retries=1",
            "--flush-session",
            "--disable-coloring",
            "--output-dir=/tmp/glep-sqlmap",
        ]

    def parse(self, result: ToolResult) -> dict:
        text = result.stdout + "\n" + result.stderr
        lowered = text.lower()
        url = str(result.args.get("url", ""))
        findings: list[dict] = []

        vulnerable = any(
            marker in lowered
            for marker in (
                "is vulnerable",
                "appears to be injectable",
                "sqlmap identified the following injection point",
                "parameter: ",
            )
        ) and "does not seem to be injectable" not in lowered

        if vulnerable:
            parameter = ""
            parameter_match = re.search(r"Parameter:\s*([^\s(]+)", text, re.I)
            if parameter_match:
                parameter = parameter_match.group(1)

            dbms = ""
            dbms_match = re.search(r"back-end DBMS:\s*(.+)", text, re.I)
            if dbms_match:
                dbms = dbms_match.group(1).strip()

            evidence_parts = []
            if parameter:
                evidence_parts.append(f"parameter={parameter}")
            if dbms:
                evidence_parts.append(f"dbms={dbms}")

            findings.append(
                {
                    "type": "sql_injection",
                    "severity": "critical",
                    "url": url,
                    "parameter": parameter,
                    "dbms": dbms,
                    "evidence": ", ".join(evidence_parts) or "sqlmap confirmó inyección SQL",
                    "source": "sqlmap",
                    "confidence": "high",
                }
            )

        errors = []
        if result.returncode != 0 and not findings:
            detail = (result.stderr or result.stdout).strip().splitlines()
            errors.append(f"sqlmap: {detail[-1][:300] if detail else result.returncode}")
        return {"findings": findings, "errors": errors}
