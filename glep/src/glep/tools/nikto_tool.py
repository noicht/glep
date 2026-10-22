import re

from glep.tools.base import Tool, ToolResult, validate_host

_SKIP_PREFIXES = (
    "target ip:",
    "target hostname:",
    "target port:",
    "start time:",
    "end time:",
    "server:",
    "no web server found",
    "0 item(s) reported",
    "1 host(s) tested",
)

_HIGH_HINTS = ("vulnerable", "osvdb", "injection", "xss", "cross site", "rce", "shell")
_MEDIUM_HINTS = (
    "found",
    "backup",
    "admin",
    "config",
    "disclosure",
    "directory",
    "listing",
    "outdated",
)


class NiktoTool(Tool):
    name = "nikto"
    binary = "nikto"
    requires_args = ("host",)

    def build_command(self, args: dict) -> list[str]:
        host = validate_host(args["host"])
        port = int(args.get("port", 80))
        if not 1 <= port <= 65535:
            raise ValueError(f"puerto inválido: {port}")
        scheme = args.get("scheme", "https" if port == 443 else "http")
        if scheme not in ("http", "https"):
            raise ValueError(f"scheme inválido: {scheme}")

        target = f"{scheme}://{host}:{port}"
        return [
            "nikto",
            "-h",
            target,
            "-nointeractive",
            "-ask",
            "no",
            "-maxtime",
            "120s",
            "-Tuning",
            "123b",  # técnicas razonables para un scan rápido, no todas
        ]

    def parse(self, result: ToolResult) -> dict:
        findings: list[dict] = []
        port = int(result.args.get("port", 80))
        host = result.args.get("host", "")
        scheme = result.args.get("scheme", "https" if port == 443 else "http")
        base_url = f"{scheme}://{host}:{port}/"

        for raw_line in result.stdout.splitlines():
            line = raw_line.strip()
            if not line.startswith("+"):
                continue
            text = line.lstrip("+").strip()
            lowered = text.lower()
            if not text or lowered.startswith(_SKIP_PREFIXES):
                continue

            if any(hint in lowered for hint in _HIGH_HINTS):
                severity = "high"
            elif any(hint in lowered for hint in _MEDIUM_HINTS):
                severity = "medium"
            else:
                severity = "low"

            # Nikto suele prefijar el path: "+ /admin/: Admin login page".
            path = ""
            match = re.match(r"^(/[^:]*):\s*(.*)$", text)
            if match:
                path = match.group(1)
                text = match.group(2)

            findings.append(
                {
                    "type": "nikto",
                    "severity": severity,
                    "port": port,
                    "url": base_url,
                    "path": path,
                    "evidence": text[:300],
                    "source": "nikto",
                }
            )

        errors = []
        if result.returncode not in (0, 1) and result.stderr.strip():
            errors.append(f"nikto: {result.stderr.strip()[:300]}")

        return {"findings": findings, "errors": errors}
