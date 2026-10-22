import re

from glep.tools.base import Tool, ToolResult, validate_host

_RECORD_TYPES = {
    "A", "AAAA", "ANY", "CNAME", "MX", "NS", "PTR", "SOA", "SRV", "TXT",
}


class DigTool(Tool):
    name = "dig"
    binary = "dig"
    requires_args = ("host",)

    def build_command(self, args: dict) -> list[str]:
        host = validate_host(args["host"])
        record_type = str(args.get("record_type", "ANY")).upper()
        if record_type not in _RECORD_TYPES:
            raise ValueError(f"record_type inválido: {record_type}")
        return [
            "dig",
            host,
            record_type,
            "+short",
            "+time=3",
            "+tries=1",
        ]

    def parse(self, result: ToolResult) -> dict:
        records = [line.strip() for line in result.stdout.splitlines() if line.strip()]
        errors = []
        if result.returncode != 0:
            errors.append(f"dig: {result.stderr.strip()[:300] or result.returncode}")
        elif not records and "connection timed out" in result.stderr.lower():
            errors.append(f"dig: timeout resolviendo {result.args.get('host', '')}")

        return {"dns_records": records, "errors": errors}


def looks_like_domain(host: str) -> bool:
    """True si el target es un nombre DNS y no una IP literal."""
    return bool(host) and not re.fullmatch(r"[0-9a-fA-F:.]+", host) and "." in host
