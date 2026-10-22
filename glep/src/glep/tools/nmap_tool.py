import re
import xml.etree.ElementTree as ET

from glep.tools.base import Tool, ToolResult, validate_host, validate_port_range


class NmapTool(Tool):
    name = "nmap"
    binary = "nmap"
    requires_args = ("host",)

    def build_command(self, args: dict) -> list[str]:
        host = validate_host(args["host"])
        port_range = validate_port_range(args.get("port_range", "1-1024"))
        return [
            "nmap",
            "-Pn",                # el lab puede no responder a ping
            "-sV",                # detectar servicio/versión para la policy
            "--version-light",    # suficiente y mucho más rápido en la Pi
            "--host-timeout",
            "120s",
            "-p",
            port_range,
            "-oX",
            "-",                  # XML a stdout: parseo estable, no depende del locale
            host,
        ]

    def parse(self, result: ToolResult) -> dict:
        if not result.stdout.strip():
            return {"open_ports": [], "services": {}, "errors": [result.stderr] if result.stderr else []}

        try:
            return self._parse_xml(result.stdout)
        except ET.ParseError:
            # Fallback por si nmap imprime warnings antes/después del XML.
            return self._parse_text(result.stdout)

    @staticmethod
    def _parse_xml(stdout: str) -> dict:
        start = stdout.find("<nmaprun")
        if start > 0:
            stdout = stdout[start:]
        root = ET.fromstring(stdout)

        open_ports: list[int] = []
        services: dict[int, str] = {}

        for port_node in root.findall(".//port"):
            state = port_node.find("state")
            if state is None or state.get("state") != "open":
                continue

            try:
                port = int(port_node.get("portid", ""))
            except ValueError:
                continue

            service = port_node.find("service")
            parts: list[str] = []
            if service is not None:
                for key in ("name", "product", "version", "extrainfo"):
                    value = (service.get(key) or "").strip()
                    if value and value not in parts:
                        parts.append(value)

            open_ports.append(port)
            services[port] = " ".join(parts) or "unknown"

        return {"open_ports": sorted(open_ports), "services": services}

    @staticmethod
    def _parse_text(stdout: str) -> dict:
        # Formato normal de nmap: "18080/tcp open  http    Python http.server 3.12"
        pattern = re.compile(
            r"^(?P<port>\d+)/(?:tcp|udp)\s+open\s+(?P<service>\S+)(?:\s+(?P<rest>.+))?$"
        )
        open_ports: list[int] = []
        services: dict[int, str] = {}
        for line in stdout.splitlines():
            match = pattern.match(line.strip())
            if not match:
                continue
            port = int(match.group("port"))
            service = match.group("service")
            rest = (match.group("rest") or "").strip()
            open_ports.append(port)
            services[port] = f"{service} {rest}".strip()
        return {"open_ports": sorted(open_ports), "services": services}
