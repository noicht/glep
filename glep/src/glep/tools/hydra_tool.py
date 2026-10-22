import re

from glep.tools.base import Tool, ToolResult, validate_host

# [22][ssh] host: 192.168.1.10   login: root   password: toor
_CRED_RE = re.compile(
    r"\[(?P<port>\d+)\]\[(?P<service>[^\]]+)\]\s+host:\s+(?P<host>\S+)\s+"
    r"login:\s+(?P<login>\S+)\s+password:\s+(?P<password>.+?)\s*$"
)


class HydraTool(Tool):
    name = "hydra"
    binary = "hydra"
    requires_args = ("host",)

    def validate_args(self, args: dict) -> str | None:
        error = super().validate_args(args)
        if error:
            return error
        for key in ("userlist", "passlist"):
            if key in args and not self._existing_file(args[key]):
                return f"wordlist no encontrada: {args[key]}"
        return None

    def build_command(self, args: dict) -> list[str]:
        host = validate_host(args["host"])
        service = str(args.get("service", "ssh")).strip()
        if not re.fullmatch(r"[A-Za-z0-9_.\-]{1,32}", service):
            raise ValueError(f"servicio inválido: {service}")

        userlist = str(args.get("userlist", "/opt/glep/wordlists/users.txt"))
        passlist = str(args.get("passlist", "/opt/glep/wordlists/passwords.txt"))
        for wordlist in (userlist, passlist):
            if not self._existing_file(wordlist):
                raise ValueError(f"wordlist no encontrada: {wordlist}")

        port = int(args.get("port", 0))
        target = f"{service}://{host}" + (f":{port}" if port else "")
        return [
            "hydra",
            "-L",
            userlist,
            "-P",
            passlist,
            "-t",
            "4",      # bajo a propósito: no tumbar el servicio objetivo
            "-f",     # cortar al encontrar la primera credencial válida
            "-I",     # ignorar restore files de corridas anteriores
            target,
        ]

    def parse(self, result: ToolResult) -> dict:
        findings: list[dict] = []
        for line in result.stdout.splitlines():
            match = _CRED_RE.search(line.strip())
            if not match:
                continue
            findings.append(
                {
                    "type": "valid_credentials",
                    "severity": "critical",
                    "host": match.group("host"),
                    "port": int(match.group("port")),
                    "service": match.group("service"),
                    "username": match.group("login"),
                    "password": match.group("password"),
                    "evidence": f"{match.group('service')}: {match.group('login')}:{match.group('password')}",
                    "source": "hydra",
                }
            )

        errors = []
        if result.returncode != 0 and not findings and result.stderr.strip():
            errors.append(f"hydra: {result.stderr.strip()[:300]}")
        return {"findings": findings, "errors": errors}
