"""Policy determinística: reglas fijas según fase + lo observado hasta
ahora. Es el modo por defecto y el fallback de LLMPolicy.

El orden importa: recon primero (nmap/dig), después se atacan solo los
puertos web que nmap detectó, se buscan candidatos de SQLi en los query
params descubiertos y recién al final se intenta confirmar con sqlmap.
Nada de fuerza bruta corre salvo que se habilite explícitamente.
"""

from glep.policy.base import Policy
from glep.state import EngagementState, Phase
from glep.tools.curl_tool import sqli_probe_url

# Puertos/servicios donde tiene sentido intentar hydra si se habilitó.
_BRUTEFORCE_SERVICES = ("ssh", "ftp", "telnet", "rdp", "mysql", "postgres")


class DeterministicPolicy(Policy):
    def __init__(
        self,
        allow_exploit: bool = True,
        allow_bruteforce: bool = False,
        max_http_probes: int = 20,
        userlist: str = "/opt/glep/wordlists/users.txt",
        passlist: str = "/opt/glep/wordlists/passwords.txt",
    ):
        self.allow_exploit = allow_exploit
        self.allow_bruteforce = allow_bruteforce
        self.max_http_probes = max_http_probes
        self.userlist = userlist
        self.passlist = passlist

    def decide(self, state: EngagementState) -> dict | None:
        if state.phase == Phase.RECON:
            return self._recon(state)
        if state.phase == Phase.VULN_SCAN:
            return self._vuln_scan(state)
        if state.phase == Phase.EXPLOIT_ATTEMPT:
            return self._exploit_attempt(state)
        return None

    # --- RECON ---------------------------------------------------------
    def _recon(self, state: EngagementState) -> dict | None:
        nmap_args = {
            "host": state.target_host,
            "port_range": state.target_port_range,
        }
        if not state.already_ran("nmap", **nmap_args):
            return {"tool": "nmap", "args": nmap_args}

        if not state.already_ran("dig", host=state.target_host):
            return {"tool": "dig", "args": {"host": state.target_host}}

        return None  # recon completo -> el loop avanza de fase

    # --- VULN_SCAN -----------------------------------------------------
    def _vuln_scan(self, state: EngagementState) -> dict | None:
        web_ports = state.web_ports()

        # 1) Traer la raíz de cada puerto web: headers, título, links.
        for port in web_ports:
            url = f"{state.scheme_for(port)}://{state.target_host}:{port}/"
            if not state.already_ran("curl", url=url):
                return {"tool": "curl", "args": {"url": url, "port": port}}

        # 2) Sondear SQLi en las URLs con query params descubiertas.
        probes = sum(
            1
            for action in state.executed_actions
            if action.get("tool") == "curl" and action.get("args", {}).get("probe") == "sqli"
        )
        if probes < self.max_http_probes:
            for url in state.urls:
                # No re-sondear una URL que ya contiene el payload: si no,
                # cada sonda genera una URL nueva y el scan no termina.
                if any(marker in url for marker in ("'", "%27", '"', "%22")):
                    continue
                probe_url = sqli_probe_url(url)
                if not probe_url:
                    continue
                if not state.already_ran("curl", url=probe_url, probe="sqli"):
                    return {
                        "tool": "curl",
                        "args": {"url": probe_url, "probe": "sqli", "max_time": 15},
                    }

        # 3) Nikto como segundo par de ojos en los puertos web.
        for port in web_ports:
            args = {
                "host": state.target_host,
                "port": port,
                "scheme": state.scheme_for(port),
            }
            if not state.already_ran("nikto", **args):
                return {"tool": "nikto", "args": args}

        return None  # vuln scan completo -> el loop avanza de fase

    # --- EXPLOIT_ATTEMPT ----------------------------------------------
    def _exploit_attempt(self, state: EngagementState) -> dict | None:
        if not self.allow_exploit:
            return None

        # Confirmar candidatos de SQLi con sqlmap (detección, no dump).
        for finding in state.findings:
            if finding.get("type") not in (
                "sql_injection_candidate",
                "sql_injection",
            ):
                continue
            url = finding.get("url")
            if not url:
                continue
            if not state.already_ran("sqlmap", url=url):
                return {"tool": "sqlmap", "args": {"url": url}}

        # Fuerza bruta solo si se habilitó explícitamente.
        if self.allow_bruteforce:
            for port in state.open_ports:
                service = state.services.get(port, "")
                if not any(name in service.lower() for name in _BRUTEFORCE_SERVICES):
                    continue
                hydra_args = {
                    "host": state.target_host,
                    "port": port,
                    "service": service.split()[0].lower(),
                    "userlist": self.userlist,
                    "passlist": self.passlist,
                }
                if not state.already_ran("hydra", **hydra_args):
                    return {"tool": "hydra", "args": hydra_args}

        return None
