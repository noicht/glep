"""Estado del engagement: qué se sabe del objetivo y en qué fase estamos.

El estado es la única fuente de verdad que ve la policy. Todo lo que una
tool devuelve en `parse()` se fusiona acá (puertos, servicios, URLs,
formularios, findings, errores) para que la próxima decisión se tome con
lo observado hasta ahora y no con lo que el modelo "recuerde".
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum, auto


class Phase(Enum):
    RECON = auto()
    VULN_SCAN = auto()
    EXPLOIT_ATTEMPT = auto()
    REPORT = auto()
    DONE = auto()


# Puertos que se consideran web aunque nmap no haya detectado el servicio
# (por ejemplo si corrió sin -sV o el target está detrás de un proxy raro).
_COMMON_WEB_PORTS = frozenset(
    {80, 443, 3000, 5000, 8000, 8008, 8080, 8081, 8443, 8888, 18080}
)


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass
class EngagementState:
    target_host: str
    target_port_range: str = "1-1024"

    phase: Phase = Phase.RECON

    # Resultados acumulados por herramienta, para que la policy decida
    # el próximo paso en base a lo observado hasta ahora.
    open_ports: list[int] = field(default_factory=list)
    services: dict[int, str] = field(default_factory=dict)
    findings: list[dict] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)
    forms: list[dict] = field(default_factory=list)
    dns_records: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    # Puertos que la config marca como web aunque nmap no los detecte.
    web_port_hints: list[int] = field(default_factory=list)

    # Historial de acciones ya ejecutadas (evita repetir lo mismo en loop).
    executed_actions: list[dict] = field(default_factory=list)

    started_at: str = field(default_factory=_utcnow)
    finished_at: str | None = None

    # --- acciones -----------------------------------------------------
    def record_action(self, action: dict) -> None:
        self.executed_actions.append(action)

    def already_ran(self, tool: str, **args) -> bool:
        """True si ya se ejecutó esa tool con (al menos) esos args.

        La comparación es por subconjunto a propósito: el loop agrega args
        que la policy puede omitir (port_range, scheme, max_time), y no
        queremos que la policy reintente la misma acción para siempre por
        una diferencia cosmética en los args.

        Incluye acciones salteadas por binario faltante: así la policy
        avanza de fase en vez de reintentar.
        """
        for action in self.executed_actions:
            if action.get("tool") != tool:
                continue
            recorded = action.get("args", {})
            if all(recorded.get(key) == value for key, value in args.items()):
                return True
        return False

    # --- observaciones -------------------------------------------------
    def add_ports(self, ports: list[int], services: dict[int, str] | None = None) -> None:
        for port in ports:
            port = int(port)
            if port not in self.open_ports:
                self.open_ports.append(port)
        self.open_ports.sort()
        if services:
            self.services.update({int(k): v for k, v in services.items()})

    def add_findings(self, findings: list[dict]) -> None:
        """Agrega findings evitando duplicados exactos (misma tool, target,
        tipo y evidencia). Un escaneo repetido no debe inflar el reporte."""
        seen = {self._finding_key(f) for f in self.findings}
        for finding in findings:
            if not isinstance(finding, dict):
                continue
            key = self._finding_key(finding)
            if key in seen:
                continue
            seen.add(key)
            finding.setdefault("source", finding.get("tool", "unknown"))
            self.findings.append(finding)

    @staticmethod
    def _finding_key(finding: dict) -> tuple:
        return (
            finding.get("type"),
            finding.get("url"),
            finding.get("port"),
            finding.get("evidence"),
            finding.get("severity"),
        )

    def add_urls(self, urls: list[str]) -> None:
        for url in urls:
            if not isinstance(url, str) or not url.startswith(("http://", "https://")):
                continue
            normalized = url.split("#", 1)[0]
            if normalized not in self.urls:
                self.urls.append(normalized)

    def add_forms(self, forms: list[dict]) -> None:
        seen = {
            (f.get("action"), f.get("method"), tuple(f.get("inputs", [])))
            for f in self.forms
        }
        for form in forms:
            if not isinstance(form, dict):
                continue
            key = (
                form.get("action"),
                form.get("method"),
                tuple(form.get("inputs", [])),
            )
            if key in seen:
                continue
            seen.add(key)
            self.forms.append(form)

    def add_errors(self, errors: list[str]) -> None:
        for error in errors:
            if error and error not in self.errors:
                self.errors.append(error)

    # --- helpers para la policy ---------------------------------------
    def web_ports(self) -> list[int]:
        ports = set(self.web_port_hints)
        for port in self.open_ports:
            service = self.services.get(port, "").lower()
            if port in _COMMON_WEB_PORTS or "http" in service or "ssl" in service:
                ports.add(port)
        return sorted(p for p in ports if p in self.open_ports or p in self.web_port_hints)

    def scheme_for(self, port: int) -> str:
        service = self.services.get(port, "").lower()
        if port in (443, 8443) or "https" in service or "ssl" in service:
            return "https"
        return "http"

    def complete_args(self, tool: str, args: dict) -> dict:
        """Completa args que la policy puede omitir (host, port_range,
        scheme) para que `already_ran` compare siempre lo mismo y para que
        una tool no explote por un KeyError evitable."""
        completed = dict(args or {})

        if tool in {"nmap", "nikto", "hydra", "dig"} and "host" not in completed:
            completed["host"] = self.target_host

        if tool == "nmap" and "port_range" not in completed:
            completed["port_range"] = self.target_port_range

        if tool == "nikto":
            try:
                port = int(completed.get("port", 80))
            except (TypeError, ValueError):
                port = 80
            completed.setdefault("scheme", self.scheme_for(port))

        return completed

    # --- serialización ------------------------------------------------
    def summary(self) -> dict:
        severity: dict[str, int] = {}
        for finding in self.findings:
            key = str(finding.get("severity", "info")).lower()
            severity[key] = severity.get(key, 0) + 1

        return {
            "target_host": self.target_host,
            "target_port_range": self.target_port_range,
            "phase": self.phase.name,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "open_ports": self.open_ports,
            "services": {str(k): v for k, v in sorted(self.services.items())},
            "urls": self.urls,
            "dns_records": self.dns_records,
            "findings": self.findings,
            "severity_counts": severity,
            "actions": self.executed_actions,
            "errors": self.errors,
        }
