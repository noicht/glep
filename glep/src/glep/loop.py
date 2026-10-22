"""El loop ReAct en sí: observar -> decidir -> ejecutar -> repetir.

La ESTRUCTURA del loop (transiciones de fase) es determinística siempre.
Lo único intercambiable es quién decide la próxima ACCIÓN dentro de cada
fase (DeterministicPolicy o LLMPolicy) — ver policy/base.py.

El loop además es el punto donde se aplican las garantías que ninguna
policy puede saltear:
- solo se ejecutan tools permitidas para la fase,
- si el binario no está instalado, se registra y se sigue (no se cuelga),
- toda observación se fusiona en el estado antes de la próxima decisión.
"""

import logging
from datetime import datetime, timezone

from glep.policy.base import Policy
from glep.state import EngagementState, Phase
from glep.tools import TOOL_REGISTRY

_NEXT_PHASE = {
    Phase.RECON: Phase.VULN_SCAN,
    Phase.VULN_SCAN: Phase.EXPLOIT_ATTEMPT,
    Phase.EXPLOIT_ATTEMPT: Phase.REPORT,
    Phase.REPORT: Phase.DONE,
}

_ALLOWED_TOOLS_BY_PHASE = {
    Phase.RECON: {"nmap", "dig"},
    Phase.VULN_SCAN: {"curl", "nikto"},
    Phase.EXPLOIT_ATTEMPT: {"hydra", "sqlmap"},
    Phase.REPORT: set(),
}


class ReactLoop:
    def __init__(
        self,
        policy: Policy,
        logger: logging.Logger,
        max_iterations: int = 200,
        tool_timeout_seconds: int = 120,
        allow_exploit: bool = True,
        allow_bruteforce: bool = False,
    ):
        self._policy = policy
        self._logger = logger
        self._max_iterations = max_iterations
        self._tool_timeout_seconds = tool_timeout_seconds
        self._allowed_tools = {
            phase: set(tools)
            for phase, tools in _ALLOWED_TOOLS_BY_PHASE.items()
        }
        if not allow_exploit:
            self._allowed_tools[Phase.EXPLOIT_ATTEMPT].discard("sqlmap")
        if not allow_bruteforce:
            self._allowed_tools[Phase.EXPLOIT_ATTEMPT].discard("hydra")

    def run(self, state: EngagementState) -> EngagementState:
        iterations = 0
        while state.phase != Phase.DONE and iterations < self._max_iterations:
            iterations += 1

            action = self._policy.decide(state)

            if action is None:
                self._advance_phase(state)
                continue

            self._execute(state, action)

        if state.phase != Phase.DONE:
            state.add_errors(
                [f"max_iterations={self._max_iterations} alcanzado antes de DONE"]
            )
            self._logger.warning(
                "Se alcanzó max_iterations=%s antes de terminar", self._max_iterations
            )

        state.finished_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
        return state

    def _advance_phase(self, state: EngagementState) -> None:
        next_phase = _NEXT_PHASE.get(state.phase, Phase.DONE)
        self._logger.info("Fase %s completa -> %s", state.phase.name, next_phase.name)
        state.phase = next_phase

    def _execute(self, state: EngagementState, action: dict) -> None:
        if not isinstance(action, dict):
            state.add_errors([f"acción inválida (no es dict): {action!r}"])
            return

        tool_name = action.get("tool")
        tool = TOOL_REGISTRY.get(tool_name)
        if tool is None:
            state.add_errors([f"tool desconocida: {tool_name!r}"])
            self._logger.warning("Tool desconocida: %r", tool_name)
            return

        if tool_name not in self._allowed_tools.get(state.phase, set()):
            state.add_errors(
                [f"tool {tool_name} no permitida en fase {state.phase.name}"]
            )
            self._logger.warning(
                "Ignorando %s: no permitida en fase %s", tool_name, state.phase.name
            )
            return

        args = state.complete_args(tool_name, action.get("args", {}))
        record = {"tool": tool_name, "args": args}

        if not tool.available():
            message = f"binario no encontrado: {tool.binary or tool_name}; {tool_name} omitida"
            record["skipped"] = "binary_missing"
            state.record_action(record)
            state.add_errors([message])
            self._logger.warning("%s", message)
            return

        self._logger.info("Ejecutando %s args=%s", tool_name, args)
        result = tool.run(args, timeout_seconds=self._tool_timeout_seconds)

        record["returncode"] = result.returncode
        record["timed_out"] = result.timed_out
        state.record_action(record)

        if result.timed_out:
            message = f"{tool_name} timeout después de {self._tool_timeout_seconds}s"
            state.add_errors([message])
            self._logger.warning("%s", message)
            return

        if result.returncode == -1:
            message = f"{tool_name} no se pudo ejecutar: {result.stderr}"
            state.add_errors([message])
            self._logger.warning("%s", message)
            return

        if result.returncode != 0 and result.stderr.strip():
            self._logger.info(
                "%s terminó con rc=%s: %s",
                tool_name,
                result.returncode,
                result.stderr.strip()[:300],
            )

        try:
            parsed = tool.parse(result)
        except Exception as exc:  # un parser roto no debe matar el engagement
            message = f"error parseando output de {tool_name}: {exc}"
            state.add_errors([message])
            self._logger.exception("%s", message)
            return

        self._merge_observation(state, parsed)

    def _merge_observation(self, state: EngagementState, parsed: dict) -> None:
        if not isinstance(parsed, dict):
            return

        if "open_ports" in parsed:
            state.add_ports(parsed.get("open_ports", []), parsed.get("services"))
        elif "services" in parsed:
            state.add_ports([], parsed.get("services"))

        if "findings" in parsed:
            state.add_findings(parsed.get("findings", []))
        if "urls" in parsed:
            state.add_urls(parsed.get("urls", []))
        if "forms" in parsed:
            state.add_forms(parsed.get("forms", []))
        if "dns_records" in parsed:
            for record in parsed.get("dns_records", []):
                if record and record not in state.dns_records:
                    state.dns_records.append(record)
        if "errors" in parsed:
            state.add_errors(
                [error for error in parsed.get("errors", []) if error]
            )
