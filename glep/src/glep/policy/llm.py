"""Policy basada en Qwen2.5-0.5B-Instruct (Q3_K_M) vía llama.cpp,
restringida por la gramática GBNF a un tool call JSON válido.

La gramática garantiza sintaxis válida, no una buena decisión. Por eso:
1. se recorta el set de tools/args según la fase,
2. el prompt es compacto (n_ctx=512 en la Pi no da para volcar todo el
   estado; se mandan solo resúmenes y paths),
3. se valida que el host/URL elegidos sean *el objetivo del engagement*
   (un modelo chico no puede pivotear a un tercero por alucinación),
4. se rechazan acciones ya ejecutadas,
5. ante timeout/JSON inválido/acción inválida se delega a
   DeterministicPolicy; tras 3 fallos seguidos el modo LLM se apaga para
   el resto del engagement (mejor determinístico que pagar 10s por paso).
"""

import json
import re
import signal
import threading
from pathlib import Path
from urllib.parse import urlsplit

from glep.policy.base import Policy
from glep.policy.deterministic import DeterministicPolicy
from glep.state import EngagementState, Phase
from glep.tools import TOOL_REGISTRY

_ALLOWED_TOOLS_BY_PHASE = {
    Phase.RECON: {"nmap", "dig"},
    Phase.VULN_SCAN: {"curl", "nikto"},
    Phase.EXPLOIT_ATTEMPT: {"hydra", "sqlmap"},
}

_MAX_CONSECUTIVE_FAILURES = 2


class _Timeout(Exception):
    pass


def _raise_timeout(signum, frame):
    raise _Timeout()


class LLMPolicy(Policy):
    def __init__(
        self,
        model_path: str,
        grammar_path: str,
        n_ctx: int = 512,
        n_threads: int = 4,
        timeout_seconds: int = 15,
        logger=None,
        allow_exploit: bool = True,
        allow_bruteforce: bool = False,
    ):
        from llama_cpp import Llama, LlamaGrammar

        self._fallback = DeterministicPolicy()
        self._timeout_seconds = max(1, int(timeout_seconds))
        self._logger = logger
        self._allow_exploit = allow_exploit
        self._allow_bruteforce = allow_bruteforce
        self._consecutive_failures = 0
        self._disabled = False

        grammar_text = Path(grammar_path).read_text()
        self._grammar_source = grammar_text
        self._grammars: dict[tuple, object] = {}
        self._llm = Llama(
            model_path=model_path,
            n_ctx=n_ctx,
            n_threads=n_threads,
            verbose=False,
        )

    # --- Policy --------------------------------------------------------
    def decide(self, state: EngagementState) -> dict | None:
        if self._disabled:
            return self._fallback.decide(state)

        allowed = self._allowed_tools(state.phase)
        if not allowed:
            return self._fallback.decide(state)

        try:
            action = self._decide_with_timeout(state)
        except _Timeout:
            self._fail("LLM timeout después de %ss", self._timeout_seconds)
            action = None
        except Exception as exc:
            self._fail("LLM falló (%s)", exc)
            action = None

        if action is None or not self._is_valid(action, state):
            if action is not None:
                self._fail(
                    "LLM propuso una acción inválida para %s: %s",
                    state.phase.name,
                    json.dumps(action, ensure_ascii=False)[:240],
                )
            return self._fallback.decide(state)

        self._consecutive_failures = 0
        self._log("LLM eligió %s args=%s", action["tool"], action.get("args"))
        return action

    def _fail(self, message: str, *args) -> None:
        self._consecutive_failures += 1
        self._log(message + "; fallback determinístico", *args)
        if (
            self._consecutive_failures >= _MAX_CONSECUTIVE_FAILURES
            and not self._disabled
        ):
            self._disabled = True
            self._log(
                "LLM deshabilitado tras %s fallos seguidos; resto del engagement "
                "con DeterministicPolicy",
                self._consecutive_failures,
            )

    def _decide_with_timeout(self, state: EngagementState) -> dict | None:
        # signal.alarm solo funciona en el hilo principal. Si la policy se
        # usa desde un worker, se ejecuta sin alarma (el timeout real lo
        # pone el proceso que la invoca).
        if threading.current_thread() is not threading.main_thread():
            return self._decide_with_llm(state)

        previous = signal.signal(signal.SIGALRM, _raise_timeout)
        try:
            signal.alarm(self._timeout_seconds)
            return self._decide_with_llm(state)
        finally:
            signal.alarm(0)
            signal.signal(signal.SIGALRM, previous)

    def _decide_with_llm(self, state: EngagementState) -> dict | None:
        allowed = self._allowed_tools(state.phase)
        result = self._llm.create_chat_completion(
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You are a network pentest planner. Reply with ONE JSON "
                        'object: {"tool": "<name>", "args": {...}}. No prose.'
                    ),
                },
                {"role": "user", "content": self._build_prompt(state)},
            ],
            grammar=self._grammar_for_phase(state.phase, allowed),
            temperature=0.1,
            max_tokens=96,
        )
        text = result["choices"][0]["message"]["content"]
        action = json.loads(text)
        return action if isinstance(action, dict) else None

    def _allowed_tools(self, phase: Phase) -> set[str]:
        """Tools válidas para la fase Y con el binario instalado.

        No tiene sentido dejar que el modelo elija nikto si nikto no está:
        gastaría el timeout para que después lo rechace la validación.
        Además respeta los gates de exploit/fuerza bruta de la config.
        """
        allowed = {
            tool
            for tool in _ALLOWED_TOOLS_BY_PHASE.get(phase, set())
            if (impl := TOOL_REGISTRY.get(tool)) is not None and impl.available()
        }
        if not getattr(self, "_allow_exploit", True):
            allowed.discard("sqlmap")
        if not getattr(self, "_allow_bruteforce", False):
            allowed.discard("hydra")
        return allowed

    def _grammar_for_phase(self, phase: Phase, allowed: set[str]):
        """Gramática con SOLO las tools válidas y disponibles de la fase.

        La gramática estática permite las 6 tools, y un modelo de 0.5B
        tiende a repetir la tool que ya usó. Restringir la regla `tool`
        por fase hace que elegir una tool inválida sea imposible a nivel
        sintáctico, no solo rechazado después.
        """
        key = (phase, tuple(sorted(allowed)))
        if key in self._grammars:
            return self._grammars[key]

        from llama_cpp import LlamaGrammar

        alternatives = " | ".join(f'"\\"{tool}\\""' for tool in sorted(allowed))
        source = re.sub(
            r"^tool\s+::=.*$",
            f"tool   ::= {alternatives}",
            self._grammar_source,
            count=1,
            flags=re.MULTILINE,
        )
        grammar = LlamaGrammar.from_string(source)
        self._grammars[key] = grammar
        return grammar

    # --- prompt/validación --------------------------------------------
    def _build_prompt(self, state: EngagementState) -> str:
        allowed = sorted(self._allowed_tools(state.phase))
        examples = self._examples(state)
        schemas = "; ".join(
            f"{tool}={json.dumps(examples[tool], ensure_ascii=False)}"
            for tool in allowed
        )

        # Paths en vez de URLs completas: ahorra tokens y evita que el
        # modelo "invente" otro host.
        paths = [self._relative_path(url) for url in state.urls[-6:]]
        findings = [
            f"{finding.get('type')}@{self._relative_path(str(finding.get('url', '')))}"
            for finding in state.findings[-4:]
        ]
        services = ", ".join(
            f"{port}:{(service.split() or ['?'])[0]}"
            for port, service in sorted(state.services.items())
        )
        executed = [
            self._action_summary(action) for action in state.executed_actions[-6:]
        ]

        return (
            f"target={state.target_host} phase={state.phase.name} "
            f"ports={state.open_ports} range={state.target_port_range}\n"
            f"services={services}\n"
            f"paths={paths}\n"
            f"findings={findings}\n"
            f"done={executed}\n"
            f"allowed: {schemas}\n"
            f"Use exactly these arg names and the literal target value "
            f"{state.target_host}. Never write <target>. Pick the single most "
            "useful next action; do not repeat done actions."
        )

    @staticmethod
    def _examples(state: EngagementState) -> dict[str, dict]:
        """Ejemplos concretos con el target real.

        Un modelo de 0.5B copia el ejemplo casi literalmente; si el ejemplo
        dice "<target>" va a devolver "<target>". Por eso los ejemplos se
        generan con la IP/hostname y los puertos ya observados.
        """
        web_ports = state.web_ports()
        web_port = web_ports[0] if web_ports else 80
        scheme = state.scheme_for(web_port)

        finding_url = ""
        for finding in state.findings:
            if finding.get("url"):
                finding_url = str(finding["url"])
                break

        ssh_port = 22
        for port, service in state.services.items():
            if "ssh" in service.lower():
                ssh_port = port
                break

        return {
            "nmap": {
                "host": state.target_host,
                "port_range": state.target_port_range,
            },
            "dig": {"host": state.target_host},
            "curl": {"url": f"{scheme}://{state.target_host}:{web_port}/"},
            "nikto": {
                "host": state.target_host,
                "port": web_port,
                "scheme": scheme,
            },
            "sqlmap": {
                "url": finding_url
                or f"{scheme}://{state.target_host}:{web_port}/?id=1"
            },
            "hydra": {
                "host": state.target_host,
                "port": ssh_port,
                "service": "ssh",
            },
        }

    @staticmethod
    def _relative_path(url: str) -> str:
        try:
            parts = urlsplit(url)
        except ValueError:
            return url[:60]
        if not parts.scheme:
            return url[:60]
        path = parts.path or "/"
        return f"{path}?{parts.query}" if parts.query else path

    @staticmethod
    def _action_summary(action: dict) -> str:
        tool = str(action.get("tool", "?"))
        args = action.get("args", {}) or {}
        if isinstance(args, dict) and args.get("url"):
            return f"{tool}:{LLMPolicy._relative_path(str(args['url']))}"
        if isinstance(args, dict) and args.get("port"):
            return f"{tool}:{args.get('port')}"
        return tool

    def _is_valid(self, action: dict, state: EngagementState) -> bool:
        tool = action.get("tool")
        allowed = self._allowed_tools(state.phase)
        if tool not in allowed:
            return False

        args = action.get("args")
        if not isinstance(args, dict):
            return False

        tool_impl = TOOL_REGISTRY.get(tool)
        if tool_impl is None or not tool_impl.available():
            return False
        if tool_impl.validate_args(args) is not None:
            return False

        completed = state.complete_args(tool, args)
        if state.already_ran(tool, **args) or state.already_ran(tool, **completed):
            return False

        # El objetivo no se negocia: host/URL deben apuntar al target.
        if "host" in completed and str(completed["host"]) != state.target_host:
            return False
        if tool == "curl" or tool == "sqlmap":
            url = str(completed.get("url", ""))
            if not self._url_is_target(url, state):
                return False

        return True

    @staticmethod
    def _url_is_target(url: str, state: EngagementState) -> bool:
        try:
            parts = urlsplit(url)
            host = parts.hostname or ""
        except ValueError:
            return False
        if not url.startswith(("http://", "https://")):
            return False
        if host != state.target_host:
            return False
        if (
            parts.port is not None
            and parts.port not in state.open_ports
            and parts.port not in state.web_port_hints
        ):
            return False
        return True

    def _log(self, message: str, *args) -> None:
        if self._logger is not None:
            self._logger.warning(message, *args)
