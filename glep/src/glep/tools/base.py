"""Interfaz base para las tools y ejecución segura vía subprocess.

Reglas duras:
- NUNCA se arma el comando con shell=True ni concatenando strings que
  vengan del estado/objetivo: siempre lista de args.
- Los args se validan antes de ejecutar (host/URL/puerto/wordlist) para que
  un output parseado de otra herramienta no pueda convertirse en un flag
  de línea de comandos (argument injection).
- Si el binario no está instalado, la tool devuelve un ToolResult con
  returncode=-1 y un error explicable; el loop lo registra y sigue.
"""

import re
import shutil
import subprocess
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path

_HOST_RE = re.compile(r"^[A-Za-z0-9._:\-\[\]]+$")
_SERVICE_RE = re.compile(r"^[A-Za-z0-9_.\-]+$")
_PORT_RANGE_RE = re.compile(r"^[0-9,\-]{1,64}$")


@dataclass
class ToolResult:
    tool: str
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False
    # Args y comando efectivamente ejecutados: algunos parsers (curl)
    # necesitan saber contra qué URL se corrió para interpretar el output.
    args: dict = field(default_factory=dict)
    command: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out


def validate_host(value: object) -> str:
    host = str(value).strip()
    if not host or host.startswith("-") or not _HOST_RE.fullmatch(host):
        raise ValueError(f"host inválido: {value!r}")
    return host


def validate_url(value: object) -> str:
    url = str(value).strip()
    if not url.lower().startswith(("http://", "https://")):
        raise ValueError(f"url inválida (se espera http/https): {value!r}")
    if any(ch in url for ch in "\r\n\t "):
        raise ValueError(f"url inválida (whitespace/CRLF): {value!r}")
    return url


def validate_port_range(value: object) -> str:
    port_range = str(value).strip()
    if not _PORT_RANGE_RE.fullmatch(port_range):
        raise ValueError(f"port_range inválido: {value!r}")
    return port_range


class Tool(ABC):
    name: str
    binary: str = ""
    # Args mínimos que build_command necesita. El loop y la LLMPolicy
    # pueden usar esto para validar antes de ejecutar.
    requires_args: tuple[str, ...] = ()

    def available(self) -> bool:
        return shutil.which(self.binary or self.name) is not None

    @abstractmethod
    def build_command(self, args: dict) -> list[str]:
        raise NotImplementedError

    def validate_args(self, args: dict) -> str | None:
        if not isinstance(args, dict):
            return "args debe ser un objeto/dict"
        missing = [key for key in self.requires_args if not args.get(key)]
        if missing:
            return f"faltan args requeridos: {', '.join(missing)}"
        return None

    def run(self, args: dict, timeout_seconds: int = 60) -> ToolResult:
        if not self.available():
            return ToolResult(
                tool=self.name,
                returncode=-1,
                stdout="",
                stderr=f"binario no encontrado: {self.binary or self.name}",
                args=args,
            )

        error = self.validate_args(args)
        if error:
            return ToolResult(
                tool=self.name, returncode=-1, stdout="", stderr=error, args=args
            )

        try:
            command = self.build_command(args)
        except (KeyError, ValueError, TypeError) as exc:
            return ToolResult(
                tool=self.name,
                returncode=-1,
                stdout="",
                stderr=f"argumentos inválidos: {exc}",
                args=args,
            )

        try:
            proc = subprocess.run(
                command,
                capture_output=True,
                text=True,
                errors="replace",
                timeout=timeout_seconds,
                stdin=subprocess.DEVNULL,
            )
            return ToolResult(
                tool=self.name,
                returncode=proc.returncode,
                stdout=proc.stdout,
                stderr=proc.stderr,
                args=args,
                command=command,
            )
        except subprocess.TimeoutExpired:
            return ToolResult(
                tool=self.name,
                returncode=-1,
                stdout="",
                stderr=f"timeout después de {timeout_seconds}s",
                timed_out=True,
                args=args,
                command=command,
            )
        except FileNotFoundError:
            return ToolResult(
                tool=self.name,
                returncode=-1,
                stdout="",
                stderr=f"binario no encontrado: {command[0]}",
                args=args,
                command=command,
            )
        except OSError as exc:
            return ToolResult(
                tool=self.name,
                returncode=-1,
                stdout="",
                stderr=f"no se pudo ejecutar {command[0]}: {exc}",
                args=args,
                command=command,
            )

    @abstractmethod
    def parse(self, result: ToolResult) -> dict:
        """Extrae del output lo que el loop necesita para actualizar el
        EngagementState (puertos abiertos, findings, URLs, etc)."""
        raise NotImplementedError

    # Helpers para que los parsers no dupliquen lógica.
    @staticmethod
    def _existing_file(path: object) -> bool:
        return bool(path) and Path(str(path)).is_file()
