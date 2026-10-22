"""Chequeo de alcance/autorización antes de tocar la red.

GLEP ejecuta herramientas ofensivas reales. Este módulo no pretende ser
una garantía legal, pero evita el error más común: escanear un target
público (o la LAN de otro) por accidente.

Política por defecto:
- loopback: permitido sin flags (es tu propia máquina / lab local).
- privado o link-local: requiere `--authorized`.
- público: requiere `--authorized` y `target.allow_public: true`.
"""

import ipaddress
import socket
from dataclasses import dataclass

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address


class ScopeError(Exception):
    pass


@dataclass
class ScopeDecision:
    host: str
    addresses: list[str]
    kind: str  # loopback | private | public
    allowed: bool
    reason: str


def resolve_host(host: str) -> list[IPAddress]:
    try:
        return [ipaddress.ip_address(host)]
    except ValueError:
        pass

    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror as exc:
        raise ScopeError(f"no se pudo resolver {host!r}: {exc}") from exc

    addresses: list[IPAddress] = []
    for info in infos:
        raw = info[4][0]
        try:
            address = ipaddress.ip_address(raw.split("%", 1)[0])
        except ValueError:
            continue
        if address not in addresses:
            addresses.append(address)
    if not addresses:
        raise ScopeError(f"{host!r} no resolvió a ninguna IP")
    return addresses


def check_target(
    host: str,
    authorized: bool = False,
    allow_public: bool = False,
) -> ScopeDecision:
    addresses = resolve_host(host)
    ip_strings = [str(address) for address in addresses]

    if any(address.is_unspecified or address.is_multicast for address in addresses):
        return ScopeDecision(
            host=host,
            addresses=ip_strings,
            kind="invalid",
            allowed=False,
            reason="el target resuelve a una dirección no escaneable (unspecified/multicast)",
        )

    public = [address for address in addresses if address.is_global]
    private = [
        address
        for address in addresses
        if not address.is_loopback and not address.is_global
    ]
    loopback = all(address.is_loopback for address in addresses)

    if loopback:
        return ScopeDecision(
            host=host,
            addresses=ip_strings,
            kind="loopback",
            allowed=True,
            reason="loopback: tu propia máquina, permitido",
        )

    if public:
        if not allow_public:
            return ScopeDecision(
                host=host,
                addresses=ip_strings,
                kind="public",
                allowed=False,
                reason=(
                    "target público bloqueado por config "
                    "(target.allow_public=false). Requiere autorización explícita "
                    "del dueño del sistema y habilitarlo en la config."
                ),
            )
        if not authorized:
            return ScopeDecision(
                host=host,
                addresses=ip_strings,
                kind="public",
                allowed=False,
                reason="target público: pasá --authorized para confirmar que tenés permiso",
            )
        return ScopeDecision(
            host=host,
            addresses=ip_strings,
            kind="public",
            allowed=True,
            reason="target público con autorización explícita",
        )

    # Privado / link-local / CGNAT / reservado.
    if not authorized:
        return ScopeDecision(
            host=host,
            addresses=ip_strings,
            kind="private",
            allowed=False,
            reason=(
                "target privado/LAN: pasá --authorized para confirmar que es un "
                "equipo tuyo o tenés permiso para testearlo"
            ),
        )

    if private:
        return ScopeDecision(
            host=host,
            addresses=ip_strings,
            kind="private",
            allowed=True,
            reason="target privado con autorización explícita",
        )

    return ScopeDecision(
        host=host,
        addresses=ip_strings,
        kind="other",
        allowed=False,
        reason="tipo de dirección no permitido por la política de alcance",
    )
