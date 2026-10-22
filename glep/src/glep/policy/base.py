"""Interfaz que deben cumplir todas las policies (deterministic, llm, ...).

Una Policy solo decide: recibe el estado actual y devuelve la próxima
acción como dict {"tool": ..., "args": {...}} o None si no hay nada más
que hacer en esta fase (el loop se encarga de avanzar de fase)."""

from abc import ABC, abstractmethod

from glep.state import EngagementState


class Policy(ABC):
    @abstractmethod
    def decide(self, state: EngagementState) -> dict | None:
        """Devuelve la próxima acción, o None si la fase actual terminó."""
        raise NotImplementedError
