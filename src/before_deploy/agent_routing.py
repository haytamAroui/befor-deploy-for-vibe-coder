"""Deterministic model routing for specialist and critic advisory runs."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

from before_deploy.agent_orchestration import SpecialistSpec
from before_deploy.agent_runtime import AgentClaim, AgentModel


@dataclass(frozen=True)
class ModelRoute:
    route_id: str
    provider_id: str
    model_id: str


class NativeModelRouter:
    """Resolve configured model adapters without allowing model-selected routing."""

    def __init__(
        self,
        models: Mapping[str, AgentModel],
        *,
        default_route: str,
        specialist_routes: Mapping[str, str] | None = None,
        critic_route: str | None = None,
    ) -> None:
        if not models:
            raise ValueError("Native model router requires at least one configured route")
        self._models = dict(models)
        self._default_route = _known_route(default_route, self._models)
        self._specialist_routes = dict(specialist_routes or {})
        for specialist, route in self._specialist_routes.items():
            if not specialist.strip():
                raise ValueError("Native model specialist route key must be non-empty")
            _known_route(route, self._models)
        self._critic_route = _known_route(critic_route or default_route, self._models)

    def specialist_model(self, specialist: SpecialistSpec) -> AgentModel:
        route = self._specialist_routes.get(specialist.specialist_id, self._default_route)
        return self._models[route]

    def critic_model(self, specialist: SpecialistSpec, candidate: AgentClaim) -> AgentModel:
        del specialist, candidate
        return self._models[self._critic_route]

    def route_manifest(self) -> tuple[ModelRoute, ...]:
        """Return deterministic configured route metadata without credentials."""
        return tuple(
            ModelRoute(
                route_id=route_id,
                provider_id=model.provider_id,
                model_id=model.model_id,
            )
            for route_id, model in sorted(self._models.items())
        )


def _known_route(route: str, models: Mapping[str, AgentModel]) -> str:
    if not isinstance(route, str) or not route.strip():
        raise ValueError("Native model route must be non-empty")
    route = route.strip()
    if route not in models:
        raise ValueError(f"Unknown native model route: {route}")
    return route
