"""Polymorph adaptive data bridge."""

from importlib import import_module
from typing import TYPE_CHECKING

from .models.schema import (
    FieldDescriptor,
    LookupKeyDescriptor,
    RelationDescriptor,
    SchemaDescriptor,
)
from .models.types import Sensitivity
from .work_budget import WorkBudget, WorkBudgetExceeded

if TYPE_CHECKING:
    from .connector_registry import (
        ConnectorManifest,
        ConnectorRegistry,
        ConnectorSpec,
        EndpointRole,
    )
    from .domain_events import (
        AsyncQueueEventSink,
        CallbackEventSink,
        CompositeEventSink,
        EventDispatcher,
        EventScope,
        EventSeverity,
        PolymorphEvent,
        PresentationHint,
        RetryPolicy,
    )
    from .embed import MoveResult, MoveSession, RoutePreparation, RouteStatus

_LAZY_EXPORTS = {
    "AsyncQueueEventSink": (".domain_events", "AsyncQueueEventSink"),
    "CallbackEventSink": (".domain_events", "CallbackEventSink"),
    "CompositeEventSink": (".domain_events", "CompositeEventSink"),
    "ConnectorManifest": (".connector_registry", "ConnectorManifest"),
    "ConnectorRegistry": (".connector_registry", "ConnectorRegistry"),
    "ConnectorSpec": (".connector_registry", "ConnectorSpec"),
    "EndpointRole": (".connector_registry", "EndpointRole"),
    "EventDispatcher": (".domain_events", "EventDispatcher"),
    "EventScope": (".domain_events", "EventScope"),
    "EventSeverity": (".domain_events", "EventSeverity"),
    "MoveResult": (".embed", "MoveResult"),
    "MoveSession": (".embed", "MoveSession"),
    "PolymorphEvent": (".domain_events", "PolymorphEvent"),
    "PresentationHint": (".domain_events", "PresentationHint"),
    "RetryPolicy": (".domain_events", "RetryPolicy"),
    "RoutePreparation": (".embed", "RoutePreparation"),
    "RouteStatus": (".embed", "RouteStatus"),
    "default_connector_registry": (".connector_registry", "default_connector_registry"),
    "move": (".embed", "move"),
}

__all__ = [
    "AsyncQueueEventSink",
    "CallbackEventSink",
    "CompositeEventSink",
    "ConnectorManifest",
    "ConnectorRegistry",
    "ConnectorSpec",
    "EndpointRole",
    "EventDispatcher",
    "EventScope",
    "EventSeverity",
    "FieldDescriptor",
    "LookupKeyDescriptor",
    "MoveResult",
    "MoveSession",
    "PolymorphEvent",
    "PresentationHint",
    "RelationDescriptor",
    "RetryPolicy",
    "RoutePreparation",
    "RouteStatus",
    "SchemaDescriptor",
    "Sensitivity",
    "WorkBudget",
    "WorkBudgetExceeded",
    "default_connector_registry",
    "move",
]
__version__ = "0.4.0a4"


def __getattr__(name: str) -> object:
    try:
        module_name, attribute_name = _LAZY_EXPORTS[name]
    except KeyError as exc:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}") from exc
    value = getattr(import_module(module_name, __name__), attribute_name)
    globals()[name] = value
    return value


def __dir__() -> list[str]:
    return sorted((*globals(), *_LAZY_EXPORTS))
