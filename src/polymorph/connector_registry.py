from __future__ import annotations

import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from importlib import metadata
from pathlib import Path
from types import MappingProxyType
from typing import Protocol, cast

from .connectors.base import (
    ConnectorCapabilities,
    DestinationConnector,
    SourceConnector,
)
from .content import ContentInspector, ContentKind, FileInspection
from .errors import ConnectorError

CONNECTOR_PLUGIN_API_VERSION = 1
CONNECTOR_ENTRY_POINT_GROUP = "polymorph.connectors"

_CONNECTOR_ID = re.compile(r"^[a-z][a-z0-9_.-]{0,127}$")


class EndpointRole(StrEnum):
    SOURCE = "source"
    DESTINATION = "destination"


class ConnectorRegistrationError(ConnectorError):
    pass


class ConnectorResolutionError(ConnectorError):
    pass


@dataclass(frozen=True, slots=True)
class ConnectorManifest:
    connector_id: str
    display_name: str
    roles: tuple[EndpointRole, ...]
    schemes: tuple[str, ...] = ()
    content_kinds: tuple[ContentKind, ...] = ()
    extensions: tuple[str, ...] = ()
    features: tuple[str, ...] = ()
    auth_modes: tuple[str, ...] = ()
    limitations: tuple[str, ...] = ()
    optional_extra: str | None = None
    provider: str = "polymorph"
    api_version: int = CONNECTOR_PLUGIN_API_VERSION

    def __post_init__(self) -> None:
        if _CONNECTOR_ID.fullmatch(self.connector_id) is None:
            raise ValueError("connector id must be a lower-case bounded machine key")
        if (
            not self.display_name
            or len(self.display_name) > 128
            or not self.display_name.isprintable()
        ):
            raise ValueError("connector display name must be bounded printable text")
        if self.api_version != CONNECTOR_PLUGIN_API_VERSION:
            raise ValueError("unsupported connector plugin API version")
        if not self.roles or len(set(self.roles)) != len(self.roles):
            raise ValueError("connector manifest requires unique endpoint roles")
        for value in (
            *self.schemes,
            *self.extensions,
            *self.features,
            *self.auth_modes,
        ):
            if not value or len(value) > 128 or not value.isascii() or not value.isprintable():
                raise ValueError("connector manifest keys must be bounded printable ASCII")
        for limitation in self.limitations:
            if not limitation or len(limitation) > 512 or not limitation.isprintable():
                raise ValueError("connector limitation must be bounded printable text")

    def as_dict(self) -> dict[str, object]:
        return {
            "api_version": self.api_version,
            "connector_id": self.connector_id,
            "display_name": self.display_name,
            "provider": self.provider,
            "roles": [item.value for item in self.roles],
            "schemes": list(self.schemes),
            "content_kinds": [item.value for item in self.content_kinds],
            "extensions": list(self.extensions),
            "features": list(self.features),
            "auth_modes": list(self.auth_modes),
            "limitations": list(self.limitations),
            "optional_extra": self.optional_extra,
        }


@dataclass(frozen=True, slots=True, repr=False)
class ConnectorSpec:
    connector_id: str
    role: EndpointRole
    config: Mapping[str, object] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if _CONNECTOR_ID.fullmatch(self.connector_id) is None:
            raise ValueError("connector id must be a lower-case bounded machine key")
        normalized: dict[str, object] = {}
        for key, value in self.config.items():
            if _CONNECTOR_ID.fullmatch(key) is None:
                raise ValueError("connector configuration keys must be bounded machine keys")
            normalized[key] = value
        object.__setattr__(self, "config", MappingProxyType(normalized))

    @classmethod
    def source(cls, connector_id: str, **config: object) -> ConnectorSpec:
        return cls(connector_id, EndpointRole.SOURCE, config)

    @classmethod
    def destination(cls, connector_id: str, **config: object) -> ConnectorSpec:
        return cls(connector_id, EndpointRole.DESTINATION, config)

    def __repr__(self) -> str:
        return f"ConnectorSpec(connector_id={self.connector_id!r}, role={self.role.value!r})"


SourceFactory = Callable[[Mapping[str, object]], SourceConnector]
DestinationFactory = Callable[[Mapping[str, object]], DestinationConnector]


@dataclass(frozen=True, slots=True)
class ConnectorPlugin:
    manifest: ConnectorManifest
    source_factory: SourceFactory | None = None
    destination_factory: DestinationFactory | None = None

    def __post_init__(self) -> None:
        roles = set(self.manifest.roles)
        if EndpointRole.SOURCE in roles and self.source_factory is None:
            raise ValueError("source connector manifest requires a source factory")
        if EndpointRole.DESTINATION in roles and self.destination_factory is None:
            raise ValueError("destination connector manifest requires a destination factory")
        if self.source_factory is not None and EndpointRole.SOURCE not in roles:
            raise ValueError("source factory requires the source role")
        if self.destination_factory is not None and EndpointRole.DESTINATION not in roles:
            raise ValueError("destination factory requires the destination role")


@dataclass(frozen=True, slots=True)
class ResolvedSource:
    connector: SourceConnector
    manifest: ConnectorManifest
    inspection: FileInspection


class SnapshotSourceConnector(SourceConnector, Protocol):
    """Optional connector extension proving the same immutable source across two passes."""

    def snapshot_token(self) -> str: ...


class ConnectorRegistry:
    def __init__(self) -> None:
        self._plugins: dict[str, ConnectorPlugin] = {}

    def register(self, plugin: ConnectorPlugin, *, replace: bool = False) -> None:
        connector_id = plugin.manifest.connector_id
        if connector_id in self._plugins and not replace:
            raise ConnectorRegistrationError(f"connector already registered: {connector_id}")
        self._plugins[connector_id] = plugin

    def manifests(self) -> tuple[ConnectorManifest, ...]:
        return tuple(
            plugin.manifest for _, plugin in sorted(self._plugins.items(), key=lambda item: item[0])
        )

    def manifest(self, connector_id: str) -> ConnectorManifest:
        return self._plugin(connector_id).manifest

    def create_source(self, spec: ConnectorSpec) -> SourceConnector:
        if spec.role is not EndpointRole.SOURCE:
            raise ConnectorResolutionError("destination spec cannot be used as a source")
        plugin = self._plugin(spec.connector_id)
        if plugin.source_factory is None:
            raise ConnectorResolutionError(
                f"connector does not support source reads: {spec.connector_id}"
            )
        try:
            connector = plugin.source_factory(spec.config)
        except ConnectorError:
            raise
        except Exception as exc:
            raise ConnectorResolutionError(
                f"connector source factory rejected its explicit configuration: "
                f"{spec.connector_id} ({type(exc).__name__})"
            ) from exc
        _require_source_contract(connector)
        return connector

    def create_destination(self, spec: ConnectorSpec) -> DestinationConnector:
        if spec.role is not EndpointRole.DESTINATION:
            raise ConnectorResolutionError("source spec cannot be used as a destination")
        plugin = self._plugin(spec.connector_id)
        if plugin.destination_factory is None:
            raise ConnectorResolutionError(
                f"connector does not support destination writes: {spec.connector_id}"
            )
        try:
            connector = plugin.destination_factory(spec.config)
        except ConnectorError:
            raise
        except Exception as exc:
            raise ConnectorResolutionError(
                f"connector destination factory rejected its explicit configuration: "
                f"{spec.connector_id} ({type(exc).__name__})"
            ) from exc
        _require_destination_contract(connector)
        return connector

    def resolve_file_source(
        self,
        path: str | Path,
        *,
        inspector: ContentInspector | None = None,
    ) -> ResolvedSource:
        source_path = Path(path)
        report = (inspector or ContentInspector()).inspect(source_path)
        if not report.safe:
            reason_codes = ", ".join(item.code.value for item in report.blocking_risks)
            raise ConnectorResolutionError(
                f"input was rejected by the content trust gate: {reason_codes}"
            )
        connector_id: str | None = {
            ContentKind.XLSX: "excel",
            ContentKind.JSON: "json",
            ContentKind.JSON5: "json",
            ContentKind.DELIMITED_TEXT: "csv",
            ContentKind.PARQUET: "parquet",
        }.get(report.kind)
        if report.kind is ContentKind.TEXT and any(
            signal.startswith("JSON-like") for signal in report.signals
        ):
            connector_id = "json"
        if connector_id is None:
            raise ConnectorResolutionError(
                f"no safe built-in source connector for detected content: {report.kind.value}"
            )
        connector = self.create_source(
            ConnectorSpec.source(
                connector_id,
                path=source_path,
                expected_source_identity=report.identity,
            )
        )
        return ResolvedSource(connector, self.manifest(connector_id), report)

    def load_entry_points(self) -> tuple[str, ...]:
        loaded: list[str] = []
        entry_points = metadata.entry_points().select(group=CONNECTOR_ENTRY_POINT_GROUP)
        for entry_point in sorted(entry_points, key=lambda item: item.name):
            try:
                candidate: object = entry_point.load()
                if not isinstance(candidate, ConnectorPlugin) and callable(candidate):
                    candidate = candidate()
                if not isinstance(candidate, ConnectorPlugin):
                    raise TypeError("entry point did not return ConnectorPlugin")
                self.register(candidate)
            except Exception as exc:
                raise ConnectorRegistrationError(
                    f"connector entry point failed: {entry_point.name} ({type(exc).__name__})"
                ) from exc
            loaded.append(candidate.manifest.connector_id)
        return tuple(loaded)

    def _plugin(self, connector_id: str) -> ConnectorPlugin:
        try:
            return self._plugins[connector_id]
        except KeyError as exc:
            raise ConnectorResolutionError(f"unknown connector: {connector_id}") from exc


def _require_source_contract(connector: object) -> None:
    capabilities = getattr(connector, "capabilities", None)
    if not isinstance(capabilities, ConnectorCapabilities):
        raise ConnectorResolutionError("source connector has no immutable capability contract")
    if not capabilities.read_schema or not capabilities.read_records:
        raise ConnectorResolutionError(
            "source connector does not advertise schema and record reads"
        )
    if not callable(getattr(connector, "inspect_schema", None)) or not callable(
        getattr(connector, "iter_records", None)
    ):
        raise ConnectorResolutionError("source connector is missing required methods")


def _require_destination_contract(connector: object) -> None:
    capabilities = getattr(connector, "capabilities", None)
    if not isinstance(capabilities, ConnectorCapabilities):
        raise ConnectorResolutionError("destination connector has no immutable capability contract")
    if not capabilities.read_schema or not capabilities.write_records:
        raise ConnectorResolutionError(
            "destination connector does not advertise schema reads and record writes"
        )
    if not callable(getattr(connector, "inspect_schema", None)) or not callable(
        getattr(connector, "write_records", None)
    ):
        raise ConnectorResolutionError("destination connector is missing required methods")


def _csv_factory(config: Mapping[str, object]) -> SourceConnector:
    from .connectors.csv_file import CsvConnector

    return CsvConnector(**dict(config))  # type: ignore[arg-type]


def _csv_destination_factory(config: Mapping[str, object]) -> DestinationConnector:
    return cast(DestinationConnector, _csv_factory(config))


def _json_factory(config: Mapping[str, object]) -> SourceConnector:
    from .connectors.json_file import JsonFileConnector

    return JsonFileConnector(**dict(config))  # type: ignore[arg-type]


def _json_destination_factory(config: Mapping[str, object]) -> DestinationConnector:
    return cast(DestinationConnector, _json_factory(config))


def _excel_factory(config: Mapping[str, object]) -> SourceConnector:
    from .connectors.excel import ExcelConnector

    return ExcelConnector(**dict(config))  # type: ignore[arg-type]


def _parquet_factory(config: Mapping[str, object]) -> SourceConnector:
    from .connectors.parquet import ParquetConnector

    return ParquetConnector(**dict(config))  # type: ignore[arg-type]


def _database_factory(config: Mapping[str, object]) -> SourceConnector:
    from .connectors.database import DatabaseConnector

    return DatabaseConnector(**dict(config))  # type: ignore[arg-type]


def _database_destination_factory(config: Mapping[str, object]) -> DestinationConnector:
    return cast(DestinationConnector, _database_factory(config))


def _http_source_factory(config: Mapping[str, object]) -> SourceConnector:
    from .connectors.http_json import HttpJsonSourceConnector

    return HttpJsonSourceConnector(**dict(config))  # type: ignore[arg-type]


def _http_destination_factory(config: Mapping[str, object]) -> DestinationConnector:
    from .connectors.http_json import HttpJsonConnector

    return HttpJsonConnector(**dict(config))  # type: ignore[arg-type]


def default_connector_registry() -> ConnectorRegistry:
    registry = ConnectorRegistry()
    registry.register(
        ConnectorPlugin(
            ConnectorManifest(
                "csv",
                "CSV / delimited text",
                (EndpointRole.SOURCE, EndpointRole.DESTINATION),
                schemes=("file",),
                content_kinds=(ContentKind.DELIMITED_TEXT,),
                extensions=(".csv", ".tsv"),
                features=(
                    "schema.read",
                    "records.read",
                    "records.write",
                    "destination.atomic_replace",
                    "source.identity_binding",
                ),
                auth_modes=("filesystem",),
                limitations=(
                    "Destination idempotency is not implied by an atomic file replacement.",
                ),
            ),
            source_factory=_csv_factory,
            destination_factory=_csv_destination_factory,
        )
    )
    registry.register(
        ConnectorPlugin(
            ConnectorManifest(
                "database",
                "SQL database",
                (EndpointRole.SOURCE, EndpointRole.DESTINATION),
                schemes=("sqlite", "postgresql"),
                features=(
                    "schema.read",
                    "records.read",
                    "records.write",
                    "destination.transactional",
                    "destination.atomic_batch",
                    "foreign_key.resolve",
                ),
                auth_modes=("credential_reference", "driver_native"),
                limitations=(
                    "The table or resource is always explicit and is never inferred from a URL.",
                    "Exact transaction and idempotency capabilities are reported at runtime.",
                ),
            ),
            source_factory=_database_factory,
            destination_factory=_database_destination_factory,
        )
    )
    registry.register(
        ConnectorPlugin(
            ConnectorManifest(
                "excel",
                "Excel workbook",
                (EndpointRole.SOURCE,),
                schemes=("file",),
                content_kinds=(ContentKind.XLSX,),
                extensions=(".xlsx",),
                features=(
                    "schema.read",
                    "records.read",
                    "source.identity_binding",
                    "layout.discovery",
                    "formula.freshness_gate",
                ),
                auth_modes=("filesystem",),
                limitations=("Read-only source connector; macros and external data are gated.",),
            ),
            source_factory=_excel_factory,
        )
    )
    registry.register(
        ConnectorPlugin(
            ConnectorManifest(
                "http-json",
                "HTTP JSON API",
                (EndpointRole.SOURCE, EndpointRole.DESTINATION),
                schemes=("http", "https"),
                content_kinds=(ContentKind.JSON,),
                extensions=(".json",),
                features=(
                    "schema.read",
                    "records.read",
                    "records.write",
                    "pagination.bounded",
                    "request_bytes.exact",
                    "write_outcome.structured",
                ),
                auth_modes=("credential_reference",),
                limitations=(
                    "Endpoints, pagination and destination schemas are explicit configuration.",
                    "Multi-request writes may return a proven committed prefix.",
                ),
            ),
            source_factory=_http_source_factory,
            destination_factory=_http_destination_factory,
        )
    )
    registry.register(
        ConnectorPlugin(
            ConnectorManifest(
                "json",
                "JSON / JSON5 file",
                (EndpointRole.SOURCE, EndpointRole.DESTINATION),
                schemes=("file",),
                content_kinds=(ContentKind.JSON, ContentKind.JSON5),
                extensions=(".json", ".json5"),
                features=(
                    "schema.read",
                    "records.read",
                    "records.write",
                    "destination.atomic_replace",
                    "source.identity_binding",
                ),
                auth_modes=("filesystem",),
                limitations=("Structured-text depth, item and byte budgets are mandatory.",),
            ),
            source_factory=_json_factory,
            destination_factory=_json_destination_factory,
        )
    )
    registry.register(
        ConnectorPlugin(
            ConnectorManifest(
                "parquet",
                "Apache Parquet",
                (EndpointRole.SOURCE,),
                schemes=("file",),
                content_kinds=(ContentKind.PARQUET,),
                extensions=(".parquet",),
                features=(
                    "schema.read",
                    "records.read",
                    "source.identity_binding",
                    "row_groups.bounded",
                ),
                auth_modes=("filesystem",),
                limitations=("Read-only in the current core release.",),
                optional_extra="parquet",
            ),
            source_factory=_parquet_factory,
        )
    )
    return registry
