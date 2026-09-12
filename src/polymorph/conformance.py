from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from .connector_registry import ConnectorManifest, EndpointRole
from .connectors.base import ConnectorCapabilities
from .errors import ConnectorError


class ConformanceStatus(StrEnum):
    PASSED = "passed"
    FAILED = "failed"
    ADVISORY = "advisory"


@dataclass(frozen=True, slots=True)
class ConformanceCheck:
    code: str
    status: ConformanceStatus
    detail: str

    def as_dict(self) -> dict[str, str]:
        return {"code": self.code, "status": self.status.value, "detail": self.detail}


@dataclass(frozen=True, slots=True)
class ConnectorConformanceReport:
    role: EndpointRole
    checks: tuple[ConformanceCheck, ...]

    @property
    def passed(self) -> bool:
        return not any(item.status is ConformanceStatus.FAILED for item in self.checks)

    def as_dict(self) -> dict[str, object]:
        return {
            "contract_version": 1,
            "role": self.role.value,
            "passed": self.passed,
            "checks": [item.as_dict() for item in self.checks],
        }


class ConnectorConformanceError(ConnectorError):
    pass


def check_connector_conformance(
    connector: object,
    role: EndpointRole,
    *,
    manifest: ConnectorManifest | None = None,
) -> ConnectorConformanceReport:
    """Inspect the public connector contract without opening a source or destination."""

    checks: list[ConformanceCheck] = []

    def record(code: str, passed: bool, passed_detail: str, failed_detail: str) -> None:
        checks.append(
            ConformanceCheck(
                code,
                ConformanceStatus.PASSED if passed else ConformanceStatus.FAILED,
                passed_detail if passed else failed_detail,
            )
        )

    capabilities = getattr(connector, "capabilities", None)
    record(
        "capabilities.immutable_contract",
        isinstance(capabilities, ConnectorCapabilities),
        "Connector exposes a validated immutable capability value.",
        "Connector must expose ConnectorCapabilities as capabilities.",
    )
    record(
        "schema.inspect_method",
        callable(getattr(connector, "inspect_schema", None)),
        "Schema inspection method is present.",
        "Connector is missing inspect_schema().",
    )
    if isinstance(capabilities, ConnectorCapabilities):
        record(
            "capabilities.schema_read",
            capabilities.read_schema,
            "Schema reads are advertised.",
            "This public connector role requires schema reads.",
        )
        if role is EndpointRole.SOURCE:
            record(
                "source.records",
                capabilities.read_records and callable(getattr(connector, "iter_records", None)),
                "Bounded record iteration is advertised and implemented.",
                "Source must advertise read_records and implement iter_records().",
            )
        else:
            record(
                "destination.records",
                capabilities.write_records and callable(getattr(connector, "write_records", None)),
                "Record writes are advertised and implemented.",
                "Destination must advertise write_records and implement write_records().",
            )
            if capabilities.atomic_batch_write is not None:
                record(
                    "destination.atomic_batch_method",
                    callable(getattr(connector, "write_batch", None)),
                    "Atomic batch capability has a matching method.",
                    "Atomic batch capability requires write_batch().",
                )
            else:
                checks.append(
                    ConformanceCheck(
                        "destination.atomic_batch_method",
                        ConformanceStatus.ADVISORY,
                        "No atomic batch capability is advertised.",
                    )
                )
    if manifest is not None:
        record(
            "manifest.role",
            role in manifest.roles,
            "Manifest advertises the requested endpoint role.",
            "Manifest does not advertise the requested endpoint role.",
        )
        record(
            "manifest.api_version",
            manifest.api_version == 1,
            "Manifest uses connector plugin API version 1.",
            "Manifest uses an unsupported connector plugin API version.",
        )
    return ConnectorConformanceReport(role, tuple(checks))


def assert_connector_conformant(
    connector: object,
    role: EndpointRole,
    *,
    manifest: ConnectorManifest | None = None,
) -> ConnectorConformanceReport:
    report = check_connector_conformance(connector, role, manifest=manifest)
    if not report.passed:
        failed = ", ".join(
            item.code for item in report.checks if item.status is ConformanceStatus.FAILED
        )
        raise ConnectorConformanceError(f"connector contract failed: {failed}")
    return report
