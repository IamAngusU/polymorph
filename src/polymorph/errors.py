from __future__ import annotations

from enum import StrEnum


class PolymorphError(Exception):
    """Base exception for Polymorph."""


class PolicyViolation(PolymorphError):
    """Raised when a requested operation violates an information-flow policy."""


class MappingAmbiguous(PolymorphError):
    """Raised when a mapping cannot be accepted safely."""


class ConnectorError(PolymorphError):
    """Raised for connector failures that are safe to surface."""


class WriteOutcome(StrEnum):
    NOT_COMMITTED = "not_committed"
    UNKNOWN = "unknown"
    PARTIAL = "partial"


class ConnectorWriteError(ConnectorError):
    """Connector write failure with an explicit durability outcome."""

    def __init__(self, message: str, *, outcome: WriteOutcome) -> None:
        super().__init__(message)
        self.outcome = outcome


class PartialConnectorWriteError(ConnectorWriteError):
    """Aggregate write stopped after a proven committed prefix."""

    def __init__(
        self,
        message: str,
        *,
        committed_count: int,
        next_record_outcome: WriteOutcome,
    ) -> None:
        if committed_count <= 0:
            raise ValueError("partial write requires a positive committed_count")
        if next_record_outcome is WriteOutcome.PARTIAL:
            raise ValueError("partial write next_record_outcome must be terminal")
        super().__init__(message, outcome=WriteOutcome.PARTIAL)
        self.committed_count = committed_count
        self.next_record_index = committed_count
        self.next_record_outcome = next_record_outcome


class IntegrityError(PolymorphError):
    """Raised when authenticated or checksummed data fails verification."""


class ProtocolError(PolymorphError):
    """Raised when a transport message violates the wire protocol."""


class ReplayDetected(PolymorphError):
    """Raised when a transfer identifier is reused with incompatible content."""


class TransferExpired(PolymorphError):
    """Raised when an authenticated transfer is outside its validity window."""
