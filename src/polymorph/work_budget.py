from __future__ import annotations

import math
import time
from collections.abc import Mapping
from dataclasses import dataclass

from .errors import PolymorphError


class WorkBudgetExceeded(PolymorphError):
    """Raised before a connector crosses an explicit aggregate work boundary."""

    def __init__(self, boundary: str) -> None:
        super().__init__(f"work budget exceeded: {boundary}")
        self.boundary = boundary


@dataclass(frozen=True, slots=True)
class WorkBudget:
    """Shared finite limits for direct connector and parser-facing work."""

    max_total_records: int = 1_000_000
    max_total_bytes: int = 1024 * 1024 * 1024
    max_structure_depth: int = 64
    max_structure_nodes: int = 1_000_000
    max_value_bytes: int = 16 * 1024 * 1024
    max_parquet_row_groups: int = 10_000
    max_parquet_metadata_bytes: int = 16 * 1024 * 1024
    max_parquet_row_group_uncompressed_bytes: int = 1024 * 1024 * 1024
    max_decoded_batch_bytes: int = 64 * 1024 * 1024
    wall_timeout_seconds: float = 3600.0

    def __post_init__(self) -> None:
        for name in (
            "max_total_records",
            "max_total_bytes",
            "max_structure_depth",
            "max_structure_nodes",
            "max_value_bytes",
            "max_parquet_row_groups",
            "max_parquet_metadata_bytes",
            "max_parquet_row_group_uncompressed_bytes",
            "max_decoded_batch_bytes",
        ):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ValueError(f"{name} must be a positive integer")
        if (
            isinstance(self.wall_timeout_seconds, bool)
            or not isinstance(self.wall_timeout_seconds, (int, float))
            or not math.isfinite(float(self.wall_timeout_seconds))
            or self.wall_timeout_seconds <= 0
        ):
            raise ValueError("wall_timeout_seconds must be a finite positive number")


class WorkMeter:
    """Mutable accounting state created for one connector operation."""

    def __init__(self, budget: WorkBudget) -> None:
        self.budget = budget
        self.records = 0
        self.bytes = 0
        self._deadline = time.monotonic() + float(budget.wall_timeout_seconds)

    def checkpoint(self) -> None:
        if time.monotonic() > self._deadline:
            raise WorkBudgetExceeded("wall_timeout_seconds")

    def consume_records(self, count: int = 1) -> None:
        if count < 0:
            raise ValueError("record count must not be negative")
        self.checkpoint()
        if self.records + count > self.budget.max_total_records:
            raise WorkBudgetExceeded("max_total_records")
        self.records += count

    def consume_bytes(self, count: int) -> None:
        if count < 0:
            raise ValueError("byte count must not be negative")
        self.checkpoint()
        if self.bytes + count > self.budget.max_total_bytes:
            raise WorkBudgetExceeded("max_total_bytes")
        self.bytes += count

    def validate_structure(self, value: object) -> None:
        """Iteratively bound nesting, node count and individual string/blob values."""

        nodes = 0
        stack: list[tuple[object, int]] = [(value, 1)]
        while stack:
            self.checkpoint()
            current, depth = stack.pop()
            if depth > self.budget.max_structure_depth:
                raise WorkBudgetExceeded("max_structure_depth")
            nodes += 1
            if nodes > self.budget.max_structure_nodes:
                raise WorkBudgetExceeded("max_structure_nodes")
            if isinstance(current, Mapping):
                for key, item in current.items():
                    self._validate_scalar_size(key)
                    stack.append((item, depth + 1))
            elif isinstance(current, (list, tuple)):
                stack.extend((item, depth + 1) for item in current)
            else:
                self._validate_scalar_size(current)

    def _validate_scalar_size(self, value: object) -> None:
        if isinstance(value, str):
            size = len(value.encode("utf-8", errors="surrogatepass"))
        elif isinstance(value, (bytes, bytearray, memoryview)):
            size = len(value)
        else:
            return
        if size > self.budget.max_value_bytes:
            raise WorkBudgetExceeded("max_value_bytes")
