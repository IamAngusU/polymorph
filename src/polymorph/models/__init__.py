"""Immutable public data models used by the bridge core."""

from .mapping import MappingCandidate, MappingDecision, MappingPlan, MappingRule, MappingStatus
from .schema import FieldDescriptor, LookupKeyDescriptor, RelationDescriptor, SchemaDescriptor
from .types import DataType, FieldPolicy, FieldRole, Sensitivity

__all__ = [
    "DataType",
    "FieldDescriptor",
    "FieldPolicy",
    "FieldRole",
    "LookupKeyDescriptor",
    "MappingCandidate",
    "MappingDecision",
    "MappingPlan",
    "MappingRule",
    "MappingStatus",
    "RelationDescriptor",
    "SchemaDescriptor",
    "Sensitivity",
]
