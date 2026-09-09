from __future__ import annotations

from dataclasses import dataclass

from .errors import PolicyViolation
from .models.schema import FieldDescriptor
from .models.types import FieldPolicy, Sensitivity


@dataclass(frozen=True, slots=True)
class PolicyEngine:
    """Central information-flow checks.

    Policies are intentionally conservative. A destination may be more restrictive than
    a source, but a route may not silently downgrade secret or opaque data.
    """

    def field_policy(self, field: FieldDescriptor) -> FieldPolicy:
        return FieldPolicy.for_sensitivity(field.sensitivity)

    def validate_route(self, source: FieldDescriptor, target: FieldDescriptor, transform: str) -> None:
        source_policy = self.field_policy(source)
        target_policy = self.field_policy(target)

        if source.sensitivity in {Sensitivity.SECRET, Sensitivity.OPAQUE}:
            if target.sensitivity not in {Sensitivity.SECRET, Sensitivity.OPAQUE}:
                raise PolicyViolation("sensitive route would downgrade destination sensitivity")
            if transform not in {"copy", "opaque_forward"}:
                raise PolicyViolation("secret or opaque fields cannot be transformed")

        if transform not in {"copy", "opaque_forward"} and not source_policy.transformable:
            raise PolicyViolation("source policy forbids transformation")

        if source.sensitivity is Sensitivity.OPAQUE and transform != "opaque_forward":
            raise PolicyViolation("opaque fields require opaque_forward")

        if target_policy.sensitivity is Sensitivity.OPAQUE and transform != "opaque_forward":
            raise PolicyViolation("opaque destinations require opaque_forward")
