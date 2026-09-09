from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from .crypto import OpaqueEnvelope, TransferContext, open_envelope, seal_for_recipient
from .errors import PolicyViolation
from .models.mapping import MappingPlan
from .models.schema import SchemaDescriptor
from .models.types import Sensitivity
from .policy import PolicyEngine
from .transforms import apply_transform


@dataclass(slots=True)
class DataPlaneExecutor:
    source_schema: SchemaDescriptor
    target_schema: SchemaDescriptor
    plan: MappingPlan

    def execute_record(
        self,
        record: Mapping[str, object],
        *,
        transfer_contexts: Mapping[str, TransferContext] | None = None,
        destination_public_key: bytes | None = None,
    ) -> dict[str, object]:
        source_fields = self.source_schema.by_id()
        target_fields = self.target_schema.by_id()
        policy = PolicyEngine()
        output: dict[str, object] = {}

        for rule in self.plan.rules:
            source = source_fields[rule.source_field_id]
            target = target_fields[rule.target_field_id]
            policy.validate_route(source, target, rule.transform)
            value = record.get(source.id)

            if rule.transform == "opaque_forward":
                if value is None:
                    output[target.id] = None
                    continue
                if isinstance(value, OpaqueEnvelope):
                    output[target.id] = value
                    continue
                if destination_public_key is None or transfer_contexts is None:
                    raise PolicyViolation("opaque forwarding requires destination key and transfer context")
                context = transfer_contexts[source.id]
                raw = value if isinstance(value, bytes) else str(value).encode("utf-8")
                output[target.id] = seal_for_recipient(raw, destination_public_key, context)
                continue

            if source.sensitivity in {Sensitivity.SECRET, Sensitivity.OPAQUE}:
                raise PolicyViolation("secret value reached ordinary transform path")
            output[target.id] = apply_transform(rule.transform, value, rule.parameters)

        return output

    @staticmethod
    def open_opaque_value(
        envelope: OpaqueEnvelope,
        private_key: X25519PrivateKey,
        context: TransferContext,
    ) -> bytes:
        return open_envelope(envelope, private_key, context)
