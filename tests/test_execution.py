from polymorph.crypto import RecipientKeyPair, TransferContext
from polymorph.execution import DataPlaneExecutor
from polymorph.models.mapping import MappingPlan, MappingRule
from polymorph.models.schema import FieldDescriptor, SchemaDescriptor
from polymorph.models.types import Sensitivity


def test_secret_is_sealed_during_execution():
    source = SchemaDescriptor("s", (FieldDescriptor("secret", "API Token", sensitivity=Sensitivity.SECRET),))
    target = SchemaDescriptor("t", (FieldDescriptor("token", "token", sensitivity=Sensitivity.SECRET),))
    plan = MappingPlan("p", "s", "t", source.fingerprint(), target.fingerprint(), (MappingRule("secret", "token", "opaque_forward"),))
    recipient = RecipientKeyPair.generate()
    context = TransferContext("tenant", "s", "t", "secret", "1", "r1", "x1")

    executor = DataPlaneExecutor(source, target, plan)
    output = executor.execute_record(
        {"secret": "sk_test_123"},
        transfer_contexts={"secret": context},
        destination_public_key=recipient.public_bytes(),
    )

    envelope = output["token"]
    assert "sk_test_123" not in repr(envelope)
    assert executor.open_opaque_value(envelope, recipient.private_key, context) == b"sk_test_123"
