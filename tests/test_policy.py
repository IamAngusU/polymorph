import pytest

from polymorph.errors import PolicyViolation
from polymorph.models.schema import FieldDescriptor
from polymorph.models.types import Sensitivity
from polymorph.policy import PolicyEngine


def test_secret_cannot_downgrade_to_internal():
    source = FieldDescriptor("s", "password", sensitivity=Sensitivity.SECRET)
    target = FieldDescriptor("t", "password", sensitivity=Sensitivity.INTERNAL)

    with pytest.raises(PolicyViolation):
        PolicyEngine().validate_route(source, target, "opaque_forward")


def test_opaque_requires_opaque_forward():
    source = FieldDescriptor("s", "token", sensitivity=Sensitivity.OPAQUE)
    target = FieldDescriptor("t", "token", sensitivity=Sensitivity.OPAQUE)

    with pytest.raises(PolicyViolation):
        PolicyEngine().validate_route(source, target, "copy")
