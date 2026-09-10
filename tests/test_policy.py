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


@pytest.mark.parametrize(
    ("source_sensitivity", "target_sensitivity"),
    [
        (Sensitivity.PERSONAL, Sensitivity.PUBLIC),
        (Sensitivity.CONFIDENTIAL, Sensitivity.INTERNAL),
        (Sensitivity.INTERNAL, Sensitivity.PUBLIC),
        (Sensitivity.OPAQUE, Sensitivity.SECRET),
    ],
)
def test_all_sensitivity_downgrades_are_rejected(
    source_sensitivity: Sensitivity,
    target_sensitivity: Sensitivity,
) -> None:
    source = FieldDescriptor("s", "value", sensitivity=source_sensitivity)
    target = FieldDescriptor("t", "value", sensitivity=target_sensitivity)

    with pytest.raises(PolicyViolation):
        PolicyEngine().validate_route(source, target, "opaque_forward")


def test_sensitivity_upgrade_is_allowed_for_explicit_plan() -> None:
    source = FieldDescriptor("s", "value", sensitivity=Sensitivity.INTERNAL)
    target = FieldDescriptor("t", "value", sensitivity=Sensitivity.PERSONAL)

    PolicyEngine().validate_route(source, target, "copy")


def test_opaque_requires_opaque_forward():
    source = FieldDescriptor("s", "token", sensitivity=Sensitivity.OPAQUE)
    target = FieldDescriptor("t", "token", sensitivity=Sensitivity.OPAQUE)

    with pytest.raises(PolicyViolation):
        PolicyEngine().validate_route(source, target, "copy")
