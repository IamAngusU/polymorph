from dataclasses import replace
from datetime import timedelta

import pytest

from polymorph.capabilities import (
    CapabilityAuthorizer,
    CapabilityGrant,
    CapabilityOperation,
    SignedCapabilityGrant,
)
from polymorph.errors import IntegrityError, PolicyViolation
from polymorph.signing import SigningKeyPair


def test_signed_capability_is_plan_and_connector_scoped():
    signer = SigningKeyPair.generate()
    grant = CapabilityGrant.issue(
        issuer="control-plane",
        subject="destination-agent-1",
        tenant="tenant-1",
        connector_id="db-1",
        operations=(CapabilityOperation.WRITE_RECORDS,),
        allowed_plan_digests=("abc",),
    )
    authorizer = CapabilityAuthorizer(
        SignedCapabilityGrant.sign(grant, signer),
        signer.public_bytes(),
        subject="destination-agent-1",
        expected_issuer="control-plane",
    )

    authorizer.authorize(
        CapabilityOperation.WRITE_RECORDS,
        tenant="tenant-1",
        connector_id="db-1",
        plan_digest="abc",
    )
    with pytest.raises(PolicyViolation):
        authorizer.authorize(
            CapabilityOperation.WRITE_RECORDS,
            tenant="tenant-1",
            connector_id="db-2",
            plan_digest="abc",
        )
    with pytest.raises(PolicyViolation):
        authorizer.authorize(
            CapabilityOperation.WRITE_RECORDS,
            tenant="tenant-1",
            connector_id="db-1",
            plan_digest="other",
        )


def test_capability_tamper_invalidates_signature():
    signer = SigningKeyPair.generate()
    grant = CapabilityGrant.issue(
        issuer="control-plane",
        subject="agent",
        tenant="tenant",
        connector_id="db",
        operations=(CapabilityOperation.WRITE_RECORDS,),
    )
    signed = SignedCapabilityGrant.sign(grant, signer)
    tampered = SignedCapabilityGrant(
        replace(grant, operations=(CapabilityOperation.WRITE_RECORDS, CapabilityOperation.REPLAY)),
        signed.signature,
    )

    with pytest.raises(IntegrityError):
        tampered.verify(signer.public_bytes())


def test_expired_capability_is_rejected():
    signer = SigningKeyPair.generate()
    grant = CapabilityGrant.issue(
        issuer="control-plane",
        subject="agent",
        tenant="tenant",
        connector_id="db",
        operations=(CapabilityOperation.WRITE_RECORDS,),
        ttl=timedelta(seconds=-1),
    )
    signed = SignedCapabilityGrant.sign(grant, signer)
    authorizer = CapabilityAuthorizer(signed, signer.public_bytes(), subject="agent")

    with pytest.raises(PolicyViolation):
        authorizer.authorize(
            CapabilityOperation.WRITE_RECORDS,
            tenant="tenant",
            connector_id="db",
        )
