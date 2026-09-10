# Recipient key authenticity and rotation

An X25519 public key provides confidentiality only to whoever owns its private half. It does not
say which destination owns that key. If a control plane can replace the raw public key, an honest
source can produce correctly source-signed ciphertext that only the attacker can open.

Protocol-v3 sources therefore use two distinct destination keys:

- a long-lived Ed25519 destination identity used only to sign recipient-key certificates
- a rotating X25519 recipient key used to decrypt record fields

The source must receive the Ed25519 identity public key through an operator-controlled channel
independent of the control plane. A certificate delivered by the control plane is untrusted input
until that pinned identity verifies it.

## Issue and bootstrap

Private identity persistence is deliberately outside the core. Production code should expose a
signing operation backed by an OS keystore or HSM. `SigningKeyPair` is suitable for local setup and
tests:

```python
from datetime import UTC, datetime, timedelta
from pathlib import Path

from polymorph.crypto import RecipientKeyPair
from polymorph.recipient_auth import RecipientKeyCertificate, RecipientKeyTrustStore
from polymorph.signing import SigningKeyPair

now = datetime.now(UTC)
identity = SigningKeyPair.generate()
recipient = RecipientKeyPair.generate()
certificate = RecipientKeyCertificate.issue(
    tenant="tenant-1",
    destination_connector="orders-db",
    public_key=recipient.public_bytes(),
    generation=1,
    previous_key_id=None,
    identity_signer=identity,
    issued_at=now,
    not_before=now,
    not_after=now + timedelta(days=90),
)
Path("recipient-certificate.json").write_text(certificate.to_json(), encoding="utf-8")

trust = RecipientKeyTrustStore(
    identity_public_key=identity.public_bytes(),
    tenant="tenant-1",
    destination_connector="orders-db",
    state_path="recipient-trust-state.json",
)
trust.accept(certificate)
```

Bootstrap accepts only generation 1 with no predecessor. The state file is written atomically and
with mode `0600` on POSIX. Certificate and state reads are bounded, reject duplicate JSON keys and
reject symbolic-link or Windows reparse-point path components.

Use the verified store directly at the source. Do not also pass a raw public key:

```python
source_agent = BlindSourceAgent(
    tenant="tenant-1",
    source_connector_id="orders-csv",
    destination_connector_id="orders-db",
    source_schema=source_schema,
    target_schema=target_schema,
    plan=plan,
    signing_key=source_signer,
    recipient_key_trust_store=trust,
)
```

`BlindSourceAgent` resolves and verifies the current certificate once per record before reading its
mapped values. Raw recipient keys fail by default. Temporary migration requires the conspicuous
`allow_unauthenticated_recipient_key=True` option and should have an explicit removal date.

That option does not permit old source-signed v3 records whose authenticated contexts omit
`recipient_key_id`. Migrating those records requires a separate
`allow_legacy_blank_recipient_key_id=True` at every boundary that reads or uses them:

- `BlindTransportRecord.from_wire`
- `RelayPolicy`
- `SourceOutbox`
- `SealedSpool`
- `BlindDestinationAgent`

Leaving any boundary strict stops the record there. The opt-in is local policy and is not encoded
into the wire record. Remove it after the old queue is empty. Protocol v2 continues to encode no
recipient key ID, including when its encryption key comes from a trust store.

## Inspect or accept a distributed certificate

The CLI can verify a certificate without changing state, or atomically advance a persistent head:

```bash
polymorph key certificate-inspect recipient-certificate.json \
  --identity-public-key-hex "$PINNED_IDENTITY_PUBLIC_KEY" \
  --tenant tenant-1 \
  --destination-connector orders-db

polymorph key certificate-accept recipient-certificate.json \
  --identity-public-key-hex "$PINNED_IDENTITY_PUBLIC_KEY" \
  --tenant tenant-1 \
  --destination-connector orders-db \
  --state recipient-trust-state.json
```

The public identity argument is a trust anchor, not discovery metadata. Supplying a value obtained
from the same possibly compromised control plane proves nothing.

## Rotate

The destination identity signs the next X25519 key with exactly the next generation and the
current key ID as predecessor:

```python
replacement = RecipientKeyPair.generate()
next_certificate = RecipientKeyCertificate.issue(
    tenant=certificate.tenant,
    destination_connector=certificate.destination_connector,
    public_key=replacement.public_bytes(),
    generation=certificate.generation + 1,
    previous_key_id=certificate.key_id,
    identity_signer=identity,
    issued_at=now,
    not_before=now,
    not_after=now + timedelta(days=90),
)
trust.accept(next_certificate)
```

Acceptance rejects a replayed generation, a second certificate that forks an accepted generation,
a skipped generation, a wrong predecessor, a backwards issuance time, a wrong route, a wrong
identity signature, an unusable low-order X25519 key, reuse of any previously accepted recipient
key and a certificate outside its validity interval. Key IDs use the RFC 7748-canonical X25519
u-coordinate, so an ignored high bit or non-canonical field encoding cannot disguise reuse as a
rotation. Multiple
processes using the same state path serialize the transition, so only one competing fork can win.
The persisted used-key set is capped
at 512 distinct keys. Once full, rotation fails closed. Reprovision a new independently pinned
identity and trust state through the operator-controlled bootstrap process instead of deleting or
truncating that history.

Trust-state files that predate the used-key history are rejected instead of being upgraded from an
unverifiable head. Migrate them only by reconstructing and auditing the complete accepted key
history, or bootstrap a new independently provisioned identity and state.

Keep the previous destination private key available until its sealed queue has drained. The new
key can be primary while the old key is explicit drain-only material:

```python
destination_agent = BlindDestinationAgent(
    replacement.private_key,
    additional_private_keys=(recipient.private_key,),
    source_trust_store=source_trust,
)
```

The authenticated recipient key ID selects exactly one key. Polymorph does not trial-decrypt a
record with every retained key. Remove old private keys after the operational drain deadline.

## Security boundary and remaining work

The local state file is a monotonic checkpoint only while the source host and that file remain
trusted. Replaying an old certificate over the network is detected after a normal restart.
Rolling the state file itself back to an older valid copy is not detectable without an external
append-only checkpoint, TPM counter, HSM state or equivalent independent monotonic authority.

State replacement flushes the new file before publishing it. On POSIX, acceptance then fsyncs the
parent directory so the new directory entry is crash-durable where the filesystem honors that
primitive. Windows has no equivalent portable directory-fsync operation in this implementation,
so power-loss durability after an atomic replacement is weaker there. A replacement or directory
sync error is reported as an uncertain outcome, never as a clean rejection. Inspect the persisted
head before retrying. An idempotent retry deliberately repeats the parent-directory sync without
rewriting the certificate, which can finish a previously uncertain POSIX sync.

The current alpha also does not implement destination identity-key rotation or an emergency
recipient revocation statement without a replacement key. An identity signer compromise requires
operator intervention and replacement of the independently pinned trust anchor. A control plane
can always withhold a valid certificate and cause denial of service; authentication cannot force it
to deliver messages.
