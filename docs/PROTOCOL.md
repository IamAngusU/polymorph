# Opaque transport protocol

## Version

The current wire record version is `3`. Cryptographic derivation uses the stable internal namespace `angusu.bridge/opaque-envelope/v3`. Product branding is deliberately excluded from this namespace so a product rename does not invalidate existing ciphertext.

Version 3 adds source authentication. The source signs the complete canonical encrypted record
with Ed25519. The signature covers every field envelope, all authenticated route and plan
metadata, the record version, the signature algorithm and the source `key_id`. A `key_id` is the
lowercase SHA-256 digest of the raw Ed25519 public key.

X25519 sealing alone is not sender authentication because anybody may know the destination's
public key. Relays and destinations therefore verify the v3 signature against a trust-store key
that is independently bound to the declared tenant and source connector.

## Field envelope

Each mapped field is independently sealed using:

- ephemeral X25519 sender key
- destination X25519 public key
- HKDF-SHA256 derived field key
- random 96-bit ChaCha20-Poly1305 nonce
- ChaCha20-Poly1305 authenticated encryption

The authenticated context includes:

- tenant
- source connector ID
- destination connector ID
- field ID
- schema version
- record ID
- transfer ID
- mapping plan ID
- mapping plan digest
- protocol version
- optional issuance and expiration timestamps

Changing authenticated metadata without re-encrypting the field causes authentication failure at the destination.

## Record integrity

A `BlindTransportRecord` rejects:

- empty records
- duplicate destination fields
- field IDs that disagree with authenticated context
- mixed record, tenant, route, transfer, plan, schema or protocol metadata
- unsupported protocol versions
- ciphertext or wire records above configured limits

The canonical wire representation is JSON with deterministic key ordering and compact separators.
The delivery digest covers the immutable encrypted record content but excludes the complete source
authentication block (`algorithm`, `key_id` and signature). This keeps replay and idempotency
identity stable if identical encrypted content is re-signed during planned key rotation. The
digest is not a payload hash of plaintext.

## Key lifecycle

Trusted source keys are bound to one tenant and source connector. `ACTIVE` and `VERIFY_ONLY` keys
may verify records. Rotation moves the previous key to `VERIFY_ONLY` while adding a new `ACTIVE`
key. The old key records an immutable rotation cutoff and accepts only records whose authenticated
`issued_at` is at or before that cutoff, which permits a bounded queue-drain window without normal
post-rotation issuance. The verification-only key also receives a finite expiry deadline, 24 hours
by default, so even backdated records stop verifying after the drain window. `REVOKED` keys fail
immediately at both relay and destination. The destination always verifies again so relay
compromise or stale relay policy cannot bypass revocation.

## Legacy records

Unsigned v2 records are rejected by default by wire parsing, relay policy and destination agents.
Migration support requires an explicit `allow_legacy_unsigned=True` setting at every boundary that
must handle v2 data. A relay must never add its own signature to a v2 record because that would
falsely claim source provenance. See [Protocol v3 migration](PROTOCOL_MIGRATION_V3.md).

## Confidentiality boundary

The protocol hides field payload values from a relay that receives only wire records and does not possess the destination private key. It does not hide routing metadata or field identifiers. It also does not protect plaintext from a compromised source or destination host.

## Expiration

A source agent may authenticate `issued_at` and `expires_at`. Destination decryption checks expiry. Relay policy can additionally require an expiry and reject lifetimes above its configured maximum.
