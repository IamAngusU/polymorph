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

Raw destination public keys are also not authenticated merely because encryption succeeds.
Protocol-v3 sources therefore require a `RecipientKeyTrustStore` by default. Its trust anchor is a
separately provisioned Ed25519 destination identity. That identity signs a certificate covering
the tenant, destination connector, X25519 key ID, generation, predecessor, validity interval and
identity key ID. The X25519 key ID hashes the RFC 7748-decoded u-coordinate, including the
required masking of the final input bit and reduction modulo the field prime. Two byte encodings
that X25519 treats as the same key
therefore cannot appear as distinct rotation generations. Supplying a raw public key instead
requires the explicit `allow_unauthenticated_recipient_key=True` migration exception.

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
- destination recipient key ID for records created by current sources

Changing authenticated metadata without re-encrypting the field causes authentication failure at the destination.

Current v3 records must carry a non-empty recipient key ID. Record decoding, relay policy,
outbox/spool persistence and destination opening reject a blank ID by default. A deployment that
must drain older source-signed v3 records can enable the separate
`allow_legacy_blank_recipient_key_id=True` migration policy at each of those boundaries. This flag
does not weaken certificate verification for newly created records and must be removed after the
legacy queue drains. Protocol v2 has no recipient key ID and retains its existing wire format;
a non-empty ID on a v2 context is rejected instead of being ignored.

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

Recipient certificate bootstrap accepts only generation 1 without a predecessor. Each rotation
must be signed by the pinned destination identity, advance by exactly one generation and name the
current recipient key ID as its predecessor. A stale generation, alternate certificate at an
already accepted generation, skipped generation, wrong predecessor, previously used recipient key
or unusable low-order X25519 key fails closed. The bounded persisted history tracks up to 512
distinct recipient keys across normal restarts. The source resolves the current certificate again
for each record, so an accepted rotation takes effect without rebuilding the source agent.

The destination can retain explicitly supplied older private keys while already using the new key
as primary. The authenticated recipient key ID selects exactly one available private key, allowing
queued records to drain without trying every key. Removing an old private key ends that drain.

When configured with a state path, certificate acceptance uses a cooperative cross-process lock
and atomic private write. This detects network or control-plane replay across normal process
restarts. It does not detect an attacker who can roll back the source host's trust-state file and
all external checkpoints together. POSIX acceptance also fsyncs the parent directory after the
atomic replacement. Windows has no portable parent-directory fsync in this implementation. See
[recipient key rotation](RECIPIENT_KEY_ROTATION.md).

### Source signing key lifecycle

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
