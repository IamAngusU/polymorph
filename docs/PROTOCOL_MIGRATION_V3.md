# Protocol v3 migration

Protocol v3 closes the sender-authentication gap in v2. Existing v2 ciphertext remains
cryptographically readable, but unsigned records are no longer accepted by default.

## Rollout

1. Create a separate Ed25519 signing identity for every tenant and source connector. Do not reuse
   capability-signing or recipient-decryption keys.
2. Register each source public key as a `TrustedSourceKey` in both relay and destination trust
   stores. Pin the displayed key fingerprint through a channel independent from the data path.
3. Deploy dual-version readers with legacy acceptance disabled. Enable
   `allow_legacy_unsigned=True` only in a dedicated relay policy containing the named route with
   an existing v2 backlog.
4. Switch source agents to v3. New `BlindSourceAgent` instances require a `SigningKeyPair` by
   default. Producing v2 requires both `protocol_version=2` and `allow_legacy_unsigned=True`.
5. Drain or quarantine the known v2 backlog, then remove every legacy exception. Do not silently
   downgrade a failed v3 record to v2 handling.

## Rotation and revocation

For planned rotation, call `SourceTrustStore.rotate(old_key_id, replacement)`. The old key becomes
verification-only with an immutable issuance cutoff while the replacement becomes active. Records
from the old key must carry an authenticated `issued_at` no later than that cutoff and verify only
until the finite grace deadline, 24 hours by default. Set `verification_grace` to a shorter explicit
window where operations permit it. Size this window to the maximum relay retention and lease time,
then revoke the old key.

For suspected compromise, call `SourceTrustStore.revoke(key_id)` immediately in both processes.
Hard revocation rejects queued records as well as new intake when the relay revalidates a lease.
The destination independently revalidates immediately before decryption. Records signed by a
revoked key should be quarantined for manual provenance review, not automatically re-signed.

Within one process, relay enqueue and lease batches keep a `SourceTrustStore` verification session
open through their SQLite commit. Revocation and registry rotation use the same lock. When
`revoke` returns, a concurrent intake has therefore either committed before the revocation or will
observe the revoked state and fail; it cannot remain verified but uncommitted and publish later.
The session covers the complete bounded batch to avoid one lock acquisition per record. This does
not distribute revocation between processes. Every relay and destination process still needs an
authenticated, durable revocation update.

## Replay identity

Replay identity remains tenant, destination connector, transfer ID and record ID. The encrypted
content digest excludes the complete source-authentication block, so rotating a key and signature
cannot create a second logical delivery. Any change to ciphertext, route, source connector, plan or
record metadata changes the digest and either fails signature verification or triggers the existing
replay conflict.

## Operational warning

The in-memory trust store is the core verification primitive, not a complete key-distribution
system. A long-running deployment still needs authenticated trust-bundle distribution, monotonic
bundle versions, durable revocation, OS or HSM-backed signing and separate relay and destination
process identities.

The issuance cutoff is an operational rotation control, not a trusted timestamp service. A stolen
old private key can sign a backdated timestamp during the finite grace window. Suspected compromise
therefore requires immediate hard revocation rather than a verification-only drain window.
