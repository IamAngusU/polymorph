# Operations and replay safety

## Delivery identity

A delivery is identified by tenant, destination connector, transfer ID and record ID. Reusing that identity with different authenticated record content is treated as a replay/integrity violation.

## Idempotency

Polymorph derives an idempotency key from authenticated delivery metadata and the sealed record digest. A destination advertises whether it supports idempotency. For HTTP, an idempotency header is used only when explicitly configured for that endpoint.

Polymorph does not assume that an arbitrary API supports idempotency merely because a client can send a header with that name.

## Unknown outcomes

A timeout or lost acknowledgement can occur after a destination has committed. Blindly retrying would risk duplicates. Such records move to `UNCERTAIN`, remain stored as ciphertext in the sealed quarantine and are blocked from normal replay when the destination is not idempotent.

A connector may return the stronger `NOT_COMMITTED` result only when it can prove the write rolled back or never replaced the destination. Those records are quarantined but marked retry-safe.

## Force replay

Force-replaying an uncertain, non-idempotent write is intentionally separate from ordinary replay and requires the corresponding signed capability when capability enforcement is enabled. Operators should first reconcile the destination by its own transaction/business identifier.

## Audit

Audit records contain delivery metadata and cryptographic digests only. They intentionally do not accept arbitrary dictionaries, raw errors or record values. `polymorph audit verify` checks the hash chain and can additionally verify Ed25519 signatures when a trusted public key is supplied.

## Quarantine

`polymorph quarantine list <db>` returns metadata such as record digest, route, plan digest and machine-readable reason code. The stored record remains encrypted. A quarantine database should still be protected as sensitive infrastructure because metadata can itself be confidential.
