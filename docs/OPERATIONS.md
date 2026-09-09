# Operations and replay safety

## Delivery identity

A delivery is identified by tenant, destination connector, transfer ID and record ID. Reusing that identity with different authenticated record content is treated as a replay/integrity violation.

## Idempotency

Polymorph derives an idempotency key from authenticated delivery metadata and the sealed record
digest. A destination advertises whether it supports idempotency. For HTTP, configuring a header
alone is only advisory. Safe replay is enabled only when `idempotency_contract=True` explicitly
asserts that the endpoint implements the contract end to end.

Polymorph does not assume that an arbitrary API supports idempotency merely because a client can send a header with that name.

## Unknown outcomes

A timeout or lost acknowledgement can occur after a destination has committed. Blindly retrying would risk duplicates. Such records move to `UNCERTAIN`, remain stored as ciphertext in the sealed quarantine and are blocked from normal replay when the destination is not idempotent.

A connector may return the stronger `NOT_COMMITTED` result only when it can prove the write rolled back or never replaced the destination. Those records are quarantined but marked retry-safe.

## Destination claim recovery

The delivery ledger separates `CLAIMED` from `WRITE_STARTED`. Claims carry a random fencing token
and expire after five minutes by default. A worker that finds an expired `CLAIMED` row replaces the
token atomically and can continue. The stale worker's token can no longer open the write boundary.

`WRITE_STARTED` is deliberately not recovered by elapsed time. A crash after that transition may
have happened before, during or after the connector side effect, and those cases cannot be told
apart locally. Normal replay is allowed only for a destination with a real idempotency contract.
Otherwise an operator must reconcile the destination and use the authorized force-replay path.
Claims created by older Polymorph versions have no fence token and also fail closed.

## Force replay

Force-replaying an uncertain, write-started or legacy unfenced delivery is intentionally separate
from ordinary replay and always requires an explicit capability authorizer plus the corresponding
signed capability.
Operators should first reconcile the destination by its own transaction or business identifier.

## Relay leases

Every relay lease has a random single-use fencing token in addition to the worker name. Ack and
release require the current unexpired token. Reusing a worker name cannot let a stale worker
acknowledge a newer lease.

Queued records are revalidated when leased. Invalid wire data, failed source authentication,
expired transfers, rejected policy and digest mismatches move atomically to the relay's sealed
dead-letter table under fixed reason codes. The relay never decrypts these records or stores
exception text. It continues scanning for deliverable work, but processes at most the requested
lease count plus 1,000 dead letters per transaction. A dead-lettered delivery identity cannot be
enqueued again implicitly; recovery requires an explicit operator workflow.

## Local SQLite durability

The Python runtime's linked SQLite version determines the journal policy. WAL is used only when
the runtime contains the upstream 2026 WAL-reset race fix. A vulnerable or older runtime falls
back to the rollback journal. Both modes use full synchronous durability. `polymorph doctor`
reports the SQLite version, selected mode and whether the fix is present.

## File destinations

CSV and JSON read-modify-publish writes take a persistent per-path operating-system lock plus an
in-process lock. This serializes cooperative Polymorph writers on one host and keeps the atomic
replace from losing a concurrent append. It is not distributed consensus and should not be used
as a multi-host write target on a network filesystem.

CSV output rejects values and headers that begin like spreadsheet formulas after leading
whitespace. `allow_spreadsheet_formulas=True` is an explicit opt-in for callers that really need
raw formula text. Polymorph does not silently prefix or mutate the value.

## Audit

Audit records contain delivery metadata and cryptographic digests only. They intentionally do not accept arbitrary dictionaries, raw errors or record values. `polymorph audit verify` checks the hash chain and can additionally verify Ed25519 signatures when a trusted public key is supplied.

## Quarantine

`polymorph quarantine list <db>` returns metadata such as record digest, route, plan digest and machine-readable reason code. The stored record remains encrypted. A quarantine database should still be protected as sensitive infrastructure because metadata can itself be confidential.
