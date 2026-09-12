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

A timeout or lost acknowledgement can occur after a destination has committed. Blindly retrying would risk duplicates. Scalar records move to `UNCERTAIN`; atomic groups move to `BATCH_UNCERTAIN`. They remain stored as ciphertext in the sealed quarantine and are blocked from normal replay unless the relevant idempotency contract makes that exact replay path safe.

A connector may return the stronger `NOT_COMMITTED` result only when it can prove the write rolled back or never replaced the destination. Those records are quarantined but marked retry-safe.

## Destination claim recovery

The delivery ledger separates `CLAIMED` from scalar `WRITE_STARTED` and
`BATCH_WRITE_STARTED`. Claims carry a random fencing token
and expire after five minutes by default. A worker that finds an expired `CLAIMED` row replaces the
token atomically and can continue. The stale worker's token can no longer open the write boundary.

Write-started states are deliberately not recovered by elapsed time. A crash after that transition
may have happened before, during or after the connector side effect, and those cases cannot be
told apart locally. Normal scalar replay is allowed only for a destination with a real idempotency
contract. A prior batch additionally requires an explicit guarantee that the same per-item key is
honored across batch and scalar APIs. Otherwise an operator must reconcile the destination and use
the authorized force-replay path. Distinct batch state names make older runtimes fail closed during
a downgrade. Claims created by older Polymorph versions have no fence token and also fail closed.

Manual retries of ambiguous rows use separate `REPLAY_*` states. They retain any original batch
attempt ID and cannot expire back into ordinary delivery. A replay that fails before its new write,
proves rollback, loses its acknowledgement or crashes still requires the current idempotency
contract or a newly authorized force replay on the next attempt.

Ledger schema upgrades are forward-only. The unknown state names fence affected rows, not every
future write from an old process. Never point a pre-v0.4 runtime at a ledger after v0.4 has opened
it, and do not mix destination runtime versions on the same ledger.

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

Relay enqueue and lease transactions acquire their shared in-process source-trust fence before the
SQLite transaction and release it only after commit or rollback. `SourceTrustStore.revoke` and
registry rotation wait for an older verified transaction to finish. Once revocation returns, new
intake cannot publish a record under that key; queued records that have not already acquired a
lease move to dead letter on the next lease scan. A lease committed before revocation remains
subject to the destination's independent source-key verification.

This ordering is process-local. Separate relay processes must receive the authenticated revocation
independently and must not be treated as one linearizable trust domain merely because they share a
SQLite file. Use one shared `SourceTrustStore` instance per process for queues that require this
fence.

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

Built-in audit records contain delivery metadata and cryptographic digests only. The API accepts a
fixed, bounded structure rather than arbitrary dictionaries or raw exception text. Integrators
must still keep record values out of identifier fields. `polymorph audit verify` checks the hash
chain and can additionally verify Ed25519 signatures when a trusted public key is supplied.

`polymorph audit summary` verifies that chain before returning counts by event type, status and
reason code. It does not expose record IDs. `polymorph explain REASON_CODE` returns the stable
meaning, retry policy and next operator action for known reasons. CLI verification refuses a
missing path instead of silently creating an empty audit database.

Audit verification and summaries now fetch rows in bounded batches. `AuditLog.export_jsonl_to(path)`
verifies the chain while atomically streaming the export. Admission has explicit event and logical-byte
quotas and refuses new events without deleting old history. Operators must archive and externally
witness a verified export before intentionally rotating a full audit store.

## Connector work budgets

Direct CSV, HTTP JSON and Parquet calls accept a `WorkBudget`. Defaults are finite; deployments should
lower them to the largest expected trusted workload. A budget covers total records, aggregate bytes,
wall time, nesting, nodes and individual values. Parquet adds row-group, metadata, uncompressed and
decoded-batch boundaries. Crossing a boundary fails the operation instead of silently truncating data.

HTTP destinations serialize each record exactly once before its request and charge those exact bytes
to the budget. Responses are opened in streaming mode and their bodies are not read. If a budget stops
an aggregate direct call after a committed prefix, `PartialConnectorWriteError` reports
`committed_count`, `next_record_index` and the next record's terminal outcome. Resume from that index;
never retry the complete iterable. The single-record idempotency contract rejects multi-record calls
before request one because one delivery key cannot safely identify multiple records.

The audit hook is optional and currently covers final destination delivery, replay and force-replay
receipts only. `DeliveryReceipt.audit_status` distinguishes `disabled`, `recorded` and
`append_failed`; an append failure cannot turn an already committed write into an apparent
retryable failure. This is not yet a complete source-to-relay-to-destination event stream,
alerting service or metrics backend.

## Quarantine

`polymorph quarantine list <db>` returns metadata such as record digest, route, plan digest and machine-readable reason code. The stored record remains encrypted. A quarantine database should still be protected as sensitive infrastructure because metadata can itself be confidential.
