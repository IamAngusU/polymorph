# Reliability model

Polymorph treats automation as a privilege earned by evidence. The system is designed to abstain when the available information cannot prove a safe route.

## The accuracy target

A universal claim of 100% semantic accuracy is not meaningful for arbitrary source data. Two different business meanings can be represented by the same bytes, labels can be wrong, dates can be ambiguous and a valid foreign key can still point to the wrong business entity.

The operational target is therefore stricter and measurable:

**No incorrect automatic promotions in the validated operating domain.**

Automation coverage is measured separately. A route that needs review is not counted as a failure of correctness. An incorrect `AUTO` decision is.

The benchmark gate reports at least:

- automatic-decision precision
- automatic coverage over explicitly automation-eligible fields
- overall automatic rate over every mappable field
- suggestion accuracy
- incorrect automatic decisions on explicitly unmappable fields
- p50 and p95 case latency
- opt-in CPU, wall-clock, Python-allocation and process-RSS diagnostics

A release or deployment can require `auto_precision == 1.0` on its labelled corpus while still accepting lower automation coverage.

## Evidence hierarchy

Evidence is deliberately asymmetric. Stronger evidence can promote a route; weaker evidence may improve ordering but cannot manufacture authorization.

1. Explicit operator configuration and current destination contracts.
2. Exact schema identity, data types, sensitivity labels, field roles and verified relationship metadata.
3. Previously approved recipe structure, rebound to the current exact schemas.
4. Deterministic name and alias evidence.
5. Local embedding similarity.
6. Local reranker score.

The final two items are advisory. The matcher requires independently strong deterministic evidence before an `AUTO` decision is allowed. Automatic copy also requires directional runtime type compatibility, no nullable-to-required gap, equal sensitivity labels and compatible field roles. Foreign-key automation additionally requires a typed, single-column unique lookup contract. If a reranker changes the winner away from the deterministic winner, the result is review-required.

## Preflight before promotion

`polymorph prepare` and `polymorph preflight` run a no-write contract sandbox. It validates the exact immutable plan and scans source records without invoking a destination write method.

The preflight checks:

- record shape against the inspected source schema
- required source and destination values
- registered source transformations
- runtime output types after transformation
- optional read-only foreign-key resolution
- spreadsheet formula-cache uncertainty
- an optional hard input-record blast-radius budget
- completeness of the scan

Secret and opaque values are not inspected. Preflight checks only their presence/nullability where required.
For a non-null business key, a resolver result of null or of the wrong target type is blocking even
when the final foreign-key column is nullable. A null source value skips lookup and is preserved only
when the final target permits null.

A bounded sample can be useful for diagnosis but cannot automatically promote or remember a recipe. Automatic recipe promotion requires a complete scan.

`--max-records` is only a diagnostic sample size. It never proves a complete run. The separate
`--max-input-records N` policy is a hard gate: preflight consumes at most `N + 1` records, validates
up to `N` of them, and emits the blocking `input_record_limit_exceeded` finding when the final probe
succeeds. If a smaller diagnostic `--max-records` sample is also configured, later records are only
counted, but the hard input limit is still enforced. This protects against a selected source growing
from an expected few thousand records to hundreds of thousands. The operator still has to choose
the budget; the alpha does not infer a safe business blast radius from historical volume.

## Recipes are memory, not truth

A recipe stores a previously validated plan together with structural source and target fingerprints. A structural match only locates a candidate recipe.

Before reuse, Polymorph:

1. compares the current structural fingerprints
2. creates a new plan bound to the current exact schema IDs and fingerprints
3. creates a new plan digest
4. validates every rule against the current policies and relationships
5. runs preflight against the current input

A recipe never bypasses current validation, capability checks or destination semantics.

## Drift

Schema drift is split into two categories.

A mechanically explainable change, such as a moved spreadsheet column with the same semantic descriptor, may produce a repair proposal. The repair is a new immutable plan with a new digest.

A semantic change, relationship change, sensitivity change, missing uniqueness proof or ambiguous replacement is review-required or blocking.

## Delivery correctness

Once a route is approved, transport reliability is still a separate problem. Polymorph therefore keeps a durable delivery identity, idempotency ledger and explicit write outcomes.

The destination runtime is pinned to one immutable mapping plan and the exact target schema
fingerprint behind that plan. After decryption and all destination-only transforms, it checks the
exact mapped field set, nullability and conservative runtime types before invoking the connector.
Every non-nullable target must be mapped unless its schema explicitly marks it as generated by the
destination, such as an auto-increment key or a server-defaulted database column.
There is no implicit string coercion at this final boundary. Contract failures are quarantined
under a fixed reason code without persisting payload values.

`NOT_COMMITTED` means the connector can prove the write did not commit. `UNKNOWN` means the connector cannot prove whether a side effect happened. An unknown outcome is never converted into a retry-safe result merely because an exception was raised.

Destination claims use a bounded lease and a random fencing token. `CLAIMED` is strictly a
pre-write state. Immediately before calling a connector, the owning worker must durably move the
entry to `WRITE_STARTED` with the same unexpired token. An expired `CLAIMED` entry can therefore
be recovered safely: a stale worker cannot cross the write boundary after another worker replaces
its token. `WRITE_STARTED` never expires into an automatic retry because the external side effect
may already exist. It follows the same idempotency or explicitly authorized recovery rules as an
unknown write outcome.

The default claim lease is five minutes and the supported maximum is one hour. A lease that
expires during destination-side validation causes that worker to stop before the connector call.
Legacy `CLAIMED` rows without fencing metadata fail closed and require explicit recovery.

Connectors may additionally advertise a bounded atomic batch writer. This is an opt-in correctness
contract, not a generic speed flag. Before one batch call, the runtime authenticates and decrypts
each record, validates the final destination contract, assigns every writable row the same random
batch-attempt ID and atomically moves those ledger entries to `BATCH_WRITE_STARTED`. The connector
must then commit every row in one transaction or report a proven `NOT_COMMITTED` result. A short
write, an unprovable row count or an unknown exception is never accepted as partial success.

The batch-attempt ID stays in the ledger and signed audit metadata across restart. This prevents a
possibly committed batch from silently falling through the scalar replay path. Scalar replay is
automatic only if the connector explicitly guarantees that each item's idempotency key has the
same meaning across both APIs and its current versioned idempotency-contract ID exactly matches
the non-null ID stored at the original write boundary. Enabling idempotency later, changing its
contract ID or opening a legacy null-ID row cannot authorize an automatic retry. An unknown
outcome is retained as `BATCH_UNCERTAIN`. Both batch
states are intentionally unknown to older runtimes, so downgrades fail closed instead of weakening
the replay gate. The built-in database connector makes no cross-path idempotency claim.

Once an ambiguous row is explicitly retried, dedicated `REPLAY_*` states preserve that provenance
across validation failures, proven rollback, unknown outcome and process death. An expired
`REPLAY_CLAIMED` lease is never picked up by normal delivery. The replay API must acquire a new
fence and repeat the current connector-capability check. Legacy ledgers are migrated once and
conservatively because old `CLAIMED` and `QUARANTINED` rows do not reveal whether they came from an
earlier ambiguous replay.

The database migration is forward-only. Unknown batch and replay states protect those individual
rows from an older reader, but they are not a database-wide mixed-version writer lock. Do not run a
pre-v0.4 destination runtime against a ledger after v0.4 has opened it.

## Source outbox

The source must stage the already sealed and signed wire record in `SourceOutbox` before its
first send. If an acknowledgement is lost, retry the exact `PendingRecord.wire_bytes`. Never
run `prepare_record` again with the same transfer and record identity. Public-key encryption
uses fresh randomness, so resealing creates different authenticated content and the relay will
correctly reject it as a replay.

The outbox stores ciphertext and authenticated routing metadata only. `ack(record_digest)` is
idempotent and removes the stored wire record after the downstream acknowledgement is durable.
