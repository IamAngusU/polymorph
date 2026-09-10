# Operational visibility

Polymorph has two deliberately separate operational records. Neither contains record payloads.

## Local operational event stream

The workflow benchmark now writes `operational-events.jsonl`. Its fixed schema records workflow,
batch, stage-summary and destination-runtime outcomes with opaque run and correlation IDs. Event
names, statuses and reasons are bounded machine-readable codes. Arbitrary detail dictionaries and
exception messages are not accepted.

Lifecycle events must carry a record count, batch completions must carry a positive batch count,
and every delivery outcome counts exactly one record. Stage summaries require both a count and a
duration. A passed run is healthy only when requested, completed, successful-delivery and summed
batch counts agree. Missing counters fail closed instead of quietly weakening the check.

Cooperating thread and process writers use the same path lock. Each complete JSON line is flushed
to disk before the append returns. A writer validates existing lines on first use and again after a
detected identity, size or modification-time change; an incomplete tail is always rejected. The
reader caps every line read at 4,097 bytes and rejects records over the 4,096-byte format limit
without first allocating an unbounded line. The final summary scans the complete stream. This
catches ordinary damage without turning every append into an increasingly expensive full-file
scan. It is not protection against deliberate same-file tampering. The benchmark report includes a
per-run summary and says whether the stream was valid and closed without a known gap.

```bash
polymorph events summary ./workflow-run/operational-events.jsonl --run-id RUN_ID
polymorph events check ./workflow-run/operational-events.jsonl --run-id RUN_ID
```

For a workflow benchmark, `RUN_ID` is stored at `workflow.observability.run_id` in its JSON report.

`events check` validates the whole stream and exits with code 10 when the selected run is missing,
does not start first and complete last exactly once with the same correlation ID, contains a reason
code, repeats an event ID, disagrees with its successful-delivery and completion counters, uses an
invalid component, event-type and status combination, or uses any status outside the explicit
healthy set: `started`, `passed`, `delivered` and `duplicate`. This
includes `ambiguous`, `failed`, `blocked`, `quarantined`, `append_failed` and unknown future
statuses. It requires a run ID and streams counters while retaining the stream's 128-bit event IDs
for exact duplicate detection. Memory for this check therefore grows with the number of events in
the file. This is a fail-closed local health gate for CI, schedulers and monitoring wrappers. It does
not send notifications itself.
Destination receipts expose `operational_event_status` as `disabled`, `recorded` or
`append_failed`. A diagnostic write failure never converts a committed destination write into a
retry.

This event file is not signed or hash-chained. It can explain local operation, but it is not
evidence against an administrator editing or deleting history. Use the delivery audit below when
tamper evidence matters.

## Delivery audit

`AuditLog` is an optional hash-chained stream of final destination receipts. Normal delivery,
replay and force replay have distinct event types. The event shape is fixed and bounded, but its
tenant, connector and record identifiers are still sensitive metadata and need retention and file
access controls.

```bash
polymorph audit verify ./audit.sqlite
polymorph audit summary ./audit.sqlite
polymorph explain write_outcome_unknown
```

Verification without `--public-key-hex` proves only the local hash-chain relationship. Signature
verification proves the configured key signed each stored event. Neither mode can detect deletion
of a valid log suffix without an external checkpoint.

The destination ledger remains authoritative if audit append fails. Each receipt reports an
`audit_status` of `disabled`, `recorded` or `append_failed`; the compatibility boolean
`audit_recorded` remains available. Retrying a committed non-idempotent write just to obtain a log
line would be worse than the missing audit event.

## Recipe feedback

`prepare` records success, quarantine or rejection for every recipe it actually reuses. Health is
derived from those metadata-only observations. After three consecutive rejections by default,
automatic reuse is suspended and the workflow falls back to fresh deterministic mapping. It does
not rewrite the recipe or learn from payload values.

```bash
polymorph recipe health --store ./recipes.sqlite3
```

This is a closed safety loop, not autonomous semantic learning. Its only automatic response is to
reduce trust in repeated failed reuse.

## Current boundary

There is no always-on supervisor, alert delivery, queue metric exporter or globally complete event
history yet. The local stream currently covers the workflow benchmark and destination receipts.
Content inspection, mapping, relay decisions and capability denials outside that workflow are not
all instrumented. Source outbox and relay state are durable, but acknowledgements outside the
instrumented workflow still do not produce a global operational journal.
There is no built-in rotation or retention policy. Storage grows with one event per observed
destination receipt, so long-running deployments must manage the JSONL file externally.

Until a dedicated service layer exists, monitor receipt fields, audit summaries, recipe health,
relay dead letters, destination quarantine and ledger state as separate sources. Do not market the
alpha as self-healing or fully self-observing.
