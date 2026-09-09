# Operational visibility

Polymorph has two deliberately separate operational records. Neither contains record payloads.

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

There is no always-on supervisor, alert delivery, queue metric exporter or complete event history
yet. Source outbox and relay state are durable, but acknowledgements remove successful queue rows
and do not produce a global operational journal. Content inspection, mapping and capability denial
also do not currently append to the destination audit log.

Until a dedicated service layer exists, monitor receipt fields, audit summaries, recipe health,
relay dead letters, destination quarantine and ledger state as separate sources. Do not market the
alpha as self-healing or fully self-observing.
