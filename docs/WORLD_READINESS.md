# World readiness

Polymorph should not compete as another optimistic column mapper. Its useful category is a
local-first trust layer for recurring imports where an incorrect identifier, amount, credential or
relationship is expensive.

## Product sentence

> Move data between incompatible systems, prove the route before writing, and let learned ranking
> improve suggestions without granting it write authority.

## Current evidence

The repository already demonstrates a real encrypted CSV-to-SQLite workflow, conservative schema
mapping, malformed-input handling, durable retry state, signed audit evidence and an advisory-only
learning campaign. Checked-in measurements are evidence for their exact machine and corpus, not a
promise about arbitrary customer data.

## North-star outcomes

Future product reports should prioritize outcomes over attractive model scores:

- unsafe automatic decisions: must remain zero on every declared release corpus
- time to first correct import plan
- operator review minutes per 1,000 fields
- correct automatic coverage at fixed observed precision
- abstention quality: whether the reason and next action are useful
- recovery success after ambiguous external commits
- reconciliation success after writes
- schema-drift detection lead time
- throughput, p50/p95 latency, peak RSS and process-attributed accelerator memory
- install success and five-minute-demo completion by operating system

## Evidence levels

Every public number should carry one of these labels:

1. `synthetic-regression`: generated or hand-authored fixtures used to prevent regressions.
2. `independent-public`: licensed public data not used to tune the evaluated candidate.
3. `customer-like-holdout`: anonymized or reconstructed data separated by source, template and time.
4. `production-observation`: consented metadata-only outcomes from an explicitly declared domain.

Never combine these levels into one accuracy percentage. Never train on a holdout and continue to
call it a holdout.

## Community corpus contract

Use `benchmarks/community-corpus-template.json` as a starting shape. A meaningful contribution also
needs a sidecar provenance document containing:

- source, license and redistribution permission
- whether labels were produced independently of Polymorph output
- source-group identifier that prevents related templates crossing train/test boundaries
- collection date or time bucket
- language, country and business domain
- format and generating application when known
- PII removal method and confirmation that no secrets remain
- explicit `null` labels for fields that must abstain
- reviewer identity or review method without publishing private personal data

Raw customer rows are not required for mapping evaluation. Schema labels and safe aggregate
statistics are preferable when they answer the question.

## Three product demonstrations

### Five-minute local proof

Install, run `World-Benchmark.cmd`, and receive a timestamped local evidence directory containing
workflow correctness, mapping safety, timing, peak RSS, CPU and best-effort NVIDIA measurements.
Nothing is uploaded.

### Dangerous ambiguity

Show an ambiguous date, identifier collision or credential downgrade. The memorable result is not a
high similarity score; it is a clear refusal with the smallest useful next action.

### Safe repeated import

Approve a plan once, change the source schema, and show that recipe memory accelerates review but
does not bypass current validation or reconciliation.

## High-impact delivery order

1. Collect independent, source-separated mapping corpora with honest provenance.
2. Make the five-minute proof work on clean Windows, Linux and macOS machines.
3. Add PostgreSQL and Parquet end-to-end evidence, then real network fault injection.
4. Add a versioned business glossary for identifiers, currencies, units, tax and ERP vocabulary.
5. Measure review time saved and abstention usefulness with real operators.
6. Build a read-only local review surface only after the CLI task is coherent.
7. Publish release evidence with limitations, never a context-free best number.

## Boundaries that make the product credible

- No telemetry or upload by default.
- No model download or activation as a side effect of validation.
- No learned component may authorize a write.
- No automatic GitHub push from a local run.
- No production claim based only on synthetic fixtures.
- No claim of exactly-once behavior where a destination cannot prove it.
