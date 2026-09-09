# Operator workflows

These are the workflows the CLI should make boring before anyone spends time on a dashboard.

## 1. First safe import

```text
doctor
  -> inspect the actual bytes
  -> inspect the destination contract
  -> propose mappings
  -> show AUTO, REVIEW and BLOCKED separately
  -> create an immutable plan
  -> full no-write preflight
  -> remember the mapping recipe if it is promotable
  -> operator promotes the plan
  -> signed source agent seals records
  -> relay queues ciphertext
  -> destination writes with an idempotency key where supported
  -> reconcile
  -> record the verified delivery outcome
```

The current `prepare` command covers inspection through preflight. Promotion, source identity and
reconciliation are the next CLI boundary to make explicit.

## 2. Recurring import

```text
inspect current source
  -> find structural recipe candidate
  -> bind it to current exact schemas
  -> validate current policies and relation metadata
  -> full preflight
  -> execute
  -> reconcile
  -> record metadata-only outcome
```

Changing a filename must not invalidate an otherwise identical file recipe. Changing a column,
unit, sensitivity, formula state or foreign-key proof must.

## 3. Schema drift

Safe positional movement may produce a new plan version. Semantic changes, removed uniqueness,
changed units and sensitivity changes stop automatic rollout. The old plan remains immutable and
old ciphertext remains bound to it.

## 4. Lost destination acknowledgement

The runtime records `UNKNOWN`, preserves the sealed record and refuses a blind non-idempotent retry.
The next action is destination-specific reconciliation. An authorized operator may force a retry,
but that is a separate capability. When a destination audit log is configured, its final receipt
uses the distinct `force_replay` event type instead of looking like an ordinary delivery.

## 5. Hostile or weird input

The content gate runs before a format parser. Unsupported content, polyglot disagreement, archive
risks, macros, external links and exceeded budgets are blocked with reason codes. When an isolated
parser pack exists, its containment grade and resource limits must be visible in `doctor` output.

## 6. Benchmark promotion

Candidate matchers and parsers run against a held-out corpus. Promotion requires no regression in
unsafe AUTO count, an explicit minimum precision and a useful coverage or resource improvement.
Results are checked in as machine-readable artifacts so a release claim can be reproduced.
