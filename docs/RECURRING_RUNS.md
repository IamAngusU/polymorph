# Recurring and incremental runs

Polymorph provides a commit-bound local state primitive rather than pretending to be a scheduler
or CDC platform. Use Windows Task Scheduler, systemd timers, Kubernetes CronJobs, or another
trusted scheduler to launch the host application. GitHub Actions are not required.

```python
from polymorph.sync_state import CommitReceipt, SyncStateStore

store = SyncStateStore(".polymorph/sync.sqlite3")
route_id = "daily-invoices-v1"

with store.hold(route_id, ttl_seconds=900):
    before = store.get(route_id)
    generation = 0 if before is None else before.generation
    cursor = None if before is None else before.cursor

    result, next_cursor = run_one_increment(cursor)
    receipt = CommitReceipt.from_result(result, run_id=result.session_id)
    store.advance(
        route_id,
        expected_generation=generation,
        next_cursor=next_cursor,
        receipt=receipt,
    )
```

## Invariants

1. The source cursor advances only from a structured `completed` write result.
2. Compare-and-swap generation prevents two local runs from silently overwriting progress.
3. A repeated run ID with identical evidence is idempotent; conflicting reuse is rejected.
4. Expiring fenced leases prevent normal overlapping runs on one trusted host.
5. Cursor JSON is bounded by bytes, depth, and node count.
6. The inspection CLI redacts cursor content unless `--show-cursor` is explicitly supplied.

## Limits

- A lease is local SQLite coordination, not a distributed consensus protocol.
- Lease expiry cannot stop an already running process. Long runs must renew their lease.
- Cursor meaning, pagination, API-version drift, and deletion semantics are connector-specific.
- CDC requires a source-specific log position, retention behavior, snapshot protocol, and tests.
- The database may contain operationally sensitive cursor data and must live in a trusted private
  directory. It is not encrypted by Polymorph.
