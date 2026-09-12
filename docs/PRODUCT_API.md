# Embedding Polymorph

Polymorph has a deliberately small product surface over a deeper trust engine. The embedded local
path is useful for application-owned file imports. The secure agent path remains the correct route
when plaintext endpoint separation, recipient-key encryption, durable relay recovery or external
source snapshot guarantees matter.

## Five-minute embedded route

```python
from polymorph import ConnectorSpec, move

session = move(
    source="./incoming/customers.csv",
    destination=ConnectorSpec.destination(
        "database",
        url="sqlite:///app.sqlite",
        table="customers",
    ),
    max_input_records=10_000,
)

session.on("review_required", lambda event: show_review(event.as_dict()))
session.on("blocked", lambda event: show_block(event.as_dict()))
session.on("progress", lambda event: update_progress(event.as_dict()))
session.on("completed", lambda event: retain_evidence(event.as_dict()))

preparation = session.prepare()
if preparation.ready:
    result = session.execute()
```

`move()` creates a session and never writes. `prepare()` performs connector resolution, schema
inspection, deterministic mapping, plan construction and a complete no-write preflight. Only an
explicit `execute()` can call the destination connector.

## Review without hidden authority

When `preparation.status == "review_required"`, inspect `preparation.decisions`. A host can record an
explicit choice and rerun preparation:

```python
session.review_mapping(
    "legacy_customer_no",
    "account_id",
    reviewed_by="operator-ticket-1842",
)
preparation = session.prepare()
```

A blocked decision cannot be converted into a reviewed decision through this API. Policy and
contract blocks remain blocks. Review identity is returned as route metadata and record values are
not placed in product events.

## Structured outcomes

| Status | Destination evidence | Retry rule |
| --- | --- | --- |
| `ready` | Preparation passed; no write was called | Call `execute()` only when intended |
| `review_required` | No write was called | Review explicitly, then prepare again |
| `blocked` | No write was called | Fix the stated contract or policy issue |
| `completed` | Connector synchronously reported the exact consumed count | Retain plan and outcome |
| `not_committed` | Connector explicitly proved no write committed | Retry only after fixing the cause |
| `partial` | Connector proved a committed prefix and the next-record outcome | Never replay the complete batch |
| `unknown` | Commit state is not proven | Reconcile destination state before retry |

An ordinary exception after the write boundary becomes `unknown`; it never becomes retry-safe by
guessing. Event callback failures are counted separately and cannot interrupt or strengthen a write
outcome.

## Source stability

The local `execute()` path currently requires a file source selected by content inspection and bound
to the accepted file identity. An explicitly supplied database, HTTP or custom source can be fully
prepared, but local execution stops with `source_snapshot_unproven`. This prevents a full-scan
preflight over one dataset from authorizing writes from a different live dataset.

Secret and opaque forwarding also stop in the local convenience path. Use the source agent,
ciphertext-only relay and destination runtime documented in the trust model for that route.

## Product events

Every `PolymorphEvent` uses contract version 1 and contains only bounded control metadata:

```text
event_type, severity, reason_code, scope
message_key, default_message, parameters
next_action, retry_policy, presentation_hint
run_id, correlation_id, event_id, occurred_at
```

Presentation hints are advisory. A CLI, desktop app, web application or ERP plugin decides whether
an event appears inline, in a toast, in a dialog or in an incident queue.

English and German message catalogs are packaged with the wheel:

```python
message = event.localized_message("de")
```

Available adapters are `CallbackEventSink`, `CompositeEventSink` and `AsyncQueueEventSink`. The queue
is bounded and reports pressure instead of growing without limit. Hosts can implement the small
`EventSink.emit(event)` protocol for JSONL, SSE, WebSocket, webhook or native UI delivery. Networked
adapters intentionally stay outside the core because authentication, replay and backpressure policy
belong to the deploying host.

## Local demo

```bash
polymorph demo --open
polymorph demo --locale de --output ./polymorph-demo.de.html
```

The generated HTML is self-contained. It runs the real matcher and preflight over synthetic records,
includes a downloadable event/route evidence object, and never calls a destination write.
