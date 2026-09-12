from __future__ import annotations

from polymorph.sync_state import CommitReceipt, SyncStateStore


def commit_progress(result: object, next_cursor: object, run_id: str) -> None:
    store = SyncStateStore(".polymorph/sync.sqlite3")
    route_id = "example-route-v1"
    with store.hold(route_id):
        current = store.get(route_id)
        receipt = CommitReceipt.from_result(result, run_id=run_id)
        store.advance(
            route_id,
            expected_generation=0 if current is None else current.generation,
            next_cursor=next_cursor,
            receipt=receipt,
        )
