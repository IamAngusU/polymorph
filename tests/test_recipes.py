from __future__ import annotations

import sqlite3
import threading
from dataclasses import replace
from datetime import UTC, datetime

import pytest

from polymorph.errors import IntegrityError
from polymorph.models.mapping import MappingPlan, MappingRule
from polymorph.models.schema import FieldDescriptor, SchemaDescriptor
from polymorph.models.types import DataType
from polymorph.recipes import RecipeHealthState, RecipeRunOutcome, RecipeStore


def _schemas(source_id: str = "source:file-a"):
    source = SchemaDescriptor(
        source_id,
        (
            FieldDescriptor("c1", "Customer Number", DataType.STRING),
            FieldDescriptor("c2", "Amount", DataType.DECIMAL),
        ),
    )
    target = SchemaDescriptor(
        "db:orders",
        (
            FieldDescriptor("customer_number", "Customer Number", DataType.STRING),
            FieldDescriptor("amount", "Amount", DataType.DECIMAL),
        ),
    )
    return source, target


def _plan(source: SchemaDescriptor, target: SchemaDescriptor) -> MappingPlan:
    return MappingPlan(
        "approved-plan",
        source.id,
        target.id,
        source.fingerprint(),
        target.fingerprint(),
        (
            MappingRule("c1", "customer_number"),
            MappingRule("c2", "amount"),
        ),
    )


def test_recipe_reuses_structure_without_trusting_old_exact_schema_identity(tmp_path) -> None:
    source, target = _schemas()
    store = RecipeStore(tmp_path / "recipes.sqlite")
    recipe = store.remember(_plan(source, target), source, target)

    next_source, _ = _schemas("source:monthly-file-b")
    found = store.find(next_source, target)
    assert found is not None

    rebound = found.rebind(next_source, target)
    assert rebound.id != recipe.plan.id
    assert rebound.source_schema_id == next_source.id
    assert rebound.source_fingerprint == next_source.fingerprint()


def test_recipe_does_not_activate_after_structural_drift(tmp_path) -> None:
    source, target = _schemas()
    store = RecipeStore(tmp_path / "recipes.sqlite")
    recipe = store.remember(_plan(source, target), source, target)
    drifted = replace(
        source,
        fields=(
            FieldDescriptor("c1", "Customer Number", DataType.STRING),
            FieldDescriptor("c2", "Gross Amount", DataType.DECIMAL),
        ),
    )

    assert store.find(drifted, target) is None
    with pytest.raises(IntegrityError):
        recipe.rebind(drifted, target)


def test_recipe_run_observation_stores_metadata_only(tmp_path) -> None:
    source, target = _schemas()
    store = RecipeStore(tmp_path / "recipes.sqlite")
    plan = _plan(source, target)
    recipe = store.remember(plan, source, target)
    store.record_run(recipe, plan, RecipeRunOutcome.SUCCESS, reason_code="validated")

    import sqlite3

    with sqlite3.connect(tmp_path / "recipes.sqlite") as connection:
        row = connection.execute(
            "SELECT outcome, reason_code FROM recipe_runs ORDER BY id DESC LIMIT 1"
        ).fetchone()
        columns = [item[1] for item in connection.execute("PRAGMA table_info(recipe_runs)")]
    assert row == ("success", "validated")
    assert "payload" not in " ".join(columns)


def test_recipe_health_suspends_reuse_after_consecutive_rejections(tmp_path) -> None:
    source, target = _schemas()
    store = RecipeStore(tmp_path / "recipes.sqlite")
    plan = _plan(source, target)
    recipe = store.remember(plan, source, target)

    with pytest.raises(ValueError, match="at least one"):
        store.health(recipe, rejection_threshold=0)

    store.record_run(recipe, plan, RecipeRunOutcome.QUARANTINED, reason_code="sampled_scan")
    assert store.health(recipe).state is RecipeHealthState.DEGRADED
    assert store.health(recipe).auto_reuse_allowed

    for _ in range(3):
        store.record_run(
            recipe,
            plan,
            RecipeRunOutcome.REJECTED,
            reason_code="required_target_null",
        )

    suspended = store.health(recipe)
    assert suspended.state is RecipeHealthState.SUSPENDED
    assert suspended.consecutive_rejections == 3
    assert not suspended.auto_reuse_allowed

    store.record_run(recipe, plan, RecipeRunOutcome.SUCCESS, reason_code="preflight_promotable")
    recovered = store.health(recipe)
    assert recovered.state is RecipeHealthState.HEALTHY
    assert recovered.consecutive_rejections == 0
    assert recovered.auto_reuse_allowed


@pytest.mark.parametrize("journal_mode", ["DELETE", "WAL"])
def test_recipe_health_reads_one_snapshot_while_a_run_is_recorded(
    tmp_path, monkeypatch, journal_mode
) -> None:
    source, target = _schemas()
    path = tmp_path / "recipes.sqlite"
    store = RecipeStore(path)
    plan = _plan(source, target)
    recipe = store.remember(plan, source, target)
    with sqlite3.connect(path) as connection:
        selected_mode = connection.execute(f"PRAGMA journal_mode = {journal_mode}").fetchone()[0]
    if selected_mode.casefold() != journal_mode.casefold():
        pytest.skip(f"SQLite did not enable requested journal mode {journal_mode}")
    original_connect = store._connect
    writer_ready = threading.Event()
    writer_done = threading.Event()
    writer_errors: list[BaseException] = []

    def write_between_health_queries() -> None:
        try:
            connection = sqlite3.connect(path, timeout=15.0)
            try:
                connection.execute("PRAGMA foreign_keys = ON")
                connection.execute("PRAGMA busy_timeout = 15000")
                connection.execute("BEGIN IMMEDIATE")
                connection.execute(
                    """
                    INSERT INTO recipe_runs(
                        recipe_id, plan_digest, outcome, reason_code, occurred_at
                    ) VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        recipe.id,
                        plan.digest(),
                        RecipeRunOutcome.REJECTED.value,
                        "required_target_null",
                        datetime.now(UTC).isoformat(),
                    ),
                )
                writer_ready.set()
                connection.commit()
            finally:
                connection.close()
        except BaseException as exc:  # surfaced in the calling test below
            writer_errors.append(exc)
            writer_ready.set()
        finally:
            writer_done.set()

    class InterleavingConnection:
        def __init__(self) -> None:
            self._connection = original_connect()
            self._started_writer = False

        def __enter__(self):
            self._connection.__enter__()
            return self

        def __exit__(self, exc_type, exc_value, traceback):
            return self._connection.__exit__(exc_type, exc_value, traceback)

        def close(self) -> None:
            self._connection.close()

        def execute(self, sql, parameters=()):
            cursor = self._connection.execute(sql, parameters)
            if "COUNT(*) AS total_runs" in sql and not self._started_writer:
                self._started_writer = True
                threading.Thread(target=write_between_health_queries, daemon=True).start()
                assert writer_ready.wait(5), "writer did not reach its commit boundary"
                if writer_errors:
                    raise writer_errors[0]
            return cursor

    monkeypatch.setattr(store, "_connect", InterleavingConnection)

    during_write = store.health(recipe)

    assert during_write.state is RecipeHealthState.UNOBSERVED
    assert during_write.total_runs == 0
    assert during_write.last_outcome is None
    assert during_write.consecutive_rejections == 0
    assert writer_done.wait(5), "writer did not commit after the reader released its snapshot"
    assert not writer_errors

    monkeypatch.setattr(store, "_connect", original_connect)
    after_write = store.health(recipe)
    assert after_write.state is RecipeHealthState.DEGRADED
    assert after_write.total_runs == 1
    assert after_write.last_outcome is RecipeRunOutcome.REJECTED


def test_recipe_run_rejects_free_form_reason_text(tmp_path) -> None:
    source, target = _schemas()
    store = RecipeStore(tmp_path / "recipes.sqlite")
    plan = _plan(source, target)
    recipe = store.remember(plan, source, target)

    with pytest.raises(ValueError, match="machine-readable"):
        store.record_run(
            recipe,
            plan,
            RecipeRunOutcome.REJECTED,
            reason_code="raw error: customer was secret-value",
        )
