from __future__ import annotations

from dataclasses import replace

import pytest

from polymorph.errors import IntegrityError
from polymorph.models.mapping import MappingPlan, MappingRule
from polymorph.models.schema import FieldDescriptor, SchemaDescriptor
from polymorph.models.types import DataType
from polymorph.recipes import RecipeRunOutcome, RecipeStore


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
