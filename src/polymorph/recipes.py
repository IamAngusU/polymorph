from __future__ import annotations

import json
import os
import sqlite3
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path

from .errors import IntegrityError, PolicyViolation
from .models.mapping import MappingPlan
from .models.schema import SchemaDescriptor
from .serialization import plan_from_dict, plan_to_dict
from .validation import PlanValidator


class RecipeRunOutcome(StrEnum):
    SUCCESS = "success"
    QUARANTINED = "quarantined"
    REJECTED = "rejected"


@dataclass(frozen=True, slots=True)
class Recipe:
    id: str
    version: int
    source_structural_fingerprint: str
    target_structural_fingerprint: str
    plan: MappingPlan
    approved_by: str
    created_at: datetime

    def rebind(
        self,
        source_schema: SchemaDescriptor,
        target_schema: SchemaDescriptor,
    ) -> MappingPlan:
        if source_schema.structural_fingerprint() != self.source_structural_fingerprint:
            raise IntegrityError("recipe source structure does not match the current source")
        if target_schema.structural_fingerprint() != self.target_structural_fingerprint:
            raise IntegrityError("recipe target structure does not match the current destination")

        rebound = MappingPlan(
            id=str(uuid.uuid4()),
            source_schema_id=source_schema.id,
            target_schema_id=target_schema.id,
            source_fingerprint=source_schema.fingerprint(),
            target_fingerprint=target_schema.fingerprint(),
            rules=self.plan.rules,
            version=self.version,
        )
        report = PlanValidator().validate(rebound, source_schema, target_schema)
        report.raise_if_invalid()
        if report.requires_review:
            raise PolicyViolation("recipe rebind requires review under the current schema")
        return rebound


class RecipeStore:
    """Local durable recipe store.

    Recipes are candidate institutional memory, not authorization. Every activation is rebound
    to the current exact schemas and validated again. Run observations contain metadata only.
    """

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()
        if os.name == "posix":
            os.chmod(self.path, 0o600)

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=15.0)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 15000")
        return connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.execute("PRAGMA journal_mode = WAL")
            connection.execute("PRAGMA synchronous = FULL")
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS recipes (
                    id TEXT PRIMARY KEY,
                    version INTEGER NOT NULL,
                    source_structural_fingerprint TEXT NOT NULL,
                    target_structural_fingerprint TEXT NOT NULL,
                    plan_json TEXT NOT NULL,
                    plan_digest TEXT NOT NULL,
                    approved_by TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    UNIQUE(source_structural_fingerprint, target_structural_fingerprint, version)
                );
                CREATE INDEX IF NOT EXISTS idx_recipes_structure
                    ON recipes(source_structural_fingerprint, target_structural_fingerprint, version DESC);
                CREATE TABLE IF NOT EXISTS recipe_runs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    recipe_id TEXT NOT NULL,
                    plan_digest TEXT NOT NULL,
                    outcome TEXT NOT NULL,
                    reason_code TEXT,
                    occurred_at TEXT NOT NULL,
                    FOREIGN KEY(recipe_id) REFERENCES recipes(id) ON DELETE RESTRICT
                );
                """
            )

    def remember(
        self,
        plan: MappingPlan,
        source_schema: SchemaDescriptor,
        target_schema: SchemaDescriptor,
        *,
        approved_by: str = "local-user",
    ) -> Recipe:
        report = PlanValidator().validate(plan, source_schema, target_schema)
        report.raise_if_invalid()
        if report.requires_review:
            raise PolicyViolation("a recipe can only remember a review-free validated plan")

        source_structural = source_schema.structural_fingerprint()
        target_structural = target_schema.structural_fingerprint()
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT COALESCE(MAX(version), 0) AS version
                FROM recipes
                WHERE source_structural_fingerprint = ? AND target_structural_fingerprint = ?
                """,
                (source_structural, target_structural),
            ).fetchone()
            version = int(row["version"]) + 1
            recipe = Recipe(
                id=str(uuid.uuid4()),
                version=version,
                source_structural_fingerprint=source_structural,
                target_structural_fingerprint=target_structural,
                plan=plan,
                approved_by=approved_by,
                created_at=datetime.now(UTC),
            )
            connection.execute(
                """
                INSERT INTO recipes(
                    id, version, source_structural_fingerprint, target_structural_fingerprint,
                    plan_json, plan_digest, approved_by, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    recipe.id,
                    recipe.version,
                    source_structural,
                    target_structural,
                    json.dumps(plan_to_dict(plan), sort_keys=True, separators=(",", ":")),
                    plan.digest(),
                    approved_by,
                    recipe.created_at.isoformat(),
                ),
            )
        return recipe

    def find(
        self, source_schema: SchemaDescriptor, target_schema: SchemaDescriptor
    ) -> Recipe | None:
        source_structural = source_schema.structural_fingerprint()
        target_structural = target_schema.structural_fingerprint()
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT * FROM recipes
                WHERE source_structural_fingerprint = ? AND target_structural_fingerprint = ?
                ORDER BY version DESC LIMIT 1
                """,
                (source_structural, target_structural),
            ).fetchone()
        return self._row_to_recipe(row) if row is not None else None

    def get(self, recipe_id: str) -> Recipe | None:
        with self._connect() as connection:
            row = connection.execute("SELECT * FROM recipes WHERE id = ?", (recipe_id,)).fetchone()
        return self._row_to_recipe(row) if row is not None else None

    def list(self, *, limit: int = 100) -> list[Recipe]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM recipes ORDER BY created_at DESC LIMIT ?", (max(1, limit),)
            ).fetchall()
        return [self._row_to_recipe(row) for row in rows]

    def record_run(
        self,
        recipe: Recipe,
        plan: MappingPlan,
        outcome: RecipeRunOutcome,
        *,
        reason_code: str | None = None,
    ) -> None:
        if reason_code is not None and len(reason_code) > 128:
            raise ValueError("recipe reason code is too long")
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO recipe_runs(recipe_id, plan_digest, outcome, reason_code, occurred_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    recipe.id,
                    plan.digest(),
                    outcome.value,
                    reason_code,
                    datetime.now(UTC).isoformat(),
                ),
            )

    @staticmethod
    def _row_to_recipe(row: sqlite3.Row) -> Recipe:
        try:
            payload = json.loads(str(row["plan_json"]))
            plan = plan_from_dict(payload)
        except (json.JSONDecodeError, ValueError, KeyError) as exc:
            raise IntegrityError("stored recipe plan is invalid") from exc
        if plan.digest() != str(row["plan_digest"]):
            raise IntegrityError("stored recipe plan digest does not match")
        return Recipe(
            id=str(row["id"]),
            version=int(row["version"]),
            source_structural_fingerprint=str(row["source_structural_fingerprint"]),
            target_structural_fingerprint=str(row["target_structural_fingerprint"]),
            plan=plan,
            approved_by=str(row["approved_by"]),
            created_at=datetime.fromisoformat(str(row["created_at"])),
        )
