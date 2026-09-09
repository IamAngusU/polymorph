from __future__ import annotations

import json
import os
import sqlite3
import uuid
from contextlib import closing
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path

from .errors import IntegrityError, PolicyViolation
from .models.mapping import MappingPlan
from .models.schema import SchemaDescriptor
from .serialization import plan_from_dict, plan_to_dict
from .sqlite_safety import configure_sqlite_durability
from .validation import PlanValidator


class RecipeRunOutcome(StrEnum):
    SUCCESS = "success"
    QUARANTINED = "quarantined"
    REJECTED = "rejected"


class RecipeHealthState(StrEnum):
    UNOBSERVED = "unobserved"
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    SUSPENDED = "suspended"


DEFAULT_RECIPE_REJECTION_THRESHOLD = 3


@dataclass(frozen=True, slots=True)
class RecipeHealth:
    recipe_id: str
    state: RecipeHealthState
    auto_reuse_allowed: bool
    rejection_threshold: int
    total_runs: int
    successful_runs: int
    quarantined_runs: int
    rejected_runs: int
    consecutive_rejections: int
    last_outcome: RecipeRunOutcome | None = None
    last_reason_code: str | None = None
    last_occurred_at: datetime | None = None

    def as_dict(self) -> dict[str, object]:
        return {
            "recipe_id": self.recipe_id,
            "state": self.state.value,
            "auto_reuse_allowed": self.auto_reuse_allowed,
            "rejection_threshold": self.rejection_threshold,
            "total_runs": self.total_runs,
            "successful_runs": self.successful_runs,
            "quarantined_runs": self.quarantined_runs,
            "rejected_runs": self.rejected_runs,
            "consecutive_rejections": self.consecutive_rejections,
            "last_outcome": self.last_outcome.value if self.last_outcome is not None else None,
            "last_reason_code": self.last_reason_code,
            "last_occurred_at": (
                self.last_occurred_at.isoformat() if self.last_occurred_at is not None else None
            ),
        }


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
        with closing(self._connect()) as connection, connection:
            configure_sqlite_durability(connection)
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
                    ON recipes(
                        source_structural_fingerprint,
                        target_structural_fingerprint,
                        version DESC
                    );
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
        with closing(self._connect()) as connection, connection:
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
        with closing(self._connect()) as connection, connection:
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
        with closing(self._connect()) as connection, connection:
            row = connection.execute("SELECT * FROM recipes WHERE id = ?", (recipe_id,)).fetchone()
        return self._row_to_recipe(row) if row is not None else None

    def list(self, *, limit: int = 100) -> list[Recipe]:
        with closing(self._connect()) as connection, connection:
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
        if reason_code is not None and (
            not reason_code or len(reason_code) > 128 or not reason_code.replace("_", "").isalnum()
        ):
            raise ValueError("recipe reason code must be a short machine-readable identifier")
        with closing(self._connect()) as connection, connection:
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

    def health(
        self,
        recipe: Recipe,
        *,
        rejection_threshold: int = DEFAULT_RECIPE_REJECTION_THRESHOLD,
    ) -> RecipeHealth:
        """Summarize metadata-only outcomes and gate unsafe automatic reuse.

        Only consecutive rejected executions open the circuit. Review outcomes remain visible as
        degraded health, but do not punish a recipe for an intentionally sampled preflight.
        A later successful observation closes the circuit. Approving a new recipe version also
        starts with independent health history.
        """

        if rejection_threshold < 1:
            raise ValueError("recipe rejection threshold must be at least one")
        with closing(self._connect()) as connection, connection:
            connection.execute("BEGIN")
            totals = connection.execute(
                """
                SELECT
                    COUNT(*) AS total_runs,
                    SUM(CASE WHEN outcome = ? THEN 1 ELSE 0 END) AS successful_runs,
                    SUM(CASE WHEN outcome = ? THEN 1 ELSE 0 END) AS quarantined_runs,
                    SUM(CASE WHEN outcome = ? THEN 1 ELSE 0 END) AS rejected_runs
                FROM recipe_runs
                WHERE recipe_id = ?
                """,
                (
                    RecipeRunOutcome.SUCCESS.value,
                    RecipeRunOutcome.QUARANTINED.value,
                    RecipeRunOutcome.REJECTED.value,
                    recipe.id,
                ),
            ).fetchone()
            last = connection.execute(
                """
                SELECT outcome, reason_code, occurred_at
                FROM recipe_runs
                WHERE recipe_id = ?
                ORDER BY id DESC
                LIMIT 1
                """,
                (recipe.id,),
            ).fetchone()
            streak = connection.execute(
                """
                SELECT COUNT(*) AS consecutive_rejections
                FROM recipe_runs
                WHERE recipe_id = ? AND outcome = ? AND id > COALESCE(
                    (
                        SELECT MAX(id)
                        FROM recipe_runs
                        WHERE recipe_id = ? AND outcome != ?
                    ),
                    0
                )
                """,
                (
                    recipe.id,
                    RecipeRunOutcome.REJECTED.value,
                    recipe.id,
                    RecipeRunOutcome.REJECTED.value,
                ),
            ).fetchone()

        total_runs = int(totals["total_runs"] or 0)
        last_outcome: RecipeRunOutcome | None = None
        last_reason_code: str | None = None
        last_occurred_at: datetime | None = None
        if last is not None:
            try:
                last_outcome = RecipeRunOutcome(str(last["outcome"]))
                last_occurred_at = datetime.fromisoformat(str(last["occurred_at"]))
            except ValueError as exc:
                raise IntegrityError("stored recipe run metadata is invalid") from exc
            stored_reason = last["reason_code"]
            last_reason_code = str(stored_reason) if stored_reason is not None else None

        consecutive_rejections = int(streak["consecutive_rejections"] or 0)
        suspended = consecutive_rejections >= rejection_threshold
        if total_runs == 0:
            state = RecipeHealthState.UNOBSERVED
        elif suspended:
            state = RecipeHealthState.SUSPENDED
        elif last_outcome is RecipeRunOutcome.SUCCESS:
            state = RecipeHealthState.HEALTHY
        else:
            state = RecipeHealthState.DEGRADED
        return RecipeHealth(
            recipe_id=recipe.id,
            state=state,
            auto_reuse_allowed=not suspended,
            rejection_threshold=rejection_threshold,
            total_runs=total_runs,
            successful_runs=int(totals["successful_runs"] or 0),
            quarantined_runs=int(totals["quarantined_runs"] or 0),
            rejected_runs=int(totals["rejected_runs"] or 0),
            consecutive_rejections=consecutive_rejections,
            last_outcome=last_outcome,
            last_reason_code=last_reason_code,
            last_occurred_at=last_occurred_at,
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
