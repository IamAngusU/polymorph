from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

from polymorph.models.schema import FieldDescriptor, SchemaDescriptor

from .deterministic import automatic_mapping_contract_safe, normalize_name


@lru_cache(maxsize=1)
def _term_index() -> dict[str, frozenset[str]]:
    path = Path(__file__).parents[1] / "data" / "business_glossary.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    index: dict[str, set[str]] = {}
    for concept in payload["concepts"]:
        concept_id = concept["id"]
        for terms in concept["terms"].values():
            for term in terms:
                normalized = normalize_name(term)
                if normalized:
                    index.setdefault(normalized, set()).add(concept_id)
    return {term: frozenset(concepts) for term, concepts in index.items()}


def _concepts(field: FieldDescriptor) -> frozenset[str]:
    found: set[str] = set()
    index = _term_index()
    for term in (field.name, *field.aliases):
        found.update(index.get(normalize_name(term), ()))
    return frozenset(found)


def advisory_glossary_target(
    source: FieldDescriptor, target_schema: SchemaDescriptor
) -> FieldDescriptor | None:
    """Return one contract-safe glossary target; this function grants no authority."""

    source_concepts = _concepts(source)
    if not source_concepts:
        return None
    matches = [
        target
        for target in target_schema.fields
        if source_concepts.intersection(_concepts(target))
        and automatic_mapping_contract_safe(source, target, target_schema)
    ]
    return matches[0] if len(matches) == 1 else None
