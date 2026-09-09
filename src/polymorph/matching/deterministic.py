from __future__ import annotations

import re
import unicodedata
from difflib import SequenceMatcher

from polymorph.models.schema import FieldDescriptor
from polymorph.models.types import DataType, FieldRole, Sensitivity

_CAMEL = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")

_SYNONYM_GROUPS = (
    {"customer", "client", "kunde", "debitor"},
    {"number", "num", "nr", "no", "nummer"},
    {"id", "identifier", "kennung", "key"},
    {"email", "mail", "emailaddress", "mailaddress"},
    {"date", "datum"},
    {"time", "zeit"},
    {"amount", "betrag", "sum", "total", "value", "wert"},
    {"price", "preis"},
    {"net", "netto"},
    {"gross", "brutto"},
    {"password", "passwort", "kennwort", "secret"},
    {"token", "credential", "credentials", "zugang", "access"},
    {"order", "auftrag", "bestellung"},
    {"invoice", "rechnung"},
    {"product", "produkt", "article", "artikel"},
    {"quantity", "qty", "menge", "anzahl"},
    {"name", "bezeichnung", "title", "titel"},
)

_SYNONYMS: dict[str, str] = {}
for index, group in enumerate(_SYNONYM_GROUPS):
    canonical = f"g{index}"
    for token in group:
        _SYNONYMS[token] = canonical


def normalize_name(value: str) -> str:
    value = _CAMEL.sub(" ", value)
    decomposed = unicodedata.normalize("NFKD", value.casefold())
    without_marks = "".join(
        character for character in decomposed if not unicodedata.combining(character)
    )
    separated = "".join(character if character.isalnum() else " " for character in without_marks)
    return " ".join(separated.split())


def normalized_tokens(value: str) -> tuple[str, ...]:
    tokens = normalize_name(value).split()
    return tuple(_SYNONYMS.get(token, token) for token in tokens)


def type_compatibility(source: DataType, target: DataType) -> float:
    if source is DataType.UNKNOWN or target is DataType.UNKNOWN:
        return 0.55
    if source is target:
        return 1.0
    numeric = {DataType.INTEGER, DataType.DECIMAL}
    if source in numeric and target in numeric:
        return 0.85
    temporal = {DataType.DATE, DataType.DATETIME}
    if source in temporal and target in temporal:
        return 0.75
    if source is DataType.STRING:
        return 0.45
    return 0.0


def sensitivity_compatible(source: Sensitivity, target: Sensitivity) -> bool:
    if source in {Sensitivity.SECRET, Sensitivity.OPAQUE}:
        return target in {Sensitivity.SECRET, Sensitivity.OPAQUE}
    return True


def name_similarity(left: FieldDescriptor, right: FieldDescriptor) -> tuple[float, tuple[str, ...]]:
    left_variants = [left.name, *left.aliases]
    right_variants = [right.name, *right.aliases]
    normalized_left = {normalize_name(value) for value in left_variants if normalize_name(value)}
    normalized_right = {normalize_name(value) for value in right_variants if normalize_name(value)}

    if normalize_name(left.name) and normalize_name(left.name) == normalize_name(right.name):
        return 1.0, ("exact normalized name",)
    if normalized_left & normalized_right:
        return 0.98, ("alias match",)

    best_score = 0.0
    best_jaccard = 0.0
    best_sequence = 0.0
    used_alias = False
    for left_index, left_value in enumerate(left_variants):
        left_norm = normalize_name(left_value)
        lt = set(normalized_tokens(left_value))
        for right_index, right_value in enumerate(right_variants):
            right_norm = normalize_name(right_value)
            rt = set(normalized_tokens(right_value))
            union = lt | rt
            jaccard = len(lt & rt) / len(union) if union else 0.0
            sequence = (
                SequenceMatcher(a=left_norm, b=right_norm).ratio()
                if left_norm and right_norm
                else 0.0
            )
            score = 0.62 * jaccard + 0.38 * sequence
            if score > best_score:
                best_score = score
                best_jaccard = jaccard
                best_sequence = sequence
                used_alias = left_index > 0 or right_index > 0

    reasons: list[str] = []
    if best_jaccard:
        reasons.append(f"token overlap {best_jaccard:.2f}")
    if best_sequence >= 0.6:
        reasons.append(f"name similarity {best_sequence:.2f}")
    if used_alias:
        reasons.append("relation alias evidence")
    return best_score, tuple(reasons)


def deterministic_score(
    source: FieldDescriptor, target: FieldDescriptor
) -> tuple[float, tuple[str, ...]]:
    if not sensitivity_compatible(source.sensitivity, target.sensitivity):
        return 0.0, ("sensitivity incompatible",)

    name_score, reasons = name_similarity(source, target)
    type_score = type_compatibility(source.data_type, target.data_type)
    role_score = 1.0 if source.role is target.role else 0.55
    relation_lookup = (
        source.role is FieldRole.NATURAL_KEY
        and target.role is FieldRole.FOREIGN_KEY
        and "relation alias evidence" in reasons
    )
    if relation_lookup:
        # A source business key is expected to differ in type from the internal FK. The
        # generated alias comes from a real UNIQUE key on the referenced relation, making
        # it stronger evidence than ordinary name similarity.
        type_score = max(type_score, 0.85)
        role_score = max(role_score, 0.85)

    score = 0.68 * name_score + 0.22 * type_score + 0.10 * role_score
    if relation_lookup:
        score = min(1.0, score + 0.12)
    extra = list(reasons)
    if relation_lookup:
        extra.append("unique foreign-key lookup path")
    if type_score == 1.0:
        extra.append("type match")
    if source.role is target.role:
        extra.append("role match")
    return min(score, 1.0), tuple(extra)
