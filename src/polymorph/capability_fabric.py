from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable, Mapping
from pathlib import Path
from urllib.parse import urlsplit

from .connector_registry import default_connector_registry
from .content import FileIdentity, require_matching_file_identity
from .errors import PolymorphError
from .filesystem import atomic_text_writer, exclusive_path_lock
from .matching.deterministic import normalize_name
from .models.schema import SchemaDescriptor
from .models.types import FieldRole, Sensitivity

PLAN_SCHEMA = "fabric.account-inventory-plan.v1"
MAX_PLAN_ENTRIES = 10_000
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
_FORMULA_PREFIXES = ("=", "+", "-", "@")
_TARGETS = (
    "origin",
    "label",
    "username",
    "password_policy",
    "risk_tier",
    "mutation_approval",
)
_ALIASES = {
    "origin": (
        "origin",
        "url",
        "website",
        "website url",
        "site",
        "site url",
        "login url",
        "account url",
        "webseite",
        "anmelde url",
    ),
    "label": (
        "label",
        "name",
        "account",
        "account name",
        "site name",
        "display name",
        "bezeichnung",
        "konto",
        "kontoname",
    ),
    "username": (
        "username",
        "user name",
        "user",
        "login",
        "login name",
        "email",
        "email address",
        "mail",
        "benutzer",
        "benutzername",
    ),
    "password_policy": (
        "password policy",
        "policy",
        "passwortrichtlinie",
    ),
    "risk_tier": (
        "risk tier",
        "risk",
        "risiko",
        "risikostufe",
    ),
    "mutation_approval": (
        "mutation approval",
        "agent approval",
        "approval policy",
        "freigabe",
        "anderungsfreigabe",
    ),
}


def canonical_json(value: object) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def plan_digest(body: Mapping[str, object]) -> str:
    return hashlib.sha256(canonical_json(body).encode("utf-8")).hexdigest()


def parse_field_overrides(values: Iterable[str]) -> dict[str, str]:
    overrides: dict[str, str] = {}
    for value in values:
        target, separator, source = value.partition("=")
        target = target.strip()
        source = source.strip()
        if not separator or target not in _TARGETS or not source:
            raise PolymorphError(
                "--map must be TARGET=SOURCE where TARGET is one of " + ", ".join(_TARGETS)
            )
        if target in overrides:
            raise PolymorphError(f"duplicate explicit mapping for target {target}")
        overrides[target] = source
    return overrides


def build_account_inventory_plan(
    source: str | Path,
    *,
    field_overrides: Mapping[str, str] | None = None,
    max_entries: int = MAX_PLAN_ENTRIES,
) -> dict[str, object]:
    if (
        isinstance(max_entries, bool)
        or not isinstance(max_entries, int)
        or not 1 <= max_entries <= MAX_PLAN_ENTRIES
    ):
        raise ValueError(f"max_entries must be between 1 and {MAX_PLAN_ENTRIES}")
    source_path = Path(source).expanduser().resolve(strict=True)
    resolved = default_connector_registry().resolve_file_source(source_path)
    schema = resolved.connector.inspect_schema()
    _reject_secret_bearing_schema(schema)
    if schema.metadata.get("formula_cells_present") == "true":
        raise PolymorphError(
            "account inventory contains spreadsheet formulas; cached formula values cannot "
            "authorize a plan"
        )

    mappings = _resolve_mappings(schema, field_overrides or {})
    if "origin" not in mappings:
        raise PolymorphError(
            "account inventory origin mapping is missing; use --map origin=SOURCE after review"
        )

    entries: list[dict[str, object]] = []
    seen_accounts: set[tuple[str, str]] = set()
    iterator = iter(resolved.connector.iter_records())
    for index in range(1, max_entries + 2):
        try:
            record = next(iterator)
        except StopIteration:
            break
        if index > max_entries:
            raise PolymorphError("account inventory exceeds the configured entry limit")
        entry = _entry_from_record(index, record, mappings)
        key = (str(entry["origin"]), str(entry.get("username", "")))
        if key in seen_accounts:
            raise PolymorphError(
                f"account inventory contains a duplicate origin/username pair at entry {index}"
            )
        seen_accounts.add(key)
        entries.append(entry)
    if not entries:
        raise PolymorphError("account inventory contains no records")

    source_hash = _hash_bound_source(source_path, resolved.inspection.identity)
    mapping_evidence = []
    fields = schema.by_id()
    explicit_targets = set(field_overrides or {})
    for target in _TARGETS:
        source_id = mappings.get(target)
        if source_id is None:
            continue
        field = fields[source_id]
        mapping_evidence.append(
            {
                "authority": "operator" if target in explicit_targets else "deterministic",
                "source_field_id": field.id,
                "source_name": field.name,
                "target": target,
            }
        )

    body: dict[str, object] = {
        "entries": entries,
        "mapping": mapping_evidence,
        "schema": PLAN_SCHEMA,
        "source": {
            "connector": resolved.manifest.connector_id,
            "kind": resolved.inspection.kind.value,
            "name": source_path.name,
            "schema_fingerprint": schema.fingerprint(),
            "sha256": source_hash,
            "size_bytes": resolved.inspection.size_bytes,
        },
    }
    digest = plan_digest(body)
    if _SHA256.fullmatch(digest) is None:  # Defensive invariant around the wire contract.
        raise AssertionError("unexpected SHA-256 representation")
    return {**body, "plan_digest": digest}


def write_account_inventory_plan(path: str | Path, plan: Mapping[str, object]) -> None:
    target = Path(path).expanduser().resolve(strict=False)
    wire = canonical_json(dict(plan)) + "\n"
    with exclusive_path_lock(target), atomic_text_writer(target, overwrite=True) as handle:
        handle.write(wire)


def _reject_secret_bearing_schema(schema: SchemaDescriptor) -> None:
    blocked = [
        field.name
        for field in schema.fields
        if (field.sensitivity is Sensitivity.SECRET or field.role is FieldRole.CREDENTIAL)
        and normalize_name(field.name)
        not in {normalize_name(alias) for alias in _ALIASES["password_policy"]}
    ]
    if blocked:
        raise PolymorphError(
            "account inventory has secret-bearing columns and is not eligible for the Fabric "
            "metadata bridge"
        )


def _resolve_mappings(
    schema: SchemaDescriptor,
    field_overrides: Mapping[str, str],
) -> dict[str, str]:
    resolved: dict[str, str] = {}
    used_sources: set[str] = set()
    for target, requested in field_overrides.items():
        if target not in _TARGETS:
            raise PolymorphError(f"unknown Fabric inventory target: {target}")
        candidates = [
            field for field in schema.fields if field.id == requested or field.name == requested
        ]
        unique = {field.id: field for field in candidates}
        if len(unique) != 1:
            raise PolymorphError(
                f"explicit mapping for {target} must identify exactly one source field"
            )
        source_id = next(iter(unique))
        if source_id in used_sources:
            raise PolymorphError("one source field cannot authorize multiple Fabric targets")
        resolved[target] = source_id
        used_sources.add(source_id)

    for target in _TARGETS:
        if target in resolved:
            continue
        aliases = {normalize_name(value) for value in _ALIASES[target]}
        candidates = [field for field in schema.fields if normalize_name(field.name) in aliases]
        candidates = [field for field in candidates if field.id not in used_sources]
        if len(candidates) > 1:
            raise PolymorphError(
                f"automatic mapping for {target} is ambiguous; use --map "
                f"{target}=SOURCE after review"
            )
        if candidates:
            resolved[target] = candidates[0].id
            used_sources.add(candidates[0].id)
    fields = schema.by_id()
    password_policy_aliases = {normalize_name(alias) for alias in _ALIASES["password_policy"]}
    for target, source_id in resolved.items():
        field = fields[source_id]
        secret_classified = (
            field.sensitivity is Sensitivity.SECRET or field.role is FieldRole.CREDENTIAL
        )
        if secret_classified and not (
            target == "password_policy" and normalize_name(field.name) in password_policy_aliases
        ):
            raise PolymorphError(
                "secret-classified source fields cannot be mapped into the Fabric plan"
            )
    return resolved


def _entry_from_record(
    index: int,
    record: Mapping[str, object],
    mappings: Mapping[str, str],
) -> dict[str, object]:
    values = {
        target: _optional_text(record.get(source_id), target, index)
        for target, source_id in mappings.items()
    }
    origin_text = values.get("origin")
    if origin_text is None:
        raise PolymorphError(f"account inventory entry {index} has no origin")
    origin = _normalize_origin(origin_text, index)
    hostname = urlsplit(origin).hostname or origin
    label = _bounded_text(values.get("label") or hostname, "label", index, 256)
    entry: dict[str, object] = {
        "entry": index,
        "label": label,
        "mutation_approval": _choice(
            values.get("mutation_approval") or "trusted-user",
            "mutation_approval",
            index,
            {"trusted-user", "preauthorized-agent", "manual-only"},
        ),
        "origin": origin,
        "password_policy": _choice(
            values.get("password_policy") or "maximum",
            "password_policy",
            index,
            {"compatible", "strong", "maximum"},
        ),
        "risk_tier": _choice(
            values.get("risk_tier") or "normal",
            "risk_tier",
            index,
            {"normal", "sensitive", "critical"},
        ),
    }
    username = values.get("username")
    if username is not None:
        entry["username"] = _bounded_text(username, "username", index, 320)
    return entry


def _optional_text(value: object, target: str, index: int) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise PolymorphError(f"account inventory entry {index} field {target} must be text")
    text = value.strip()
    if not text:
        return None
    if _CONTROL.search(text):
        raise PolymorphError(
            f"account inventory entry {index} field {target} contains control characters"
        )
    if text.lstrip().startswith(_FORMULA_PREFIXES):
        raise PolymorphError(f"account inventory entry {index} contains a formula-like value")
    return text


def _bounded_text(value: str, target: str, index: int, maximum: int) -> str:
    if not value or len(value) > maximum:
        raise PolymorphError(
            f"account inventory entry {index} field {target} exceeds its allowed length"
        )
    return value


def _choice(value: str, target: str, index: int, allowed: set[str]) -> str:
    normalized = normalize_name(value).replace(" ", "-")
    if normalized not in allowed:
        raise PolymorphError(
            f"account inventory entry {index} field {target} has an unsupported value"
        )
    return normalized


def _normalize_origin(value: str, index: int) -> str:
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise PolymorphError(f"account inventory entry {index} has an invalid origin") from exc
    scheme = parsed.scheme.casefold()
    if scheme not in {"http", "https"} or parsed.username or parsed.password or not parsed.hostname:
        raise PolymorphError(f"account inventory entry {index} has an invalid HTTP(S) origin")
    try:
        hostname = parsed.hostname.encode("idna").decode("ascii").casefold()
    except UnicodeError as exc:
        raise PolymorphError(f"account inventory entry {index} has an invalid hostname") from exc
    if ":" in hostname:
        hostname = f"[{hostname}]"
    default_port = 443 if scheme == "https" else 80
    authority = hostname if port is None or port == default_port else f"{hostname}:{port}"
    return f"{scheme}://{authority}"


def _hash_bound_source(path: Path, expected: FileIdentity) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            require_matching_file_identity(handle, expected, purpose="Fabric inventory plan")
            while chunk := handle.read(1024 * 1024):
                digest.update(chunk)
            require_matching_file_identity(handle, expected, purpose="Fabric inventory plan")
    except OSError as exc:
        raise PolymorphError("could not hash the inspected account inventory") from exc
    return digest.hexdigest()
