"""Signed, advisory-only knowledge packages. General updates never edit private recipes."""
from __future__ import annotations

import base64
import hashlib
import json
import math
import re
import sqlite3
import stat
import time
import urllib.error
import urllib.request
from datetime import UTC, datetime, timedelta
from contextlib import contextmanager
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

FORMAT = "angusu.bridge.knowledge/1"
DOMAIN = b"angusu.bridge.knowledge/1\x00"
MODEL_FORMAT = "angusu.bridge.lexical-ranker/1"
FEATURE_VERSION = "token-cross/1"
MAX_MODEL_BYTES = 2 * 1024 * 1024
MAX_PACK_BYTES = 4 * 1024 * 1024
MAX_STORE_BYTES = 128 * 1024 * 1024
VERSION = re.compile(r"[a-z0-9][a-z0-9.-]{0,63}\Z")
HEX = re.compile(r"[0-9a-f]{64}\Z")


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False).encode("utf-8")


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate knowledge field")
        result[key] = value
    return result


def _reject_constant(_: str) -> Any:
    raise ValueError("non-finite knowledge number")


def document(raw: bytes, maximum: int = MAX_PACK_BYTES) -> dict[str, Any]:
    if len(raw) > maximum:
        raise ValueError("knowledge byte budget exceeded")
    try:
        value = json.loads(raw, object_pairs_hook=_pairs, parse_constant=_reject_constant)
    except (ValueError, RecursionError, UnicodeError) as exc:
        raise ValueError("invalid knowledge JSON") from exc
    if not isinstance(value, dict):
        raise ValueError("knowledge document must be an object")
    return value


def no_links(path: Path) -> None:
    for part in (path.absolute(), *path.absolute().parents):
        try:
            info = part.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise ValueError("linked knowledge paths are not accepted")


def read_bytes(path: Path, maximum: int = MAX_PACK_BYTES) -> bytes:
    no_links(path)
    if not path.is_file():
        raise ValueError("knowledge input must be a regular file")
    with path.open("rb") as handle:
        raw = handle.read(maximum + 1)
    if len(raw) > maximum:
        raise ValueError("knowledge byte budget exceeded")
    return raw


def _keys(value: Any, names: set[str]) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != names:
        raise ValueError("unsupported knowledge fields")
    return value


def _integer(value: Any, maximum: int = 10**12, minimum: int = 0) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError("invalid knowledge counter")
    return value


def _digest(value: Any) -> str:
    if not isinstance(value, str) or not HEX.fullmatch(value):
        raise ValueError("invalid knowledge digest")
    return value


def timestamp(value: Any) -> datetime:
    if not isinstance(value, str) or len(value) > 40:
        raise ValueError("invalid knowledge timestamp")
    result = datetime.fromisoformat(value)
    if result.utcoffset() != timedelta(0):
        raise ValueError("knowledge timestamps must be UTC")
    return result


def model_document(raw: bytes) -> dict[str, Any]:
    obj = _keys(document(raw, MAX_MODEL_BYTES), {"format", "feature_version", "dimensions", "weights"})
    if (obj["format"] != MODEL_FORMAT or obj["feature_version"] != FEATURE_VERSION
            or type(obj["dimensions"]) is not int or obj["dimensions"] != 16384):
        raise ValueError("unsupported knowledge model contract")
    weights = obj["weights"]
    if not isinstance(weights, list) or len(weights) != 16384:
        raise ValueError("invalid knowledge weight count")
    for weight in weights:
        if type(weight) not in (int, float) or abs(weight) > 1e4 or not math.isfinite(weight):
            raise ValueError("invalid knowledge weight")
    return obj


def verify_pack(raw: bytes, trusted_key: bytes, *, now: datetime | None = None) -> dict[str, Any]:
    """Validate a package against an out-of-band publisher key, never a downloaded key."""
    envelope = _keys(document(raw), {"signed", "signature"})
    signed = _keys(envelope["signed"], {
        "format", "version", "sequence", "publisher_key_id", "created_at", "expires_at",
        "authority", "origin", "model_b64", "model_sha256", "evidence",
    })
    if len(trusted_key) != 32:
        raise ValueError("publisher public key must contain 32 bytes")
    try:
        signature = base64.b64decode(envelope["signature"], validate=True)
        Ed25519PublicKey.from_public_bytes(trusted_key).verify(signature, DOMAIN + canonical(signed))
    except (InvalidSignature, TypeError, ValueError) as exc:
        raise ValueError("knowledge publisher signature rejected") from exc
    if signed["format"] != FORMAT or signed["authority"] != "advisory_only":
        raise ValueError("knowledge cannot alter authority")
    if signed["publisher_key_id"] != sha256(trusted_key):
        raise ValueError("knowledge publisher does not match pinned key")
    if not isinstance(signed["version"], str) or not VERSION.fullmatch(signed["version"]):
        raise ValueError("invalid knowledge version")
    _integer(signed["sequence"], minimum=1)
    if signed["origin"] not in {"synthetic_lab", "reviewed_external"}:
        raise ValueError("unsupported knowledge origin")
    created, expires = timestamp(signed["created_at"]), timestamp(signed["expires_at"])
    current = now or datetime.now(UTC)
    if current.tzinfo is None:
        raise ValueError("verification clock must be timezone-aware")
    if not created <= current < expires or not timedelta(0) < expires - created <= timedelta(days=366):
        raise ValueError("knowledge validity window rejected")
    evidence = _keys(signed["evidence"], {
        "corpus_sha256", "training_sha256", "evaluation_sha256", "runtime_sha256",
        "unique_train_queries", "unique_train_comparisons", "training_source_groups",
        "weight_updates", "holdout_queries", "holdout_correct", "baseline_correct",
        "paired_regressions", "independent_customer_sources",
    })
    for name in ("corpus_sha256", "training_sha256", "evaluation_sha256", "runtime_sha256"):
        _digest(evidence[name])
    for name in set(evidence) - {"corpus_sha256", "training_sha256", "evaluation_sha256", "runtime_sha256"}:
        _integer(evidence[name])
    if (evidence["unique_train_queries"] < 1 or evidence["unique_train_comparisons"] < 1
            or evidence["holdout_queries"] < 1
            or max(evidence["holdout_correct"], evidence["baseline_correct"]) > evidence["holdout_queries"]):
        raise ValueError("inconsistent knowledge evidence counters")
    try:
        model = base64.b64decode(signed["model_b64"], validate=True)
    except (ValueError, TypeError) as exc:
        raise ValueError("invalid knowledge model encoding") from exc
    if sha256(model) != _digest(signed["model_sha256"]):
        raise ValueError("knowledge model checksum mismatch")
    model_document(model)
    return signed


class KnowledgeStore:
    """One durable general-knowledge database, separate from every local customization.

    SQLite serializes installers. Package insert, high-water mark and activation
    share a transaction; failed updates retain the previous active selection.
    The local host and publisher signing key are trusted. Not full-host rollback protection.
    """

    def __init__(self, home: Path, trusted_key: bytes) -> None:
        if len(trusted_key) != 32:
            raise ValueError("publisher key must contain 32 bytes")
        self.path = home.absolute() / "knowledge" / "general.sqlite"
        self.key = trusted_key
        no_links(self.path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS packages (
                  version TEXT PRIMARY KEY, sequence INTEGER UNIQUE NOT NULL,
                  digest TEXT UNIQUE NOT NULL, raw BLOB NOT NULL);
                CREATE TABLE IF NOT EXISTS state (
                  id INTEGER PRIMARY KEY CHECK(id=1), publisher TEXT NOT NULL,
                  highest INTEGER NOT NULL, active TEXT);
            """)
            db.execute("INSERT OR IGNORE INTO state VALUES (1, ?, 0, NULL)", (sha256(trusted_key),))
            if db.execute("SELECT publisher FROM state WHERE id=1").fetchone()[0] != sha256(trusted_key):
                raise ValueError("publisher change requires an explicit trust migration")

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        no_links(self.path)
        for suffix in ("-journal", "-wal", "-shm"):
            no_links(Path(str(self.path) + suffix))
        db = sqlite3.connect(self.path, timeout=10)
        try:
            db.execute("PRAGMA synchronous=FULL")
            with db:
                yield db
        finally:
            db.close()

    def install(self, raw: bytes, *, activate: bool = False) -> dict[str, Any]:
        signed = verify_pack(raw, self.key)
        runtime = Path(__file__).parent / "matching" / "lexical.py"
        if signed["evidence"]["runtime_sha256"] != sha256(read_bytes(runtime)):
            raise ValueError("knowledge feature implementation is incompatible")
        digest = sha256(raw)
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            highest = db.execute("SELECT highest FROM state WHERE id=1").fetchone()[0]
            if signed["sequence"] < highest:
                raise ValueError("stale knowledge update rejected")
            existing = db.execute("SELECT version, sequence, digest FROM packages WHERE version=? OR sequence=?",
                                  (signed["version"], signed["sequence"])).fetchall()
            if existing and existing != [(signed["version"], signed["sequence"], digest)]:
                raise ValueError("knowledge version or sequence fork rejected")
            if not existing:
                total = db.execute("SELECT COALESCE(SUM(length(raw)),0) FROM packages").fetchone()[0]
                if total + len(raw) > MAX_STORE_BYTES:
                    raise ValueError("knowledge history storage budget exceeded")
                db.execute("INSERT INTO packages VALUES (?,?,?,?)",
                           (signed["version"], signed["sequence"], digest, raw))
            db.execute("UPDATE state SET highest=MAX(highest,?) WHERE id=1", (signed["sequence"],))
            if activate:
                db.execute("UPDATE state SET active=? WHERE id=1", (signed["version"],))
            stored = db.execute("SELECT sequence,digest,raw FROM packages WHERE version=?",
                                (signed["version"],)).fetchone()
            state = db.execute("SELECT highest,active FROM state WHERE id=1").fetchone()
            if (stored != (signed["sequence"], digest, raw) or state[0] < signed["sequence"]
                    or (activate and state[1] != signed["version"])):
                raise ValueError("knowledge transaction postcondition failed")
        return {"version": signed["version"], "sequence": signed["sequence"],
                "sha256": digest, "activated": activate, "authority": "advisory_only"}

    def activate(self, version: str, *, allow_rollback: bool = False) -> None:
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT sequence,digest,raw FROM packages WHERE version=?", (version,)).fetchone()
            if row is None:
                raise ValueError("knowledge version is not installed")
            if sha256(row[2]) != row[1]:
                raise ValueError("stored knowledge changed")
            signed = verify_pack(row[2], self.key)
            if signed["sequence"] != row[0] or signed["version"] != version:
                raise ValueError("stored knowledge identity changed")
            highest = db.execute("SELECT highest FROM state WHERE id=1").fetchone()[0]
            if row[0] < highest and not allow_rollback:
                raise ValueError("older activation needs explicit --allow-rollback")
            db.execute("UPDATE state SET active=? WHERE id=1", (version,))
            if db.execute("SELECT active FROM state WHERE id=1").fetchone()[0] != version:
                raise ValueError("knowledge activation postcondition failed")

    def status(self) -> dict[str, Any]:
        with self._connect() as db:
            publisher, highest, active = db.execute("SELECT publisher,highest,active FROM state WHERE id=1").fetchone()
            versions = db.execute("SELECT version,sequence,digest FROM packages ORDER BY sequence DESC").fetchall()
        return {"publisher": publisher, "highest_seen_sequence": highest, "active": active,
                "versions": [{"version": v, "sequence": s, "sha256": d} for v, s, d in versions],
                "local_customizations": "not_read_or_modified"}

    def active_ranker(self) -> Any:
        from .matching.lexical import LearnedRanker

        with self._connect() as db:
            row = db.execute("SELECT p.version,p.digest,p.raw FROM packages p JOIN state s ON p.version=s.active WHERE s.id=1").fetchone()
        if row is None:
            return None
        if sha256(row[2]) != row[1]:
            raise ValueError("stored knowledge changed")
        signed = verify_pack(row[2], self.key)
        if signed["version"] != row[0]:
            raise ValueError("active knowledge identity changed")
        expected_runtime = sha256(read_bytes(Path(__file__).parent / "matching" / "lexical.py"))
        if signed["evidence"]["runtime_sha256"] != expected_runtime:
            raise ValueError("knowledge feature implementation is incompatible")
        model = model_document(base64.b64decode(signed["model_b64"], validate=True))
        return LearnedRanker(tuple(model["weights"]), signed["model_sha256"])


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req: Any, fp: Any, code: int, msg: str,
                         headers: Any, newurl: str) -> Any:
        raise ValueError("knowledge redirects are disabled")


def _download(url: str, maximum: int) -> bytes:
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())
    start = time.monotonic()
    request = urllib.request.Request(url, headers={"Accept": "application/json", "User-Agent": "Polymorph-Knowledge/1"})
    with opener.open(request, timeout=15) as response:
        output = bytearray()
        while True:
            chunk = response.read(min(65536, maximum + 1 - len(output)))
            output.extend(chunk)
            if len(output) > maximum or time.monotonic() - start > 60:
                raise ValueError("knowledge download budget exceeded")
            if not chunk:
                return bytes(output)


def fetch_latest(*, ref: str = "main") -> bytes:
    """Download an untrusted discovery pointer and bytes, never its trust key."""
    if ref != "main" and re.fullmatch(r"[0-9a-f]{40}", ref) is None:
        raise ValueError("knowledge ref must be main or an exact commit")
    base = f"https://raw.githubusercontent.com/IamAngusU/polymorph/{ref}/knowledge/"
    pointer = document(_download(base + "latest.json", 8192), 8192)
    if pointer.get("package") is None:
        raise ValueError("no general knowledge release has been published")
    pointer = _keys(pointer, {"format", "package", "sha256", "sequence"})
    if pointer["format"] != "angusu.bridge.knowledge-pointer/1":
        raise ValueError("unsupported knowledge pointer")
    path = pointer["package"]
    if not isinstance(path, str) or not re.fullmatch(r"packs/[a-z0-9][a-z0-9.-]{0,63}\.json", path):
        raise ValueError("unsafe knowledge discovery path")
    _integer(pointer["sequence"], minimum=1)
    raw = _download(base + path, MAX_PACK_BYTES)
    if sha256(raw) != _digest(pointer["sha256"]):
        raise ValueError("knowledge discovery checksum mismatch")
    signed = document(raw).get("signed", {})
    if signed.get("sequence") != pointer["sequence"] or path != f"packs/{signed.get('version')}.json":
        raise ValueError("knowledge discovery identity mismatch")
    return raw
