from __future__ import annotations

import json
import math
import os
import stat
import struct
import unicodedata
import zipfile
import zlib
from dataclasses import dataclass
from enum import StrEnum
from io import StringIO
from pathlib import Path
from typing import BinaryIO, Protocol
from xml.sax import SAXException
from xml.sax.handler import ContentHandler
from xml.sax.xmlreader import AttributesImpl

import json5

# defusedxml ships without typing metadata, but remains a required runtime dependency.
from defusedxml import sax as defused_sax  # type: ignore[import-untyped]
from defusedxml.common import DefusedXmlException  # type: ignore[import-untyped]

from .errors import ConnectorError


class ContentKind(StrEnum):
    XLSX = "xlsx"
    DOCX = "docx"
    PPTX = "pptx"
    ZIP = "zip"
    JSON = "json"
    JSON5 = "json5"
    DELIMITED_TEXT = "delimited_text"
    TEXT = "text"
    XML = "xml"
    PDF = "pdf"
    SQLITE = "sqlite"
    PARQUET = "parquet"
    OLE = "ole_compound"
    GZIP = "gzip"
    IMAGE = "image"
    EXECUTABLE = "executable"
    BINARY = "binary"
    EMPTY = "empty"
    UNKNOWN = "unknown"


class RiskCode(StrEnum):
    SYMLINK_INPUT = "symlink_input"
    NON_REGULAR_INPUT = "non_regular_input"
    FILE_TOO_LARGE = "file_too_large"
    ARCHIVE_TOO_MANY_ENTRIES = "archive_too_many_entries"
    ARCHIVE_METADATA_TOO_LARGE = "archive_metadata_too_large"
    ARCHIVE_TOO_LARGE = "archive_too_large"
    ARCHIVE_MEMBER_TOO_LARGE = "archive_member_too_large"
    ARCHIVE_HIGH_COMPRESSION_RATIO = "archive_high_compression_ratio"
    ARCHIVE_SCAN_BUDGET_EXCEEDED = "archive_scan_budget_exceeded"
    ARCHIVE_PATH_TRAVERSAL = "archive_path_traversal"
    ARCHIVE_SYMLINK = "archive_symlink"
    ARCHIVE_DUPLICATE_ENTRY = "archive_duplicate_entry"
    ARCHIVE_ENCRYPTED_MEMBER = "archive_encrypted_member"
    OFFICE_MACRO = "office_macro"
    OFFICE_EXTERNAL_LINK = "office_external_link"
    OFFICE_EXTERNAL_DATA = "office_external_data"
    CLASSIFIER_DISAGREEMENT = "classifier_disagreement"
    MALFORMED_ARCHIVE = "malformed_archive"
    JSON_NESTING_TOO_DEEP = "json_nesting_too_deep"
    JSON_TOO_MANY_ITEMS = "json_too_many_items"
    XML_NESTING_TOO_DEEP = "xml_nesting_too_deep"
    XML_TOO_MANY_ELEMENTS = "xml_too_many_elements"
    XML_TOO_MANY_ATTRIBUTES = "xml_too_many_attributes"
    FILE_CHANGED_DURING_INSPECTION = "file_changed_during_inspection"


@dataclass(frozen=True, slots=True)
class ContentRisk:
    code: RiskCode
    detail: str
    blocking: bool = True


@dataclass(frozen=True, slots=True)
class ClassifierEvidence:
    provider: str
    label: str
    mime_type: str | None = None
    score: float | None = None


@dataclass(frozen=True, slots=True)
class FileIdentity:
    """Portable metadata identity for a file, not a digest of its exact bytes."""

    device: int
    inode: int
    size_bytes: int
    mtime_ns: int

    @classmethod
    def from_stat(cls, metadata: os.stat_result) -> FileIdentity:
        return cls(
            device=metadata.st_dev,
            inode=metadata.st_ino,
            size_bytes=metadata.st_size,
            mtime_ns=metadata.st_mtime_ns,
        )

    def as_dict(self) -> dict[str, int]:
        return {
            "device": self.device,
            "inode": self.inode,
            "size_bytes": self.size_bytes,
            "mtime_ns": self.mtime_ns,
        }


class FileDescriptor(Protocol):
    def fileno(self) -> int: ...


def require_matching_file_identity(
    handle: FileDescriptor,
    expected: FileIdentity,
    *,
    purpose: str,
) -> None:
    """Fail closed unless an already-open file handle is the inspected file."""

    try:
        metadata = os.fstat(handle.fileno())
    except (OSError, ValueError) as exc:
        raise ConnectorError(f"{purpose} could not verify the opened input file") from exc
    observed = FileIdentity.from_stat(metadata)
    if not stat.S_ISREG(metadata.st_mode) or observed != expected:
        raise ConnectorError(f"{purpose} rejected input changed after content inspection")


@dataclass(frozen=True, slots=True)
class FileInspection:
    path: str
    size_bytes: int
    identity: FileIdentity
    kind: ContentKind
    confidence: float
    signals: tuple[str, ...] = ()
    risks: tuple[ContentRisk, ...] = ()
    classifier: ClassifierEvidence | None = None

    @property
    def safe(self) -> bool:
        return not any(item.blocking for item in self.risks)

    @property
    def blocking_risks(self) -> tuple[ContentRisk, ...]:
        return tuple(item for item in self.risks if item.blocking)

    def as_dict(self) -> dict[str, object]:
        classifier = None
        if self.classifier is not None:
            classifier = {
                "provider": self.classifier.provider,
                "label": self.classifier.label,
                "mime_type": self.classifier.mime_type,
                "score": self.classifier.score,
            }
        return {
            "path": self.path,
            "size_bytes": self.size_bytes,
            "identity": self.identity.as_dict(),
            "kind": self.kind.value,
            "confidence": self.confidence,
            "safe": self.safe,
            "signals": list(self.signals),
            "risks": [
                {"code": item.code.value, "detail": item.detail, "blocking": item.blocking}
                for item in self.risks
            ],
            "classifier": classifier,
        }


@dataclass(frozen=True, slots=True)
class FileTrustPolicy:
    max_file_bytes: int = 2 * 1024 * 1024 * 1024
    max_probe_bytes: int = 256 * 1024
    max_text_parse_bytes: int = 4 * 1024 * 1024
    max_archive_entries: int = 4096
    max_archive_uncompressed_bytes: int = 1024 * 1024 * 1024
    max_archive_member_bytes: int = 256 * 1024 * 1024
    max_compression_ratio: float = 200.0
    allow_office_macros: bool = False
    allow_office_external_links: bool = False
    allow_symlink_inputs: bool = False
    classifier_disagreement_threshold: float = 0.90
    classifier_disagreement_is_blocking: bool = True
    # Appended to preserve the positional order of the original public policy API.
    max_json5_parse_bytes: int = 64 * 1024
    max_structured_text_depth: int = 128
    max_archive_metadata_bytes: int = 16 * 1024 * 1024
    max_xml_elements: int = 100_000
    max_gzip_scan_bytes: int = 64 * 1024 * 1024
    max_json_items: int = 100_000
    max_xml_attributes_per_element: int = 1024

    def __post_init__(self) -> None:
        integer_limits = {
            "max_file_bytes": self.max_file_bytes,
            "max_probe_bytes": self.max_probe_bytes,
            "max_text_parse_bytes": self.max_text_parse_bytes,
            "max_json5_parse_bytes": self.max_json5_parse_bytes,
            "max_structured_text_depth": self.max_structured_text_depth,
            "max_archive_entries": self.max_archive_entries,
            "max_archive_metadata_bytes": self.max_archive_metadata_bytes,
            "max_archive_uncompressed_bytes": self.max_archive_uncompressed_bytes,
            "max_archive_member_bytes": self.max_archive_member_bytes,
            "max_xml_elements": self.max_xml_elements,
            "max_gzip_scan_bytes": self.max_gzip_scan_bytes,
            "max_json_items": self.max_json_items,
            "max_xml_attributes_per_element": self.max_xml_attributes_per_element,
        }
        for name, value in integer_limits.items():
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ValueError(f"{name} must be a positive integer")

        if isinstance(self.max_compression_ratio, bool) or not isinstance(
            self.max_compression_ratio, (int, float)
        ):
            raise ValueError("max_compression_ratio must be a finite positive number")
        try:
            compression_ratio = float(self.max_compression_ratio)
        except (OverflowError, ValueError):
            raise ValueError("max_compression_ratio must be a finite positive number") from None
        if not math.isfinite(compression_ratio) or compression_ratio <= 0:
            raise ValueError("max_compression_ratio must be a finite positive number")

        if isinstance(self.classifier_disagreement_threshold, bool) or not isinstance(
            self.classifier_disagreement_threshold, (int, float)
        ):
            raise ValueError(
                "classifier_disagreement_threshold must be a finite number between zero and one"
            )
        try:
            disagreement_threshold = float(self.classifier_disagreement_threshold)
        except (OverflowError, ValueError):
            raise ValueError(
                "classifier_disagreement_threshold must be a finite number between zero and one"
            ) from None
        if not math.isfinite(disagreement_threshold) or not 0 <= disagreement_threshold <= 1:
            raise ValueError(
                "classifier_disagreement_threshold must be a finite number between zero and one"
            )

        boolean_flags = {
            "allow_office_macros": self.allow_office_macros,
            "allow_office_external_links": self.allow_office_external_links,
            "allow_symlink_inputs": self.allow_symlink_inputs,
            "classifier_disagreement_is_blocking": self.classifier_disagreement_is_blocking,
        }
        for name, value in boolean_flags.items():
            if not isinstance(value, bool):
                raise ValueError(f"{name} must be a boolean")


_ZIP_EOCD_SIGNATURE = b"PK\x05\x06"
_ZIP_EOCD_SIZE = 22
_ZIP_MAX_COMMENT_BYTES = (1 << 16) - 1
_ZIP64_LOCATOR_SIGNATURE = b"PK\x06\x07"
_ZIP64_LOCATOR_SIZE = 20
_ZIP64_EOCD_SIGNATURE = b"PK\x06\x06"
_ZIP64_EOCD_MIN_SIZE = 56
_ZIP_CENTRAL_DIRECTORY_SIGNATURE = b"PK\x01\x02"
_ZIP_CENTRAL_DIRECTORY_HEADER_SIZE = 46
_MAX_ARCHIVE_RISK_DETAIL_CHARS = 512
_GZIP_MIN_SIZE = 18
_GZIP_RESERVED_FLAGS = 0xE0
_GZIP_DEFLATE_METHOD = 8
_GZIP_STREAM_CHUNK_BYTES = 64 * 1024
_GZIP_RATIO_MIN_OUTPUT_BYTES = 1024 * 1024
_WINDOWS_RESERVED_NAMES = frozenset(
    {
        "con",
        "prn",
        "aux",
        "nul",
        "conin$",
        "conout$",
        *(f"com{index}" for index in range(1, 10)),
        *(f"lpt{index}" for index in range(1, 10)),
        "com¹",
        "com²",
        "com³",
        "lpt¹",
        "lpt²",
        "lpt³",
    }
)
_WINDOWS_INVALID_NAME_CHARS = frozenset('<>:"|?*')


def _is_windows_reparse_point(metadata: os.stat_result) -> bool:
    attributes = int(getattr(metadata, "st_file_attributes", 0))
    reparse_flag = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
    return bool(attributes & reparse_flag)


def _first_link_like_parent(path: Path) -> tuple[Path, str] | None:
    """Return the first linked parent without resolving the caller's path."""

    candidate = path if path.is_absolute() else Path.cwd() / path
    current = Path(candidate.anchor)
    parts = candidate.parts[1:] if candidate.anchor else candidate.parts
    for part in parts[:-1]:
        if part in {"", "."}:
            continue
        if part == "..":
            current = current.parent
            continue
        current /= part
        metadata = current.lstat()
        if stat.S_ISLNK(metadata.st_mode):
            return current, "symbolic link"
        if _is_windows_reparse_point(metadata):
            return current, "Windows reparse point"
    return None


@dataclass(frozen=True, slots=True)
class _ZipDirectoryMetadata:
    entry_count: int
    size_bytes: int
    offset: int
    physical_offset: int


class _ArchiveRiskCollector:
    """Keep one bounded summary per archive risk category."""

    def __init__(self) -> None:
        self._counts: dict[tuple[RiskCode, bool], tuple[int, str]] = {}

    @staticmethod
    def _bounded_detail(detail: str) -> str:
        marker = "... [truncated]"
        if len(detail) <= _MAX_ARCHIVE_RISK_DETAIL_CHARS:
            return detail
        kept = _MAX_ARCHIVE_RISK_DETAIL_CHARS - len(marker)
        return detail[:kept] + marker

    def add(self, risk: ContentRisk) -> None:
        key = (risk.code, risk.blocking)
        current = self._counts.get(key)
        if current is None:
            self._counts[key] = (1, self._bounded_detail(risk.detail))
            return
        count, first_detail = current
        self._counts[key] = (count + 1, first_detail)

    def materialize(self) -> tuple[ContentRisk, ...]:
        output: list[ContentRisk] = []
        for (code, blocking), (count, first_detail) in self._counts.items():
            detail = (
                first_detail
                if count == 1
                else f"{count} occurrences total (details aggregated); first: {first_detail}"
            )
            output.append(ContentRisk(code, self._bounded_detail(detail), blocking))
        return tuple(output)


class _XmlDepthLimitExceeded(Exception):
    pass


class _XmlElementLimitExceeded(Exception):
    pass


class _XmlAttributeLimitExceeded(Exception):
    pass


class _BoundedXmlContentHandler(ContentHandler):
    """Discard SAX events while enforcing depth and element-count limits."""

    def __init__(self, max_depth: int, max_elements: int, max_attributes: int) -> None:
        super().__init__()
        self._max_depth = max_depth
        self._max_elements = max_elements
        self._max_attributes = max_attributes
        self._depth = 0
        self._elements = 0

    def startElement(self, _name: str, _attrs: AttributesImpl) -> None:  # noqa: N802
        if len(_attrs) > self._max_attributes:
            raise _XmlAttributeLimitExceeded
        self._depth += 1
        self._elements += 1
        if self._depth > self._max_depth:
            raise _XmlDepthLimitExceeded
        if self._elements > self._max_elements:
            raise _XmlElementLimitExceeded

    def endElement(self, _name: str) -> None:  # noqa: N802
        self._depth -= 1


class FileClassifier(Protocol):
    def classify(self, path: Path) -> ClassifierEvidence: ...


class MagikaClassifier:
    """Optional content classifier. Its output is supporting evidence, never authority."""

    def __init__(self) -> None:
        try:
            from magika import Magika
        except ImportError as exc:
            raise ConnectorError(
                "Magika is not installed; install the optional 'fileid' extra"
            ) from exc
        self._magika = Magika()

    def classify(self, path: Path) -> ClassifierEvidence:
        result = self._magika.identify_path(path)
        output = result.output
        score = getattr(result, "score", None)
        if score is None:
            score = getattr(output, "score", None)
        return ClassifierEvidence(
            provider="magika",
            label=str(output.label),
            mime_type=str(getattr(output, "mime_type", "")) or None,
            score=float(score) if isinstance(score, (float, int)) else None,
        )


class ContentInspector:
    """Content-first file inspection with bounded reads and archive metadata checks.

    The filename and suffix are intentionally ignored for primary classification. Optional
    classifiers can add evidence, but parser selection remains deterministic and is checked
    against actual structure.
    """

    def __init__(
        self,
        policy: FileTrustPolicy | None = None,
        *,
        classifier: FileClassifier | None = None,
    ) -> None:
        self.policy = policy or FileTrustPolicy()
        self.classifier = classifier

    def inspect(self, path: str | Path) -> FileInspection:
        source = Path(path)
        try:
            metadata = source.lstat()
            linked_parent = _first_link_like_parent(source)
        except OSError as exc:
            raise ConnectorError(f"cannot inspect input file: {source}") from exc

        risks: list[ContentRisk] = []
        path_identity = FileIdentity.from_stat(metadata)
        is_symlink = stat.S_ISLNK(metadata.st_mode)
        is_reparse_point = _is_windows_reparse_point(metadata)
        is_link_like = is_symlink or is_reparse_point or linked_parent is not None
        effective_metadata = metadata
        if is_link_like:
            if is_symlink:
                detail = "input path is a symbolic link"
            elif is_reparse_point:
                detail = "input path is a Windows reparse point"
            else:
                assert linked_parent is not None
                detail = f"input path has a {linked_parent[1]} parent"
            risks.append(
                ContentRisk(
                    RiskCode.SYMLINK_INPUT,
                    detail,
                    blocking=not self.policy.allow_symlink_inputs,
                )
            )
            if self.policy.allow_symlink_inputs:
                try:
                    effective_metadata = source.stat()
                except OSError as exc:
                    raise ConnectorError(f"cannot resolve input link: {source}") from exc
        if not stat.S_ISREG(effective_metadata.st_mode):
            risks.append(ContentRisk(RiskCode.NON_REGULAR_INPUT, "input is not a regular file"))
        if effective_metadata.st_size > self.policy.max_file_bytes:
            risks.append(
                ContentRisk(
                    RiskCode.FILE_TOO_LARGE,
                    f"input exceeds {self.policy.max_file_bytes} bytes",
                )
            )

        identity = FileIdentity.from_stat(effective_metadata)
        size = identity.size_bytes
        head = b""
        tail = b""
        source_handle: BinaryIO | None = None
        opened_identity_matches = False

        def record_change(detail: str) -> None:
            if any(item.code is RiskCode.FILE_CHANGED_DURING_INSPECTION for item in risks):
                return
            risks.append(ContentRisk(RiskCode.FILE_CHANGED_DURING_INSPECTION, detail))

        can_read = (
            stat.S_ISREG(effective_metadata.st_mode)
            and (not is_link_like or self.policy.allow_symlink_inputs)
            and effective_metadata.st_size <= self.policy.max_file_bytes
        )
        if can_read:
            try:
                source_handle = source.open("rb")
                opened_metadata = os.fstat(source_handle.fileno())
            except OSError as exc:
                if source_handle is not None:
                    source_handle.close()
                raise ConnectorError(f"cannot read input file: {source}") from exc
            opened_identity = FileIdentity.from_stat(opened_metadata)
            opened_identity_matches = (
                stat.S_ISREG(opened_metadata.st_mode) and opened_identity == identity
            )
            if not opened_identity_matches:
                record_change("input identity changed between metadata check and open")
            identity = opened_identity
            size = identity.size_bytes
            if size > self.policy.max_file_bytes and not any(
                item.code is RiskCode.FILE_TOO_LARGE for item in risks
            ):
                risks.append(
                    ContentRisk(
                        RiskCode.FILE_TOO_LARGE,
                        f"input exceeds {self.policy.max_file_bytes} bytes",
                    )
                )
            if opened_identity_matches and size <= self.policy.max_file_bytes:
                try:
                    head = source_handle.read(self.policy.max_probe_bytes)
                    if size >= 4:
                        tail_size = min(size, 8)
                        source_handle.seek(size - tail_size)
                        tail = source_handle.read(tail_size)
                except OSError as exc:
                    source_handle.close()
                    raise ConnectorError(f"cannot read input file: {source}") from exc

        try:
            kind: ContentKind
            confidence: float
            signals: tuple[str, ...]
            structure_risks: tuple[ContentRisk, ...]
            admission_blocked = any(
                item.blocking
                and item.code
                in {
                    RiskCode.SYMLINK_INPUT,
                    RiskCode.NON_REGULAR_INPUT,
                    RiskCode.FILE_TOO_LARGE,
                }
                for item in risks
            )
            if admission_blocked:
                kind = ContentKind.UNKNOWN
                confidence = 0.0
                signals = ("structured inspection skipped after blocking admission risk",)
                structure_risks = ()
            elif source_handle is not None and not opened_identity_matches:
                kind = ContentKind.UNKNOWN
                confidence = 0.0
                signals = ("file identity changed before parser selection",)
                structure_risks = ()
            else:
                kind, confidence, signals, structure_risks = self._identify(
                    source_handle, head, tail, size
                )
            risks.extend(structure_risks)

            classifier: ClassifierEvidence | None = None
            if (
                self.classifier is not None
                and source_handle is not None
                and opened_identity_matches
                and not admission_blocked
            ):
                try:
                    classifier = self.classifier.classify(source)
                except (
                    Exception
                ) as exc:  # supporting evidence must never break deterministic inspection
                    signals = (*signals, f"classifier unavailable: {type(exc).__name__}")
                else:
                    classifier_kind = self._classifier_kind(classifier)
                    score = classifier.score
                    if score is not None and not self._classifier_score_is_valid(score):
                        risks.append(
                            ContentRisk(
                                RiskCode.CLASSIFIER_DISAGREEMENT,
                                "classifier returned an invalid confidence score",
                                blocking=self.policy.classifier_disagreement_is_blocking,
                            )
                        )
                        signals = (*signals, "invalid classifier evidence was ignored")
                        classifier = ClassifierEvidence(
                            provider=classifier.provider,
                            label=classifier.label,
                            mime_type=classifier.mime_type,
                            score=None,
                        )
                    else:
                        compatible_json_probe = (
                            kind is ContentKind.TEXT
                            and classifier_kind is ContentKind.JSON
                            and any(signal.startswith("JSON-like") for signal in signals)
                        )
                        if (
                            classifier_kind is not None
                            and classifier_kind is not kind
                            and not compatible_json_probe
                            and score is not None
                            and score >= self.policy.classifier_disagreement_threshold
                        ):
                            risks.append(
                                ContentRisk(
                                    RiskCode.CLASSIFIER_DISAGREEMENT,
                                    (
                                        f"deterministic detector found {kind.value}, "
                                        f"classifier reported {classifier.label}"
                                    ),
                                    blocking=self.policy.classifier_disagreement_is_blocking,
                                )
                            )
                            signals = (*signals, "independent content detectors disagree")
                        elif compatible_json_probe:
                            signals = (*signals, "classifier also reported JSON for bounded probe")

            if source_handle is not None:
                try:
                    final_handle_identity = FileIdentity.from_stat(os.fstat(source_handle.fileno()))
                except OSError:
                    record_change("opened input could not be re-identified after inspection")
                else:
                    if final_handle_identity != identity:
                        record_change("opened input changed while it was being inspected")
        finally:
            if source_handle is not None:
                source_handle.close()

        try:
            final_path_metadata = source.lstat()
            final_linked_parent = _first_link_like_parent(source)
        except OSError:
            record_change("input path disappeared while it was being inspected")
        else:
            final_path_identity = FileIdentity.from_stat(final_path_metadata)
            final_is_symlink = stat.S_ISLNK(final_path_metadata.st_mode)
            final_is_link_like = (
                final_is_symlink
                or _is_windows_reparse_point(final_path_metadata)
                or final_linked_parent is not None
            )
            if final_path_identity != path_identity or final_is_link_like != is_link_like:
                record_change("input path identity changed while it was being inspected")
            if is_link_like and self.policy.allow_symlink_inputs:
                try:
                    final_target_identity = FileIdentity.from_stat(source.stat())
                except OSError:
                    record_change("input link target disappeared during inspection")
                else:
                    if final_target_identity != identity:
                        record_change("input link target changed during inspection")
            elif not is_link_like and final_path_identity != identity:
                record_change("input file changed while it was being inspected")

        return FileInspection(
            path=str(source),
            size_bytes=size,
            identity=identity,
            kind=kind,
            confidence=confidence,
            signals=signals,
            risks=tuple(risks),
            classifier=classifier,
        )

    def require(
        self,
        path: str | Path,
        *,
        allowed: set[ContentKind],
        purpose: str,
    ) -> FileInspection:
        report = self.inspect(path)
        if report.blocking_risks:
            codes = ", ".join(item.code.value for item in report.blocking_risks)
            raise ConnectorError(f"{purpose} rejected unsafe input ({codes})")
        if report.kind not in allowed:
            expected = ", ".join(sorted(item.value for item in allowed))
            raise ConnectorError(
                f"{purpose} expected content type [{expected}], detected {report.kind.value}"
            )
        return report

    @staticmethod
    def _json_like_limits_exceeded(
        text: str,
        *,
        max_depth: int,
        max_items: int,
    ) -> tuple[bool, bool]:
        """Bound JSON/JSON5 nesting and members before materializing a parse tree."""

        depth = 0
        root_started = False
        item_count = 0
        current_item: list[bool] = []
        quote: str | None = None
        escaped = False
        line_comment = False
        block_comment = False
        index = 0
        while index < len(text):
            char = text[index]
            following = text[index + 1] if index + 1 < len(text) else ""

            if line_comment:
                if char in {"\r", "\n", "\u2028", "\u2029"}:
                    line_comment = False
                index += 1
                continue
            if block_comment:
                if char == "*" and following == "/":
                    block_comment = False
                    index += 2
                else:
                    index += 1
                continue
            if quote is not None:
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == quote:
                    quote = None
                index += 1
                continue

            if char == "/" and following == "/":
                line_comment = True
                index += 2
                continue
            if char == "/" and following == "*":
                block_comment = True
                index += 2
                continue
            if char in {"'", '"'}:
                if not root_started:
                    return False, False
                if current_item:
                    current_item[-1] = True
                quote = char
                index += 1
                continue
            if not root_started:
                if char.isspace() or char == "\ufeff":
                    index += 1
                    continue
                if char not in "[{":
                    return False, False
                root_started = True

            if char in "[{":
                if current_item:
                    current_item[-1] = True
                depth += 1
                if depth > max_depth:
                    return True, False
                current_item.append(False)
            elif char == "," and current_item:
                if current_item[-1]:
                    item_count += 1
                    if item_count > max_items:
                        return False, True
                current_item[-1] = False
            elif char in "]}" and depth and current_item:
                if current_item.pop():
                    item_count += 1
                    if item_count > max_items:
                        return False, True
                depth -= 1
            elif current_item and not char.isspace():
                current_item[-1] = True
            index += 1
        return False, False

    @staticmethod
    def _json_like_nesting_exceeds(text: str, max_depth: int) -> bool:
        """Scan JSON and JSON5 structural tokens without invoking a recursive parser."""

        depth_exceeded, _ = ContentInspector._json_like_limits_exceeded(
            text,
            max_depth=max_depth,
            max_items=(1 << 63) - 1,
        )
        return depth_exceeded

    @staticmethod
    def _starts_json_like_container(text: str) -> bool:
        """Recognize a JSON or JSON5 object/array prefix without running a parser."""

        index = 0
        while index < len(text):
            char = text[index]
            following = text[index + 1] if index + 1 < len(text) else ""
            if char.isspace() or char == "\ufeff":
                index += 1
                continue
            if char == "/" and following == "/":
                index += 2
                while index < len(text) and text[index] not in {"\r", "\n", "\u2028", "\u2029"}:
                    index += 1
                continue
            if char == "/" and following == "*":
                closing = text.find("*/", index + 2)
                if closing < 0:
                    return False
                index = closing + 2
                continue
            return char in "[{"
        return False

    @staticmethod
    def _xml_attribute_limit_exceeded(text: str, max_attributes: int) -> bool:
        """Count unquoted assignment tokens in start tags before SAX allocates attrs."""

        index = 0
        while True:
            opening = text.find("<", index)
            if opening < 0 or opening + 1 >= len(text):
                return False
            if text.startswith("<!--", opening):
                closing = text.find("-->", opening + 4)
                if closing < 0:
                    return False
                index = closing + 3
                continue
            if text.startswith("<![CDATA[", opening):
                closing = text.find("]]>", opening + 9)
                if closing < 0:
                    return False
                index = closing + 3
                continue

            if text.startswith("<?", opening):
                closing = text.find("?>", opening + 2)
                if closing < 0:
                    return False
                index = closing + 2
                continue

            marker = text[opening + 1]
            if marker in {"/", "!"}:
                closing = text.find(">", opening + 2)
                if closing < 0:
                    return False
                index = closing + 1
                continue

            attributes = 0
            quote: str | None = None
            cursor = opening + 2
            while cursor < len(text):
                char = text[cursor]
                if quote is not None:
                    if char == quote:
                        quote = None
                elif char in {"'", '"'}:
                    quote = char
                elif char == "=":
                    attributes += 1
                    if attributes > max_attributes:
                        return True
                elif char == ">":
                    index = cursor + 1
                    break
                elif char == "<":
                    index = cursor
                    break
                cursor += 1
            else:
                return False

    @staticmethod
    def _zip_directory_metadata(handle: BinaryIO) -> _ZipDirectoryMetadata:
        """Read bounded EOCD metadata before zipfile allocates central-directory objects."""

        handle.seek(0, os.SEEK_END)
        file_size = handle.tell()
        tail_size = min(file_size, _ZIP_EOCD_SIZE + _ZIP_MAX_COMMENT_BYTES)
        handle.seek(file_size - tail_size)
        tail = handle.read(tail_size)
        if len(tail) != tail_size:
            raise ValueError("truncated ZIP end record")

        tail_start = file_size - tail_size
        index = tail.rfind(_ZIP_EOCD_SIGNATURE)
        if index < 0 or index + _ZIP_EOCD_SIZE > len(tail):
            raise ValueError("ZIP end record is missing or malformed")
        unpacked = struct.unpack_from("<4s4H2LH", tail, index)
        comment_length = int(unpacked[7])
        if index + _ZIP_EOCD_SIZE + comment_length != len(tail):
            # CPython zipfile also selects the last EOCD-looking signature. Reject an
            # ambiguous signature in the comment instead of preflighting a different
            # directory from the one the downstream parser would consume.
            raise ValueError("ZIP end record comment is ambiguous or malformed")
        earlier_index = tail.find(_ZIP_EOCD_SIGNATURE)
        while 0 <= earlier_index < index:
            if earlier_index + _ZIP_EOCD_SIZE <= len(tail):
                earlier_comment_length = struct.unpack_from("<H", tail, earlier_index + 20)[0]
                if earlier_index + _ZIP_EOCD_SIZE + earlier_comment_length == len(tail):
                    raise ValueError("ZIP end record comment contains an ambiguous end record")
            earlier_index = tail.find(_ZIP_EOCD_SIGNATURE, earlier_index + 1)

        (
            eocd_offset,
            disk_number,
            directory_disk,
            disk_entries,
            total_entries,
            directory_size,
            directory_offset,
        ) = (
            tail_start + index,
            int(unpacked[1]),
            int(unpacked[2]),
            int(unpacked[3]),
            int(unpacked[4]),
            int(unpacked[5]),
            int(unpacked[6]),
        )
        if disk_number != 0 or directory_disk != 0:
            raise ValueError("multi-disk ZIP archives are not supported")

        zip64_sentinel = (
            disk_entries == 0xFFFF
            or total_entries == 0xFFFF
            or directory_size == 0xFFFFFFFF
            or directory_offset == 0xFFFFFFFF
        )
        directory_end_limit = eocd_offset
        physical_directory_end = eocd_offset
        locator_offset = eocd_offset - _ZIP64_LOCATOR_SIZE
        locator_values: tuple[bytes, int, int, int] | None = None
        if locator_offset >= 0:
            handle.seek(locator_offset)
            locator = handle.read(_ZIP64_LOCATOR_SIZE)
            if len(locator) == _ZIP64_LOCATOR_SIZE and locator.startswith(_ZIP64_LOCATOR_SIGNATURE):
                locator_values = struct.unpack("<4sLQL", locator)

        if locator_values is not None:
            if int(locator_values[1]) != 0 or int(locator_values[3]) != 1:
                raise ValueError("ZIP64 locator is malformed")

            # zipfile reads the fixed ZIP64 end record immediately before the locator,
            # including for archives with prepended data. Mirror that physical record
            # selection so the bounded preflight and the later parser cannot disagree.
            physical_zip64_offset = locator_offset - _ZIP64_EOCD_MIN_SIZE
            if physical_zip64_offset < 0:
                raise ValueError("ZIP64 end record offset is invalid")
            handle.seek(physical_zip64_offset)
            zip64_record = handle.read(_ZIP64_EOCD_MIN_SIZE)
            if len(zip64_record) != _ZIP64_EOCD_MIN_SIZE:
                raise ValueError("ZIP64 end record is truncated")
            zip64_values = struct.unpack("<4sQ2H2L4Q", zip64_record)
            record_size = int(zip64_values[1])
            if (
                zip64_values[0] != _ZIP64_EOCD_SIGNATURE
                or record_size != 44
                or int(zip64_values[4]) != 0
                or int(zip64_values[5]) != 0
                or int(zip64_values[6]) != int(zip64_values[7])
            ):
                raise ValueError("ZIP64 end record is malformed")

            reported_zip64_offset = int(locator_values[2])
            if reported_zip64_offset > physical_zip64_offset:
                raise ValueError("ZIP64 end record offset is invalid")
            prepended_bytes = physical_zip64_offset - reported_zip64_offset

            zip64_disk_entries = int(zip64_values[6])
            zip64_total_entries = int(zip64_values[7])
            zip64_directory_size = int(zip64_values[8])
            zip64_directory_offset = int(zip64_values[9])
            standard_values = (
                (disk_entries, 0xFFFF, zip64_disk_entries),
                (total_entries, 0xFFFF, zip64_total_entries),
                (directory_size, 0xFFFFFFFF, zip64_directory_size),
                (directory_offset, 0xFFFFFFFF, zip64_directory_offset),
            )
            if any(
                standard != sentinel and standard != extended
                for standard, sentinel, extended in standard_values
            ):
                raise ValueError("ZIP and ZIP64 directory metadata disagree")

            total_entries = zip64_total_entries
            directory_size = zip64_directory_size
            directory_offset = zip64_directory_offset
            directory_end_limit = physical_zip64_offset - prepended_bytes
            physical_directory_end = physical_zip64_offset
        elif zip64_sentinel:
            raise ValueError("ZIP64 locator is missing")
        elif disk_entries != total_entries:
            raise ValueError("ZIP directory entry counts disagree")

        if directory_offset + directory_size > directory_end_limit:
            raise ValueError("ZIP central directory extends beyond its end record")
        physical_directory_offset = physical_directory_end - directory_size
        if physical_directory_offset < 0:
            raise ValueError("ZIP central directory has an invalid physical offset")
        return _ZipDirectoryMetadata(
            total_entries,
            directory_size,
            directory_offset,
            physical_directory_offset,
        )

    @staticmethod
    def _count_zip_directory_entries(
        handle: BinaryIO,
        metadata: _ZipDirectoryMetadata,
        *,
        stop_after: int,
    ) -> tuple[int, bool]:
        """Count central-directory records without materializing ZipInfo objects."""

        handle.seek(metadata.physical_offset)
        remaining = metadata.size_bytes
        count = 0
        while remaining:
            if remaining < _ZIP_CENTRAL_DIRECTORY_HEADER_SIZE:
                raise ValueError("truncated ZIP central-directory header")
            header = handle.read(_ZIP_CENTRAL_DIRECTORY_HEADER_SIZE)
            if len(header) != _ZIP_CENTRAL_DIRECTORY_HEADER_SIZE:
                raise ValueError("truncated ZIP central directory")
            values = struct.unpack("<4s6H3L5H2L", header)
            if values[0] != _ZIP_CENTRAL_DIRECTORY_SIGNATURE:
                raise ValueError("invalid ZIP central-directory signature")
            variable_size = int(values[10]) + int(values[11]) + int(values[12])
            record_size = _ZIP_CENTRAL_DIRECTORY_HEADER_SIZE + variable_size
            if record_size > remaining:
                raise ValueError("ZIP central-directory entry exceeds declared size")
            count += 1
            if count > stop_after:
                return count, True
            handle.seek(variable_size, os.SEEK_CUR)
            remaining -= record_size
        return count, False

    def _identify(
        self,
        handle: BinaryIO | None,
        head: bytes,
        tail: bytes,
        size: int,
    ) -> tuple[ContentKind, float, tuple[str, ...], tuple[ContentRisk, ...]]:
        if size == 0:
            return ContentKind.EMPTY, 1.0, ("zero-length file",), ()

        if head.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")):
            if handle is None:
                return (
                    ContentKind.ZIP,
                    0.6,
                    ("ZIP container signature",),
                    (ContentRisk(RiskCode.MALFORMED_ARCHIVE, "ZIP structure could not be read"),),
                )
            return self._inspect_zip(handle)
        if head.startswith(b"%PDF-"):
            return ContentKind.PDF, 1.0, ("PDF magic signature",), ()
        if head.startswith(b"SQLite format 3\x00"):
            return ContentKind.SQLITE, 1.0, ("SQLite magic signature",), ()
        if head.startswith(b"PAR1") and tail.endswith(b"PAR1"):
            return ContentKind.PARQUET, 1.0, ("Parquet head and tail magic",), ()
        if head.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
            return ContentKind.OLE, 1.0, ("OLE compound-file signature",), ()
        if head.startswith(b"\x1f\x8b"):
            if handle is None:
                return (
                    ContentKind.GZIP,
                    0.6,
                    ("gzip magic signature",),
                    (ContentRisk(RiskCode.MALFORMED_ARCHIVE, "gzip stream could not be read"),),
                )
            return self._inspect_gzip(handle, head, tail, size)
        if head.startswith((b"\x89PNG\r\n\x1a\n", b"\xff\xd8\xff", b"GIF87a", b"GIF89a")) or (
            head.startswith(b"RIFF") and len(head) >= 12 and head[8:12] == b"WEBP"
        ):
            return ContentKind.IMAGE, 0.98, ("image magic signature",), ()
        if head.startswith((b"MZ", b"\x7fELF")):
            return ContentKind.EXECUTABLE, 1.0, ("executable magic signature",), ()

        text = self._decode_text(head)
        if text is None:
            return ContentKind.BINARY, 0.95, ("probe is not valid bounded text",), ()
        stripped = text.lstrip("\ufeff\x00 \t\r\n")
        if not stripped:
            return ContentKind.TEXT, 0.75, ("textual content",), ()

        # Only parse complete small textual files here. Large structured files are still
        # recognized by their dedicated connector's full, size-bounded parser.
        complete_text: str | None = None
        if handle is not None and size <= self.policy.max_text_parse_bytes:
            try:
                complete_text = self._read_text(handle, self.policy.max_text_parse_bytes)
            except (OSError, UnicodeError, ValueError):
                complete_text = None

        if complete_text is not None:
            json_depth_exceeded, json_items_exceeded = self._json_like_limits_exceeded(
                complete_text,
                max_depth=self.policy.max_structured_text_depth,
                max_items=self.policy.max_json_items,
            )
            if json_depth_exceeded:
                return (
                    ContentKind.TEXT,
                    0.0,
                    ("JSON-like structure exceeds the configured nesting depth",),
                    (
                        ContentRisk(
                            RiskCode.JSON_NESTING_TOO_DEEP,
                            (
                                "JSON-like structure exceeds "
                                f"{self.policy.max_structured_text_depth} nesting levels"
                            ),
                        ),
                    ),
                )
            if json_items_exceeded:
                return (
                    ContentKind.TEXT,
                    0.0,
                    ("JSON-like structure exceeds the configured item limit",),
                    (
                        ContentRisk(
                            RiskCode.JSON_TOO_MANY_ITEMS,
                            (
                                "JSON-like structure exceeds "
                                f"{self.policy.max_json_items} members and array items"
                            ),
                        ),
                    ),
                )
            try:
                json.loads(complete_text)
            except RecursionError:
                return (
                    ContentKind.TEXT,
                    0.0,
                    ("JSON parser exceeded safe recursion depth",),
                    (
                        ContentRisk(
                            RiskCode.JSON_NESTING_TOO_DEEP,
                            "JSON parser exceeded safe recursion depth",
                        ),
                    ),
                )
            except (json.JSONDecodeError, ValueError):
                if size <= self.policy.max_json5_parse_bytes:
                    try:
                        json5.loads(complete_text)
                    except RecursionError:
                        return (
                            ContentKind.TEXT,
                            0.0,
                            ("JSON5 parser exceeded safe recursion depth",),
                            (
                                ContentRisk(
                                    RiskCode.JSON_NESTING_TOO_DEEP,
                                    "JSON5 parser exceeded safe recursion depth",
                                ),
                            ),
                        )
                    except (ValueError, TypeError):
                        pass
                    else:
                        return ContentKind.JSON5, 0.99, ("JSON5 parser accepted full content",), ()
                elif self._starts_json_like_container(complete_text):
                    return (
                        ContentKind.TEXT,
                        0.5,
                        ("JSON-like content exceeds the configured JSON5 parse limit",),
                        (),
                    )
            else:
                return ContentKind.JSON, 1.0, ("JSON parser accepted full content",), ()

            xml_candidate = complete_text.lstrip("\ufeff\x00 \t\r\n")
            if xml_candidate.startswith("<"):
                if self._xml_attribute_limit_exceeded(
                    xml_candidate,
                    self.policy.max_xml_attributes_per_element,
                ):
                    return (
                        ContentKind.TEXT,
                        0.0,
                        ("XML start tag exceeds the configured attribute limit",),
                        (
                            ContentRisk(
                                RiskCode.XML_TOO_MANY_ATTRIBUTES,
                                (
                                    "XML start tag exceeds "
                                    f"{self.policy.max_xml_attributes_per_element} attributes"
                                ),
                            ),
                        ),
                    )
                try:
                    defused_sax.parse(
                        StringIO(complete_text),
                        _BoundedXmlContentHandler(
                            self.policy.max_structured_text_depth,
                            self.policy.max_xml_elements,
                            self.policy.max_xml_attributes_per_element,
                        ),
                        forbid_dtd=True,
                        forbid_entities=True,
                        forbid_external=True,
                    )
                except _XmlDepthLimitExceeded:
                    return (
                        ContentKind.TEXT,
                        0.0,
                        ("XML structure exceeds the configured nesting depth",),
                        (
                            ContentRisk(
                                RiskCode.XML_NESTING_TOO_DEEP,
                                (
                                    "XML structure exceeds "
                                    f"{self.policy.max_structured_text_depth} nesting levels"
                                ),
                            ),
                        ),
                    )
                except _XmlElementLimitExceeded:
                    return (
                        ContentKind.TEXT,
                        0.0,
                        ("XML structure exceeds the configured element limit",),
                        (
                            ContentRisk(
                                RiskCode.XML_TOO_MANY_ELEMENTS,
                                f"XML structure exceeds {self.policy.max_xml_elements} elements",
                            ),
                        ),
                    )
                except _XmlAttributeLimitExceeded:
                    return (
                        ContentKind.TEXT,
                        0.0,
                        ("XML start tag exceeds the configured attribute limit",),
                        (
                            ContentRisk(
                                RiskCode.XML_TOO_MANY_ATTRIBUTES,
                                (
                                    "XML start tag exceeds "
                                    f"{self.policy.max_xml_attributes_per_element} attributes"
                                ),
                            ),
                        ),
                    )
                except (DefusedXmlException, SAXException, ValueError):
                    pass
                else:
                    return (
                        ContentKind.XML,
                        0.99,
                        ("safe streaming XML parser accepted content",),
                        (),
                    )

        if self._starts_json_like_container(text):
            return (
                ContentKind.TEXT,
                0.5,
                ("JSON-like leading token; not parser-confirmed within configured limits",),
                (),
            )
        if self._looks_delimited(text):
            return ContentKind.DELIMITED_TEXT, 0.78, ("consistent delimited-text structure",), ()
        return ContentKind.TEXT, 0.7, ("bounded probe is textual",), ()

    def _inspect_gzip(
        self,
        handle: BinaryIO,
        head: bytes,
        tail: bytes,
        size: int,
    ) -> tuple[ContentKind, float, tuple[str, ...], tuple[ContentRisk, ...]]:
        signals = ["gzip magic signature"]
        risks: list[ContentRisk] = []
        if (
            size < _GZIP_MIN_SIZE
            or len(head) < 4
            or head[2] != _GZIP_DEFLATE_METHOD
            or head[3] & _GZIP_RESERVED_FLAGS
            or len(tail) < 8
        ):
            risks.append(ContentRisk(RiskCode.MALFORMED_ARCHIVE, "gzip framing is malformed"))
            return ContentKind.GZIP, 0.6, tuple(signals), tuple(risks)
        if size > self.policy.max_gzip_scan_bytes:
            risks.append(
                ContentRisk(
                    RiskCode.ARCHIVE_SCAN_BUDGET_EXCEEDED,
                    (
                        f"gzip input exceeds the {self.policy.max_gzip_scan_bytes}-byte "
                        "streaming validation budget"
                    ),
                )
            )
            signals.append("gzip streaming skipped above the configured input budget")
            return ContentKind.GZIP, 0.8, tuple(signals), tuple(risks)

        # Validate every footer through zlib instead of trusting attacker-controlled
        # ISIZE evidence, which also becomes ambiguous once padding is permitted.
        total_output = 0
        total_compressed_input = 0
        completed_members = 0
        pending = b""
        decompressor = None
        member_output = 0
        member_input = 0

        try:
            handle.seek(0)
            while True:
                if decompressor is None:
                    if not pending:
                        pending = handle.read(_GZIP_STREAM_CHUNK_BYTES)
                    if completed_members:
                        # RFC 1952 permits zero padding after a member.
                        while pending:
                            pending = pending.lstrip(b"\x00")
                            if pending:
                                break
                            pending = handle.read(_GZIP_STREAM_CHUNK_BYTES)
                    if not pending:
                        break
                    if completed_members >= self.policy.max_archive_entries:
                        while len(pending) < 2:
                            extra = handle.read(_GZIP_STREAM_CHUNK_BYTES)
                            if not extra:
                                break
                            pending += extra
                        if not pending.startswith(b"\x1f\x8b"):
                            raise ValueError("non-padding data follows the final gzip member")
                        risks.append(
                            ContentRisk(
                                RiskCode.ARCHIVE_TOO_MANY_ENTRIES,
                                (
                                    "gzip stream contains more than "
                                    f"{self.policy.max_archive_entries} members"
                                ),
                            )
                        )
                        signals.append("gzip streaming stopped at a configured safety limit")
                        return ContentKind.GZIP, 1.0, tuple(signals), tuple(risks)
                    decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS)
                    member_output = 0
                    member_input = 0

                if not pending:
                    pending = handle.read(_GZIP_STREAM_CHUNK_BYTES)
                    if not pending:
                        raise ValueError("truncated gzip member")

                input_size = len(pending)
                output = decompressor.decompress(pending, _GZIP_STREAM_CHUNK_BYTES)
                member_output += len(output)
                total_output += len(output)

                if decompressor.eof:
                    consumed = input_size - len(decompressor.unused_data)
                    pending = decompressor.unused_data
                else:
                    consumed = input_size - len(decompressor.unconsumed_tail)
                    pending = decompressor.unconsumed_tail
                member_input += consumed
                total_compressed_input += consumed

                if member_output > self.policy.max_archive_member_bytes:
                    risks.append(
                        ContentRisk(
                            RiskCode.ARCHIVE_MEMBER_TOO_LARGE,
                            (
                                f"gzip member {completed_members + 1} exceeds "
                                f"{self.policy.max_archive_member_bytes} bytes"
                            ),
                        )
                    )
                if total_output > self.policy.max_archive_uncompressed_bytes:
                    risks.append(
                        ContentRisk(
                            RiskCode.ARCHIVE_TOO_LARGE,
                            (
                                "gzip stream expands beyond "
                                f"{self.policy.max_archive_uncompressed_bytes} bytes"
                            ),
                        )
                    )
                if risks:
                    signals.append("gzip streaming stopped at a configured safety limit")
                    return ContentKind.GZIP, 1.0, tuple(signals), tuple(risks)

                if decompressor.eof:
                    completed_members += 1
                    member_ratio = member_output / max(1, member_input)
                    if (
                        member_output >= _GZIP_RATIO_MIN_OUTPUT_BYTES
                        and member_ratio > self.policy.max_compression_ratio
                    ):
                        risks.append(
                            ContentRisk(
                                RiskCode.ARCHIVE_HIGH_COMPRESSION_RATIO,
                                (
                                    f"gzip member {completed_members} compression ratio "
                                    f"is {member_ratio:.1f}"
                                ),
                            )
                        )
                        signals.append("gzip streaming stopped at a configured safety limit")
                        return ContentKind.GZIP, 1.0, tuple(signals), tuple(risks)
                    decompressor = None
                elif consumed == 0 and not output:
                    raise ValueError("gzip decompressor made no progress")
        except (OSError, ValueError, zlib.error):
            risks.append(
                ContentRisk(RiskCode.MALFORMED_ARCHIVE, "gzip structure could not be read")
            )
            return ContentKind.GZIP, 0.6, tuple(signals), tuple(risks)

        if completed_members == 0:
            risks.append(
                ContentRisk(RiskCode.MALFORMED_ARCHIVE, "gzip contains no complete member")
            )
            return ContentKind.GZIP, 0.6, tuple(signals), tuple(risks)
        # A prefix of complete members can still be diluted by later legitimate data.
        # Judge the aggregate only after the entire stream is validated, and count only
        # consumed member bytes so zero padding cannot dilute the ratio.
        aggregate_ratio = total_output / max(1, total_compressed_input)
        if (
            total_output >= _GZIP_RATIO_MIN_OUTPUT_BYTES
            and aggregate_ratio > self.policy.max_compression_ratio
        ):
            risks.append(
                ContentRisk(
                    RiskCode.ARCHIVE_HIGH_COMPRESSION_RATIO,
                    f"aggregate gzip compression ratio exceeds {aggregate_ratio:.1f}",
                )
            )
            signals.append("gzip streaming stopped at a configured safety limit")
            return ContentKind.GZIP, 1.0, tuple(signals), tuple(risks)
        signals.append(f"validated {completed_members} gzip member(s) with bounded streaming")
        return ContentKind.GZIP, 1.0, tuple(signals), ()

    def _inspect_zip(
        self, handle: BinaryIO
    ) -> tuple[ContentKind, float, tuple[str, ...], tuple[ContentRisk, ...]]:
        risks = _ArchiveRiskCollector()
        signals = ["ZIP container signature"]
        try:
            metadata = self._zip_directory_metadata(handle)
            signals.append("bounded ZIP directory metadata")
            if metadata.entry_count > self.policy.max_archive_entries:
                risks.add(
                    ContentRisk(
                        RiskCode.ARCHIVE_TOO_MANY_ENTRIES,
                        f"archive reports {metadata.entry_count} entries",
                    )
                )
            if metadata.size_bytes > self.policy.max_archive_metadata_bytes:
                risks.add(
                    ContentRisk(
                        RiskCode.ARCHIVE_METADATA_TOO_LARGE,
                        f"archive central directory has {metadata.size_bytes} bytes",
                    )
                )
            if risks.materialize():
                return ContentKind.ZIP, 0.6, tuple(signals), risks.materialize()

            actual_entry_count, entry_limit_exceeded = self._count_zip_directory_entries(
                handle,
                metadata,
                stop_after=self.policy.max_archive_entries,
            )
            signals.append("streamed ZIP central-directory preflight")
            if actual_entry_count != metadata.entry_count:
                risks.add(
                    ContentRisk(
                        RiskCode.MALFORMED_ARCHIVE,
                        "archive directory entry count disagrees with its end record",
                    )
                )
            if entry_limit_exceeded:
                risks.add(
                    ContentRisk(
                        RiskCode.ARCHIVE_TOO_MANY_ENTRIES,
                        f"archive has more than {self.policy.max_archive_entries} entries",
                    )
                )
            if risks.materialize():
                return ContentKind.ZIP, 0.6, tuple(signals), risks.materialize()

            handle.seek(0)
            with zipfile.ZipFile(handle) as archive:
                infos = archive.infolist()
                if len(infos) != metadata.entry_count:
                    risks.add(
                        ContentRisk(
                            RiskCode.MALFORMED_ARCHIVE,
                            "archive directory entry count disagrees with its end record",
                        )
                    )
                if len(infos) > self.policy.max_archive_entries:
                    risks.add(
                        ContentRisk(
                            RiskCode.ARCHIVE_TOO_MANY_ENTRIES,
                            f"archive has {len(infos)} entries",
                        )
                    )
                    return ContentKind.ZIP, 0.6, tuple(signals), risks.materialize()

                total_uncompressed = 0
                total_compressed = 0
                names: set[str] = set()
                for info in infos:
                    name = info.filename.replace("\\", "/")
                    normalized_name = self._archive_path_collision_key(name)
                    if normalized_name in names:
                        risks.add(
                            ContentRisk(
                                RiskCode.ARCHIVE_DUPLICATE_ENTRY,
                                f"archive contains duplicate normalized entry: {name}",
                            )
                        )
                    names.add(normalized_name)
                    if info.flag_bits & 0x1:
                        risks.add(
                            ContentRisk(
                                RiskCode.ARCHIVE_ENCRYPTED_MEMBER,
                                f"archive contains encrypted member: {name}",
                            )
                        )
                    total_uncompressed += max(0, info.file_size)
                    total_compressed += max(0, info.compress_size)
                    if info.file_size > self.policy.max_archive_member_bytes:
                        risks.add(
                            ContentRisk(
                                RiskCode.ARCHIVE_MEMBER_TOO_LARGE,
                                f"archive member exceeds limit: {name}",
                            )
                        )
                    compressed = max(1, info.compress_size)
                    ratio = info.file_size / compressed
                    if info.file_size >= 1024 * 1024 and ratio > self.policy.max_compression_ratio:
                        risks.add(
                            ContentRisk(
                                RiskCode.ARCHIVE_HIGH_COMPRESSION_RATIO,
                                f"archive member compression ratio {ratio:.1f}: {name}",
                            )
                        )
                    if self._unsafe_archive_path(name):
                        risks.add(
                            ContentRisk(
                                RiskCode.ARCHIVE_PATH_TRAVERSAL,
                                f"unsafe archive path: {name}",
                            )
                        )
                    mode = (info.external_attr >> 16) & 0xFFFF
                    if stat.S_IFMT(mode) == stat.S_IFLNK:
                        risks.add(ContentRisk(RiskCode.ARCHIVE_SYMLINK, f"archive symlink: {name}"))

                if total_uncompressed > self.policy.max_archive_uncompressed_bytes:
                    risks.add(
                        ContentRisk(
                            RiskCode.ARCHIVE_TOO_LARGE,
                            f"archive expands to {total_uncompressed} bytes",
                        )
                    )

                aggregate_ratio = total_uncompressed / max(1, total_compressed)
                if (
                    total_uncompressed >= 1024 * 1024
                    and aggregate_ratio > self.policy.max_compression_ratio
                ):
                    risks.add(
                        ContentRisk(
                            RiskCode.ARCHIVE_HIGH_COMPRESSION_RATIO,
                            f"aggregate archive compression ratio is {aggregate_ratio:.1f}",
                        )
                    )

                macro = any(name.endswith("vbaproject.bin") for name in names)
                if macro:
                    risks.add(
                        ContentRisk(
                            RiskCode.OFFICE_MACRO,
                            "Office container contains a VBA project",
                            blocking=not self.policy.allow_office_macros,
                        )
                    )

                external_links = any(name.startswith("xl/externallinks/") for name in names)
                if external_links:
                    risks.add(
                        ContentRisk(
                            RiskCode.OFFICE_EXTERNAL_LINK,
                            "Office workbook contains external-link parts",
                            blocking=not self.policy.allow_office_external_links,
                        )
                    )

                external_data = "xl/connections.xml" in names or any(
                    name.startswith("xl/querytables/") for name in names
                )
                if external_data:
                    risks.add(
                        ContentRisk(
                            RiskCode.OFFICE_EXTERNAL_DATA,
                            "Office workbook contains external data-connection parts",
                            blocking=not self.policy.allow_office_external_links,
                        )
                    )

                if "[content_types].xml" in names and "xl/workbook.xml" in names:
                    signals.append("OOXML workbook structure")
                    return ContentKind.XLSX, 1.0, tuple(signals), risks.materialize()
                if "[content_types].xml" in names and "word/document.xml" in names:
                    signals.append("OOXML Word structure")
                    return ContentKind.DOCX, 1.0, tuple(signals), risks.materialize()
                if "[content_types].xml" in names and "ppt/presentation.xml" in names:
                    signals.append("OOXML PowerPoint structure")
                    return ContentKind.PPTX, 1.0, tuple(signals), risks.materialize()
                return ContentKind.ZIP, 0.98, tuple(signals), risks.materialize()
        except (OSError, ValueError, struct.error, zipfile.BadZipFile, RuntimeError):
            risks.add(ContentRisk(RiskCode.MALFORMED_ARCHIVE, "ZIP structure could not be read"))
            return ContentKind.ZIP, 0.6, tuple(signals), risks.materialize()

    @staticmethod
    def _classifier_kind(evidence: ClassifierEvidence) -> ContentKind | None:
        """Map only high-level labels that have an unambiguous local equivalent.

        Unknown classifier labels are deliberately ignored. A secondary classifier may veto
        a high-confidence disagreement, but it never chooses the parser.
        """

        label = evidence.label.casefold().replace("-", "_")
        mime = (evidence.mime_type or "").casefold()
        if label in {"pdf"} or mime == "application/pdf":
            return ContentKind.PDF
        if label in {"json"} or mime == "application/json":
            return ContentKind.JSON
        if label in {"xlsx", "msooxml_xlsx", "excel_ooxml"}:
            return ContentKind.XLSX
        if label in {"docx", "msooxml_docx", "word_ooxml"}:
            return ContentKind.DOCX
        if label in {"pptx", "msooxml_pptx", "powerpoint_ooxml"}:
            return ContentKind.PPTX
        if label in {"zip"} or mime == "application/zip":
            return ContentKind.ZIP
        if label in {"sqlite", "sqlite3"}:
            return ContentKind.SQLITE
        if label in {"parquet", "apache_parquet"}:
            return ContentKind.PARQUET
        if label in {"gzip", "gz"} or mime in {"application/gzip", "application/x-gzip"}:
            return ContentKind.GZIP
        if label in {"png", "jpeg", "jpg", "gif", "webp"} or mime.startswith("image/"):
            return ContentKind.IMAGE
        if label in {"elf", "pebin", "pe", "exe", "executable"}:
            return ContentKind.EXECUTABLE
        return None

    @staticmethod
    def _classifier_score_is_valid(score: object) -> bool:
        if isinstance(score, bool) or not isinstance(score, (int, float)):
            return False
        try:
            numeric_score = float(score)
        except (OverflowError, ValueError):
            return False
        return math.isfinite(numeric_score) and 0 <= numeric_score <= 1

    @staticmethod
    def _archive_path_collision_key(name: str) -> str:
        normalized = name.replace("\\", "/")
        components: list[str] = []
        for component in normalized.split("/"):
            if component in {"", "."}:
                continue
            if component == "..":
                if components and components[-1] != "..":
                    components.pop()
                else:
                    components.append(component)
                continue
            windows_component = component.rstrip(" .")
            folded = unicodedata.normalize("NFC", windows_component).casefold()
            components.append(unicodedata.normalize("NFC", folded))
        return "/".join(components)

    @staticmethod
    def _unsafe_archive_path(name: str) -> bool:
        if not name:
            return True
        normalized = name.replace("\\", "/")
        if normalized.startswith("/"):
            return True
        raw_components = normalized.split("/")
        if any(not component for component in raw_components[:-1]):
            return True
        for component in raw_components:
            if not component:
                continue
            if component in {".", ".."} or component != component.rstrip(" ."):
                return True
            canonical = unicodedata.normalize("NFC", component).casefold()
            if any(character in _WINDOWS_INVALID_NAME_CHARS for character in canonical):
                return True
            if any(ord(character) < 32 for character in canonical):
                return True
            # Win32 treats spaces before an extension as part of the device-name
            # normalization, for example ``CON .txt`` and ``COM1 .log``.
            basename = canonical.split(".", 1)[0].rstrip(" ")
            if basename in _WINDOWS_RESERVED_NAMES:
                return True
        return False

    @staticmethod
    def _decode_text(data: bytes) -> str | None:
        if data.startswith((b"\xff\xfe", b"\xfe\xff")):
            try:
                return data.decode("utf-16")
            except UnicodeDecodeError:
                return None
        try:
            text = data.decode("utf-8-sig")
        except UnicodeDecodeError:
            return None
        if not text:
            return text
        control = sum(1 for char in text if ord(char) < 32 and char not in {"\t", "\r", "\n", "\f"})
        if control / max(1, len(text)) > 0.01:
            return None
        return text

    @staticmethod
    def _read_text(handle: BinaryIO, max_bytes: int) -> str:
        handle.seek(0)
        raw = handle.read(max_bytes + 1)
        if len(raw) > max_bytes:
            raise ValueError("text input grew beyond the bounded parse limit")
        if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
            return raw.decode("utf-16")
        return raw.decode("utf-8-sig")

    @staticmethod
    def _looks_delimited(text: str) -> bool:
        lines = [line for line in text.splitlines()[:40] if line.strip()]
        if len(lines) < 2:
            return False
        for delimiter in (",", ";", "\t", "|"):
            counts = [line.count(delimiter) for line in lines]
            nonzero = [value for value in counts if value > 0]
            if len(nonzero) >= max(2, int(len(lines) * 0.8)):
                common = max(set(nonzero), key=nonzero.count)
                if common > 0 and nonzero.count(common) / len(nonzero) >= 0.75:
                    return True
        return False


def default_content_inspector(*, use_magika: bool = False) -> ContentInspector:
    classifier = MagikaClassifier() if use_magika else None
    return ContentInspector(classifier=classifier)
