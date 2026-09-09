from __future__ import annotations

import json
import os
import stat
import zipfile
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path, PurePosixPath
from typing import BinaryIO, Protocol

import json5

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
    ARCHIVE_TOO_LARGE = "archive_too_large"
    ARCHIVE_MEMBER_TOO_LARGE = "archive_member_too_large"
    ARCHIVE_HIGH_COMPRESSION_RATIO = "archive_high_compression_ratio"
    ARCHIVE_PATH_TRAVERSAL = "archive_path_traversal"
    ARCHIVE_SYMLINK = "archive_symlink"
    ARCHIVE_DUPLICATE_ENTRY = "archive_duplicate_entry"
    ARCHIVE_ENCRYPTED_MEMBER = "archive_encrypted_member"
    OFFICE_MACRO = "office_macro"
    OFFICE_EXTERNAL_LINK = "office_external_link"
    OFFICE_EXTERNAL_DATA = "office_external_data"
    CLASSIFIER_DISAGREEMENT = "classifier_disagreement"
    MALFORMED_ARCHIVE = "malformed_archive"
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
    """Portable identity evidence for the exact file bytes that were inspected."""

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
        score = getattr(result, "score", getattr(output, "score", None))
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
        except OSError as exc:
            raise ConnectorError(f"cannot inspect input file: {source}") from exc

        risks: list[ContentRisk] = []
        path_identity = FileIdentity.from_stat(metadata)
        is_symlink = stat.S_ISLNK(metadata.st_mode)
        effective_metadata = metadata
        if is_symlink:
            risks.append(
                ContentRisk(
                    RiskCode.SYMLINK_INPUT,
                    "input path is a symbolic link",
                    blocking=not self.policy.allow_symlink_inputs,
                )
            )
            if self.policy.allow_symlink_inputs:
                try:
                    effective_metadata = source.stat()
                except OSError as exc:
                    raise ConnectorError(f"cannot resolve input symlink: {source}") from exc
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

        can_read = stat.S_ISREG(effective_metadata.st_mode) and (
            not is_symlink or self.policy.allow_symlink_inputs
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
            if opened_identity_matches:
                try:
                    head = source_handle.read(self.policy.max_probe_bytes)
                    if size >= 4:
                        source_handle.seek(max(0, size - 4))
                        tail = source_handle.read(4)
                except OSError as exc:
                    source_handle.close()
                    raise ConnectorError(f"cannot read input file: {source}") from exc

        try:
            kind: ContentKind
            confidence: float
            signals: tuple[str, ...]
            structure_risks: tuple[ContentRisk, ...]
            if source_handle is not None and not opened_identity_matches:
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
            ):
                try:
                    classifier = self.classifier.classify(source)
                except (
                    Exception
                ) as exc:  # supporting evidence must never break deterministic inspection
                    signals = (*signals, f"classifier unavailable: {type(exc).__name__}")
                else:
                    classifier_kind = self._classifier_kind(classifier)
                    if (
                        classifier_kind is not None
                        and classifier_kind is not kind
                        and classifier.score is not None
                        and classifier.score >= self.policy.classifier_disagreement_threshold
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
        except OSError:
            record_change("input path disappeared while it was being inspected")
        else:
            final_path_identity = FileIdentity.from_stat(final_path_metadata)
            final_is_symlink = stat.S_ISLNK(final_path_metadata.st_mode)
            if final_path_identity != path_identity or final_is_symlink != is_symlink:
                record_change("input path identity changed while it was being inspected")
            if is_symlink and self.policy.allow_symlink_inputs:
                try:
                    final_target_identity = FileIdentity.from_stat(source.stat())
                except OSError:
                    record_change("input symlink target disappeared during inspection")
                else:
                    if final_target_identity != identity:
                        record_change("input symlink target changed during inspection")
            elif not is_symlink and final_path_identity != identity:
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
        if head.startswith(b"PAR1") and tail == b"PAR1":
            return ContentKind.PARQUET, 1.0, ("Parquet head and tail magic",), ()
        if head.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
            return ContentKind.OLE, 1.0, ("OLE compound-file signature",), ()
        if head.startswith(b"\x1f\x8b"):
            return ContentKind.GZIP, 1.0, ("gzip magic signature",), ()
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
            try:
                json.loads(complete_text)
            except (json.JSONDecodeError, ValueError):
                try:
                    json5.loads(complete_text)
                except (ValueError, TypeError):
                    pass
                else:
                    return ContentKind.JSON5, 0.99, ("JSON5 parser accepted full content",), ()
            else:
                return ContentKind.JSON, 1.0, ("JSON parser accepted full content",), ()

        if stripped.startswith(("{", "[")):
            return ContentKind.TEXT, 0.76, ("JSON-like leading token; full parser required",), ()
        if stripped.startswith("<"):
            return ContentKind.XML, 0.72, ("text starts with XML-like markup",), ()
        if self._looks_delimited(text):
            return ContentKind.DELIMITED_TEXT, 0.78, ("consistent delimited-text structure",), ()
        return ContentKind.TEXT, 0.7, ("bounded probe is textual",), ()

    def _inspect_zip(
        self, handle: BinaryIO
    ) -> tuple[ContentKind, float, tuple[str, ...], tuple[ContentRisk, ...]]:
        risks: list[ContentRisk] = []
        signals = ["ZIP container signature"]
        try:
            handle.seek(0)
            with zipfile.ZipFile(handle) as archive:
                infos = archive.infolist()
                if len(infos) > self.policy.max_archive_entries:
                    risks.append(
                        ContentRisk(
                            RiskCode.ARCHIVE_TOO_MANY_ENTRIES,
                            f"archive has {len(infos)} entries",
                        )
                    )

                total_uncompressed = 0
                names: set[str] = set()
                for info in infos:
                    name = info.filename.replace("\\", "/")
                    normalized_name = name.casefold()
                    if normalized_name in names:
                        risks.append(
                            ContentRisk(
                                RiskCode.ARCHIVE_DUPLICATE_ENTRY,
                                f"archive contains duplicate normalized entry: {name}",
                            )
                        )
                    names.add(normalized_name)
                    if info.flag_bits & 0x1:
                        risks.append(
                            ContentRisk(
                                RiskCode.ARCHIVE_ENCRYPTED_MEMBER,
                                f"archive contains encrypted member: {name}",
                            )
                        )
                    total_uncompressed += max(0, info.file_size)
                    if info.file_size > self.policy.max_archive_member_bytes:
                        risks.append(
                            ContentRisk(
                                RiskCode.ARCHIVE_MEMBER_TOO_LARGE,
                                f"archive member exceeds limit: {name}",
                            )
                        )
                    compressed = max(1, info.compress_size)
                    ratio = info.file_size / compressed
                    if info.file_size >= 1024 * 1024 and ratio > self.policy.max_compression_ratio:
                        risks.append(
                            ContentRisk(
                                RiskCode.ARCHIVE_HIGH_COMPRESSION_RATIO,
                                f"archive member compression ratio {ratio:.1f}: {name}",
                            )
                        )
                    if self._unsafe_archive_path(name):
                        risks.append(
                            ContentRisk(
                                RiskCode.ARCHIVE_PATH_TRAVERSAL,
                                f"unsafe archive path: {name}",
                            )
                        )
                    mode = (info.external_attr >> 16) & 0xFFFF
                    if stat.S_IFMT(mode) == stat.S_IFLNK:
                        risks.append(
                            ContentRisk(RiskCode.ARCHIVE_SYMLINK, f"archive symlink: {name}")
                        )

                if total_uncompressed > self.policy.max_archive_uncompressed_bytes:
                    risks.append(
                        ContentRisk(
                            RiskCode.ARCHIVE_TOO_LARGE,
                            f"archive expands to {total_uncompressed} bytes",
                        )
                    )

                macro = any(name.endswith("vbaproject.bin") for name in names)
                if macro:
                    risks.append(
                        ContentRisk(
                            RiskCode.OFFICE_MACRO,
                            "Office container contains a VBA project",
                            blocking=not self.policy.allow_office_macros,
                        )
                    )

                external_links = any(name.startswith("xl/externallinks/") for name in names)
                if external_links:
                    risks.append(
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
                    risks.append(
                        ContentRisk(
                            RiskCode.OFFICE_EXTERNAL_DATA,
                            "Office workbook contains external data-connection parts",
                            blocking=not self.policy.allow_office_external_links,
                        )
                    )

                if "[content_types].xml" in names and "xl/workbook.xml" in names:
                    signals.append("OOXML workbook structure")
                    return ContentKind.XLSX, 1.0, tuple(signals), tuple(risks)
                if "[content_types].xml" in names and "word/document.xml" in names:
                    signals.append("OOXML Word structure")
                    return ContentKind.DOCX, 1.0, tuple(signals), tuple(risks)
                if "[content_types].xml" in names and "ppt/presentation.xml" in names:
                    signals.append("OOXML PowerPoint structure")
                    return ContentKind.PPTX, 1.0, tuple(signals), tuple(risks)
                return ContentKind.ZIP, 0.98, tuple(signals), tuple(risks)
        except (OSError, zipfile.BadZipFile, RuntimeError):
            risks.append(ContentRisk(RiskCode.MALFORMED_ARCHIVE, "ZIP structure could not be read"))
            return ContentKind.ZIP, 0.6, tuple(signals), tuple(risks)

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
    def _unsafe_archive_path(name: str) -> bool:
        if not name or name.startswith(("/", "\\")):
            return True
        normalized = name.replace("\\", "/")
        path = PurePosixPath(normalized)
        if any(part == ".." for part in path.parts):
            return True
        first = path.parts[0] if path.parts else ""
        return len(first) >= 2 and first[1] == ":"

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
