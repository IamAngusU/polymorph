# File trust gate

Uploaded files are untrusted byte streams. Their file name, extension, MIME label supplied by a client and user-facing description are not parser-selection authority.

## Content-first selection

`ContentInspector` uses bounded reads and structure-specific evidence. Current deterministic detection includes:

- ZIP and Office Open XML containers
- PDF
- SQLite
- Parquet head/tail magic
- OLE compound files
- gzip with bounded streaming validation of every concatenated member
- common image signatures
- PE and ELF executables
- JSON through bounded full parsing and JSON5 behind a smaller CPU-abuse limit
- XML through a defused streaming parser with depth and element limits
- delimited text structure
- generic text/binary fallbacks

A file named `orders.csv` that starts as a PE executable is an executable. A valid OOXML workbook renamed to `.bin` is still an XLSX container.

## File identity and parser handoff

An accepted inspection includes the device, inode, byte size and nanosecond modification time reported by `lstat`, `stat` and the opened inspection handle. The leaf and every supplied parent component are checked for symbolic links and Windows reparse points. The inspector reads deterministic evidence from one open handle where the parser format permits it. It compares that handle and the path again after inspection. A change observed during the inspection is a blocking `file_changed_during_inspection` risk.

CSV, JSON and Excel cache trust only together with that identity. Before any later parser receives bytes, the connector opens the path and compares `fstat` for the actual handle with the accepted identity. It checks the handle again after reading. Replacing the path after the first gate therefore fails closed instead of reusing a stale boolean such as "content checked". Cached schemas and parsed JSON records also revalidate the path identity before they are returned.

This is a portable TOCTOU reduction, not an atomic filesystem transaction. A hostile process with write access may still exploit filesystem-specific behavior or modify bytes while preserving all available identity fields. Deployments should keep untrusted upload directories non-writable after intake and isolate parsers when the host offers a separately enforced sandbox.

## Destination writer serialization

CSV and JSON destinations hold an exclusive per-path lock across their complete read, validation
and atomic replace cycle. The implementation combines an in-process lock with an adjacent kernel
file lock: byte-range locking on Windows and `flock` on POSIX. This prevents cooperating Polymorph
processes from reading the same old snapshot and silently replacing each other's append.

The lock sidecar is intentionally persistent and contains no payload data. Deleting a live or idle
sidecar is unsafe because two writers could then lock different file identities. Lock acquisition is
bounded by `write_lock_timeout`. A timeout or unsafe lock file is reported as `NOT_COMMITTED`, and
the destination file is not touched. New targets use create-if-absent publication, while existing
targets are rechecked against the inspected file identity immediately before atomic replacement.

This is cooperative serialization, not protection against arbitrary programs that ignore the lock.
Destination directories should only be writable by the Polymorph service account. Network file
systems must provide the platform lock and atomic rename semantics they claim; otherwise use a
database destination or a single writer process.

## Archive checks

ZIP containers receive a bounded end-record and central-directory preflight before `ZipFile`
allocates one object per entry. The gate rejects underreported entry counts, oversized metadata,
aggregate and per-member expansion, suspicious compression ratios, traversal, encrypted members,
symlinks, duplicate normalized paths and Windows device-name collisions.

GZIP validation does not trust the final `ISIZE` footer. It streams every concatenated member
through zlib in fixed chunks, validates framing, CRC and size, discards output, and stops at member
count, member size, aggregate size, compression-ratio or compressed-input scan limits. Padding bytes
permitted by the format are excluded from the compression-ratio denominator, so padding cannot hide
an expansion bomb.

Office containers additionally reject VBA projects and workbook external-link parts by default. These are independent of whether a downstream parser claims it will ignore them.

Small JSON and XML inputs are structurally checked before recursive or tree-building parsers are
allowed to decide their type. JSON and JSON5 share a default 100,000-item structural budget; JSON5
parsing also has a separate 64 KiB default cap. XML uses defused SAX with default limits of 128
nesting levels, 100,000 elements and 1,024 attributes per element. The attribute gate runs before
SAX materializes the attribute mapping.

## Independent classifier evidence

Magika can be enabled as a second local content detector. It does not select a parser. When a high-confidence Magika classification maps to a known local content kind and conflicts with the deterministic detector, automatic parser selection is blocked by default.

This provides a useful failure mode: disagreement creates less trust, not an arbitrary tie-break.

## CSV dialects

Delimited text is not parsed by trusting `.csv`. The CSV connector evaluates a bounded set of candidate delimiters, the standard-library sniffer and optionally CleverCSV. Candidates are scored by structural consistency. A close tie raises an ambiguity error instead of silently selecting a delimiter.

## Spreadsheet formulas

openpyxl does not calculate formulas. `data_only=True` returns workbook-provided cached results. Those cached values may be stale even if their type looks correct.

The Excel connector therefore scans the selected worksheet for formula cells and marks the schema with `formula_value_source=cached_workbook_value`. Preflight converts this into a review requirement. A formula-bearing sheet cannot become a new automatic recipe merely because cached values happened to pass type checks.

## What the gate is not

The content trust gate reduces parser attack surface and resource abuse, but it is not an operating-system hostile-code sandbox. Supported parsers still run in the local Polymorph process after the gate accepts the input.

`polymorph inspect isolated-content` can run this gate in a short-lived worker against an exact-byte
snapshot. Its default policy requires an OS sandbox and never silently downgrades. On Linux the
strict backend uses Bubblewrap. On Windows, Job Object-backed resource containment is available
only through an explicit weaker policy and is not called a filesystem or network sandbox.

This first worker contains content identification only. CSV, JSON and Excel schema parsing and
record iteration still run in-process. See [Parser isolation](PARSER_ISOLATION.md) for the exact
scope and remaining boundary.
