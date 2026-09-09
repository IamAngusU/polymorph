# Changelog

All notable changes to this alpha are documented here.

## Unreleased

### Added

- metadata-only recipe outcome tracking and a conservative automatic-reuse circuit after repeated
  rejected runs
- verified audit summaries, reason-code explanations and safe next-action guidance
- distinct destination audit event types for normal delivery, replay and force replay
- pinned csv-spectrum parser regressions with byte-level integrity and provenance checks
- a measured file, model and full secure-transport performance baseline
- a reproducible end-to-end workflow benchmark with real CSV, SQLite, signed audit, stage timing,
  CPU, RSS, storage and durability evidence
- a six-scenario failure lab for content confusion, ambiguous mapping, recipe suspension, relay
  tampering, lost acknowledgements and uncertain destination outcomes
- a dedicated CI job that publishes workflow and failure-lab evidence

### Changed

- commercial licensing and external contribution boundaries are stated explicitly
- standard benchmarks no longer enable high-overhead CPython allocation tracing unless explicitly
  requested
- delivery receipts distinguish disabled, recorded and failed audit writes
- audit metadata and recipe reason codes now enforce their documented bounded machine format
- audit summaries and recipe health use one consistent SQLite read snapshot
- database connectors cache their immutable reflected table instead of reflecting it before every
  record write

### Fixed

- current Magika score handling no longer touches its removed legacy fallback field or pollutes
  standard error during valid inspection
- a compatible Magika JSON report no longer rejects a large bounded JSON-like probe as a
  classifier conflict
- audit verification and export no longer create a missing database and report it as a valid empty
  log
- workflow verification checks every destination value without assuming relay delivery order,
  reports post-commit audit failures truthfully and strips local paths and PID from standard JSON

## 0.4.0a1 - 2026-09-09

### Added

- protocol v3 Ed25519 source authentication with tenant and connector identity binding
- source trust store with active, verification-only and revoked key states
- adversarial source-authentication coverage for forged signatures, tampering, revocation and
  wrong connector identity
- finite source-key rotation drain with immutable issuance cutoff and immediate hard revocation
- durable ciphertext-only source outbox that retries the exact signed wire bytes
- strict schema and plan JSON loading with duplicate-key, non-finite-value and size rejection
- built-in SHA-256 pins for every required ONNX, tokenizer and model configuration asset
- complete CSV-to-JSON workflow test across mapping, preflight, source signing, outbox, relay,
  destination delivery and acknowledgement
- crash-after-commit workflow coverage across the outbox, fenced relay lease and destination ledger
- opened-handle file identity binding for CSV, JSON and Excel parser handoff
- destination runtime contract checks for the exact plan, schema fingerprint, mapped field set,
  required fields, nullability and runtime types before the first write
- portable development bootstrap, multi-version Windows/Linux CI, strict typing, formatting,
  safety-corpus, package-content and clean-wheel gates
- restored typed schema and mapping model modules that the supplied archive accidentally excluded

### Changed

- relay and destination intake now fail closed when a v3 source key is absent or untrusted
- unsigned protocol v2 records require explicit legacy migration policy at every boundary
- malformed decrypted payloads are quarantined with fixed non-sensitive reason codes before write
- model execution is skipped when deterministic mapping evidence is already decisive
- model runtimes load lazily and use the pinned native SentencePiece model instead of duplicating
  the large JSON tokenizer representation in memory
- model install directories carry an exact-profile ownership marker and reject unrelated content
- relay acknowledgement and release now require the current unexpired random lease token
- invalid queued relay records move to a sealed dead-letter table without blocking later work
- destination claims use expiring pre-write fences and an irreversible `WRITE_STARTED` boundary;
  only stale pre-write claims recover automatically
- CSV and JSON destinations append atomically instead of replacing previous records
- CSV and JSON destination appends are serialized across cooperative local processes to prevent
  lost updates
- CSV exports reject spreadsheet formula-like values by default unless explicitly enabled
- HTTP destinations accept only 2xx as success and require an explicit endpoint idempotency contract
- HTTP, JSON5, schema, plan and transport payload parsing reject duplicate or non-finite values
- database exceptions report a known no-commit outcome only for supported transactional dialects
  after successful rollback; SQLAlchemy hides bound parameter values in errors
- recipient key creation is no-clobber and key loading is bounded by file-size and Argon2 cost limits
- built-in model verification pins model, tokenizer and configuration assets to static hashes
- Unicode mapping normalization preserves non-Latin descriptors and no longer conflates a generic
  account label with a customer identity
- source-control ignore rules no longer exclude the package's own `polymorph.models` modules
- local state uses `POLYMORPH_HOME` and product-named platform defaults; the old
  `ANGUSU_BRIDGE_HOME` variable and existing legacy default directories remain compatible
- SQLite WAL is enabled only on runtimes containing the upstream 2026 WAL-reset race fix; older
  bundled runtimes automatically use the rollback journal with full synchronous durability
- development and release tooling exclude PyPA build 1.6.0 because its Windows symlink regression
  breaks isolated builds under Microsoft Store Python

## 0.3.0 - 2026-09-08

### Added

- content-first file trust gate that ignores filename and extension as parser authority
- ZIP and OOXML metadata checks for traversal, symlinks, duplicate members, encrypted members, suspicious expansion, macros and external workbook links and data connections
- mandatory `defusedxml` hardening for the Excel parser path
- optional Magika classifier as independent veto evidence with corrected current Python prediction-score handling
- deterministic CSV dialect ensemble with optional CleverCSV evidence and fail-closed close-tie handling
- spreadsheet formula detection and freshness-unproven cached-value review gate
- optional multilingual cross-encoder reranker for ambiguous mapping candidates
- deterministic-only authorization rule for automatic mappings, including deterministic score and margin floors
- target-collision demotion across plausible mappings
- structural schema fingerprints and versioned local recipe storage
- recipe rebind to current exact schemas with a new plan ID and digest
- full no-write preflight for transformations, required values and optional read-only foreign-key resolution
- automatic recipe remembering only after complete promotable preflight
- one-command `prepare` workflow combining content inspection, recipe lookup, mapping and preflight
- opt-in resource benchmarking with wall time, CPU time, Python allocation and optional RSS metrics
- labelled mapping-corpus benchmark for automatic precision, automation coverage, suggestion accuracy and unsafe-auto detection
- local doctor reporting for parser trust features, XML hardening, optional model profiles and sandbox-tool availability
- current project brand mark in WebP with PNG source fallback

### Changed

- semantic model scores are advisory and cannot independently create an `AUTO` mapping
- recipe history is treated as candidate memory rather than execution permission
- sampled preflight is explicitly non-promotable
- Excel files are opened only after independent OOXML content validation
- project version advanced to 0.3.0

## 0.2.0 - 2026-09-08

### Added

- full-record blind transport bound to mapping plan digests
- protocol size limits and canonical sealed-record wire format
- ciphertext-only relay queue with route policy, deduplication and worker leases
- durable delivery ledger and sealed quarantine
- explicit write outcome classification for safe replay decisions
- signed capability grants and metadata-only tamper-evident audit chain
- natural-key to foreign-key resolution using actual database uniqueness constraints
- automatic Excel header discovery, repeated-header handling and fixed-width ID preservation
- CSV/TSV connector and bounded paginated HTTP JSON source connector
- JSON/JSON5 file limits, merged type inference and non-finite number rejection
- encrypted recipient key files using Argon2id and ChaCha20-Poly1305
- secret-provider abstractions including optional OS keyring support
- atomic local file, schema and plan writes
- immutable plan validation, serialization and conservative drift repair
- pinned local semantic model profile with install-time and runtime integrity verification
- expanded command-line tooling for schema inspection, plan lifecycle, key files, audit and quarantine metadata

### Changed

- cryptographic namespaces are product-name independent to support a later rename
- database writes now distinguish known rollback from unknown commit outcome
- HTTP connectors disable redirects and environment proxy inheritance
- semantic runtime loading no longer searches arbitrary ONNX files

## 0.1.0 - 2026-09-08

- initial typed schema, matching, policy and opaque transport foundation
