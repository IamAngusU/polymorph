# Changelog

All notable changes to this private alpha are documented here.

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
