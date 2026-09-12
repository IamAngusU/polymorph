# Changelog

## 0.4.0a10 - 2026-09-12

### Fixed

- Detect namespace-prefixed OOXML formula tags and retain formula-cache uncertainty.
- Preserve empty CSV cells as value-free quality evidence.
- Route automatic INTEGER mappings through one strict transform exercised by preflight and execution.
- Accept existing local SQLite files in `polymorph inspect db` without requiring a hand-written SQLAlchemy URL.

### Evidence

- External adversarial fixtures retained zero unsafe automatic decisions, zero writes, and zero network use.
- A complete 1,000,000-row local CSV trial observed bounded process-tree memory from 100,000 to 1,000,000 rows on the measured Windows host.
## [0.4.0a9] - 2026-09-12

- expose own-data Trial and release Trust Center through the primary polymorph CLI while preserving toolkit aliases
- move the no-clone own-data command and a real WebP product screenshot into the README hero
- replace stale version-based roadmap promises with implemented, evidence-needed, in-progress and planned states
- state clearly that GitHub Actions are prepared but repository-wide disabled
- add structured bug, connector-request and evidence-contribution issue forms


## [0.4.0a8] - 2026-09-12

- add a one-command, local-only own-data trial with no destination, network use or write authority
- add a commit-bound static Trust Center generator with explicit provenance and non-coverage
- publish an OpenSSF Security Insights 2.2.0 declaration validated against the official CUE schema
- reposition the README around local-first, fail-closed mapping and explicit write outcomes


All notable changes to this alpha are documented here.

## Unreleased

## 0.4.0a7 - 2026-09-12

- Replaced the per-append full audit-table quota scan with transactionally maintained constant-time
  usage metadata, preserving pre-write quota checks across multiple writers.
- Added automatic usage backfill for existing audit stores and postconditions that roll back an
  append if the hash-chain tail, inserted rows, or usage metadata disagree.
- Reused the already serialized audit event bytes for hashing and quota accounting.
- Added regression coverage for legacy migration, shared-writer quotas, and absence of aggregate
  table scans in the append hot path.

## 0.4.0a6 - 2026-09-12

- Fixed the portable review integration against the real `MoveSession`: preparations now expose
  both schema fingerprints, helpers accept the actual `as_dict()` contract, and the artifact's
  reviewer identity is propagated into every reviewed mapping.
- Added a real file-to-destination integration regression covering prepare, review artifact,
  execute, reviewer provenance, destination rows, and commit-receipt creation.
- Added a bounded `RoutePreparation` to review-UI model adapter and matching toolkit command so
  embedding hosts do not need to recreate the schema-only translation.
- Suppressed OAuth refresh exception chaining so standard traceback logging cannot reveal a
  callback exception containing credentials.
- Made recurring checkpoints fail closed when a completed result has no stable run ID, and added
  support for the real `MoveResult.as_dict()` contract without inventing identity.
- Corrected quality CLI wording to promise local content-inspected files rather than unsupported
  arbitrary connector specs.
- Updated Windows documentation to reflect Job Object resource containment without implying
  filesystem or network sandboxing.
- Reworked the review component toward Polymorph's quiet cool-gray visual language. Evidence
  classes are primary, numeric advisory scores are drilldown-only, and decorative gradients were
  removed to reinforce that confidence is not authority.

## 0.4.0a5 - 2026-09-12

- Added `polymorph-kit`, a local-first integration toolkit with no generated or activated GitHub
  Actions workflows.
- Added a no-overwrite, fail-closed source connector scaffolder whose capability manifest starts
  entirely false and includes provider lifecycle and quota guidance.
- Added bounded streaming data-quality reports that retain row numbers and issue metadata but no
  customer values, plus lazy schema-bound cleaning plans requiring explicit operator construction.
- Added portable EN/DE review UI assets and canonical review artifacts bound to exact source and
  destination schema fingerprints. Artifacts can record mappings but never grant write authority.
- Added a thread-safe in-memory OAuth access-token provider driven by a trusted-host refresh
  callback, with redacted representations, bounded token lifetime, and no refresh-token storage.
- Added durable local recurring-run checkpoints with commit-only advancement, compare-and-swap
  generations, idempotent receipts, bounded cursors, and fenced expiring single-host leases.
- Added honest enterprise-readiness, recurring-run, review-UI, and ecosystem boundary documents
  plus copy-paste integration recipes.

## 0.4.0a4 - 2026-09-12

### Added

- a public connector registry with content-based source resolution, explicit destinations,
  machine-readable manifests and opt-in Python entry-point discovery
- a connector contract conformance kit that checks capability and method consistency without
  opening user endpoints
- a versioned, payload-free product event contract with stable reason, next-action, retry and
  presentation metadata plus English and German message catalogs
- callback, composite and bounded asynchronous queue event sinks whose failures cannot change
  destination write semantics
- an explicit two-phase `polymorph.move(...)` embedded API for mapping, complete no-write
  preflight and immutable-file local streaming execution
- structured embedded outcomes for review, block, not-committed, committed-prefix partial and
  unknown destination states
- `polymorph connectors` for local connector discovery and `polymorph demo` for a responsive,
  self-contained, synthetic no-account/no-network/no-write product walkthrough

### Changed

- CSV, JSON, Excel, Parquet, database and HTTP source/destination capabilities are now exposed
  through one stable public discovery surface
- public onboarding now starts with separate try, embed and security routes
- security coverage now distinguishes the embedded same-process path, best-effort product events
  and trusted-code connector plugins from the encrypted relay and signed audit boundaries

## 0.4.0a3 - 2026-09-12

### Added

- one shared finite work-budget contract for direct CSV, HTTP JSON and Parquet connector calls
- HTTP JSON depth, node, value, aggregate byte, wall-time and total-record limits
- exact HTTP request-byte accounting, unread destination response bodies and structured committed-prefix
  outcomes for non-atomic aggregate calls
- Parquet row, row-group, metadata, uncompressed, nesting and decoded-batch limits
- Windows Job Object CPU, memory, descendant-count and kill-on-close enforcement for parser workers
- streaming audit verification, summaries and atomic JSONL exports with finite admission quotas
- local CycloneDX SBOM and release-manifest generation plus offline hash verification
- a multilingual adversarial ambiguity corpus that rewards abstention rather than guessed mappings

### Changed

- CSV destination updates now copy the committed source and append rows through an atomic streaming
  rewrite instead of rebuilding the complete file in memory
- release links now follow the latest tested pre-release instead of drifting to an older tag

## 0.4.0a2 - 2026-09-12

### Added

- five-minute English and German onboarding guides plus a packaged local evidence runner
- read-only Parquet schema inspection and bounded record streaming behind the content trust gate
- an explicit real PostgreSQL connector write and rollback lab that never records its URL
- a multilingual ERP, finance, unit and tax glossary with strictly advisory-only authority
- metadata-only review-session timing for measuring operator effort instead of estimating it
- a source-separated public multilingual schema corpus with retained provenance and limitations

- capability-gated atomic destination writes with explicit count, aggregate sealed-wire and
  cross-path idempotency contracts
- durable random batch-attempt IDs in the delivery ledger, receipts and signed audit metadata so
  an uncertain batch cannot silently fall through scalar replay after restart
- bounded multi-record operations for source sealing, outbox, relay, ledger, quarantine, audit and
  operational events
- regression cases for atomic partial-write rollback, unknown rollback outcomes, post-commit crash
  replay, duplicate ordering, exact byte limits and 10,001-item generator rejection
- destination-signed, tenant- and connector-bound recipient-key certificates with strict validity,
  exact predecessor rotation, durable local head checkpoints and concurrent fork rejection
- authenticated recipient key IDs in encrypted record context plus explicit multi-key destination
  drain support for planned rotations
- CLI certificate inspection and atomic trust-head acceptance backed by a separately provisioned
  destination identity public key
- an explicit preflight input-record blast-radius gate that blocks readiness above the configured
  per-run budget without confusing that policy with diagnostic sampling
- bounded operational event streams with matching writer and health-reader budgets
- bounded persisted recipient-key reuse detection, low-order X25519 rejection and POSIX
  trust-head directory durability
- fail-closed handling of blank recipient key IDs in source-signed v3 records, with a separate
  per-boundary legacy-drain opt-in
- a real localhost TLS acknowledgement-loss lab with an idempotent retry invariant
- fail-closed isolated content inspection with exact-byte snapshots, a strict JSON worker protocol,
  explicit containment levels, POSIX resource limits and a Linux Bubblewrap backend
- parser-worker timing and failure evidence plus adversarial timeout, output, protocol, snapshot and
  containment tests
- early JSON and JSON5 depth and size gates, bounded XML SAX validation, streamed multi-member GZIP
  validation with member-count and padding-safe ratio checks, and ZIP central-directory guards
  before expensive parsers run
- Windows reparse-input rejection plus archive path collision checks for case folding, trailing
  spaces, Unicode normalization and reserved device aliases
- linked input parents are rejected, JSON breadth and XML attributes are bounded before parser
  materialization, and connector-specific JSON5 limits reach the content gate
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
- a local metadata-only operational event stream with run and correlation identifiers
- `events summary` and `events check` commands for structural validation and scheduler-friendly
  health exits
- a 42-case mapping safety regression corpus with precision, coverage and suggestion gates
- a ten-scenario concurrent recovery suite covering restarts, lease fencing, process-contended
  schema migration and duplicate
  suppression
- compact, hash-pinned JSONTestSuite and W3C CSVW regression subsets with retained upstream
  licenses and byte-level provenance

### Changed

- public licensing moved from PolyForm Noncommercial to **AGPL-3.0-only**, with an alternative
  commercial license for proprietary use; previously received copies keep the terms under which
  they were received
- the real SQLite workflow uses safe all-or-none destination batches, batched state transactions,
  audit appends, event appends and acknowledgements without weakening per-record crypto or fences
- recipient trust-state reads cache only a verified unchanged file snapshot; route, certificate
  lifetime and on-disk identity are still checked for every newly sealed record
- sealed queue reads are bounded by aggregate wire bytes as well as row count
- default bootstrap is model-free; both existing model profiles require explicit research opt-in
  pending commercial training-data provenance review
- commercial licensing and external contribution boundaries are stated explicitly
- standard benchmarks no longer enable high-overhead CPython allocation tracing unless explicitly
  requested
- delivery receipts distinguish disabled, recorded and failed audit writes
- audit metadata and recipe reason codes now enforce their documented bounded machine format
- audit summaries and recipe health use one consistent SQLite read snapshot
- database connectors cache their immutable reflected table instead of reflecting it before every
  record write
- automatic mapping now requires compatible declared types and field roles, except for verified
  natural-key to foreign-key lookup paths
- automatic mapping treats nullable-to-required routes and every sensitivity-label change as
  review-required or blocking
- mapping reports separate unsafe automatic failures from lower-risk review suggestion mismatches
- benchmark manifests require unique cases, strict fields, complete labels and executable matcher
  output contracts
- foreign-key lookup metadata now carries the lookup column type; legacy untyped keys stay
  reviewable but cannot justify automatic promotion
- destination preflight and runtime use the same non-coercing value contract
- JSON destinations count Python tuple arrays, reject non-string object keys and non-JSON values,
  and revalidate combined old plus new output before replacement

### Fixed

- SQLite trigger-based short writes now roll back instead of being reported as a committed batch
- uncertain batch commits cannot be replayed through a weaker scalar idempotency contract
- failed workflow batches now report exact durable progress and a valid stage reason code

- the hard input-record budget remains enforced when a smaller diagnostic preflight sample is used
- strict JSON identification rejects CPython's non-standard `NaN`, `Infinity` and `-Infinity`
  constants instead of labeling them RFC 8259 JSON
- transient Windows replacement sharing violations receive a bounded retry while the cooperative
  writer lock remains held
- lock files are published only after their lock byte is durable, and a failed temporary-file
  cleanup after successful hard-link publication is no longer reported as an uncommitted write
- JSON destination byte limits include the final newline, and pre-write iterator or value failures
  are classified as definitely not committed
- a source-volume blast-radius stop degrades a reused recipe without counting as a semantic recipe
  rejection
- canonical X25519 recipient key IDs now collapse equivalent RFC 7748 encodings, and protocol-v2
  contexts reject recipient key IDs instead of silently carrying version-incompatible metadata
- current Magika score handling no longer touches its removed legacy fallback field or pollutes
  standard error during valid inspection
- a compatible Magika JSON report no longer rejects a large bounded JSON-like probe as a
  classifier conflict
- audit verification and export no longer create a missing database and report it as a valid empty
  log
- workflow verification checks every destination value without assuming relay delivery order,
  reports post-commit audit failures truthfully and strips local paths and PID from standard JSON
- concurrent legacy Relay and Ledger schema upgrades are serialized instead of racing duplicate
  column changes
- composite foreign keys and composite primary-key members are no longer advertised as executable
  single-column lookups
- partial or filtered unique indexes and expression indexes are no longer advertised as executable
  relationship lookup keys
- non-null business keys that resolve to null, wrong-typed resolver results and source transforms
  that produce null for required targets now fail before a destination write
- per-record foreign-key inputs are checked against the selected lookup-column type before a
  database can apply implicit comparison coercion
- operational event health rejects duplicate event IDs, invalid event semantics and oversized
  newline-free records without unbounded reads
- operational event health rejects incomplete workflow counters, unknown stage components, deeply
  nested JSON and out-of-range timestamps instead of weakening health checks
- inspect and mapping benchmark reports no longer persist an unstable local process id

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
