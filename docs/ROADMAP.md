# Roadmap

## v0.1 foundation

- typed schema descriptors and fingerprints
- deterministic and optional local semantic matching
- information-flow policy engine
- opaque field transport
- Excel, JSON/JSON5, database and constrained HTTP destinations

## v0.2 blind delivery runtime

- full-record opaque transport
- authenticated plan digests and protocol limits
- ciphertext-only relay queue with leases
- delivery ledger, sealed quarantine and replay safety
- signed capabilities and tamper-evident audit
- natural-key to foreign-key resolution through unique constraints
- adaptive Excel layout discovery and conservative drift repair
- CSV and paginated HTTP JSON sources
- encrypted recipient key files and credential references
- atomic local file writes
- pinned optional descriptor encoder

## v0.3 reliability gate

- content-first file trust gate independent of filename/extension
- archive traversal, expansion, macro and external-link checks
- optional Magika classifier evidence
- CSV dialect candidate ensemble with optional CleverCSV
- optional multilingual cross-encoder reranker
- deterministic-only automatic-approval authority
- complete no-write preflight before automatic promotion
- recipe memory with exact rebind and revalidation
- formula-cache uncertainty detection
- one-command `prepare` workflow
- opt-in file resource benchmarks
- labelled mapping-corpus precision/coverage benchmark

## v0.4 deployable agents

- long-running source, relay and destination services
- mutually authenticated agent control channel
- durable authenticated distribution of public-key registration, rotation and revocation state
- external checkpoints or hardware counters for recipient trust-state rollback detection
- destination identity-key rotation and emergency recipient-key revocation ceremonies
- OS/HSM-backed key-provider interfaces
- extend the exact-snapshot content worker to schema parsing and bounded record streaming
- connector-account least-privilege policy checks
- metadata-only recipe outcome health with conservative suspension after repeated rejected runs
- verified audit summaries and stable reason-code explanations
- backpressure, health/readiness and metrics without payload labels
- complete source-to-relay-to-destination operational journal and alerts
- optional distributed relay backend after SQLite/spool benchmarks establish the need

## v0.5 contract ingestion

- OpenAPI 3.1 ingestion
- request/response schema graph
- OpenAPI-ingested and independently verified API idempotency and retry contracts
- bounded rate-limit handling
- richer nested JSON path mapping
- XML and document-format adapters behind parser containment
- Parquet/Arrow high-throughput adapter
- scanned/image table extraction as an optional specialist path

## v0.6 adaptive operations

- signed plan promotion workflow
- tenant-scoped recipe approval history
- safe staged schema-drift rollout
- destination-native validation adapters where a true no-side-effect validation API exists
- benchmark-derived thresholds per connector/domain
- optional high-precision specialist model profile if it beats the CPU-first stack on the project corpus

## Evidence and adoption gates

These gates span versions and prevent feature count from replacing product usefulness:

- clean-machine five-minute proof on Windows, Linux and macOS
- source-, template- and time-separated public or customer-like holdout corpora
- zero unsafe automatic decisions on every declared release corpus
- operator studies for review time, abstention usefulness and recovery success
- PostgreSQL and Parquet end-to-end evidence before broad connector claims
- stable longitudinal JSON for correctness, latency, throughput, peak RSS and accelerator memory
- public release evidence that includes machine, corpus, timestamp and limitations
- local-first defaults with no telemetry, model activation or cloud workflow side effects

See [`WORLD_READINESS.md`](WORLD_READINESS.md) for the product thesis and measurement priorities.
