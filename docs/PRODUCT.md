# Product direction

## The useful version of this product

Another AI column mapper is not a product. It is a feature and several vendors already have it.

Polymorph earns its place if it becomes the local-first trust layer between systems that were
never designed to agree with each other. It should move sensitive data while refusing to trust a
filename, parser, model score, remembered mapping, relay, retry or stale formula cache by default.

The short version:

> Move data between incompatible systems. Prove the route before writing. Keep plaintext at the
> endpoints. Stop cleanly when the evidence is not good enough.

## Who it is for

Initial users should be developers and technical operators with recurring imports that are too
important for a hopeful script and too awkward for a large integration platform:

- agencies moving customer exports into several client systems
- small operations teams importing Excel, CSV and API data into an ERP or database
- security-conscious teams that cannot send payloads to a hosted mapping service
- software vendors that need a self-hosted ingestion edge for customer data
- regulated teams that need a reviewable plan and an honest record of uncertain writes

The first wedge is not every connector. It is boring recurring imports where a wrong identifier,
amount, credential or foreign key is expensive.

## Product promises

1. **No blind trust.** Every signal has an explicit authority level.
2. **Plaintext stays at the endpoints.** The relay only receives ciphertext and routing metadata.
3. **AUTO means proven inside a declared operating domain.** Unknown means review, not optimism.
4. **Retries do not pretend external side effects are knowable.** Ambiguous commits remain
   ambiguous until reconciled.
5. **Memory accelerates proof.** A recipe never replaces current validation.
6. **Local is the default deployment.** Distributed infrastructure is optional and must justify
   its operational cost with measurements.

## Accuracy that is not marketing sludge

The target is 100 percent observed precision for decisions released as `AUTO` on a source-,
template- and time-separated holdout corpus. That is not a promise of 100 percent automation.

The benchmark must publish at least:

- AUTO precision
- automation coverage
- review rate
- blocked rate
- unsafe AUTO count
- mapping accuracy among suggestions
- preflight rejection reasons
- post-write reconciliation failures
- latency and peak memory, only in explicit benchmark mode

An ambiguous date such as `03/04/26` does not contain enough information to infer locale. A correct
system asks or abstains. It does not invent certainty with a larger model.

## Modes

### Conservative

The default. Native parsers, deterministic constraints, content inspection, optional MiniLM
candidate retrieval, a durable local SQLite store and complete preflight. The reranker runs only for close top-k
candidates. A model cannot authorize a write.

### Precision

Opt-in. Independent parser quorum for formats where two mature parsers exist, stricter profiling,
document extraction workers and additional diagnostics. Parsed PDF or OCR tables remain review-only
until a domain corpus proves otherwise.

### Lab

Heavy model challengers, experimental parsers and threshold studies. Nothing graduates from this
mode unless it improves coverage on the held-out corpus without adding an unsafe AUTO decision.

## High-value differentiators

### Proof-carrying recipes

A promoted recipe should carry the evidence that justified it: exact schema fingerprints, plan
digest, preflight attestation, parser identity and version, model profile hashes, policy version,
corpus calibration version and operator signature where applicable. The next run verifies and
rebinds that evidence instead of trusting a row in a history table.

### Reconciliation as a first-class stage

Preflight proves that a write is reasonable. Reconciliation checks that the destination actually
contains the intended result. Connectors should expose read-back proofs where the destination can do
so safely. A successful HTTP status is not the same as a verified business result.

### Source-authenticated blind transport

Encryption to the destination does not prove who created a record. Protocol v3 therefore gives
source agents signed identities with tenant and connector scope, finite rotation drain and hard
revocation. Relay and destination reject unsigned or revoked producers by default. Durable trust
bundle distribution remains part of the deployable-agent work.

### Parser quorum

For a precision profile, a second parser may inspect the same bounded workbook inside a
crash-isolated worker. Sheet names, dimensions, headers, types and normalized values must agree
before it adds confidence. Disagreement reduces automation. Current Calamine releases have open
process-aborting allocation bugs, so they are not eligible for in-process use. See the
[ecosystem review](https://github.com/IamAngusU/polymorph/blob/main/docs/ECOSYSTEM_REVIEW.md).

### Failure-aware automation budget

Repeated failures should spend trust, not trigger increasingly creative guesses. Recipe health now
suspends automatic reuse after consecutive rejected runs. The same pattern can later govern parser
packs, connectors and model profiles with explicit half-open probes and operator-visible recovery.

### Reproducible file lab

A manifest-driven local lab should replay valid, malformed, polyglot and resource-hostile fixtures
against every parser version. It records hashes, decisions, disagreements, exit codes, timeouts,
latency and peak RSS. This makes parser upgrades evidence-backed instead of a dependency bot gamble.

### Business glossary and units

Users need a small, versioned glossary for terms such as `Debitor`, `Mandant`, `net`, `gross`, VAT,
currencies and units. Unit and currency compatibility should become hard constraints, not embedding
hints. This will improve real accuracy more than adding a fashionable general model.

### Explainable abstention

Every review or block needs a compact reason and the smallest next action: choose a locale, approve
a relation, confirm a unit, install an isolated parser pack or fix a target constraint. Good refusal
is part of the UX.

## Site inventory, without designing a UI yet

The first public site can remain documentation-first:

- landing page with the trust model and one end-to-end terminal example
- "Why not another ETL" comparison with hosted mappers, scripts and classic pipelines
- security model, threat model and explicit non-guarantees
- supported sources, destinations and containment grades
- model and parser registry with versions, licenses, hashes and authority levels
- benchmark dashboard generated from checked-in result files
- recipes and protocol documentation
- five-minute local setup
- deployment profiles for laptop, single server and later distributed agents
- roadmap and maturity status
- commercial licensing page

No dashboard is needed before the CLI workflows are coherent. A thin read-only status surface may
be useful later for health, queue depth, review work and reconciliation state.

## Deliberate non-goals for now

- a generic workflow canvas
- hundreds of shallow connectors
- hosted plaintext ingestion
- automatic execution of generated code
- generative models in the default runtime
- Redis merely because queues are fashionable
- claiming exactly-once delivery across systems that do not expose idempotency or reconciliation

## Infrastructure choice

SQLite and the sealed spool remain the single-host default. Polymorph enables WAL only when the
linked SQLite runtime contains the upstream WAL-reset race fix, and otherwise selects the rollback
journal. This keeps correctness ahead of a concurrency benchmark while remaining inspectable and
simple to operate.

For real multi-node agents, benchmark a broker interface with NATS JetStream first and Valkey
Streams second. The delivery ledger remains mandatory because no broker can prove whether an
external database or HTTP service committed before its acknowledgement disappeared.
