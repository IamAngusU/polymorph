<p align="center">
  <img src="https://raw.githubusercontent.com/IamAngusU/polymorph/main/docs/assets/brand-mark.webp" width="116" alt="Polymorph mark">
</p>

# Polymorph

Polymorph is a local-first, policy-driven data bridge for moving data between structurally different systems without turning a central orchestration service into a universal plaintext trust point.

It is built around one reliability rule: **uncertainty must reduce automation, never increase guessing**. File names, extensions, model scores, old recipes and successful parser calls are evidence, not authority. Automatic promotion requires independently strong deterministic evidence, an immutable validated plan and a complete no-write preflight.

Stable protocol and persisted-state namespaces are intentionally decoupled from the product name so a later rename does not invalidate encrypted envelopes, delivery state or recipe history.

## v0.4 alpha hardening

- Content-first file inspection. Parser selection does not trust the extension or display name.
- A fail-closed parser-worker foundation can run content inspection against an exact-byte snapshot.
  Non-setid Linux Bubblewrap 0.12.0 or newer is the strict backend; a normal Windows child process
  is reported only as process separation. Structured schema and record parsers are not claimed as
  isolated yet.
- Opened-handle identity binding for CSV, JSON and Excel closes ordinary path-swap gaps between
  inspection and parsing. This is not a claim of hostile-code process isolation.
- ZIP/OOXML central-directory checks for traversal, symlinks, duplicate or encrypted members, suspicious expansion, oversized members, macros and external workbook links and data connections before a workbook parser is opened.
- GZIP members are validated with bounded streaming and member-count limits. JSON and XML have
  explicit parse, depth, item, element and per-tag attribute budgets before expensive parser work.
- Optional local Magika evidence. A high-confidence conflict between independent detectors blocks automatic parser selection rather than picking a favorite.
- Excel parsing requires XML hardening through `defusedxml`, then performs layout discovery for title rows, moved columns, repeated headers and fixed-width identifiers such as `000042`.
- Spreadsheet formulas are detected separately. Cached formula results are treated as freshness-unproven and prevent automatic recipe promotion.
- CSV dialect selection uses a deterministic candidate ensemble and can optionally include CleverCSV. A close tie is rejected instead of guessed.
- Deterministic schema matching remains the automatic authority. Optional local embeddings and a multilingual cross-encoder reranker can improve candidate order, but neither can independently authorize a write mapping.
- One-command `prepare` flow for content inspection, mapping, recipe reuse and full no-write preflight.
- Versioned local recipes. A recipe is reusable memory, not permission: it is structurally matched, rebound to the current exact schemas, assigned a new plan digest and validated again before use.
- Metadata-only recipe outcomes drive a conservative reuse circuit. Repeated rejected runs suspend
  the old recipe and fall back to fresh mapping instead of silently changing it.
- Full-scan preflight exercises source transforms and optional read-only foreign-key resolution without destination writes. Sampled scans can inform review but cannot auto-promote a recipe.
- Opt-in resource benchmarks and labelled mapping-corpus evaluation. Normal runs do not enable tracing or RSS polling.
- Full-record blind transport using X25519, HKDF-SHA256 and ChaCha20-Poly1305.
- Ed25519 source authentication bound to tenant and connector identity, including finite rotation
  drain and hard revocation.
- Destination recipient keys are accepted from a separately pinned Ed25519 destination identity,
  not from control-plane claims alone. Signed, route-bound certificates form a monotonic rotation
  chain, and an optional local checkpoint rejects stale generations and competing forks.
- Durable source outbox that persists exact signed ciphertext for safe retry after a lost
  acknowledgement.
- Ciphertext-only relay queue with fenced leases, durable idempotency ledger, sealed quarantine
  and explicit unknown-write-outcome handling.
- Capability-gated atomic destination batches keep the same per-record authentication, ledger,
  audit and replay evidence while collapsing safe SQLite and PostgreSQL writes into one
  transaction. Count and sealed-wire budgets bound every internal batch.
- Destination runtime pinned to one exact plan and target contract, with final field, required,
  nullability and type checks before a connector write.
- CSV exports reject spreadsheet formula-like values by default. HTTP redirects never count as a
  committed write.
- Ed25519-signed capabilities and a hash-chained metadata-only audit log.
- Reason-code explanations plus verified audit and recipe-health summaries for operator diagnosis.
- Credential references and encrypted destination recipient key files.

## Trust model

```text
              schema + policy + exact plan
                         |
                         v
                 +---------------+
                 | control plane |
                 +---------------+
                         |
                    plan digest
                         |
      source trust      |                 destination trust
         boundary       |                    boundary
            |           |                       |
            v           |                       v
     +--------------+   |              +------------------+
     | source agent |   |              | destination agent|
     +--------------+   |              +------------------+
       | plaintext       |                    ^ plaintext
       | local transforms|                    | FK lookup
       v                 |                    |
    seal to destination public key            |
       |                                      |
       v                                      |
    +--------------------------------------------------+
    |        ciphertext-only relay / data plane        |
    | route metadata, leases, digests, no private key  |
    +--------------------------------------------------+
```

The relay still sees the metadata required to route a record. Payload confidentiality is not traffic-analysis resistance. The source and destination endpoints necessarily see plaintext at their respective trust boundaries.

The destination identity public key must reach the source through an operator-controlled channel
that is independent of the control plane. The control plane may distribute signed recipient-key
certificates, but cannot replace their tenant, destination, key, validity or rotation metadata.
See [recipient key authenticity and rotation](https://github.com/IamAngusU/polymorph/blob/main/docs/RECIPIENT_KEY_ROTATION.md).

## Fast path

Python 3.11 through 3.14 is exercised in CI. For a development checkout with the core development
checks and the deterministic model-free path:

```bash
git clone https://github.com/IamAngusU/polymorph.git
cd polymorph
python scripts/bootstrap.py
python scripts/dev.py doctor
```

The fully durable, signed and audited local transport moved 1,000 five-field records at a median
52.41 records/s with a SQLite destination and 85.42 MiB median peak RSS. Treat those as local
measurements, not cross-platform guarantees. Optional research models are not needed for the core:

```bash
python scripts/bootstrap.py --skip-models
```

See [Development setup](https://github.com/IamAngusU/polymorph/blob/main/docs/DEVELOPMENT.md) for the deliberately local data layout. The software
is source-available under a noncommercial license, not OSI Open Source. Check the license before
using it inside a commercial organization.

`python examples.py` runs a tiny deterministic mapping example without models or external services.

Create source and target schemas as usual, or let `prepare` inspect a supported file directly. The easiest safe workflow is:

```bash
polymorph inspect db 'sqlite:///target.sqlite' --table orders -o target.schema.json
polymorph prepare ./incoming-file target.schema.json --output-plan orders.plan.json --remember \
  --max-input-records 5000
```

`prepare` performs content detection, schema inspection, recipe lookup, fresh mapping when needed and a full no-write preflight. A plan is only written when the route is promotable. If the evidence is insufficient, the command exits as review-required instead of manufacturing confidence. `--max-input-records` is a hard per-run blast-radius budget: the first record above it blocks readiness instead of turning an unexpectedly large source into an approved plan.

For a foreign-key route, add a read-only destination resolver so preflight can prove the natural-key lookup before promotion:

```bash
polymorph prepare ./orders-upload target.schema.json --resolver-db-url 'sqlite:///target.sqlite' --resolver-db-table orders
```

## Manual plan workflow

```bash
polymorph inspect auto ./upload.bin -o source.schema.json
polymorph map source.schema.json target.schema.json
polymorph plan create source.schema.json target.schema.json -o route.plan.json
polymorph plan validate route.plan.json source.schema.json target.schema.json
polymorph preflight ./upload.bin target.schema.json route.plan.json
```

Review-level decisions are not inserted into a plan by default. `--allow-review` exists for an explicit operator decision, not as a way to make the matcher more permissive.

## Optional research model profiles

The core is fully functional without a model. The CPU descriptor encoder is local-only at runtime,
pinned to an upstream revision and hash-verified during installation. The native SentencePiece
tokenizer avoids loading the much larger JSON vocabulary representation.

```bash
pip install -e ".[semantic]"
polymorph model install --profile multilingual-cpu
```

After explicit installation, `--models` enables the encoder without repeating its path:

```bash
polymorph prepare ./incoming-file target.schema.json --models
```

Both current profiles are research-only for product use. The encoder's English teacher used
`msmarco-triplets`; the reranker documents mMARCO/MS MARCO directly. Their weight cards say
Apache-2.0, while the underlying MS MARCO dataset terms say noncommercial research. The standard
bootstrap therefore downloads neither model. After reviewing the provenance, a lab can install
them explicitly with `--include-research-encoder` or `--include-research-reranker`. See the model
profile document before using either in a commercial path.

Models receive schema descriptors, not record payload values. Their evidence can improve ranking and reduce review work, but automatic promotion still requires an independently strong deterministic mapping.

See [Model profiles](https://github.com/IamAngusU/polymorph/blob/main/docs/MODEL_PROFILE.md).

## File trust and benchmarks

```bash
pip install -e ".[fileid,csv-detection,benchmark]"
polymorph inspect auto ./unknown-upload --magika
# Strict Linux boundary. Fails closed when compatible Bubblewrap is unavailable.
polymorph inspect isolated-content ./unknown-upload
polymorph doctor
polymorph benchmark inspect ./unknown-upload --records 10000 --magika
polymorph benchmark parser-worker ./unknown-upload --runs 5
polymorph benchmark mapping ./benchmarks/safety-regression.json --require-auto-precision 1.0 --require-automation-coverage 0.70
polymorph benchmark workflow --records 1000 --batch-size 100 --work-dir ./workflow-run --output workflow.json
polymorph recipe health
polymorph audit summary ./audit.sqlite
polymorph events check ./workflow-run/operational-events.jsonl --run-id RUN_ID
polymorph explain write_outcome_unknown
```

`RUN_ID` is the `workflow.observability.run_id` value in `workflow.json`.
If the workflow used an event budget above 64 MiB, pass the same
`--event-stream-max-mib` value to `events summary` or `events check`.
On Windows, trusted local files can be measured with
`--backend process --require-containment process`. That is process separation only, not a
filesystem or network sandbox.

The benchmark commands are explicit diagnostics. Production code paths do not start Python allocation tracing or memory polling.

## Documentation

- [Architecture](https://github.com/IamAngusU/polymorph/blob/main/docs/ARCHITECTURE.md)
- [Reliability model](https://github.com/IamAngusU/polymorph/blob/main/docs/RELIABILITY.md)
- [File trust gate](https://github.com/IamAngusU/polymorph/blob/main/docs/FILE_TRUST.md)
- [Parser isolation](https://github.com/IamAngusU/polymorph/blob/main/docs/PARSER_ISOLATION.md)
- [Recipes](https://github.com/IamAngusU/polymorph/blob/main/docs/RECIPES.md)
- [Benchmarking](https://github.com/IamAngusU/polymorph/blob/main/docs/BENCHMARKING.md)
- [Workflow and failure lab](https://github.com/IamAngusU/polymorph/blob/main/docs/WORKFLOW_LAB.md)
- [Measured performance baseline](https://github.com/IamAngusU/polymorph/blob/main/docs/PERFORMANCE_BASELINE.md)
- [Protocol](https://github.com/IamAngusU/polymorph/blob/main/docs/PROTOCOL.md)
- [Threat model](https://github.com/IamAngusU/polymorph/blob/main/docs/THREAT_MODEL.md)
- [Operations and replay safety](https://github.com/IamAngusU/polymorph/blob/main/docs/OPERATIONS.md)
- [Operational visibility](https://github.com/IamAngusU/polymorph/blob/main/docs/OBSERVABILITY.md)
- [Ecosystem and dataset review](https://github.com/IamAngusU/polymorph/blob/main/docs/ECOSYSTEM_REVIEW.md)
- [Security reporting](https://github.com/IamAngusU/polymorph/blob/main/SECURITY.md)
- [Roadmap](https://github.com/IamAngusU/polymorph/blob/main/docs/ROADMAP.md)
- [Product direction](https://github.com/IamAngusU/polymorph/blob/main/docs/PRODUCT.md)
- [Operator workflows](https://github.com/IamAngusU/polymorph/blob/main/docs/WORKFLOWS.md)
- [Test strategy](https://github.com/IamAngusU/polymorph/blob/main/docs/TEST_STRATEGY.md)

## Status

Polymorph remains an alpha. Inspection, mapping, planning and preflight are available through the
CLI. Source transport, relay and destination delivery are tested Python APIs; long-running agent
services, an authenticated control channel and a deployment supervisor are still roadmap work.

Strict Linux containment is available for the content-inspection stage when Bubblewrap is usable.
Structured schema parsing and record iteration are not isolated yet. There is also no durable
trust-bundle distribution, cumulative per-tenant queue quota or external audit checkpoint against
log-suffix truncation. Raw database URLs can leak credentials through shell history, so production
automation should use `DatabaseEndpoint` plus a secret provider. Automatic-promotion policy still
needs a large, source-separated adversarial corpus and independent security review.

The alpha is not fully self-monitoring. The benchmark and destination runtime now write a local
payload-free event stream with run and correlation IDs, plus a CLI health gate for lifecycle,
event-ID uniqueness, event semantics and delivery-count agreement. Coverage outside that workflow
is incomplete, destination audit remains optional, and there is no notification service or queue
metric exporter. Recipe health is a real closed safety loop, but its only automatic response is to
reduce trust after repeated rejected runs.

## License

Polymorph is source-available under the **PolyForm Noncommercial License 1.0.0**, not OSI Open
Source. Permitted use is defined by the license itself. Commercial use requires a separate license
from Angus Uelsmann.

Paid commercial terms, including any revenue participation or white-label rights, are agreed in a
separate written agreement. See [commercial licensing](https://github.com/IamAngusU/polymorph/blob/main/COMMERCIAL.md).

Required notices reference [angusu.de](https://angusu.de) and this repository. Third-party components retain their own licenses; see [THIRD_PARTY.md](https://github.com/IamAngusU/polymorph/blob/main/THIRD_PARTY.md).
