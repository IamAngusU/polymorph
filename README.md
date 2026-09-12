<p align="center">
  <img src="https://raw.githubusercontent.com/IamAngusU/polymorph/main/docs/assets/brand-mark.webp" width="116" alt="Polymorph mark">
</p>

<p align="center">
  <strong>English</strong> · <a href="README.de.md">Deutsch</a>
</p>

<h1 align="center">Polymorph</h1>

<p align="center">
  <strong>Move data between incompatible systems. Prove the route before writing.<br>Keep plaintext at the endpoints. Stop cleanly when the evidence is not good enough.</strong>
</p>

<p align="center">
  <a href="docs/PERFORMANCE_BASELINE.md#file-inspection"><img src="docs/assets/badges/fixture-rows.svg" height="42" alt="50k-row file fixtures"></a>
  <a href="#measured-local-baseline"><img src="docs/assets/badges/workflow.svg" height="42" alt="1,000-record secure workflow baseline"></a>
  <a href="#measured-local-baseline"><img src="docs/assets/badges/throughput.svg" height="42" alt="375.83 records per second median local throughput"></a>
  <a href="#optional-model-evidence"><img src="docs/assets/badges/auto-precision.svg" height="42" alt="17 of 17 observed automatic decisions correct"></a>
</p>

<p align="center"><sub>Measured baselines, not universal promises. Click a metric for context.</sub></p>
<p align="center"><sub>Open source under AGPL-3.0-only · alternative commercial licensing available.</sub></p>

Polymorph is a local-first, policy-driven data bridge for recurring imports and integrations that are too important for a hopeful script and too awkward for a large integration platform.

System A calls a field `customer_no`. System B expects `account_id`. Then someone moves a spreadsheet column, renames a header, adds a formula, changes a foreign-key contract or sends the same report with a different layout.

The traditional solution is often some variation of "map it once and hope nobody touches anything".

Polymorph has trust issues instead.

Its core reliability rule is simple:

**Uncertainty must reduce automation, never increase guessing.**

A filename is evidence. A successful parser call is evidence. A model score is evidence. A recipe that worked yesterday is evidence.

Yesterday was also a different day.

Automatic promotion requires independently strong deterministic evidence, an immutable validated plan and a complete no-write preflight. If the system cannot prove a route inside its declared operating domain, it asks for review instead of manufacturing confidence.

Stable protocol and persisted-state namespaces are intentionally decoupled from the product name so a later rename does not invalidate encrypted envelopes, delivery state or recipe history. Branding is allowed to have a midlife crisis. Persisted cryptographic state is not.

## Start here

| I want to... | Start with | What happens |
| --- | --- | --- |
| **Try Polymorph locally** | `python scripts/dev.py demo --open` | Builds a self-contained synthetic HTML walkthrough. No account, network, model or destination write. |
| **Embed Polymorph** | [`docs/PRODUCT_API.md`](docs/PRODUCT_API.md) | Use the explicit `move(...).prepare()` then `execute()` API, product events and structured outcomes. |
| **Evaluate the security model** | [`SECURITY.md`](SECURITY.md) | Review trust boundaries, honest limitations, failure semantics and hardening status before deployment. |

Connector authors can start at [`docs/CONNECTORS.md`](docs/CONNECTORS.md). Installed third-party
connector code is never discovered or imported unless the host explicitly opts in.

## Why Polymorph exists

Another AI column mapper is not much of a product. It is a feature, and several vendors already have one.

Polymorph is intended to be the trust layer between systems that were never designed to agree with each other.

The useful version does four things well:

1. **Understand the source conservatively.** Inspect bytes, structure, schema, relationships and policy before trusting labels.
2. **Prove the route before writing.** Mapping, transforms and foreign-key resolution are validated against one exact plan.
3. **Keep plaintext at the endpoints.** The relay receives ciphertext and routing metadata, not the payload values it transports.
4. **Fail in boring ways.** Ambiguous mappings require review. Unknown write outcomes remain unknown. Retries do not become optimism with a loop around them.

Initial users are developers and technical operators with recurring imports where a wrong identifier, amount, credential or foreign key is expensive:

- agencies moving customer exports into several client systems
- small operations teams importing Excel, CSV and API data into an ERP or database
- security-conscious teams that cannot send payloads to a hosted mapping service
- software vendors that need a self-hosted ingestion edge for customer data
- regulated teams that need a reviewable plan and an honest record of uncertain writes

## Evidence is not authority

Polymorph deliberately separates useful signals from signals that may authorize automation.

| Signal | Useful? | Can authorize a write by itself? |
| --- | --- | --- |
| File extension or display name | Yes | No |
| Successful parser call | Yes | No |
| Magika classification | Yes | No |
| Old recipe | Yes | No |
| Embedding similarity | Yes | No |
| Cross-encoder score | Yes | No |
| Current schema, policy and deterministic contract evidence | Yes | Yes, when all gates pass |

**Useful is not authority.**

A model may improve candidate ordering. It does not get a pen.

If a high-confidence model result disagrees with the independently strongest deterministic target, the mapping is review-required. A larger number after the decimal point is not a new trust boundary.

## What v0.4 alpha already does

### Input trust

- Content-first file inspection. Parser selection does not trust the extension or display name.
- Opened-handle identity binding for CSV, JSON and Excel closes ordinary path-swap gaps between inspection and parsing.
- ZIP and OOXML central-directory checks reject traversal, symlinks, duplicate or encrypted members, suspicious expansion, oversized members, macros and external workbook links or data connections before a workbook parser is opened.
- GZIP members are validated with bounded streaming and member-count limits.
- JSON and XML have explicit parse, depth, item, element and per-tag attribute budgets before expensive parser work.
- Optional local Magika evidence can challenge deterministic detection. A strong conflict blocks automatic parser selection rather than starting a confidence popularity contest.
- A fail-closed parser-worker foundation can inspect an exact-byte snapshot. Non-setid Linux Bubblewrap 0.12.0 or newer is the strict backend. On Windows, the worker enters a Job Object for CPU, memory and process-tree containment. That is resource containment, not filesystem or network sandboxing.
- Excel parsing requires XML hardening through `defusedxml`, then performs layout discovery for title rows, moved columns, repeated headers and fixed-width identifiers such as `000042`.
- Spreadsheet formulas are detected separately. Cached formula results have unproven freshness and therefore block automatic recipe promotion.
- CSV dialect selection uses a deterministic candidate ensemble and may include CleverCSV. A close tie is rejected instead of guessed. Revolutionary, apparently.

### Mapping and preflight

- Deterministic schema matching is the automatic authority.
- Matching uses names, aliases, declared types, nullability, sensitivity, field roles and verified relationship evidence.
- Optional local embeddings and a multilingual cross-encoder reranker may improve candidate order, but neither may independently authorize a mapping.
- Target collisions, directional type problems, sensitivity conflicts and weak relationship proof demote or block automation even when a score looks impressive.
- Versioned recipes store reusable memory, not permission. Every reuse is rebound to current exact schemas, receives a new plan digest, is validated again and must pass preflight again.
- Repeated rejected recipe runs reduce trust and suspend automatic reuse instead of making the matcher increasingly creative.
- `prepare` combines content inspection, mapping, recipe reuse and a complete no-write preflight.
- Full-scan preflight exercises source transforms and optional read-only foreign-key resolution without destination writes.
- Sampled scans are diagnostic only. They cannot auto-promote a recipe.
- `--max-input-records` is a hard per-run blast-radius budget. The first record above the limit blocks readiness instead of silently approving a source that grew by two orders of magnitude over lunch.

### Blind transport and delivery

- Full-record blind transport uses X25519, HKDF-SHA256 and ChaCha20-Poly1305.
- Source records are authenticated with Ed25519 identities bound to tenant and connector scope, including finite rotation drain and hard revocation.
- Destination recipient keys come from separately pinned Ed25519 destination identities, not from control-plane claims alone.
- Signed route-bound recipient certificates form a monotonic rotation chain. An optional local checkpoint rejects stale generations and competing forks.
- A durable source outbox persists the exact signed ciphertext used for the first send. Lost acknowledgement? Retry those exact bytes. Resealing the same logical record produces different authenticated ciphertext, because cryptography is not obligated to cooperate with a convenient retry implementation.
- The relay queue stores ciphertext plus required routing metadata, uses fenced leases and keeps a durable idempotency ledger.
- Destination delivery distinguishes proven `NOT_COMMITTED` writes from `UNKNOWN` outcomes. Unknown does not become retry-safe because an exception looked apologetic.
- Capability-gated atomic destination batches preserve per-record authentication, ledger, audit and replay evidence while using one transaction for supported SQLite and PostgreSQL writes.
- Every batch is bounded by record count and sealed-wire size.
- The destination runtime is pinned to one exact plan and target contract, then rechecks field set, required values, nullability and types before crossing the connector write boundary.
- CSV exports reject spreadsheet formula-like values by default.
- HTTP redirects never count as a committed write.

### Operations and diagnosis

- Ed25519-signed capabilities scope privileged operations.
- Metadata-only audit events form a SHA-256 hash chain and may additionally be signed.
- Reason-code explanations expose why something was blocked or demoted.
- Recipe-health summaries make repeated rejection visible.
- Payload-free operational events carry run and correlation IDs for the currently instrumented workflow.
- Credential references and encrypted destination recipient key files avoid pretending raw connection strings are a secret-management strategy.

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

The relay still sees metadata required to route a record, including tenant, connector IDs, record and transfer IDs, plan digest and field IDs. Payload confidentiality is not traffic-analysis resistance. Source and destination endpoints necessarily see plaintext at their respective trust boundaries.

The destination identity public key must reach the source through an operator-controlled channel independent of the control plane. The control plane may distribute signed recipient-key certificates, but it cannot replace their tenant, destination, key, validity or rotation metadata.

See [recipient key authenticity and rotation](docs/RECIPIENT_KEY_ROTATION.md).

## Quick start

Python 3.11 through 3.14 is exercised in CI.

Clone the repository or use GitHub's **Code > Download ZIP** and extract it. Polymorph uses no Git
submodules or Git LFS assets. The shortest model-free local setup is the same on either path:

```bash
git clone https://github.com/IamAngusU/polymorph.git
cd polymorph
python scripts/bootstrap.py --skip-checks
python scripts/dev.py doctor
python scripts/dev.py connectors
python scripts/dev.py demo --open
python examples.py
```

When using the ZIP, start with `cd` in the extracted `polymorph-main` directory and run the final
three commands. The bootstrap creates `.venv`, installs the local checkout and ends with `doctor`;
manual virtual-environment activation is not required. Run `python scripts/bootstrap.py` without
`--skip-checks` when you also want the complete development test suite.

Optional research models are not required for the core:

```bash
python scripts/bootstrap.py --skip-models
```

`python examples.py` runs a tiny deterministic mapping example without models or external services.

See [Development setup](docs/DEVELOPMENT.md) for the deliberately local data layout.

## Embed in an application

The convenience API remains deliberately two-phase. Creating and preparing a session never writes:

```python
from polymorph import ConnectorSpec, move

run = move(
    source="./incoming/customers.csv",
    destination=ConnectorSpec.destination(
        "database",
        url="sqlite:///application.sqlite",
        table="customers",
    ),
    max_input_records=10_000,
)
run.on("review_required", review_ui.open)
run.on("progress", progress_view.update)

prepared = run.prepare()
if prepared.ready:
    outcome = run.execute()
```

`execute()` is a same-process local convenience path, not the ciphertext-only relay. It currently
requires a content-inspected immutable file source and refuses secret or opaque forwarding. Database,
HTTP and custom sources can still be inspected and prepared; use the separately authorized secure
agent workflow when source snapshot identity or endpoint separation matters. Destinations are always
explicit. Polymorph never guesses a database table or remote resource from a URL.

See [Embedding and product events](docs/PRODUCT_API.md) for review handling, event localization and
every structured outcome.

## The easiest safe workflow

Inspect the destination schema, then let `prepare` inspect the source, find or build a mapping plan and run the complete no-write preflight:

```bash
polymorph inspect db 'sqlite:///target.sqlite' --table orders -o target.schema.json
polymorph prepare ./incoming-file target.schema.json --output-plan orders.plan.json --remember \
  --max-input-records 5000
```

A plan is written only when the route is promotable.

If evidence is insufficient, `prepare` exits as review-required instead of producing a confident-looking JSON file and leaving future-you to discover what it meant.

For a foreign-key route, add a read-only resolver so preflight can prove the natural-key lookup before promotion:

```bash
polymorph prepare ./orders-upload target.schema.json \
  --resolver-db-url 'sqlite:///target.sqlite' \
  --resolver-db-table orders
```

## Manual plan workflow

When you want each stage separately:

```bash
polymorph inspect auto ./upload.bin -o source.schema.json
polymorph map source.schema.json target.schema.json
polymorph plan create source.schema.json target.schema.json -o route.plan.json
polymorph plan validate route.plan.json source.schema.json target.schema.json
polymorph preflight ./upload.bin target.schema.json route.plan.json
```

Review-level decisions are not inserted into a plan by default. `--allow-review` exists for an explicit operator decision, not as a way to ask the matcher to please stop being difficult.

## Optional model evidence

The core is fully functional without a model.

The optional CPU descriptor encoder is local-only at runtime, pinned to an upstream revision and hash-verified during installation. The native SentencePiece tokenizer avoids loading the much larger JSON vocabulary representation.

```bash
pip install -e ".[semantic]"
polymorph model install --profile multilingual-cpu
polymorph prepare ./incoming-file target.schema.json --models
```

Both current model profiles are research-only for product use. Their provenance and dataset terms are documented in [Model profiles](docs/MODEL_PROFILE.md). The standard bootstrap downloads neither model.

Models receive schema descriptors, not record payload values. Their evidence may improve ordering and reduce review work, but automatic promotion still requires independently strong deterministic evidence.

And currently, on the checked-in synthetic regression corpus, the model paths make the same automatic decisions as the deterministic profile.

| Profile | Result | Wall time | Peak RSS |
| --- | --- | ---: | ---: |
| Deterministic | Same decisions | 4.02 ms | 73.30 MiB |
| Encoder | Same decisions | 0.926 s | 284.52 MiB |
| Encoder + reranker | Same decisions | 2.325 s | 437.87 MiB |

The encoder run produced 100% observed automatic precision on 17 of 17 automatic decisions and 89.47% automation coverage among explicitly eligible fields. That is regression evidence on a synthetic corpus, not a claim of universal mapping accuracy.

So yes, the model stack works.

On this corpus it currently converts more electricity into heat without improving the decision set. We keep measuring instead of assigning architectural importance to fan noise.

See [Measured performance baseline](docs/PERFORMANCE_BASELINE.md).

## Diagnostics and benchmarks

```bash
pip install -e ".[fileid,csv-detection,benchmark]"
polymorph inspect auto ./unknown-upload --magika

# Strict Linux boundary. Fails closed when compatible Bubblewrap is unavailable.
polymorph inspect isolated-content ./unknown-upload

polymorph doctor
polymorph benchmark inspect ./unknown-upload --records 10000 --magika
polymorph benchmark parser-worker ./unknown-upload --runs 5
polymorph benchmark mapping ./benchmarks/safety-regression.json \
  --require-auto-precision 1.0 \
  --require-automation-coverage 0.70
polymorph benchmark workflow --records 1000 --batch-size 100 \
  --work-dir ./workflow-run --output workflow.json
polymorph recipe health
polymorph audit summary ./audit.sqlite
polymorph events check ./workflow-run/operational-events.jsonl --run-id RUN_ID
polymorph explain write_outcome_unknown
```

`RUN_ID` is the `workflow.observability.run_id` value in `workflow.json`.

The benchmark commands are explicit diagnostics. Normal production paths do not enable CPython allocation tracing or RSS polling merely so a graph can feel involved.

## Measured local baseline

On 2026-09-12, five fresh-workflow-state runs of the fully durable, signed and audited local
transport moved 1,000 five-field records at **367.99 to 376.81 records/s**, with a median of
**375.83 records/s**, using a SQLite destination and batches of 100. Median measured wall time was
**2.661 s** and median sampled peak RSS was **81.33 MiB** on Windows build 26200, Python 3.11.9 and
an Intel Core i9-12900K.

Each run included recipient-certificate verification, X25519 and ChaCha20-Poly1305 sealing, Ed25519 source signatures, durable source outbox, relay validation and fenced leases, destination authentication and decryption, contract validation, SQLite writes, sealed-spool cleanup, signed hash-chain audit and acknowledgements.

All 1,000 records were delivered once in every retained run. The exact five observations and
measurement metadata are checked in as
[`benchmarks/results/workflow-windows-20260912.json`](benchmarks/results/workflow-windows-20260912.json).

The deterministic workflow benchmark does not load the optional mapping models. A separate
500 ms `nvidia-smi` sample over two of the same runs observed total device memory remain at
2,788 MiB on an RTX 3080 with 10,240 MiB: **0 MiB observed change**. GPU utilization was
device-wide and cannot be attributed to this process. Model benchmarks must report VRAM
separately.

See [Performance baseline](docs/PERFORMANCE_BASELINE.md) for the exact machine, methodology and caveats.

## Ecosystem and operations kit (new in 0.4.0a5)

The new local toolkit closes practical integration gaps without turning evidence into authority:

```powershell
polymorph-kit connector scaffold "Acme CRM" --output .\acme-connector
polymorph-kit quality inspect .\incoming.csv --output .\quality.json
polymorph-kit ui export .\review-ui
polymorph-kit review finalize .\review-draft.json --output .\review.json
polymorph-kit sync inspect .\.polymorph\sync.sqlite3
```

The review component is dependency-free, light-mode, responsive, bilingual, and framework-neutral.
Its drafts contain schema metadata but no rows and carry no write authority. Cleaning plans are
explicit and lazy. OAuth access tokens stay in memory. Recurring cursors advance only after a
structured completed write. See [the ecosystem kit](docs/ECOSYSTEM_KIT.md),
[embedded review UI](docs/REVIEW_UI.md), [recurring runs](docs/RECURRING_RUNS.md), and the
[enterprise readiness facts](docs/ENTERPRISE_READINESS.md).

## Documentation

- [Architecture](docs/ARCHITECTURE.md)
- [Reliability model](docs/RELIABILITY.md)
- [Product direction](docs/PRODUCT.md)
- [File trust gate](docs/FILE_TRUST.md)
- [Parser isolation](docs/PARSER_ISOLATION.md)
- [Recipes](docs/RECIPES.md)
- [Benchmarking](docs/BENCHMARKING.md)
- [Workflow and failure lab](docs/WORKFLOW_LAB.md)
- [Measured performance baseline](docs/PERFORMANCE_BASELINE.md)
- [Protocol](docs/PROTOCOL.md)
- [Threat model](docs/THREAT_MODEL.md)
- [Operations and replay safety](docs/OPERATIONS.md)
- [Operational visibility](docs/OBSERVABILITY.md)
- [Recipient key authenticity and rotation](docs/RECIPIENT_KEY_ROTATION.md)
- [Security coverage](docs/SECURITY_COVERAGE.md)
- [Ecosystem and dataset review](docs/ECOSYSTEM_REVIEW.md)
- [Operator workflows](docs/WORKFLOWS.md)
- [Test strategy](docs/TEST_STRATEGY.md)
- [Roadmap](docs/ROADMAP.md)
- [Security reporting](SECURITY.md)
- [Contributing](CONTRIBUTING.md)
- [Licensing explained](LICENSING.md)
- [Name and logo policy](TRADEMARKS.md)

## Status: alpha means alpha

Polymorph remains an alpha.

Inspection, mapping, planning and preflight are available through the CLI. Source transport, relay and destination delivery are tested Python APIs. Long-running agent services, an authenticated control channel and a deployment supervisor are still roadmap work.

Important current limits:

- Strict Linux containment currently covers the content-inspection worker only.
- Structured schema parsing and record iteration still execute in the local process after the content gate accepts a file.
- Windows workers use Job Object resource containment for CPU, memory and process-tree limits. They still provide no filesystem or network sandboxing.
- There is no durable trust-bundle distribution yet.
- There is no cumulative per-tenant relay queue quota yet.
- There is no external audit checkpoint protecting against log-suffix truncation yet.
- Raw database URLs may leak credentials through shell history. Production automation should use `DatabaseEndpoint` plus a secret provider.
- Automatic-promotion policy still needs a large, source-separated adversarial corpus and independent security review.
- Operational event coverage is incomplete outside the currently instrumented workflow.
- Destination audit remains optional.
- There is no notification service or queue metric exporter yet.

The project documents these limits because "alpha" is a software maturity label, not a decorative badge we remove when the README starts looking expensive.

## License

Polymorph is open source under the **GNU Affero General Public License version 3 only** (`AGPL-3.0-only`).

Commercial use is allowed under the AGPL. If those terms work for your use case, no separate paid license is required. A separate commercial license is available for proprietary or closed-source use and other use cases that need different terms.

**Open source does not mean authorless.** Copyright and license notices remain part of the project, and modified versions must follow the notice and source obligations in the AGPL.

See [LICENSING.md](LICENSING.md) for the human-readable overview, [COMMERCIAL.md](COMMERCIAL.md) for alternative commercial licensing, and [TRADEMARKS.md](TRADEMARKS.md) for the Polymorph name and logo policy.

Copyright 2026 Angus Uelsmann · [angusu.de](https://angusu.de) · [NOTICE](NOTICE)

Third-party components retain their own licenses; see [THIRD_PARTY.md](THIRD_PARTY.md).

## Local acceptance snapshot (2026-09-12)

On an Intel Core i9-12900K with Windows and Python 3.11, the final full Polymorph Run acceptance check measured three integrity-gated 1,000-row workflow samples at 357.75-373.56 records/s (median 373.29), 2.677-2.795 s wall time (median 2.679), and 80.88-81.23 MiB peak RSS. The dedicated five-run baseline remains the less noisy headline measurement at 367.99-376.81 records/s (median 375.83); raw results and limitations are in `benchmarks/results/workflow-windows-20260912.json`.

The `0.4.0a3` streaming CSV rewrite copied 500,000 existing rows and appended 500,000 generated rows into a 23,277,791-byte file in 2.704 s: 184,939 appended rows/s with a measured RSS increase of 9,613,312 bytes over the 38,072,320-byte baseline. This is a local single-run Windows measurement, not a cross-platform storage guarantee.

Two post-fix GPU samples observed device-wide allocated VRAM staying at 2,788 MiB, an observed delta of 0 MiB. This is not process-attributed telemetry and does not prove that unrelated applications used no GPU. The fixed-validation advisory ranking comparison improved from 47/84 untrained to 61/84 trained, with 14 paired gains, zero paired regressions, zero unsafe automatic decisions, and unchanged deterministic authority. It is synthetic validation, not an independent production holdout.

## Downloads

- [Download the current source as a ZIP](https://github.com/IamAngusU/polymorph/archive/refs/heads/main.zip)
- [Download the tested v0.4.0a7 pre-release, wheel, sdist, and Polymorph Run 1.1.0 buddy](https://github.com/IamAngusU/polymorph/releases/tag/v0.4.0a7)

## Long-term run metrics

![Polymorph Run performance history](docs/assets/performance-history.svg)

Every supported buddy run refreshes the append-only local history under `.polymorph/metrics`. The tracked SVG and JSONL are published only after an explicit review with `python scripts/run_metrics.py --project "D:\polymorph" --export-public`; the command never commits or pushes. See [the metrics history contract](docs/METRICS_HISTORY.md).

## Start in five minutes

New users should begin with [`START-HERE.md`](START-HERE.md). On Windows, the complete local proof is:

```powershell
git clone https://github.com/IamAngusU/polymorph.git
cd polymorph
py -3.11 -m venv .venv
.venv\Scripts\python -m pip install ".[benchmark]"
World-Benchmark.cmd
```

The proof does not upload data, activate a model, push to GitHub or start GitHub Actions. Parquet,
PostgreSQL and metadata-only review timing are documented in the start guide.
