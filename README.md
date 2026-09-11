<p align="center"><img src="docs/assets/brand-mark.webp" width="100" alt="Polymorph mark"></p>

# Polymorph

[English](README.md) · [Deutsch](README.de.md)

![Knowledge](docs/assets/knowledge.svg) ![Training queries](docs/assets/training.svg) ![Training comparisons](docs/assets/comparisons.svg)

**System A calls it `customer_no`. System B expects `account_id`.
The file changed again. Nobody should guess.**

Polymorph is a local-first data bridge for developers who receive CSV, Excel, JSON,
API or database data and need to move it into a different structure without silently
corrupting the destination. It inspects inputs, proposes mappings, checks plans and
keeps uncertain writes from becoming enthusiastic duplicates.

**Uncertainty reduces automation.**

A file extension is a suggestion. A model score is evidence, not a permission slip.
A recipe worked yesterday? Yesterday was also a different day.

## Start with a real import problem

```text
Customer export → inspect → map → no-write preflight → review or approved plan
                                                             ↓
                                    source → sealed relay → destination
```

`prepare` is the inspection/planning command. It does **not** silently write to the
live destination. The encrypted delivery path is currently a Python API and an
explicit benchmark, not an always-on deployment service.

```bash
git clone https://github.com/IamAngusU/polymorph.git
cd polymorph
python scripts/bootstrap.py
python scripts/dev.py doctor

# Read destination metadata, then inspect a file without trusting its extension.
python scripts/dev.py inspect db 'sqlite:///target.sqlite' --table orders -o target.schema.json
python scripts/dev.py prepare ./incoming-file target.schema.json --output-plan orders.plan.json --remember --max-input-records 5000
```

Python 3.11+ is required. The bootstrap installs local dependencies; it does not
install a model by default. See [development setup](docs/DEVELOPMENT.md) and
[operator workflows](docs/WORKFLOWS.md). The original CI matrix is configured for
Python 3.11–3.14 on Linux and Windows. Configuration is not evidence of successful
runs: GitHub Actions is unavailable for this account; use [local validation](docs/LOCAL_VALIDATION.md).

## What does the work

| Boundary | Contract |
| --- | --- |
| Input | Content inspection, ZIP/OOXML budgets, XML hardening, bounded JSON/GZIP and conservative CSV dialect selection. Filename optimism is not a parser. |
| Mapping | Names, types, relationships, sensitivity and ambiguity checks. Optional learned evidence cannot grant AUTO permission. |
| Recipes | Reusable local memory. Rebind current schemas, create a new plan digest and run preflight again. Memory, not permission. |
| Transport | Source/destination see plaintext at their boundaries. The relay receives signed ciphertext and routing metadata, not the private decryption key. |
| Trust | Source Ed25519 authentication, destination identity-pinned recipient certificates, plan-bound encryption and capability checks. |
| Delivery | Fenced leases, durable outbox, ledger, quarantine and distinct `NOT_COMMITTED` / `UNKNOWN` outcomes. A timeout is not a receipt from the universe. |
| Batching | Only for a connector with the required atomic contract. Keep authentication and replay evidence; amortize transactions, not honesty. |

A post-commit audit or cleanup error does not turn an already successful write into
a request to write again. Those are the boring distinctions that save exciting
postmortems.

### Current limits, before the sales department gets ideas

This is an **alpha**, not a universal safe-upload service. The isolated worker
currently protects **content inspection only**. CSV/JSON/XLSX schema parsing and
record iteration still run in the host process. Linux uses compatible Bubblewrap;
Windows process separation is **not** a filesystem/network sandbox.

The endpoints and database/driver remain trust boundaries. Encryption does not hide
routing metadata or traffic patterns. A local trust checkpoint does not resist a
rollback of the entire host. Continuous agents, comprehensive queue backpressure,
complete lifecycle supervision and large independent customer corpora remain work.

No SOC 2 audit, ISO certification, universal accuracy or permanent row immutability
is claimed. See [threat model](docs/THREAT_MODEL.md), [security coverage](docs/SECURITY_COVERAGE.md)
and [parser isolation](docs/PARSER_ISOLATION.md).

## General knowledge without overwriting your knowledge

The external lab trains advisory ranking artifacts. A release is a **versioned,
signed data package**, not downloaded Python, a recipe migration or a new security
policy. Install it side by side with older versions, then explicitly activate it.

```text
General knowledge: <data-home>/knowledge/general.sqlite
Private recipes:   <data-home>/recipes.sqlite              ← never touched by updates
Private models:    operator-managed                        ← never merged or uploaded
```

A separately approved publisher public key verifies every package. A sequence
high-water mark rejects stale updates and reused version identities. Rollback is
explicit and does not lower the update high-water mark. The model stays advisory.
There is no shipped publisher private key or automatic trust bootstrap.

```bash
# After a publisher has released a package and you have verified publisher.pub:
python scripts/knowledge.py --trusted-key publisher.pub fetch
python scripts/knowledge.py --trusted-key publisher.pub status
python scripts/knowledge.py --trusted-key publisher.pub activate VERSION
```

The first command installs but does not activate. No general release has been
published yet. [Knowledge releases](docs/KNOWLEDGE_RELEASES.md) describes the local
publisher workflow, compatibility, expiry and integration API. Existing private
recipes still need their usual revalidation; a public model never outranks a policy.

## Evidence, not decorative numbers

<!-- EVIDENCE:START -->
**General knowledge package:** none published. **Training queries:** 365. **Unique preference comparisons:** 1,656. Scope: `lab candidate`.

Counters describe the selected artifact, not all epochs or repeated tests added together. Parsed rows are not learned mapping decisions.

One table across measurement machines. Missing CPU, RAM and storage details are not guessed. The two historical entries below are from the same Windows host. The new code needs a new complete measurement.

| Date / evidence | CPU / RAM / storage | OS / Python | Workload / knowledge | Records/s | Peak RSS |
| --- | --- | --- | --- | ---: | ---: |
| [2026-09-10](knowledge/benchmarks/20260910-batch-checkpoint.json) / provisional batch checkpoint | not recorded; RAM not recorded; not recorded | Windows build 26200 / not recorded | 1,000 rows; batch 100; 7 runs; none | 353.52 | 95.23 MiB max |
| [2026-09-10](knowledge/benchmarks/20260910-legacy.json) / historical documented baseline | not recorded; RAM not recorded; not recorded | Windows build 26200 / 3.11.9 | 1,000 rows; batch 100; 3 runs; none | 52.41 | 85.42 MiB median |
<!-- EVIDENCE:END -->

The 52.41 result is the **pre-batching historical baseline**, not today's throughput
claim. The 353.52 result is a seven-run **development checkpoint** before subsequent
security changes. A later log reports approximately 381 records/s in three preliminary
runs. Neither replaces a full benchmark of the final code. No second or third hardware
profile has been measured here just to fill a table.

[Performance evidence and provenance](docs/PERFORMANCE_EVIDENCE.md) explains the old
measurements, the missing machine details and the format for adding genuine runs.
The historical [baseline document](docs/PERFORMANCE_BASELINE.md) is retained, not rewritten
into a result that never ran. CPU, effective core quota, storage/fsync latency, RAM,
OS/Python, driver, durability, record shape and batch size matter. A GPU helps only
when the measured path actually uses it.

Badges and this section are generated locally from versioned JSON, with no third-party
badge service or Actions dependency:

```bash
python scripts/render_evidence.py
python scripts/render_evidence.py --check
```

The lab's example candidate used 365 unique queries and 1,656 unique preference
comparisons. It improved its own baseline from 32/53 to 44/53 first choices on a
synthetic holdout. That is **not** a comparison against Polymorph AUTO, not 1,656
independent customers, and not a count of imported rows.

On the older mapping corpus, deterministic matching and the optional research
models made the same decisions; encoder + reranker used substantially more time and
memory. Extra machinery mainly converted electricity into heat. A useful benchmark
is allowed to tell us not to ship something. See [model profile](docs/MODEL_PROFILE.md).

## Measure locally

```bash
python scripts/validate_local.py
python scripts/dev.py benchmark mapping benchmarks/safety-regression.json --require-auto-precision 1.0 --max-unsafe-auto 0
python scripts/dev.py benchmark workflow --records 1000 --batch-size 100 --work-dir workflow-run --output workflow.json
```

The separate lab supplies fixed reference corpora, exploration, training and
paired evaluation. Repeated rows test volume; diverse labeled mappings teach a
ranker. They are not interchangeable counters. Public contribution suggestions
belong in a reviewed corpus inbox, not directly in a training set or production plan.

## Read deeper

[Architecture](docs/ARCHITECTURE.md) · [Reliability](docs/RELIABILITY.md) ·
[Recipes](docs/RECIPES.md) · [File trust](docs/FILE_TRUST.md) ·
[Recipient keys](docs/RECIPIENT_KEY_ROTATION.md) · [Database write proof](docs/DATABASE_WRITE_PROOF.md) ·
[Operations](docs/OPERATIONS.md) · [Observability](docs/OBSERVABILITY.md) ·
[Benchmarking](docs/BENCHMARKING.md) · [External lab](docs/EXTERNAL_LAB.md) ·
[Roadmap](docs/ROADMAP.md) · [Security](SECURITY.md)

## License

Source-available under **PolyForm Noncommercial 1.0.0**, not OSI Open Source.
Commercial use requires a separate license from Angus Uelsmann. The license itself
defines permitted use. [Commercial terms](COMMERCIAL.md) · [Third-party notices](THIRD_PARTY.md).

Built by [angusu.de](https://angusu.de). Names can change. Protocol identities should not have to.
