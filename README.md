<p align="center">
  <img src="docs/assets/brand-mark.webp" width="116" alt="Polymorph mark">
</p>

# Polymorph

Polymorph is a local-first, policy-driven data bridge for moving data between structurally different systems without turning a central orchestration service into a universal plaintext trust point.

It is built around one reliability rule: **uncertainty must reduce automation, never increase guessing**. File names, extensions, model scores, old recipes and successful parser calls are evidence, not authority. Automatic promotion requires independently strong deterministic evidence, an immutable validated plan and a complete no-write preflight.

The package and protocol namespaces are intentionally decoupled from the product name so a later rename does not invalidate encrypted envelopes, persisted delivery state or recipe history.

## v0.3 reliability layer

- Content-first file inspection. Parser selection does not trust the extension or display name.
- ZIP/OOXML central-directory checks for traversal, symlinks, duplicate or encrypted members, suspicious expansion, oversized members, macros and external workbook links and data connections before a workbook parser is opened.
- Optional local Magika evidence. A high-confidence conflict between independent detectors blocks automatic parser selection rather than picking a favorite.
- Excel parsing requires XML hardening through `defusedxml`, then performs layout discovery for title rows, moved columns, repeated headers and fixed-width identifiers such as `000042`.
- Spreadsheet formulas are detected separately. Cached formula results are treated as freshness-unproven and prevent automatic recipe promotion.
- CSV dialect selection uses a deterministic candidate ensemble and can optionally include CleverCSV. A close tie is rejected instead of guessed.
- Deterministic schema matching remains the automatic authority. Optional local embeddings and a multilingual cross-encoder reranker can improve candidate order, but neither can independently authorize a write mapping.
- One-command `prepare` flow for content inspection, mapping, recipe reuse and full no-write preflight.
- Versioned local recipes. A recipe is reusable memory, not permission: it is structurally matched, rebound to the current exact schemas, assigned a new plan digest and validated again before use.
- Full-scan preflight exercises source transforms and optional read-only foreign-key resolution without destination writes. Sampled scans can inform review but cannot auto-promote a recipe.
- Opt-in resource benchmarks and labelled mapping-corpus evaluation. Normal runs do not enable tracing or RSS polling.
- Full-record blind transport using X25519, HKDF-SHA256 and ChaCha20-Poly1305.
- Ciphertext-only relay queue, durable idempotency ledger, sealed quarantine and explicit unknown-write-outcome handling.
- Ed25519-signed capabilities and a hash-chained metadata-only audit log.
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

## Fast path

Create source and target schemas as usual, or let `prepare` inspect a supported file directly. The easiest safe workflow is:

```bash
polymorph inspect db 'sqlite:///target.sqlite' --table orders -o target.schema.json
polymorph prepare ./incoming-file target.schema.json \
  --output-plan orders.plan.json \
  --remember
```

`prepare` performs content detection, schema inspection, recipe lookup, fresh mapping when needed and a full no-write preflight. A plan is only written when the route is promotable. If the evidence is insufficient, the command exits as review-required instead of manufacturing confidence.

For a foreign-key route, add a read-only destination resolver so preflight can prove the natural-key lookup before promotion:

```bash
polymorph prepare ./orders-upload target.schema.json \
  --resolver-db-url 'sqlite:///target.sqlite' \
  --resolver-db-table orders
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

## Optional local specialist models

The core is fully functional without a model. The CPU-first profile uses a small multilingual descriptor encoder and an optional cross-encoder reranker. Both are local-only at runtime, pinned to upstream revisions and hash-verified during installation.

```bash
pip install -e '.[semantic]'
polymorph model install --profile multilingual-cpu
polymorph model install --profile reranker-multilingual-cpu
```

Models receive schema descriptors, not record payload values. Their evidence can improve ranking and reduce review work, but automatic promotion still requires an independently strong deterministic mapping.

See [Model profiles](docs/MODEL_PROFILE.md).

## File trust and benchmarks

```bash
pip install -e '.[fileid,csv-detection,benchmark]'
polymorph inspect auto ./unknown-upload --magika
polymorph doctor
polymorph benchmark inspect ./unknown-upload --records 10000 --magika
polymorph benchmark mapping ./benchmarks/mapping-corpus.json --require-auto-precision 1.0
```

The benchmark commands are explicit diagnostics. Production code paths do not start Python allocation tracing or memory polling.

## Documentation

- [Architecture](docs/ARCHITECTURE.md)
- [Reliability model](docs/RELIABILITY.md)
- [File trust gate](docs/FILE_TRUST.md)
- [Recipes](docs/RECIPES.md)
- [Benchmarking](docs/BENCHMARKING.md)
- [Protocol](docs/PROTOCOL.md)
- [Threat model](docs/THREAT_MODEL.md)
- [Operations and replay safety](docs/OPERATIONS.md)
- [Security reporting](SECURITY.md)
- [Roadmap](docs/ROADMAP.md)

## Status

Polymorph remains an alpha until its automatic-promotion policy has been exercised against an adversarial, source-separated benchmark corpus and the security boundaries have received independent review. The project intentionally prefers an honest alpha label over a maturity claim that is not yet backed by evidence.

## License

Polymorph is source-available under the **PolyForm Noncommercial License 1.0.0**. Noncommercial research, private use and testing are permitted under its terms. Commercial use requires a separate license from Angus Uelsmann.

Required notices reference [angusu.de](https://angusu.de) and this repository. Third-party components retain their own licenses; see [THIRD_PARTY.md](THIRD_PARTY.md).
