# Test strategy

Unit tests are necessary and wildly insufficient for this project. The release gate needs several
layers.

## Always-on CI

- unit and integration tests on every supported Python version
- Ruff and strict type checking
- wheel build plus installation into a clean environment
- CLI smoke tests from the installed wheel, not only the source tree
- mapping safety corpus with zero unsafe AUTO decisions
- deterministic serialization and digest tests
- Windows and Linux jobs for filesystem, SQLite and process behavior

## Workflow tests

- file to schema to plan to preflight to recipe reuse
- source agent to blind relay to destination runtime to reconciliation
- multiple records delivered to every destination type without replacement or loss
- connector crash before write, during commit and after commit before acknowledgement
- restart from each durable ledger state
- key rotation and revoked-source rejection
- recipe reuse after filename changes and refusal after structural drift

## Adversarial input corpus

- extension and MIME lies
- polyglots and truncated magic values
- ZIP traversal, symlinks, duplicate normalized names, encryption and expansion bombs
- Office macros, external links, data connections and stale formula caches
- XML entity and quadratic expansion attacks
- duplicate JSON keys, non-finite numbers, deep nesting and oversized scalar values
- CSV delimiter, quoting, encoding and line-ending ambiguity
- Excel date epochs, leading zeros, hidden rows, merged cells and repeated headers
- malformed Parquet footers when the columnar pack exists

## Mapping corpus design

Split by source organization, template family and time. Random row splitting leaks template
knowledge and produces flattering nonsense. Include unmappable fields, multilingual homonyms,
currency and unit conflicts, natural-key versus internal-ID traps and deliberate glossary
poisoning.

Track AUTO precision and coverage separately. A model that maps more fields but creates one new
unsafe AUTO decision does not graduate into the conservative profile.

## Property and metamorphic tests

- serialization round trips preserve digests
- any authenticated context mutation invalidates ciphertext or source signature
- column reordering changes exact identity but preserves meaning only through explicit repair
- irrelevant metadata changes do not change structural recipe identity
- duplicate delivery never produces a second committed side effect
- adding a weak model signal cannot promote a deterministically unsafe mapping

## Manual release evidence

Large model downloads and real ONNX inference are intentionally not required on every small CI job.
Tag and manual CI runs execute both pinned model profiles and retain the mapping safety report plus
model installation status. Resource benchmarks are explicit local evidence until a release
publication workflow is added.
