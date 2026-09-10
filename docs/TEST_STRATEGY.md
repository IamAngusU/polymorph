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
- a Linux job that installs Bubblewrap, exercises a real strict worker and retains its benchmark
  plus JUnit evidence
- a real localhost TLS acknowledgement-loss case in the workflow failure job

## Workflow tests

- file to schema to plan to preflight to recipe reuse
- source agent to blind relay to destination runtime to reconciliation
- multiple records delivered to every destination type without replacement or loss
- connector crash before write, during commit and after commit before acknowledgement
- real TLS connection loss after an idempotent HTTP destination commit
- restart from each durable ledger state
- key rotation and revoked-source rejection
- recipe reuse after filename changes and refusal after structural drift

## Adversarial input corpus

- extension and MIME lies
- polyglots and truncated magic values
- ZIP traversal, symlinks, duplicate normalized names, encryption and expansion bombs
- Office macros, external links, data connections and stale formula caches
- XML entity and quadratic expansion attacks, deep trees, excessive elements and attribute bombs
- duplicate JSON keys, non-finite numbers, deep nesting, excessive item counts and oversized
  scalar values
- concatenated GZIP member floods, forged footers, padding-diluted ratios and aggregate expansion
- CSV delimiter, quoting, encoding and line-ending ambiguity
- byte-pinned JSONTestSuite and W3C CSVW subsets with retained upstream licenses and hashes
- Excel date epochs, leading zeros, hidden rows, merged cells and repeated headers
- malformed Parquet footers when the columnar pack exists

The parser-worker suite separately attacks the boundary itself: malformed and duplicated protocol
fields, non-finite values, stdout and stderr floods, timeouts, descendant processes, snapshot
replacement or growth, environment leakage, unavailable backends and containment downgrades. A
binary-presence check is not accepted as proof that the sandbox invocation works.

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

The Hypothesis delivery state machine composes real SQLite outbox, relay, ledger, quarantine,
signed audit and operational-event stores across up to 30 reordered steps. Its deterministic
scaffold first proves every connector fault, claim-expiry recovery and successful quarantine
replay; generated steps then inject restarts, stale leases and reordered acknowledgements. Exact
reference sets cover outbox, relay and quarantine, while receipt-specific counters verify audit
status, reason and record digest plus operational component, correlation and item count. This avoids
a green property test whose randomly chosen action never reached the transition it claimed to
exercise. Acknowledgement safety is currently an orchestration invariant: the relay and outbox APIs
do not independently consult the destination ledger, so callers outside the tested delivery driver
can still misuse those low-level APIs.

## Manual release evidence

Large model downloads and real ONNX inference are intentionally not required on every small CI job.
Tag and manual CI runs explicitly execute the pinned research encoder and retain the mapping safety
report plus model installation status. Rerankers run only in a separate provenance-reviewed
lab. Resource benchmarks are explicit local evidence until a release
publication workflow is added.
