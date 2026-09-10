# Benchmarking

Benchmarking is opt-in. Normal production paths do not start `tracemalloc`, process-RSS polling or benchmark timers.

The current development-machine measurements and exact test shape are recorded in
[Performance baseline](PERFORMANCE_BASELINE.md).

## Real workflow benchmark

```bash
polymorph benchmark workflow --records 1000 --batch-size 100 \
  --work-dir ./benchmark-run --output ./workflow-result.json
```

This is a real local data-path test, not a sleep-based microbenchmark. It creates a deterministic
CSV export and an actual SQLite destination, then exercises:

- content-first file inspection
- source and destination schema inspection
- deterministic mapping and immutable plan construction
- a complete no-write preflight over every generated record
- per-field recipient encryption and Ed25519 source authentication
- durable source outbox staging and reload
- authenticated relay enqueue and fenced leases
- destination decryption, contract validation and real SQLite commits
- delivery ledger transitions, sealed quarantine storage and signed audit events
- relay and source acknowledgements
- final counts, all five destination values, empty queues, audit signature verification and five
  plaintext-canary checks across blind SQLite files and sidecars

The JSON report contains total wall/CPU/RSS measurements plus wall time, CPU time, call count,
bounded latency sample count, p50/p95 call latency for repeated stages, throughput, storage bytes,
runtime versions and SQLite durability settings. Single-call stages report null p50/p95. It
contains counts and fixed reason codes, not generated record values, exception messages, PID or an
absolute work path. A failed workflow is still emitted as JSON with the first failing stage and
exits with code 7.

The signed destination audit is enabled by default. Use `--no-audit` to measure the same path
without it. `--work-dir` must point to a new or empty directory and is retained for inspection.
Without that option, state is created in an automatically cleaned temporary directory. Add
`--keep-work-dir` to retain an automatically named directory.

Like the other benchmark commands, this uses sampled process RSS when `psutil` is installed and
does not enable `tracemalloc` by default. `--tracemalloc` is available for allocation debugging,
but its timings are not comparable with standard mode. The generated workflow proves integration
correctness and measures local mechanics. It does not prove mapping accuracy on customer data.

See the [Workflow lab](WORKFLOW_LAB.md) for reproducible commands, failure injection,
report-safety limits and cold-versus-warm rules.

## File-path resource benchmark

```bash
polymorph benchmark inspect ./orders.xlsx --records 10000
```

The default report separates content inspection, schema inspection and bounded record reading.
When `psutil` is available through the optional `benchmark` extra, it also samples process RSS.
The JSON output labels this light observer mode as `standard`, and `peak_python_bytes` is `null`.

CPython allocation tracing is separately opt-in because its observer effect can materially distort
parser wall time:

```bash
polymorph benchmark inspect ./orders.xlsx --records 10000 --tracemalloc
```

That mode is labelled `python_allocation_trace` in the output and reports
`peak_python_bytes`. Do not compare its wall times with standard-mode results. Native libraries
such as ONNX Runtime do not allocate all memory through Python, so sampled process RSS remains
the relevant whole-process memory measurement.

Model profiles verify their pinned assets immediately but load their runtime lazily. A benchmark
with `--models` therefore includes research-encoder startup only when the corpus actually contains
ambiguous fields. Report both `rss_before_bytes` and `peak_rss_bytes`; quoting only installed model
size is not a memory benchmark.

## Parser-worker boundary benchmark

```bash
polymorph benchmark parser-worker ./incoming-file --runs 10
```

The default is fail-closed and requires the Linux Bubblewrap backend. For a trusted local file on
Windows, process separation can be measured explicitly:

```bash
polymorph benchmark parser-worker ./incoming-file --runs 10 \
  --backend process --require-containment process
```

Every sample creates and hashes a fresh private snapshot, starts a new worker, validates the bounded
protocol response and verifies the snapshot again. The report keeps per-run evidence plus min, p50,
p95 and max timing for snapshot creation, worker execution and the complete call. It also records
the actual containment level, capabilities, configured limits and protocol byte counts. Identical
input digests and inspection results across all samples are a correctness gate, not just metadata.
If a run fails, the command writes the completed-run count, failed sample number, stable reason
code, bounded stderr digest and operator guidance before returning a non-zero exit status.

When the `benchmark` extra is installed, the supervisor samples the worker and its descendants at
5 ms intervals and reports observed peak RSS, maximum observed CPU time, I/O counters and sample
counts. This observer runs only for the explicit benchmark, has measurable overhead and can miss a
short-lived final resource peak. Without `psutil`, these fields are null and the report says that
measurement was unavailable. The POSIX worker independently enforces its configured address-space,
CPU, file, process and open-file limits. CI builds a checksum-pinned Bubblewrap 0.12.0, executes a
real strict-boundary smoke test and runs the dedicated adversarial isolation suite. Its retained
toolchain report records the installed binary hash, compiler, libcap, Meson, Ninja, Python and
relevant package versions. The source archive is reproducibly identified; the build is not claimed
to be bit-for-bit reproducible because Ubuntu and PyPI toolchains are not fully locked.

## Mapping correctness corpus

```bash
polymorph benchmark mapping ./my-mapping-corpus.json \
  --require-auto-precision 1.0 \
  --require-automation-coverage 0.70 \
  --max-unsafe-auto 0
```

Mapping benchmarks accept the same `--tracemalloc` option and observer-mode labels. Optional
`--require-suggestion-accuracy` and `--require-automation-coverage` gates stop a run that remains
safe only by becoming useless. Every case id must be unique, every source field must have exactly
one label, and every non-null expected target must exist. The manifest is rejected before scoring
when those invariants are broken. Duplicate JSON keys, non-finite numbers and unknown manifest
fields are also rejected so a misspelled safety label cannot silently disappear.

The repository keeps two corpora:

- `benchmarks/safety-smoke.json` is a tiny machinery smoke suite.
- `benchmarks/safety-regression.json` contains 42 synthetic safety cases and 45 labelled fields.
  CI requires automatic precision 1.0, zero unsafe automatic decisions and at least 70 percent
  automation coverage among explicitly automation-eligible mappings.

The report separates unsafe automatic failures from lower-risk suggestion mismatches. A review
candidate can therefore be visibly wrong without being misreported as an automatic write. Both
repository corpora are regression fixtures, not real-world accuracy evidence. It also validates
the matcher's output contract: exactly one decision per source, known targets, status and target
consistency, plus finite scores and margins in the unit interval.

A version-1 corpus uses inline schema descriptors and explicit expected mappings:

```json
{
  "version": 1,
  "cases": [
    {
      "id": "de-orders-001",
      "source_schema": {
        "id": "source",
        "fields": [
          {"id": "c1", "name": "Debitor Nr", "data_type": "string"}
        ]
      },
      "target_schema": {
        "id": "target",
        "fields": [
          {"id": "customer_number", "name": "customer number", "data_type": "string"}
        ]
      },
      "expected": {
        "c1": "customer_number"
      },
      "review_only": ["c1"]
    }
  ]
}
```

Use `null` as the expected target for a field that must not be mapped. Use `review_only` for a
known correspondence that is useful as a suggestion but unsafe for automatic execution. Automation
coverage uses only non-null labels outside `review_only` as its denominator. The report also emits
`overall_automation_rate` across every non-null correspondence so the narrower safety denominator
cannot hide total review load.

## Dataset discipline

A useful corpus must be split by original source/template/organization before synthetic mutations are generated. Randomly splitting near-duplicate variants can make a matcher look much more accurate than it is on a genuinely new customer format.

Recommended suites include:

- ordinary clean exports
- renamed and reordered columns
- multilingual labels
- duplicate and near-duplicate target candidates
- wrong units and currencies
- ambiguous dates and identifiers
- natural-key/foreign-key routes
- sensitivity conflicts
- missing destination keys
- messy CSV quoting/dialect cases
- malformed or misleading file names
- workbook formulas and external links
- schema drift after recipe approval

The safety gate should be tuned against false automatic approvals first. Coverage can be optimized only after that constraint holds.

## External corpus candidates

[Valentine](https://github.com/delftdata/valentine) is an Apache-2.0 schema-matching experiment
suite, and its separate
[data fabricator](https://github.com/delftdata/valentine-data-fabricator) can generate mappings,
schemas and perturbed table pairs. It is useful for repeatable name and structure perturbations.

The [WDC Schema Matching Benchmark](https://webdatacommons.org/structureddata/smb/) provides fixed
training, validation and test splits with positive and negative correspondences. Its tasks use
instance values and Web-table semantics, while the current Polymorph safety corpus primarily
evaluates schema metadata. An adapter is useful, but quoting WDC scores as if they measured the
whole Polymorph workflow would be wrong.

Do not silently train on either benchmark and then report its test score. Keep external test splits
read-only, record the exact upstream version and license, and retain the conversion manifest.
