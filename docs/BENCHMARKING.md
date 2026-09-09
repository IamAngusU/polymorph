# Benchmarking

Benchmarking is opt-in. Normal production paths do not start `tracemalloc`, process-RSS polling or benchmark timers.

The current development-machine measurements and exact test shape are recorded in
[Performance baseline](PERFORMANCE_BASELINE.md).

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
with `--models` therefore includes model startup only when the corpus actually contains ambiguous
fields. Report both `rss_before_bytes` and `peak_rss_bytes`; quoting only installed model size is
not a memory benchmark.

## Mapping correctness corpus

```bash
polymorph benchmark mapping ./my-mapping-corpus.json \
  --require-auto-precision 1.0 \
  --max-unsafe-auto 0
```

Mapping benchmarks accept the same `--tracemalloc` option and observer-mode labels.

The repository includes `benchmarks/safety-smoke.json` as a tiny CI/release smoke suite. It checks the benchmark mechanism and several fail-closed cases only. It is explicitly not a real-world accuracy corpus and must not be used for product accuracy claims.

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
      }
    }
  ]
}
```

Use `null` as the expected target for a field that must not be automatically mapped.

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
