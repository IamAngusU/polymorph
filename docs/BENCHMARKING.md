# Benchmarking

Benchmarking is opt-in. Normal production paths do not start `tracemalloc`, process-RSS polling or benchmark timers.

## File-path resource benchmark

```bash
polymorph benchmark inspect ./orders.xlsx --records 10000
```

The report separates content inspection, schema inspection and bounded record reading. When `psutil` is available through the optional `benchmark` extra, it also samples process RSS during the operation. Python allocation peak is reported separately because native libraries such as ONNX Runtime do not allocate all memory through Python.

## Mapping correctness corpus

```bash
polymorph benchmark mapping ./benchmarks/mapping-corpus.json \
  --require-auto-precision 1.0 \
  --max-unsafe-auto 0
```

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
