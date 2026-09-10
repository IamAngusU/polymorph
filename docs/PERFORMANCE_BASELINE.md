# Performance baseline

Measured on 2026-09-09 and 2026-09-10 on the current Windows development machine:

- Python 3.11.9 on AMD64
- Windows build 26200
- SQLite 3.45.1 using `DELETE` journal mode and `FULL` synchronous durability
- local pinned models on the D drive
- fresh CLI process per file run, warm filesystem cache, Magika enabled
- standard benchmark mode, without CPython allocation tracing

These are local engineering measurements, not cross-platform performance promises.

## File inspection

Each fixture contains 50,000 rows and seven fields. Schema discovery inspected the complete input,
then the read stage consumed at most 10,000 records. Each number is based on three fresh-process
runs. The p95 is interpolated over those three observations, so treat it as a smoke baseline rather
than a capacity result.

| Format | Input size | Total p50 | Total p95 | Content p50 | Schema p50 | Read 10k p50 | Peak RSS median |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| CSV | 3.99 MB | 1.150 s | 1.151 s | 90.9 ms | 173.1 ms | 290.4 ms | 116.4 MiB |
| JSON | 8.74 MB | 0.806 s | 0.808 s | 89.5 ms | 140.8 ms | 0.6 ms | 161.7 MiB |
| XLSX | 1.90 MB | 6.178 s | 6.195 s | 78.9 ms | 3.631 s | 1.888 s | 115.9 MiB |

The JSON connector materializes and caches records during schema inspection, which is why its
bounded read stage is unusually small. XLSX parsing is the clear file-path bottleneck.

Use the built-in command for another machine or another file:

```bash
polymorph benchmark inspect ./input-file --records 10000 --magika
```

## Mapping models

The expanded synthetic regression corpus was run with both pinned model profiles in a fresh
process on 2026-09-10:

```bash
python scripts/dev.py benchmark mapping benchmarks/safety-regression.json --models \
  --require-auto-precision 1.0 --require-automation-coverage 0.70 \
  --require-suggestion-accuracy 0.60 --max-unsafe-auto 0
```

| Metric | Result |
| --- | ---: |
| Cases and labelled fields | 42 / 45 |
| Wall time | 2.389 s |
| CPU time | 36.109 s |
| Throughput | 18.84 fields/s |
| Peak RSS | 441.03 MiB |
| Automatic precision | 100% (17 of 17 automatic decisions) |
| Eligible automation coverage | 89.47% (17 of 19 eligible fields) |
| Overall automation rate | 62.96% (17 of 27 mappable fields) |
| Unsafe automatic decisions | 0 |
| Suggestion accuracy | 68.89% (31 of 45 fields) |

The deterministic profile produced the same decisions in 4.52 ms at 78.16 MiB peak RSS. On this
corpus, the models add ranking evidence but no measurable decision-quality gain. Keeping them
optional is therefore the correct default until a source-separated holdout shows a benefit. This
corpus verifies regression behavior and model packaging, not real-world mapping quality.

## Full secure transport

The full local path was measured over 1,000 records with seven string fields and batches of 100:

1. X25519 and ChaCha20-Poly1305 seal, then Ed25519 source signature
2. durable source outbox stage
3. relay validation, enqueue and fenced lease
4. destination authentication, decrypt, contract validation and ledger fences
5. memory destination write, sealed spool cleanup and signed hash-chain audit
6. relay and source-outbox acknowledgement

| Metric | Result |
| --- | ---: |
| Full wall time | 15.179 s |
| Throughput | 65.88 records/s |
| Peak RSS | 85.33 MiB |
| Destination delivery p50 / p95 | 6.974 / 7.947 ms |
| Seal and sign p50 / p95 | 0.826 / 1.044 ms |
| Audit verification, 1,000 events | 83.61 ms |
| Audit summary, 1,000 events | 84.90 ms |

All 1,000 records were delivered once, both queues ended empty, and all 1,000 signed audit events
passed hash-chain and signature verification. The destination used an in-memory connector to
isolate Polymorph's transport overhead. A real database, HTTP service or file sink adds its own
latency.

Separate durable SQLite commits dominate this profile. Cryptography stays below 1 ms per record.
The useful optimization targets are transaction batching with the existing per-record fences,
connection reuse and batch acknowledgements. Relaxing durability or deleting safety checks just to
improve this number would make the benchmark prettier and the product worse.

## Measurement rules

- Keep standard and `--tracemalloc` results separate. Allocation tracing changed observed parser
  time by roughly 5.6x to 10.3x in local comparison runs.
- Report cold starts when models are involved.
- State the connector, durability mode, batch size, record shape and record count.
- Keep correctness assertions in the benchmark. A fast partial workflow is a broken workflow.
- Use held-out, source-separated corpora for mapping quality claims.
