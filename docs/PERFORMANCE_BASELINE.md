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
| Wall time | 2.635 s |
| CPU time | 37.500 s |
| Throughput | 17.08 fields/s |
| Peak RSS | 438.30 MiB |
| Automatic precision | 100% (17 of 17 automatic decisions) |
| Eligible automation coverage | 89.47% (17 of 19 eligible fields) |
| Overall automation rate | 62.96% (17 of 27 mappable fields) |
| Unsafe automatic decisions | 0 |
| Suggestion accuracy | 68.89% (31 of 45 fields) |

The deterministic profile produced the same decisions in 4.52 ms at 78.16 MiB peak RSS. On this
corpus, the models add ranking evidence but no measurable decision-quality gain. Keeping them
optional is therefore the correct default until a source-separated holdout shows a benefit. This
corpus verifies regression behavior and model packaging, not real-world mapping quality.

## Parser-worker boundary

The content-inspection worker was measured against the repository's 68-byte quoted-CSV fixture.
Each run created and hashed a new private snapshot and started a new Python process. The benchmark
extra sampled the child process every 5 ms, which adds observer overhead. Windows provides process
separation only, so these numbers are not Linux sandbox measurements.

| Mode | Runs | End-to-end p50 / p95 | Worker p50 | Snapshot p50 | Observed child peak RSS | Maximum observed child CPU |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Deterministic inspection | 20 | 208.78 / 224.11 ms | 205.71 ms | 1.35 ms | 49.98 MiB | 0.188 s |
| Inspection with Magika | 10 | 380.94 / 428.86 ms | 377.88 ms | 1.33 ms | 95.88 MiB | 1.156 s |

All samples returned the same input digest and normalized inspection. The deterministic cold call
was 201.62 ms. These tiny-file results primarily measure worker startup and containment-boundary
overhead; they are not useful as file-throughput claims. Sampled resource values are conservative
because a process can exit between polling intervals.

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
| Full wall time | 17.829 s |
| Throughput | 56.09 records/s |
| Peak RSS | 86.43 MiB |
| Destination delivery p50 / p95 | 9.519 / 10.674 ms |
| Seal and durable outbox stage p50 / p95 | 2.465 / 2.873 ms |
| Complete final verification | 96.26 ms |
| Destination operational-event check | 1.31 ms |

All 1,000 records were delivered once, both queues ended empty, and all 1,000 signed audit events
passed hash-chain and signature verification. The destination was a local SQLite database using
`DELETE` journal mode and `FULL` synchronous durability. The operational stream contained 1,029
contract-valid events with unique IDs, a closed workflow lifecycle and no unhealthy status. A
network database, HTTP service or file sink adds its own latency.

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
