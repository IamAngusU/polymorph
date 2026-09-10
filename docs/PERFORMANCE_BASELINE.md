# Performance baseline

Measured on 2026-09-09 and 2026-09-10 on the current Windows development machine:

- Python 3.11.9 on AMD64
- Windows build 26200
- SQLite 3.45.1 using `DELETE` journal mode and `FULL` synchronous durability
- local pinned models on the D drive
- fresh CLI process per file run, warm filesystem cache, Magika enabled
- standard benchmark mode, without CPython allocation tracing

These are local engineering measurements, not cross-platform performance promises.

## Release verification snapshot

The final Windows verification run on 2026-09-10 collected 903 tests: 895 passed, eight were
platform-conditional skips, and none failed or errored in 36.425 seconds. Statement coverage was
82 percent, with 8,563 of 10,426 statements covered. The narrower failure, recovery, key-auth,
network-fault and external-corpus job collected 93 tests: 92 passed and the POSIX directory-fsync
case skipped on Windows in 11.839 seconds. Coverage percentage is a navigation aid, not a claim
that every critical state transition is proven; use the security matrix for that.

After the Windows atomic-publication fix, 20 fresh-process repetitions of the six-writer JSON
contention test passed 20 of 20 in 37.830 seconds. Each repetition required every child to complete
four appends and then verified all 24 unique records. This is regression evidence on one NTFS host,
not a filesystem-wide atomicity guarantee.

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

The expanded synthetic regression corpus was run with the research-only encoder in a fresh process
on 2026-09-10:

```bash
python scripts/dev.py benchmark mapping benchmarks/safety-regression.json --models \
  --require-auto-precision 1.0 --require-automation-coverage 0.70 \
  --require-suggestion-accuracy 0.60 --max-unsafe-auto 0
```

| Metric | Result |
| --- | ---: |
| Cases and labelled fields | 42 / 45 |
| Wall time | 0.926 s |
| CPU time | 8.672 s |
| Throughput | 48.59 fields/s |
| Peak RSS | 284.52 MiB |
| Automatic precision | 100% (17 of 17 automatic decisions) |
| Eligible automation coverage | 89.47% (17 of 19 eligible fields) |
| Overall automation rate | 62.96% (17 of 27 mappable fields) |
| Unsafe automatic decisions | 0 |
| Suggestion accuracy | 68.89% (31 of 45 fields) |

The deterministic profile produced the same decisions in 4.02 ms at 73.30 MiB peak RSS. An
explicit encoder-plus-mMARCO-reranker comparison also produced the same decisions, but took
2.325 seconds, 32.875 CPU seconds and 437.87 MiB peak RSS. On this corpus, neither model path
adds measurable decision quality. The reranker additionally needs a commercial-provenance review
before product use. This corpus verifies regression behavior and model packaging, not real-world
mapping quality.

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

The current local path was measured in three fresh work directories over 1,000 records with five
string fields and batches of 100. Each run included:

1. destination-signed recipient certificate verification and a persisted recipient trust head
2. X25519 and ChaCha20-Poly1305 seal, then Ed25519 source signature
3. durable source outbox stage
4. relay validation, enqueue and fenced lease
5. destination authentication, decrypt, contract validation and ledger fences
6. SQLite destination write, sealed spool cleanup and signed hash-chain audit
7. relay and source-outbox acknowledgement

| Metric | Result |
| --- | ---: |
| Successful runs | 3 of 3 |
| Full wall time | 19.074 to 19.769 s; median 19.079 s |
| Throughput | 50.59 to 52.43 records/s; median 52.41 records/s |
| CPU time | median 12.344 s |
| Peak RSS | 85.33 to 85.49 MiB; median 85.42 MiB |
| Destination delivery wall time | median 9.480 s |
| Destination delivery p50 / p95 | median 9.341 / 10.592 ms |
| Seal and durable outbox stage p50 / p95 | median 3.917 / 4.425 ms |
| Acknowledgement p50 / p95 | median 2.821 / 3.426 ms |
| Retained fixture and state files | median 2.702 MiB |

All 1,000 records were delivered once in every run. The outbox, relay and quarantine ended empty,
and all 1,000 signed audit events per run passed hash-chain and signature verification. The
destination was a local SQLite database using `DELETE` journal mode and `FULL` synchronous
durability. Every operational stream contained 1,029 contract-valid events with unique IDs, exact
workflow counts, a closed lifecycle and no unhealthy status. The event reservation was 1,055,744
bytes against the default 64 MiB stream budget. Each run atomically persisted a 1,015-byte
recipient trust head, reopened it and verified its signature, route, generation and history before
the source used it. A network database, HTTP service or file sink adds its own latency.

Separate durable SQLite commits dominate this profile. The retained report measures sealing and
the durable source-outbox append together at 3.917 ms p50; it does not isolate cryptographic CPU
time. The useful optimization targets are transaction batching with the existing per-record
fences, connection reuse and batch acknowledgements. Relaxing durability or deleting safety
checks just to improve this number would make the benchmark prettier and the product worse.

## Measurement rules

- Keep standard and `--tracemalloc` results separate. Allocation tracing changed observed parser
  time by roughly 5.6x to 10.3x in local comparison runs.
- Report cold starts when models are involved.
- State the connector, durability mode, batch size, record shape and record count.
- Keep correctness assertions in the benchmark. A fast partial workflow is a broken workflow.
- Use held-out, source-separated corpora for mapping quality claims.
