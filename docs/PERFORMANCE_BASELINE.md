# Performance baseline

Measured on 2026-09-09, 2026-09-10 and 2026-09-12 on the current Windows development machine:

- Python 3.11.9 on AMD64
- Windows build 26200
- Intel Core i9-12900K, 16 physical cores and 24 logical CPUs
- NVIDIA GeForce RTX 3080 with 10,240 MiB VRAM; model-free workflow GPU use sampled separately
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
extra sampled the child process every 5 ms, which adds observer overhead. Windows uses Job Object
resource containment here, so these numbers prove neither Linux sandbox behavior nor filesystem or
network isolation.

| Mode | Runs | End-to-end p50 / p95 | Worker p50 | Snapshot p50 | Observed child peak RSS | Maximum observed child CPU |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Deterministic inspection | 20 | 208.78 / 224.11 ms | 205.71 ms | 1.35 ms | 49.98 MiB | 0.188 s |
| Inspection with Magika | 10 | 380.94 / 428.86 ms | 377.88 ms | 1.33 ms | 95.88 MiB | 1.156 s |

All samples returned the same input digest and normalized inspection. The deterministic cold call
was 201.62 ms. These tiny-file results primarily measure worker startup and containment-boundary
overhead; they are not useful as file-throughput claims. Sampled resource values are conservative
because a process can exit between polling intervals.

## Full secure transport

The current local path was measured on 2026-09-12 in five fresh work directories over 1,000
records with five string fields and batches of 100. Each run included:

1. destination-signed recipient certificate verification and a persisted recipient trust head
2. X25519 and ChaCha20-Poly1305 seal, then Ed25519 source signature
3. durable source outbox stage
4. relay validation, enqueue and fenced lease
5. destination authentication, decrypt, contract validation and ledger fences
6. SQLite destination write, sealed spool cleanup and signed hash-chain audit
7. relay and source-outbox acknowledgement

| Metric | Result |
| --- | ---: |
| Successful runs | 5 of 5 |
| Full wall time | 2.654 to 2.717 s; median 2.661 s |
| Throughput | 367.99 to 376.81 records/s; median 375.83 records/s |
| CPU time | median 2.453 s |
| Peak RSS | 80.76 to 88.73 MiB; median 81.33 MiB |
| RSS growth | median 15.77 MiB |
| Destination delivery wall time | median 0.624 s |
| Destination batch p50 / p95 | median 61.75 / 64.43 ms |
| Seal and durable outbox batch p50 / p95 | median 88.48 / 90.18 ms |
| Acknowledgement batch p50 / p95 | median 4.58 / 4.99 ms |
| Retained fixture and state files | median 3.014 MiB |

All 1,000 records were delivered once in every run. The outbox, relay and quarantine ended empty,
and all 1,000 signed audit events per run passed hash-chain and signature verification. The
destination was a local SQLite database using `DELETE` journal mode and `FULL` synchronous
durability. Every operational stream contained 1,039 contract-valid events with unique IDs, exact
workflow counts, a closed lifecycle and no unhealthy status. The event reservation was 1,065,984
bytes against the default 64 MiB stream budget. Each run atomically persisted a 1,015-byte
recipient trust head, reopened it and verified its signature, route, generation and history before
the source used it. A network database, HTTP service or file sink adds its own latency.

The current connector performs ten capability-gated atomic transactions of 100 records while
retaining per-record ledger fences, authentication and audit evidence. Stage p50 and p95 values in
this table are therefore per batch, not per record. Relaxing durability or deleting safety checks
just to improve this number would make the benchmark prettier and the product worse.

The exact five report-derived observations are retained in
[`benchmarks/results/workflow-windows-20260912.json`](../benchmarks/results/workflow-windows-20260912.json).
A separate 500 ms `nvidia-smi` sample over two runs observed total device memory remain at 2,788
MiB across all 13 observations. GPU utilization is device-wide and not process-attributed; the
observed VRAM change was 0 MiB. The workflow does not load optional mapping models.

## Measurement rules

- Keep standard and `--tracemalloc` results separate. Allocation tracing changed observed parser
  time by roughly 5.6x to 10.3x in local comparison runs.
- Report cold starts when models are involved.
- State the connector, durability mode, batch size, record shape and record count.
- Keep correctness assertions in the benchmark. A fast partial workflow is a broken workflow.
- Use held-out, source-separated corpora for mapping quality claims.

## Parquet and public-schema evidence, 2026-09-12

Polymorph 0.4.0a2 inspected and streamed a deterministic local Zstandard-compressed Parquet fixture
with 10,000 rows and five flat columns. The 90,788-byte fixture was read at 1,543,972 rows/second;
record-read peak RSS was 95,776,768 bytes. This is a warm local parser-path measurement, not the
encrypted end-to-end workflow rate and not a large-data claim. The sanitized report is retained at
`benchmarks/results/parquet-windows-20260912.json`.

The independent public multilingual schema corpus scored 14 of 14 suggestions correctly, with 13
review decisions, one deterministic automatic decision and zero unsafe automatic decisions. Its
four source groups are too small for a universal accuracy claim. The sanitized report is retained
at `benchmarks/results/mapping-independent-public-v1-windows-20260912.json`.

## Streaming CSV rewrite evidence, 2026-09-12

Polymorph 0.4.0a3 copied 500,000 existing rows and appended 500,000 generator-produced rows through
an atomic temporary file. The resulting 23,277,791-byte CSV completed in 2.704 seconds at 184,939
appended rows/second. Process RSS rose from 38,072,320 to 47,685,632 bytes, a 9,613,312-byte delta.
This one local Windows run demonstrates practical bounded behavior for that input; it is not a
cross-platform maximum or a substitute for adversarial filesystem testing.
