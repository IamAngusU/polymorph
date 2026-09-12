# Workflow lab

The workflow lab measures one complete successful local data path, checks injected failure
boundaries including a real localhost TLS acknowledgement loss, stresses local restart and
concurrency recovery, and validates the resulting operational event stream. None of these commands
is a production load test.

## Reproduce the successful workflow

Install the development and benchmark dependencies first. Run this command from the repository
root in a fresh process:

```bash
python -m pip install -e ".[dev,benchmark]"
```

```bash
polymorph benchmark workflow --records 1000 --batch-size 100 --work-dir ./.polymorph/workflow-real-1000 --output ./.polymorph/workflow-real-1000.json
```

The work directory must be new or empty. Pick a different directory for every repetition. The
command creates a deterministic CSV source and a real SQLite destination. It then performs content
inspection, schema discovery, deterministic mapping, complete no-write preflight, recipient
identity and recipient-certificate verification, recipient encryption, source signing, durable
outbox staging, authenticated relay transport, destination decryption, contract validation, real
SQLite writes, delivery-ledger transitions, signed audit, relay acknowledgement and source
acknowledgement.

The final verification requires all requested destination rows and committed ledger entries,
exact values for all five fixture fields independent of relay order, empty outbox and relay queues,
empty sealed quarantine, a valid signed audit event for every delivery and absence of five known
plaintext canaries from every blind SQLite file, sidecar and operational event file. It also
requires a structurally valid event stream with one correlated destination event per receipt and a
clean workflow completion.

## Reproduce the failure suite

```bash
python -W error -m pytest tests/test_workflow_failure_lab.py tests/test_recovery_stress.py \
  tests/test_recovery_processes.py tests/test_delivery_state_machine.py \
  tests/test_recipient_auth.py tests/test_content_differential.py \
  tests/test_network_fault_lab.py tests/test_json_test_suite.py tests/test_w3c_csvw.py \
  --strict-config --strict-markers --durations=0 \
  --junitxml=./.polymorph/workflow-failure-and-recovery-lab.xml
```

The executable cases and expected outcomes are also listed in
[`benchmarks/workflow-failure-manifest.json`](../benchmarks/workflow-failure-manifest.json). The
manifest describes expectations. The pytest assertions are the authority for whether the current
implementation still meets them.

The concurrency and restart cases are listed separately in
[`benchmarks/recovery-manifest.json`](../benchmarks/recovery-manifest.json).

## Failure scenarios

| Scenario | Real path | Injected condition | Required outcome |
| --- | --- | --- | --- |
| Misleading file extension | Real file inspector and Excel connector gate | CSV content is named `orders.xlsx` | Content is identified as `delimited_text`; explicit Excel parsing is rejected before the workbook parser opens |
| Ambiguous mapping | Real `prepare` CLI, JSON inspection, matcher and plan gate | One source label ties two destination labels | Exit code 3, decision remains `review`, reason `no_auto_approved_mapping_rules`, no plan file |
| Recipe circuit | Real `prepare` CLI, preflight and SQLite recipe store | Three consecutive `required_target_null` rejection observations are inserted | Old recipe becomes `suspended`; automatic reuse is denied; a fresh validated recipe version is produced |
| Unsigned and tampered relay input | Real signing, trust store, relay policy and relay SQLite queue | One unsigned record enters ingress; one accepted signed record has its persisted signature changed | Unsigned ingress is rejected; the tampered record is never leased and is dead-lettered as `relay_source_authentication_failed` |
| Lost relay acknowledgement | Real source outbox, relay, crypto, destination runtime, ledger and JSON destination | Relay lease time is advanced after the destination commit without acknowledging the first lease | Redelivery returns `duplicate`, the ledger stays `committed`, and the JSON destination contains one record |
| Unknown destination outcome | Real crypto, destination runtime, ledger, sealed spool, signed audit and JSON file replacement | A connector wrapper raises after the real JSON replacement has completed | Receipt is `quarantined` with `write_outcome_unknown`; ledger is `uncertain`; signed audit records the reason; normal replay is refused; only one write call occurred |
| Real TLS acknowledgement loss | Real TLS socket, HTTP client and idempotent HTTPS endpoint | The endpoint commits the key, then closes the connection before returning any HTTP response | Connector outcome is `unknown`; retry uses the identical key; the endpoint reports two attempts but exactly one committed effect |

The first two scenarios need no injected subsystem failure. The recipe case inserts explicit
operational outcomes. The next three keep the real security and persistence path but inject the
specific external fault under test: stored-wire tampering, lease time advancement or a lost
connector acknowledgement. The final case uses a temporary self-signed localhost certificate and
an actual TLS connection. No matcher, signature check, relay policy, ledger transition or replay
decision is mocked.

The file-extension case tests an explicitly selected wrong connector. Automatic CLI inspection
would select the CSV connector from the content instead of trusting the `.xlsx` suffix.

## Recovery stress scenarios

The recovery suite exercises these local boundaries with real SQLite state, independent clients,
real worker threads and separate Python processes:

- twelve simultaneous retries of one source outbox item converge safely
- six relay workers lease 24 records without overlapping ownership
- stale lease tokens cannot acknowledge or mutate a newer lease
- concurrent duplicate delivery produces one destination write
- a lease may expire while an already-authorized destination write is still running
- restart after a committed destination result but before transport acknowledgement stays duplicate
- an unknown outcome remains `uncertain` and fail-closed across restart
- parallel startup migrates legacy Relay and Ledger schemas without racing
- twelve separate processes contend on each legacy Relay and Ledger startup migration without
  duplicate schema changes or row loss

## Measured result

Five standard-mode runs on 2026-09-12 used the current Windows development machine, Python 3.11.9,
SQLite 3.45.1 with `DELETE` journal mode and `FULL` synchronous durability, a fresh Python process
and new work directory per run, 1,000 records, batches of 100 and the default signed audit. The host
was already warmed by earlier development runs.

| Metric | Observed value |
| --- | ---: |
| Successful, content-correct, delivered and acknowledged | 5 of 5 runs, 1,000 of 1,000 each |
| Total measured wall time | 2.654 to 2.717 s; median 2.661 s |
| End-to-end throughput | 367.99 to 376.81 records/s; median 375.83 records/s |
| Process CPU time | median 2.453 s |
| Sampled peak RSS | median 81.33 MiB; maximum 88.73 MiB |
| Sampled RSS growth | median 15.77 MiB |
| Retained fixture and state files | median 3.014 MiB |
| Destination delivery wall time | median 0.624 s |
| Destination batch p50 / p95 | median 61.75 / 64.43 ms |
| Seal plus durable outbox batch p50 / p95 | median 88.48 / 90.18 ms |
| Acknowledgement batch p50 / p95 | median 4.58 / 4.99 ms |
| Destination rows / committed ledger rows / verified audit events | 1,000 / 1,000 / 1,000 in every run |
| Final content mismatches / outbox / relay / quarantine | 0 / 0 / 0 / 0 in every run |

The current path uses ten capability-gated atomic destination transactions and retains per-record
authentication, ledger and audit evidence. Batch latency is therefore not comparable to the older
per-record commit baseline. This is a local effect measurement, not a cross-platform promise or a
formal confidence interval. The exact five observations are retained in
[`benchmarks/results/workflow-windows-20260912.json`](../benchmarks/results/workflow-windows-20260912.json).

The final expanded failure command collected 93 tests on 2026-09-10. It passed 92 and skipped the
POSIX-only directory-fsync case on Windows, with no failures or errors in 11.839 seconds. That run
included all six manifest scenarios, a real TLS acknowledgement loss, 25 generated delivery state
machines of up to 30 steps, recipient rotation and fork tests, 10,000 differential JSON structures,
20 pinned JSONTestSuite files and seven pinned W3C CSVW sources. Pytest timing includes runner
overhead and is not comparable with the workflow benchmark. This suite does not collect CPU or RSS.

The complete release run collected 903 tests: 895 passed, eight were platform-conditional skips,
and none failed or errored in 36.425 seconds with 82 percent statement coverage. Coverage is not a
substitute for the transition-oriented security matrix.

Every run persisted a 1,015-byte recipient trust head, reopened it and verified it before source
encryption. The retained successful reports are
`.polymorph/workflow-recipient-auth-persisted-v5-20260910-1.json`,
`.polymorph/workflow-recipient-auth-persisted-v5-20260910-2.json` and
`.polymorph/workflow-recipient-auth-persisted-v5-20260910-3.json`. Retained database and trust-state
files are diagnostic artifacts and are not part of the reports.

An earlier instrumented 1,000-record run completed in 17.870 seconds at 55.96 records per second
with 92.39 MiB sampled peak RSS. Its local stream contained 1,029 structurally valid events. Event
IDs were unique, event semantics and workflow counters agreed, and the lifecycle closed cleanly.
One hundred isolated durable event appends took 69.9 ms in total, with 0.67 ms p50 and 0.86 ms p95
latency. These figures are retained as historical observer-overhead evidence, not as the current
throughput baseline or a cross-platform claim.

The combined ten-case recovery suite passed in 1.950 seconds. Ten repetitions of the eight threaded
cases passed 80 of 80 in 19.067 seconds. Ten repetitions of the two 12-process migration cases
passed 20 of 20 in 8.462 seconds across 240 child-process starts. Before the serialized migration
fix, the parallel legacy Relay
setup failed in 98 of 100 stress cycles with a duplicate-column error. After the fix, Relay and
Ledger migration use exclusive SQLite initialization transactions and preserve legacy rows.

After the Windows atomic-publication repair, 20 fresh-process repetitions of the six-writer JSON
contention case passed 20 of 20 in 37.830 seconds. Every repetition required 24 unique durable
records. This specifically guards the sharing-violation race found during this release work.

## Report safety boundaries

The workflow JSON is deliberately value-free. It contains configuration, progress counts, mapping
counts, preflight counts, content mismatch counts, storage byte counts, SQLite durability settings,
stage names, timing, CPU, optional RSS, fixed reason codes, bounded exception class names and basic
runtime versions. It does not contain generated record values, exception messages, ciphertext, key
material, a process ID or an absolute work path. The serialized `work_directory` is always null.

That does not make every adjacent artifact safe to publish:

- The retained source CSV and destination SQLite database contain the deterministic benchmark
  plaintext by design.
- Pytest failure output and JUnit reports may contain local paths, stack traces and source snippets.
- OS release, machine architecture and logical CPU count are reproducibility metadata, but can
  still contribute to machine fingerprinting.
- A third-party connector can still log data outside this report. The lab cannot prove otherwise.
- The operational event stream is payload-free but includes opaque identifiers, timestamps,
  component names, statuses and bounded reason codes. It is local operational metadata, not an
  anonymous artifact.
- Sampled RSS can miss a short peak. A missing `psutil` installation produces unavailable RSS
  fields, not a zero-memory result.
- `--tracemalloc` measures CPython allocations, omits some native allocations and materially changes
  timing. Its results must stay separate from standard mode.
- Per-call latency samples are capped at 10,000 per stage with a deterministic bounded reservoir.
  Stages called only once report null p50 and p95 instead of fake distribution statistics.

The JSON is suitable for the synthetic fixture after reviewing the environment metadata. Never
publish a retained work directory as if it were a sanitized report.

## Cold and warm measurement rules

Use these labels consistently:

- `fresh-process`: every sample starts a new Python process and a new or empty work directory.
- `first-run`: the first measured fresh-process run after installation, update or machine restart.
- `warmed-host`: a fresh-process sample after one unreported priming run. The OS file cache,
  antivirus cache and loaded native libraries may be warm even though workflow state is new.
- `same-process`: repeated Python API calls inside one interpreter. Do not compare these directly
  with CLI fresh-process results.

The reported workflow timer begins inside the benchmark call. It includes fixture generation and
all listed stages, but not Python interpreter startup, module imports or CLI argument parsing. Call
it a fresh-workflow-state measurement, not a complete command cold-start measurement.

Never reuse retained workflow state for another sample. The command rejects a non-empty work
directory for this reason. For a local smoke baseline, use at least one priming run followed by
three or more fresh-process runs with new directories, then publish every sample plus median and
range. Use at least 30 measured repetitions before treating a whole-run p95 as meaningful. Do not
mix standard and `--tracemalloc` samples.

The workflow benchmark does not load the optional mapping models because its deterministic fixture
does not need them. Model cold-start and warm-inference numbers belong to the mapping benchmark and
must be labelled separately.

## Delivery claim

The lab demonstrates duplicate suppression for the tested local path. After a destination write
is durably recorded as `committed`, redelivery of the same authenticated record returns
`duplicate` and does not write the JSON record again.

It does not guarantee a single write across every possible failure boundary. A crash or lost
acknowledgement between an external write and the durable ledger transition creates an ambiguous
or `uncertain` outcome. Polymorph then quarantines the sealed record and refuses an ordinary
non-idempotent replay. Safe recovery requires destination idempotency or an explicit
operator-authorized decision. Networked connectors, process crashes and database failover beyond
the tested local SQLite concurrency cases still need their own integration and fault-injection
evidence.
