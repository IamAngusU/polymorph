# Workflow lab

The workflow lab has two jobs. The workflow benchmark measures one complete successful local data
path. The failure suite checks that uncertainty stops or reduces automation at the intended
boundary. Neither command is a production load test.

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
encryption, source signing, durable outbox staging, authenticated relay transport, destination
decryption, contract validation, real SQLite writes, delivery-ledger transitions, signed audit,
relay acknowledgement and source acknowledgement.

The final verification requires all requested destination rows and committed ledger entries,
exact values for all five fixture fields independent of relay order, empty outbox and relay queues,
empty sealed quarantine, a valid signed audit event for every delivery and absence of five known
plaintext canaries from every blind SQLite file and sidecar.

## Reproduce the failure suite

```bash
python -W error -m pytest tests/test_workflow_failure_lab.py --strict-config --strict-markers \
  --durations=0 --junitxml=./.polymorph/workflow-failure-lab.xml
```

The executable cases and expected outcomes are also listed in
[`benchmarks/workflow-failure-manifest.json`](../benchmarks/workflow-failure-manifest.json). The
manifest describes expectations. The pytest assertions are the authority for whether the current
implementation still meets them.

## Failure scenarios

| Scenario | Real path | Injected condition | Required outcome |
| --- | --- | --- | --- |
| Misleading file extension | Real file inspector and Excel connector gate | CSV content is named `orders.xlsx` | Content is identified as `delimited_text`; explicit Excel parsing is rejected before the workbook parser opens |
| Ambiguous mapping | Real `prepare` CLI, JSON inspection, matcher and plan gate | One source label ties two destination labels | Exit code 3, decision remains `review`, reason `no_auto_approved_mapping_rules`, no plan file |
| Recipe circuit | Real `prepare` CLI, preflight and SQLite recipe store | Three consecutive `required_target_null` rejection observations are inserted | Old recipe becomes `suspended`; automatic reuse is denied; a fresh validated recipe version is produced |
| Unsigned and tampered relay input | Real signing, trust store, relay policy and relay SQLite queue | One unsigned record enters ingress; one accepted signed record has its persisted signature changed | Unsigned ingress is rejected; the tampered record is never leased and is dead-lettered as `relay_source_authentication_failed` |
| Lost relay acknowledgement | Real source outbox, relay, crypto, destination runtime, ledger and JSON destination | Relay lease time is advanced after the destination commit without acknowledging the first lease | Redelivery returns `duplicate`, the ledger stays `committed`, and the JSON destination contains one record |
| Unknown destination outcome | Real crypto, destination runtime, ledger, sealed spool, signed audit and JSON file replacement | A connector wrapper raises after the real JSON replacement has completed | Receipt is `quarantined` with `write_outcome_unknown`; ledger is `uncertain`; signed audit records the reason; normal replay is refused; only one write call occurred |

The first two scenarios need no injected subsystem failure. The recipe case inserts explicit
operational outcomes. The last three keep the real security and persistence path but inject the
specific external fault under test: stored-wire tampering, lease time advancement or a lost
connector acknowledgement. No matcher, signature check, relay policy, ledger transition or replay
decision is mocked.

The file-extension case tests an explicitly selected wrong connector. Automatic CLI inspection
would select the CSV connector from the content instead of trusting the `.xlsx` suffix.

## Measured result

Three standard-mode runs on 2026-09-10 used the current Windows development machine, Python 3.11.9,
SQLite 3.45.1 with `DELETE` journal mode and `FULL` synchronous durability, a fresh Python process
and new work directory per run, 1,000 records, batches of 100 and the default signed audit. The host
was already warmed by earlier development runs.

| Metric | Observed value |
| --- | ---: |
| Successful, content-correct, delivered and acknowledged | 3 of 3 runs, 1,000 of 1,000 each |
| Total measured wall time | 16.095 / 16.231 / 16.779 s; median 16.231 s |
| End-to-end throughput | 59.60 to 62.13 records/s; median 61.61 records/s |
| Process CPU time | median 9.594 s |
| Sampled peak RSS | median 85.89 MiB; maximum 87.28 MiB |
| Sampled RSS growth | median 14.25 MiB |
| Retained fixture and SQLite files | median 2.259 MiB |
| Destination delivery wall time | median 8.382 s |
| Destination delivery p50 / p95 | median 8.22 / 9.39 ms |
| Seal plus durable outbox p50 / p95 | median 2.33 / 2.74 ms |
| Acknowledgement p50 / p95 | median 2.74 / 3.29 ms |
| Destination rows / committed ledger rows / verified audit events | 1,000 / 1,000 / 1,000 in every run |
| Final content mismatches / outbox / relay / quarantine | 0 / 0 / 0 / 0 in every run |

Destination delivery remained the largest measured stage. The benchmark exposed repeated SQL table
reflection in every destination write. Caching the immutable reflected table reduced one direct
1,000-record comparison from 18.700 to 16.866 seconds, a 9.8 percent improvement. This is a local
effect measurement, not a cross-platform promise or a formal confidence interval.

The final failure suite passed all six cases in 0.595 seconds in a separate local run. Individual
case times were 4 to 68 ms. That pytest time includes test-runner overhead and is not comparable
with the workflow benchmark. The failure suite does not currently collect CPU or RSS measurements.

The retained successful reports are `.polymorph/workflow-lab-final-1000-1.json`,
`.polymorph/workflow-lab-final-1000-3.json` and
`.polymorph/workflow-lab-final-1000-4.json`. Retained database files are diagnostic artifacts and
are not part of the reports.

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
operator-authorized decision. Networked connectors, database failover and concurrent multi-process
recovery need their own integration and fault-injection evidence.
