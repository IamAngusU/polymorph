# Measurement schema

Polymorph retains two complementary local histories.

## Functional run history

`scripts/run_metrics.py` backfills Buddy reports into:

```text
.polymorph/metrics/run-history.jsonl
```

It records functional status, step timings, benchmark throughput, test and lab counts, mapping
quality, training comparison and the machine inventory found in each retained report.

## Observed process history

`scripts/observe_run.py` writes one `polymorph.observed-run` JSON document and can append it to:

```text
.polymorph/metrics/observed-runs.jsonl
```

Version 1 retains:

- UTC start and end timestamps and duration
- exact argument vector and exit code
- OS, Python, architecture, processor, CPU counts and total RAM
- sample interval and sample count
- peak process-tree RSS and CPU percentage
- NVIDIA inventory when `nvidia-smi` is available
- best-effort process-attributed NVIDIA VRAM
- device-wide peak VRAM and utilization, explicitly labelled as device-wide
- observer limitations

The command is opt-in because sampling has overhead. It never uploads data.

## One-command evidence

On Windows:

```bat
World-Benchmark.cmd
```

Portable form:

```bash
python scripts/evidence_bundle.py --project .
```

The command runs the real 1,000-row workflow and mapping safety corpus, creates checksummed JSON
evidence under `.polymorph/evidence/<UTC timestamp>/`, appends observed resource history and refreshes
local Buddy history when available.

Use `--export-public` only when intentionally refreshing checked-in public graph inputs. It still
does not commit or upload anything.

## Interpretation rules

- RSS and CPU peaks are sampled estimates, not hardware-counter maxima.
- Process CPU can exceed 100 percent on a multi-core machine.
- NVIDIA WDDM may hide per-process VRAM from `nvidia-smi`.
- Device-wide VRAM includes browsers, desktops and unrelated workloads.
- Compare throughput only when records, batch size, checks and observer mode match.
- Public reports need machine, version, corpus, timestamp and limitations beside the number.
- Preserve raw JSON. Future graph designs can change; lost observations cannot be reconstructed.
