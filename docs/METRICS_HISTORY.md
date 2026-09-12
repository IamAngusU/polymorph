# Run metrics history

`scripts/run_metrics.py` collects the sanitized share reports retained by
Polymorph Run. It backfills every available run, deduplicates by run ID, and
keeps the complete timeline instead of replacing the previous point.

Collected fields include timestamps, total and per-step duration, run status,
commit, package size, Python and hardware class, test counts, workflow rows per
second, wall time, peak RSS, laboratory cases and verified rows, automation
coverage and precision, campaign rounds and updates, CPU/GPU use, validation
accuracy, and paired candidate gains or regressions.

The automatic local outputs are:

- `.polymorph/metrics/run-history.jsonl`
- `.polymorph/metrics/latest.json`
- `.polymorph/metrics/performance-history.svg`

To refresh the tracked, sanitized GitHub-ready copies explicitly:

```powershell
python scripts/run_metrics.py --project "D:\polymorph" --export-public
```

This writes `benchmarks/results/run-history.jsonl` and
`docs/assets/performance-history.svg`. It deliberately does not run `git add`,
commit, push, or upload. Review the diff before publication because CPU/GPU model
names and performance history are useful benchmark context but still describe
the local machine.

The SVG is light-mode, dependency-free, and renders directly on GitHub. The
JSONL is the durable source for future graphs; the image can always be rebuilt.
Measurements remain local, synthetic, and hardware-specific rather than a
production performance or security guarantee.
