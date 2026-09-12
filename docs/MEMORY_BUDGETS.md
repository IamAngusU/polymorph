# RAM budgets and adaptive batch recommendations

Polymorph can choose a workflow batch size from measurements made on the same
machine. The operator remains in control of the maximum advisory RAM budget.
The recommendation keeps signed audit and durable workflow behavior enabled.

No model, network service or GPU is used by the advisor.

## Quick recommendation

Use the newest local performance matrix and a user-selected 128 MiB budget:

```powershell
polymorph-memory recommend --max-ram-mib 128
```

`python -m polymorph.memory_advisor` remains an equivalent portable fallback.

If `--max-ram-mib` is omitted, Polymorph makes a conservative first estimate
from currently available system memory. The detected memory, budget source and
complete decision are included in the JSON response.

Automatic discovery prefers the newest matrix with at least three runs per
profile. If no such publishable matrix exists, it uses the newest preliminary
matrix and labels that evidence level explicitly.

Recommendations require an exact calibration contract match. The contract binds
the evidence to Polymorph version and runtime bytes, Python, OS, architecture,
CPU fingerprint, installed RAM, SQLite, connector, durability, signed-audit
mode, event budget and synthetic record shape. A mismatch returns `stale` and
requires recalibration. `--allow-stale` exists only as an explicit diagnostic
override and is never selected automatically.

## Calibrate this machine

Run the secure local SQLite workflow for the standard candidate batches and
store machine-readable evidence:

```powershell
polymorph-memory calibrate --max-ram-mib 128
```

Use three repetitions when publishing or comparing performance evidence:

```powershell
polymorph-memory calibrate `
  --max-ram-mib 128 `
  --records 5000 `
  --runs 3
```

A one-run calibration is intentionally labelled `preliminary`. It is useful for
a fast first estimate, but it does not replace an existing three-run profile as
the default recommendation source.

The default artifact location is:

```text
.polymorph/performance-matrix/<UTC timestamp>/matrix.json
```

Every run retains wall time, CPU time, peak RSS, throughput, storage size and
per-stage p50/p95 latency. Raw benchmark reports remain inside the local matrix
so later graphing does not require rerunning old releases.

## Selection policy

The advisor applies the following deterministic policy:

1. Add 15 percent headroom to the maximum observed RSS for every profile.
2. Reject profiles whose required budget exceeds the operator budget.
3. Find the fastest eligible profile.
4. Consider profiles within 2 percent of that speed near-optimal.
5. Select the lowest-memory near-optimal profile.

This policy selects batch 500 rather than batch 1000 on the current reference
machine because their throughput is close while batch 1000 consumes materially
more memory.

Both percentages are explicit CLI options. The JSON evidence records the exact
values used for every decision.

## Important boundary

`--max-ram-mib` is currently an advisory admission and tuning budget. It is not
an operating-system hard memory limit. Calibration can discover that a profile
is too large only after observing that run. The command then excludes larger
candidates, but it cannot retroactively prevent the observed peak.

A hard process or process-tree boundary requires a separately tested host
control such as a Windows Job Object or cgroup v2. Until such a boundary is
implemented and verified, reports deliberately contain:

```json
{
  "advisory_only": true,
  "hard_limit_enforced": false
}
```

Recalibrate after changing hardware, Python, Polymorph, payload shape, connector
or durability policy. A profile from another machine is evidence for that
machine, not a portable RAM guarantee.
