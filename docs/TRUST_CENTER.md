# Polymorph Trust Center

Polymorph publishes evidence with boundaries instead of turning a green checkmark into a universal claim.

## What a release Trust Center proves

`polymorph-kit trust` accepts a release manifest and a local validation summary. It creates `index.html` and `evidence.json` only when all of these statements are true:

- the release manifest says the source tree was clean
- validation passed
- the source was clean before and after validation
- the source commit before and after validation exactly matches the release commit
- the validation source digest did not change during the run
- the test report contains no failures or errors
- bounded workflow measurements are present

The output strips local paths and labels provenance as maintainer-controlled local evidence. It explicitly does **not** claim an independent audit, external witness, GitHub Actions run or cross-platform certification.

```powershell
polymorph-kit trust `
  .polymorph\release\assets\release-manifest.json `
  .polymorph\validation\RUN\summary.json `
  --output .polymorph\trust\RELEASE `
  --open
```

An output directory is never overwritten. Use a new path for every evidence set.

## Try your own data without a write

The shortest useful Polymorph evaluation does not need credentials, a destination or a cloud account:

```powershell
polymorph-kit trial C:\path\to\your-file.csv --open
```

The trial uses the existing content inspection and bounded quality scanner, then creates a local static report. The report contains schema descriptors and metadata-only quality evidence. It does not configure a destination connector, obtain write authority or make a network request. Unsupported or unsafe input fails closed.

The default report directory is `.polymorph/trials/<UTC timestamp>-<source name>`. Pass `--output` to select a new directory and tune the bounded scan with `--max-records`, `--max-samples` and `--max-groups`.

## Current public evidence

Release `0.4.0a7` was locally validated on Windows / AMD64 / Python 3.11.9 at commit `8ea3edd401a116138e41638c9c6befdadb55a082`:

- 1,246 tests passed
- 8 tests were explicitly skipped
- 0 failures and 0 errors
- three SQLite workflow measurements: 188.07 to 190.64 rows/s
- maximum measured peak RSS: 79.73 MiB

These figures came from one maintainer-controlled machine while the host was under material unrelated load. They are useful run evidence, not a hardware-independent performance guarantee. The validation did not cover other operating systems, live PostgreSQL, release-package installation or full parser OS isolation.

Release asset hashes remain the verification authority. See the matching `release-manifest.json` attached to the GitHub release.
