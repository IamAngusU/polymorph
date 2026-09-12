# Polymorph Trust Center

Polymorph publishes evidence with boundaries instead of turning a green checkmark into a universal claim.

## What a release Trust Center proves

`polymorph trust` accepts a release manifest and a local validation summary. It creates `index.html` and `evidence.json` only when all of these statements are true:

- the release manifest says the source tree was clean
- validation passed
- the source was clean before and after validation
- the source commit before and after validation exactly matches the release commit
- the validation source digest did not change during the run
- the test report contains no failures or errors
- bounded workflow measurements are present

The output strips local paths and labels provenance as maintainer-controlled local evidence. It explicitly does **not** claim an independent audit, external witness, GitHub Actions run or cross-platform certification.

```powershell
polymorph trust `
  .polymorph\release\assets\release-manifest.json `
  .polymorph\validation\RUN\summary.json `
  --output .polymorph\trust\RELEASE `
  --open
```

An output directory is never overwritten. Use a new path for every evidence set.

## Try your own data without a write

The shortest useful Polymorph evaluation does not need credentials, a destination or a cloud account:

```powershell
polymorph trial C:\path\to\your-file.csv --open
```

The trial uses the existing content inspection and bounded quality scanner, then creates a local static report. The report contains schema descriptors and metadata-only quality evidence. It does not configure a destination connector, obtain write authority or make a network request. Unsupported or unsafe input fails closed.

The default report directory is `.polymorph/trials/<UTC timestamp>-<source name>`. Pass `--output` to select a new directory and tune the bounded scan with `--max-records`, `--max-samples` and `--max-groups`.

## Public release evidence

Every evidenced release publishes two deliberately separate artifacts:

- `release-manifest.json` is the SHA-256 authority for downloadable assets.
- `polymorph-trust-center.zip` is the human-readable static view plus a sanitized `evidence.json`.

Use the [GitHub releases page](https://github.com/IamAngusU/polymorph/releases) rather than a version copied into this document. Each Trust Center names its exact release, commit, host, tests, measurements and non-coverage, so this page cannot silently become stale when a newer alpha is published.

Release `0.4.0a8` is the first release carrying the Trust Center bundle. Its clean local validation bound commit `a4f58dd02ec4cc996d91c588290d6ab1b3cf08db`, recorded 1,250 passing tests and measured a three-run SQLite workflow median of 197.75 rows/s with 79.75 MiB maximum peak RSS. A separate clean-venv wheel installation and installed Trial smoke also passed. These are maintainer-controlled local observations, not an independent audit or hardware-independent performance guarantee.

The main `polymorph` command is now the primary interface. `polymorph-kit trial` and `polymorph-kit trust` remain compatible aliases for existing scripts.
