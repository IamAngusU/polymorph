# Contributing

Polymorph is security-sensitive infrastructure. Changes should preserve explicit trust boundaries and should prefer failing closed over silently altering data semantics.

## Before proposing a change

- Add or update tests for every security- or delivery-relevant behavior.
- Do not add dynamic code execution, `eval`, arbitrary SQL generation or payload-defined connector behavior.
- Do not place real credentials, private keys or customer payloads in fixtures.
- Keep semantic matching separate from execution authorization.
- Do not let model scores, file extensions or recipe history become sole authorization evidence.
- Any new file parser must document its content-identification rule, resource limits, hostile-input risks and containment expectations.
- Any new retry behavior must state whether a failed write is proven not committed, known committed or has unknown outcome.
- Any new destination-side relationship transform must prove its allowed lookup path from destination metadata or an explicit reviewed contract.
- Any new persisted store must document whether it can contain plaintext values.
- Benchmark data must be split by original source, template or organization before synthetic variants are generated, otherwise near-duplicate leakage can inflate measured accuracy.

## Local checks

```bash
python scripts/bootstrap.py --skip-models
```

That command installs the development stack and runs compile, Ruff lint and formatting, strict
mypy, pytest with warnings as errors, the mapping safety smoke and `pip check`. CI also runs the
supported Python-version matrix and package release gates on every push and pull request.
