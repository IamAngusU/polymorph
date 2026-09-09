# Contributing

Polymorph is security-sensitive infrastructure. Changes should preserve explicit trust boundaries and should prefer failing closed over silently altering data semantics.

## External contributions

Issues, design feedback, test cases and responsible security reports are welcome. Before sending a
code contribution, open an issue or contact the maintainer first.

The project combines a public noncommercial license with separately negotiated commercial
licenses. Third-party code cannot be merged until a contributor agreement covering that licensing
model has been reviewed and accepted by both sides. This file is not that agreement. Unsolicited
pull requests may be discussed, but should not be expected to merge until that process exists.

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
