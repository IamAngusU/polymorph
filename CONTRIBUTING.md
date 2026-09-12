# Contributing

<p align="center">
  <strong>English</strong> · <a href="CONTRIBUTING.de.md">Deutsch</a>
</p>

Polymorph is security-sensitive infrastructure. Contributions are welcome, but the bar is intentionally higher than "the happy path passed on my machine".

A change should preserve explicit trust boundaries, keep uncertainty visible and prefer failing closed over silently changing data semantics. If a patch makes the system more helpful by guessing, it is probably helping in the wrong direction.

## External contributions

Issues, design feedback, reproducible test cases and responsible security reports are welcome.

Polymorph is publicly licensed under AGPL-3.0-only and may also be offered under separate commercial terms. To preserve that dual-licensing model, substantive third-party code cannot be merged until a contributor agreement gives the maintainer sufficient rights to publish the contribution under AGPL and include it in alternative commercial licenses.

Before sending a code contribution, open an issue or contact the maintainer first.

This file is not the contributor agreement. A pull request is also not a surprise copyright assignment. Until that process exists and has been accepted for a contribution, unsolicited PRs may be useful for discussion but should not be expected to merge.

## Before proposing a change

- Add or update tests for every security-, persistence- or delivery-relevant behavior.
- Keep semantic matching separate from execution authorization.
- Do not let model scores, file extensions, MIME labels, parser success or recipe history become sole authorization evidence.
- Do not add dynamic code execution, `eval`, arbitrary SQL generation or payload-defined connector behavior.
- Do not place real credentials, private keys, access tokens or customer payloads in fixtures, logs, issues or commits.
- Any new file parser must document its content-identification rule, resource limits, hostile-input risks and containment expectations.
- Any new retry behavior must state whether a failed write is proven `NOT_COMMITTED`, known committed or has `UNKNOWN` outcome.
- Any new destination-side relationship transform must prove its allowed lookup path from destination metadata or an explicit reviewed contract.
- Any new persisted store must document whether it can contain plaintext values.
- Any new automatic promotion rule must identify the independent evidence that authorizes it. "The score was high" is not independent evidence. It is a number with good posture.
- Benchmark data must be split by original source, template or organization before synthetic variants are generated. Near-duplicate leakage makes charts happier and conclusions worse.

## Changes to trust boundaries

If a change touches encryption, signatures, identity binding, replay, leases, capabilities, parser containment, secret handling or destination writes, document:

1. what is trusted before the change
2. what becomes trusted after the change
3. what evidence crosses the boundary
4. what happens when that evidence is missing, stale or contradictory
5. how the failure path is tested

A new abstraction is not a security argument. Neither is a class named `SafeSomething`.

## Parsers and hostile input

File parsing is an attack surface.

A parser contribution should include malformed and resource-hostile fixtures where practical, explicit byte or record budgets, and a clear statement of its containment grade. A parser running in another process is process separation. It becomes a sandbox only when the operating-system boundary actually enforces that claim.

File extensions remain decorative metadata. They are allowed to be correct. They are not required to be.

## Mapping and models

Models may improve retrieval, ranking and operator ergonomics. They may not silently become authorization.

An `AUTO` decision must still satisfy the current deterministic and policy gates. If model evidence changes the winner away from the independently strongest deterministic target, review is the expected result, not an invitation to lower a threshold until CI becomes green again.

## Delivery and retry semantics

External side effects deserve boring state machines.

If a connector cannot prove whether a write committed, the outcome is `UNKNOWN`. Do not convert it to retry-safe because an exception was raised, a socket closed or retrying would be convenient.

Any change to replay behavior must preserve durable provenance and idempotency assumptions across restart. Yesterday's successful retry path was also a different day.

## Benchmarks

Performance changes should keep correctness assertions in the benchmark.

Please report the connector, durability mode, batch size, record shape, record count and machine context for retained measurements. Do not compare `--tracemalloc` runs to normal runs as if instrumentation overhead had politely disappeared.

Faster by removing durability, validation or evidence checks is not an optimization. Removing brakes also improves vehicle mass.

## Local checks

The normal model-free development path is:

```bash
python scripts/bootstrap.py --skip-models
```

That command installs the development stack and runs compile checks, Ruff lint and formatting, strict mypy, pytest with warnings as errors, the mapping safety smoke and `pip check`.

The repository contains a prepared Python-version matrix and package release gates, but GitHub Actions are currently disabled repository-wide. Published alpha evidence is produced by the documented local validation and manual release process. Do not interpret a workflow file as proof that a public run occurred.

Before opening a PR, the expectation is simple: the relevant tests pass, new behavior is covered, and the documentation still tells the truth.

## Security reports

Do not open a public issue for a suspected vulnerability. Use the private reporting path described in [SECURITY.md](SECURITY.md).

## License

The public project license is AGPL-3.0-only. A contributor agreement may additionally grant the maintainer the rights needed to offer the contribution under alternative commercial terms; a PR alone does not do that job.

See [LICENSING.md](LICENSING.md) and [`LICENSE`](LICENSE).
