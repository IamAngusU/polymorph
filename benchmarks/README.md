# Benchmark corpora

These fixtures exist to answer a narrow question:

> When Polymorph releases a decision as `AUTO`, was that decision wrong on the labelled operating domain?

They do **not** answer whether Polymorph will correctly understand every customer export, every spreadsheet layout or every creatively named field someone has produced since Excel became culturally unavoidable.

That distinction matters.

A review-required result is not a correctness failure. An unsafe automatic decision is.

## `safety-smoke.json`

The tiny release smoke suite for the benchmark machinery.

Use it to verify that the benchmark path itself still behaves as expected without pretending a small fixture set says anything profound about real-world mapping quality.

## `safety-regression.json`

The larger synthetic safety gate.

It currently covers **42 cases and 45 labelled source fields** across:

- multilingual names
- ambiguous candidates
- directional type compatibility
- nullability conflicts
- sensitivity and role conflicts
- credentials and PII
- Unicode edge cases
- verified foreign-key evidence
- explicitly unmappable fields that should abstain

CI currently requires:

- perfect observed automatic precision on the checked-in corpus
- zero unsafe automatic decisions
- at least 70% automation coverage among fields explicitly eligible for automation

The important word is **observed**.

A benchmark can prove what happened on its corpus. It cannot prove that next Tuesday's customer workbook will be spiritually identical to it.

Yesterday's successful mapping is useful evidence. Yesterday was also a different day.

## What these corpora are not

Both files are synthetic regression evidence.

Neither is:

- a customer-data quality benchmark
- a claim of universal semantic accuracy
- proof that a model understands business meaning
- permission to raise automation thresholds because a chart became green

Meaningful product evaluation still needs source-separated, customer-like corpora with explicit mappings and explicit `null` labels for fields that must abstain.

The target is not "make the system say yes more often".

The target is to increase coverage **without adding an unsafe `AUTO` decision**.

If an extra model makes the same decisions while consuming more time and memory, it has successfully converted additional electricity into heat. That is a benchmark result too.

See [`docs/BENCHMARKING.md`](../docs/BENCHMARKING.md) for methodology and [`docs/PERFORMANCE_BASELINE.md`](../docs/PERFORMANCE_BASELINE.md) for retained measurements and caveats.

## Growing independent evidence

`community-corpus-template.json` is a shape for independently labelled contributions, not another
release score. Keep each source family, export template and time period together when assigning
train, development and holdout splits. Include explicit abstention labels and a provenance sidecar.

The evidence levels, privacy rules and required metadata are defined in
[`docs/WORLD_READINESS.md`](../docs/WORLD_READINESS.md). A useful corpus expands domains and failure
modes; duplicating easy aliases only makes the chart greener.
