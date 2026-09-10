# Benchmark corpora

`safety-smoke.json` is the tiny release smoke suite for the benchmark machinery.

`safety-regression.json` is the larger synthetic safety gate. It currently covers 42 cases and 45
labelled source fields across multilingual names, ambiguity, directional type compatibility,
nullability, sensitivity and role conflicts, credentials, PII, Unicode edge cases and verified
foreign-key evidence. CI requires perfect automatic precision, zero unsafe automatic decisions and
at least 70 percent automation coverage among fields explicitly eligible for automation.

Both files are synthetic regression evidence. Neither is a customer-data quality benchmark and
neither may be used to claim real-world mapping accuracy. Meaningful evaluation still needs
source-separated customer-like corpora with explicit mappings and explicit `null` labels for fields
that must abstain. See `docs/BENCHMARKING.md`.
