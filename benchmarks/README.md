# Benchmark corpus

`safety-smoke.json` is a tiny release smoke suite for the benchmark machinery and fail-closed policy. It is not a quality benchmark and must never be used to claim real-world mapping accuracy.

Meaningful evaluation should use source-separated customer-like corpora with explicit expected mappings and explicit `null` labels for fields that must abstain. See `docs/BENCHMARKING.md`.
