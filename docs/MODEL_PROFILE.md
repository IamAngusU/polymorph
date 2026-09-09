# Local specialist model profiles

Models are optional evidence providers. Polymorph does not require a generative model and does not send record payload values to a model interface.

## CPU-first descriptor encoder

Default optional profile:

`sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2`

Role: retrieve plausible target fields from schema descriptor text such as names, aliases, descriptions and container names.

Selected properties:

- 384-dimensional embeddings
- multilingual descriptor support
- ONNX Runtime on CPU
- native SentencePiece tokenization to keep the 250,000-piece vocabulary compact in memory
- quantized x86_64/AVX2 and ARM64 artifacts
- Apache License 2.0 upstream
- no generative decoding path in Polymorph

Pinned upstream revision:

`e8f8c211226b894fcb81acc59f3b34ba3efd5f42`

## Ambiguity reranker

Optional profile:

`cross-encoder/mmarco-mMiniLMv2-L12-H384-v1`

Role: compare only the top few target candidates when initial deterministic/embedding evidence is close. The reranker is not called for clear cases.

Selected properties:

- multilingual cross-encoder
- quantized ONNX artifacts around 119 MB
- AVX2 x86_64 and ARM64 variants
- Apache License 2.0 upstream
- no record-value interface

Pinned upstream revision:

`1427fd652930e4ba29e8149678df786c240d8825`

The reranker score is bounded into evidence used for candidate ordering. It is not treated as a calibrated probability.

## Automatic-approval rule

Neither profile is an authorization mechanism. Automatic promotion requires the selected target to also be the independently strongest deterministic target, to exceed the deterministic floor and to have a sufficient deterministic margin.

If model evidence changes the winner away from the deterministic winner, the mapping becomes review-required.

## Why not use one larger model everywhere

Larger specialist models can improve retrieval quality, but they increase startup time, memory, download size and the cost of running on ordinary CPUs. They also do not solve missing business context.

Current lab candidates include the Qwen3 0.6B embedding/reranking pair for a future precision mode. They support a much larger multilingual surface but are substantially heavier and the reranker is implemented on a causal-language-model base. They should earn inclusion by improving Polymorph's own source-separated mapping corpus without introducing incorrect automatic promotions.

`multilingual-e5-small` is another useful benchmark candidate with broad multilingual support. The current CPU-first default remains MiniLM because the upstream profile we pin provides practical quantized AVX2 and ARM64 artifacts for the architectures we want to support directly.

## Supply-chain pinning

Profile installation is pinned to exact upstream revisions. Every required ONNX, tokenizer and
configuration asset is compared with a built-in SHA-256 value. Polymorph also records those
expected hashes in `polymorph-model-manifest.json` and verifies them again before every load.

Runtime loading verifies the manifest and uses local files directly. Model weights are not redistributed in this repository.

## Resource behavior

Profile verification is eager. ONNX sessions and tokenizers are lazy, so a deterministic mapping
does not pay model startup or inference cost. The reranker is also skipped whenever deterministic
evidence is already decisive.

On the current Windows x86_64 reference machine, Python 3.11 and ONNX Runtime 1.29 produced these
local measurements:

- encoder verification only: about 33 MiB process RSS
- encoder after first inference: about 240 MiB process RSS
- seven-case safety smoke with both profiles: 73 MiB before, 424 MiB after, 435 MiB peak
- both installed profiles after removing obsolete JSON tokenizer copies: about 247 MB on disk

These numbers are evidence for one machine, not a hardware guarantee. Operators should run the
included benchmark on their target CPU and corpus. The ONNX graph optimizer, memory pattern and
prepacking defaults stay enabled because disabling them changed scores or made private-memory use
worse in local comparison runs. Only the encoder CPU memory arena is disabled, saving a modest
amount of steady RSS for a small latency cost on the reference machine.

The ARM64 artifacts are pinned and architecture-selected, but the current hosted model smoke runs
on x86_64 only. ARM64 remains unverified until a native runner executes installation and inference.
