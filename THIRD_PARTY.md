# Third-party components

Polymorph itself is licensed separately under the terms in `LICENSE`.

## Optional descriptor encoder

- Component: `sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2`
- Upstream: https://huggingface.co/sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2
- Upstream license: Apache License 2.0
- Pinned profile revision: `e8f8c211226b894fcb81acc59f3b34ba3efd5f42`
- Model weights are downloaded explicitly by the operator and are not redistributed in this repository.

## Optional ambiguity reranker

- Component: `cross-encoder/mmarco-mMiniLMv2-L12-H384-v1`
- Upstream: https://huggingface.co/cross-encoder/mmarco-mMiniLMv2-L12-H384-v1
- Upstream license: Apache License 2.0
- Pinned profile revision: `1427fd652930e4ba29e8149678df786c240d8825`
- Model weights are downloaded explicitly by the operator and are not redistributed in this repository.

## Optional file identification

- Component: Magika
- Upstream: https://github.com/google/magika
- Upstream license: Apache License 2.0
- Purpose: independent local file-content classification evidence. It is not parser authority.

## Optional messy-CSV dialect evidence

- Component: CleverCSV
- Upstream: https://github.com/alan-turing-institute/CleverCSV
- Upstream license: MIT License
- Purpose: an additional candidate in the bounded dialect ensemble. It is not trusted alone.

## Optional benchmark process metrics

- Component: psutil
- Upstream: https://github.com/giampaolo/psutil
- Upstream license: BSD 3-Clause
- Purpose: opt-in RSS measurements during explicit benchmark commands only.

## Runtime dependencies

Python dependencies listed in `pyproject.toml` retain their respective upstream licenses. Optional extras are not bundled merely by cloning this repository.
