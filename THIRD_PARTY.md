# Third-party components

Polymorph itself is licensed separately under the terms in `LICENSE`.

## Optional research descriptor encoder

- Component: `sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2`
- Upstream: https://huggingface.co/sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2
- Upstream license: Apache License 2.0
- Pinned profile revision: `e8f8c211226b894fcb81acc59f3b34ba3efd5f42`
- Model weights are downloaded explicitly by the operator and are not redistributed in this repository.
- Training provenance: Sentence Transformers documents the English teacher model as trained on
  several datasets including `msmarco-triplets`, and documents this profile as its multilingual
  distilled version. Microsoft's official MS MARCO terms restrict that dataset to noncommercial
  research. This profile is excluded from default bootstrap and the recommended commercial path
  pending a separate rights review.
- Training documentation: https://sbert.net/examples/sentence_transformer/training/paraphrases/README.html
- Dataset terms: https://microsoft.github.io/msmarco/Notice.html

## Optional ambiguity reranker

- Component: `cross-encoder/mmarco-mMiniLMv2-L12-H384-v1`
- Upstream: https://huggingface.co/cross-encoder/mmarco-mMiniLMv2-L12-H384-v1
- Upstream license: Apache License 2.0
- Pinned profile revision: `1427fd652930e4ba29e8149678df786c240d8825`
- Model weights are downloaded explicitly by the operator and are not redistributed in this repository.
- Training provenance: the model card documents mMARCO/MS MARCO. Microsoft's official MS MARCO
  terms restrict the dataset to noncommercial research. This profile is excluded from default
  bootstrap and the recommended commercial path pending a separate rights review.
- Dataset terms: https://microsoft.github.io/msmarco/Notice.html

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

## Optional model tokenization

- Component: SentencePiece
- Upstream: https://github.com/google/sentencepiece
- Upstream license: Apache License 2.0
- Purpose: compact local tokenization for the pinned XLM-R-compatible model profiles.

## Optional benchmark process metrics

- Component: psutil
- Upstream: https://github.com/giampaolo/psutil
- Upstream license: BSD 3-Clause
- Purpose: opt-in RSS measurements during explicit benchmark commands only.

## Linux parser sandbox

- Component: Bubblewrap 0.12.0 or newer
- Upstream: https://github.com/containers/bubblewrap
- Upstream license: LGPL-2.0-or-later
- Purpose: optional operating-system containment for the content-inspection worker on Linux.
- Distribution: Polymorph does not bundle the binary. The strict CI job builds a checksum-pinned
  upstream release and records the resulting toolchain evidence.

## CSV parser regression fixtures

- Component: csv-spectrum 2.0.0
- Upstream: https://github.com/max-mapper/csv-spectrum
- Pinned commit: `d30e80f8b99d2eecb3778f1d7b9ed1cb425502ec`
- Upstream license declaration: BSD-2-Clause
- Upstream author: Max Ogden
- Purpose: 11 small CSV and expected-JSON pairs used as test fixtures only.
- Provenance and exact SHA-256 checksums: `tests/fixtures/csv-spectrum/PROVENANCE.md`
- Redistributed license terms: `tests/fixtures/csv-spectrum/LICENSE.txt`
- No JavaScript code or npm dependency is included.

## JSON parser regression fixtures

- Component: JSONTestSuite
- Upstream: https://github.com/nst/JSONTestSuite
- Pinned commit: `1ef36fa01286573e846ac449e8683f8833c5b26a`
- Upstream license: MIT License
- Upstream author: Nicolas Seriot
- Purpose: 20 small parser-boundary fixtures used in tests only.
- Provenance and exact SHA-256 checksums: `tests/fixtures/json-test-suite/PROVENANCE.md`
- Redistributed license terms: `tests/fixtures/json-test-suite/LICENSE.txt`
- No upstream runner or executable code is included.

## CSVW parser regression fixtures

- Component: W3C CSV on the Web test suite
- Upstream: https://github.com/w3c/csvw
- Pinned archived commit: `b3f461db0e86a68c019bc1f912e86f3555907e34`
- Redistribution license: W3C 3-Clause BSD License
- Copyright: World Wide Web Consortium
- Purpose: seven small CSV/TSV parser-boundary sources used in tests only.
- Provenance and exact SHA-256 checksums: `tests/fixtures/w3c-csvw/PROVENANCE.md`
- Redistributed license terms: `tests/fixtures/w3c-csvw/LICENSE.txt`
- No metadata, expected RDF, harness code or dependency is included.

## Runtime dependencies

Python dependencies listed in `pyproject.toml` retain their respective upstream licenses. Optional extras are not bundled merely by cloning this repository.
