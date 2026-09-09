# Ecosystem review

Reviewed on 2026-09-09. A useful dependency must improve a measured failure mode without becoming
new parser authority or an implicit network service.

## Keep in the current profile

| Component | Role | Decision |
| --- | --- | --- |
| [Magika](https://github.com/google/magika) | Independent file-type evidence | Keep. It may veto a conflict but never selects a parser by itself. |
| [CleverCSV](https://github.com/alan-turing-institute/CleverCSV) | Additional CSV dialect candidate | Keep. A close disagreement still abstains. |
| multilingual MiniLM | Schema descriptor retrieval | Keep the pinned local profile. |
| multilingual mMARCO cross-encoder | Ambiguous candidate reranking | Keep the pinned local profile. It cannot authorize an automatic mapping. |

No additional embedding model should be installed by default. A challenger must beat the current
pair on a held-out, source-separated corpus for safety, useful coverage, CPU support, cold and warm
latency, and peak RSS.

## Add or evaluate next

### Small regression corpora

- [csv-spectrum](https://github.com/max-mapper/csv-spectrum) is a BSD-2-Clause collection of tiny
  CSV correctness cases. It is suitable for checked-in regression fixtures with pinned provenance.
- [Magika test data](https://github.com/google/magika/tree/main/tests_data) contains compact file
  identification and polyglot regressions. Use a curated subset, never as training data.
- [Apache parquet-testing](https://github.com/apache/parquet-testing) contains valid and invalid
  Parquet files. Run dangerous cases only inside a hard-limited worker. A 4 KB fixture in that set
  intentionally expands one column chunk beyond 2 GiB.

### Encoding evidence

[charset-normalizer](https://github.com/jawah/charset_normalizer) is a small MIT-licensed candidate
for non-UTF CSV evidence. A safe integration needs an allowlist, confidence and margin thresholds,
decode/re-encode checks and stable CSV structure. Short ASCII, mixed-language and cp1252 versus
ISO-8859-1 ambiguity must abstain. User choice and BOM evidence outrank a detector.

### Parquet

[PyArrow ParquetFile](https://arrow.apache.org/docs/python/generated/pyarrow.parquet.ParquetFile.html)
is the obvious optional connector because Parquet exposes physical and logical schemas, row groups
and bounded batch iteration. It is not added to the alpha runtime yet. A single huge scalar or
nested value can still exhaust the host even when batch rows are limited. The connector therefore
belongs behind the planned parser worker with memory, CPU and wall-time limits, bounded metadata,
disabled extension loading and no URI access.

### Documents

[python-docx](https://github.com/python-openxml/python-docx) is a reasonable narrow DOCX table
extractor after the existing OOXML container checks. It must preserve merged, omitted and nested
cell uncertainty instead of flattening it into a confident matrix. Full package reads and native
XML dependencies still make an isolated worker the correct boundary.

[Docling](https://github.com/docling-project/docling) is a later PDF-table research profile, not a
core dependency. Its parser, layout and table models add hundreds of megabytes and a much larger
attack surface. Models must be explicitly prefetched, revision-pinned and hash-verified before the
first user file.

## Evaluation-only baselines

- [WDC Schema Matching Benchmark](https://webdatacommons.org/structureddata/smb/) is a strong fit
  for header-only, values-only and hybrid mapping evaluation. Its public page does not state a
  redistribution license, so fetch it for local evaluation but do not vendor it.
- [Valentine](https://github.com/delftdata/valentine) provides classical schema-matching baselines.
  Use it in the lab, not the runtime.
- [multilingual-e5-small](https://huggingface.co/intfloat/multilingual-e5-small) is a model
  challenger, not an additional default. Its documented prefixes, pooling and normalization are
  mandatory. Compare it with MiniLM before replacing anything.
- [DuckDB CSV auto detection](https://duckdb.org/docs/current/data/csv/auto_detection) can be a
  differential dialect oracle on a bounded decoded sample. Run it with extension loading, external
  access, extra threads and unbounded temp storage disabled. Its generated SQL prompt is output,
  never executable authority.
- [Microsoft Presidio](https://github.com/data-privacy-stack/presidio) may later improve local
  sensitivity classification. Start with deterministic recognizers and emit only category, count
  and confidence metadata. Never log the matching values.

## Explicit rejection for the current runtime

`python-calamine` is not safe to add in-process today. Its current Calamine backend has open cases
where tiny legal workbooks request process-killing allocations:

- [Issue 684](https://github.com/tafia/calamine/issues/684) reports roughly 96 GB from a crafted
  shared-string count.
- [Issue 693](https://github.com/tafia/calamine/issues/693) reports roughly 550 GB from legal extreme
  worksheet dimensions.
- [Fix PR 697](https://github.com/tafia/calamine/pull/697) remained open at review time.

ZIP size and compression-ratio checks do not stop either case. Reconsider only after a pinned fixed
release and then only in a crash-isolated differential worker.

Broad dispatchers such as MarkItDown, full Unstructured stacks and automatic office formula
engines are also rejected for the core. They duplicate parsers, broaden URI and plugin behavior or
execute content that Polymorph should treat as uncertainty.

## Dataset and model manifest rule

Every external model or corpus must have a machine-readable manifest containing:

- upstream URL and exact revision
- expected files, byte sizes and SHA-256 hashes
- license and redistribution decision
- intended role and explicit authority ceiling
- download mode and whether network access is required
- parser or model runtime version
- resource limits and expected failure classification

Never load pickle artifacts or enable `trust_remote_code`. Test splits do not tune thresholds. A
timeout or resource-limit exit is a classified safe outcome; a dead host is a failed parser test.
