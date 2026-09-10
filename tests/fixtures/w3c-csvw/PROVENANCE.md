# W3C CSVW fixture provenance

This is a compact subset of the official W3C CSV on the Web test suite.

- Source: https://github.com/w3c/csvw
- Archived branch: `gh-pages`
- Pinned commit: `b3f461db0e86a68c019bc1f912e86f3555907e34`
- Commit date: 2026-05-22
- Retrieved: 2026-09-10
- License: W3C 3-clause BSD License
- Integrity: every redistributed data file is listed in `SHA256SUMS`

At the pinned commit, `tests/manifest.ttl`, the profile manifests, and
`tests/index.html` declare the CSVW tests dual-licensed under the W3C Test
Suite License and the W3C 3-clause BSD License. This redistribution uses the
3-clause BSD option. Its terms and attribution are retained in `LICENSE.txt`.

Selected upstream sources:

- `tests/test008.csv`: quoted values containing comma delimiters
- `tests/test009.csv`: a CRLF-delimited table
- `tests/test055.csv`: all-empty rows
- `tests/test091.csv`: inconsistent row widths, an approved negative test
- `tests/test125.csv`: an empty field inside a populated row
- `tests/test248.csv`: UTF-8 and deliberately distinct Unicode code points
- `tests/tree-ops.tsv`: tab delimiters, used by approved test 050

The six files under `csv/` are byte-for-byte copies of their Git blobs.
`test009.csv` is stored as a single-line base64 payload because its Git blob
uses CRLF and must survive checkout without newline rewriting. Decoding
`encoded/test009.csv.base64` yields the exact 260-byte upstream blob with
SHA-256 `696d489e33252a0e291bee583edb4fef38bd4b16ef2b03ef24b06aeeb60b43ad`.

No CSVW metadata, expected JSON/RDF, harness code, or dependencies are copied.
The regression tests exercise Polymorph's own connector contract. They do not
claim that Polymorph implements the full CSVW metadata or validation model.
For test 091, automatic dialect detection abstains; an explicit comma
configuration then parses the ragged rows and pads missing trailing cells with
nulls, which is Polymorph's intentionally narrower source contract.
