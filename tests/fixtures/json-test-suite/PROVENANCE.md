# JSONTestSuite fixture provenance

These regression fixtures come from the official JSONTestSuite repository:

- Source: https://github.com/nst/JSONTestSuite
- Commit: `1ef36fa01286573e846ac449e8683f8833c5b26a`
- Commit date: 2024-11-22
- Retrieved: 2026-09-10
- Upstream license: MIT
- Upstream author: Nicolas Seriot
- Upstream directory: `test_parsing`
- Integrity: every redistributed JSON file is listed in `SHA256SUMS`

The selected files are exact byte-for-byte copies from the pinned commit. The
subset covers valid record-shaped JSON, valid non-record JSON roots, duplicate
object keys, Unicode and escapes, malformed numbers, truncated containers, and
an implementation-defined nesting case. No upstream runner, executable, or
dependency is vendored.

Upstream prefixes have their original meaning:

- `y_` files must be accepted by an RFC 8259 parser.
- `n_` files must be rejected by an RFC 8259 parser.
- `i_` files have implementation-defined outcomes.

Polymorph intentionally adds a record protocol after JSON syntax parsing. A
valid scalar or a heterogeneous array is therefore valid JSON but not a valid
Polymorph record source. Polymorph also rejects duplicate object keys so a
silent last-key-wins interpretation cannot alter mappings. The included `i_`
case is observed across the content inspector and connector without assigning
it an upstream conformance verdict.
