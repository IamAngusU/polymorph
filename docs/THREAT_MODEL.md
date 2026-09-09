# Threat model

## Protected assets

- record payload values
- passwords, tokens and connector credentials
- destination recipient private keys
- capability signing keys
- mapping authorization integrity
- destination record integrity

## Untrusted inputs

- file bytes, file names, extensions and caller-provided MIME labels
- spreadsheet cells, formulas, headers and worksheet names
- CSV fields and headers
- JSON and JSON5 keys and values
- HTTP responses
- database rows and metadata from a source system
- route-supplied identifiers
- optional model outputs and old recipe history

## Malicious or misleading files

A filename is not evidence of format. Deterministic magic and container structure select supported parsers. ZIP metadata is inspected without extraction and blocking risks stop processing before an Office parser opens the workbook.

Current checks include traversal paths, archived symlinks, duplicate normalized members, encrypted members, entry count, total expansion, individual member size, suspicious compression ratios, VBA projects and external workbook-link and data-connection parts.

Excel uses `defusedxml` hardening through openpyxl. This addresses XML entity-expansion classes that plain openpyxl does not guard against by default. Formula results are still a semantic freshness problem rather than an XML problem: openpyxl does not calculate formulas, so cached results are marked unproven and require review before automatic promotion.

Magika can add independent local classification evidence. A confident disagreement is a veto signal, not permission to trust Magika over deterministic structure.

These measures reduce parser attack surface but are not OS-level containment. A malicious parser implementation, native dependency bug or novel parser vulnerability can still affect the local process in v0.3. Hostile parser isolation is therefore a separate roadmap item.

## Control-plane or relay compromise

A relay that only receives `BlindTransportRecord` objects can observe routing metadata and ciphertext but cannot recover payload plaintext without a destination recipient private key. Relay persistence is ciphertext-only.

This property depends on deployment separation. Running source, relay and destination in one compromised process collapses those host-level trust boundaries even though the APIs remain separated.

## Source compromise

The source connector and source agent observe values before sealing. A compromised source can leak or alter those values. Preventing that requires protection upstream of Polymorph and is outside the transport protocol.

## Destination compromise

The destination agent must recover plaintext to write a destination that expects plaintext. A compromised destination can therefore observe values and misuse its authorized connector capabilities.

## Descriptor-model compromise

Optional ONNX models receive field descriptor strings only. Their interfaces do not expose record values, connector credentials or network operations. A malicious or poor model can still return misleading scores.

Model scores therefore cannot independently authorize automatic mapping. The selected automatic target must also be the independently strongest deterministic target with sufficient deterministic score and margin. A model that changes the winner produces a review-required decision.

## Recipe poisoning

Recipes are not capabilities and do not bypass validation. Selection requires matching structural source and target fingerprints. Reuse creates a new exact plan and digest, then re-validates the plan and performs preflight against current input.

The built-in SQLite recipe digest detects accidental plan corruption but is not presented as protection against a fully compromised local host. Host compromise remains a non-goal. Signed recipe provenance can be added where an operator needs cross-host recipe distribution.

## Network destinations

HTTP connectors require an explicit HTTPS base URL and keep requests on the configured host and port. Redirects and inherited proxy environment settings are disabled. DNS resolution and the security of the configured endpoint remain deployment responsibilities. Private and internal APIs are intentionally possible, so the connector does not impose a blanket public-IP-only policy.

## Database writes

SQLAlchemy reflection determines allowed target tables and columns. Foreign-key lookup tables and return columns are derived from actual constraints rather than user-supplied SQL. Database accounts should still be provisioned with least privilege because a compromised destination process operates with the connector account's effective permissions.

## Key files

The built-in recipient key file protects a raw X25519 private key with Argon2id-derived encryption. It is not equivalent to hardware-backed non-exportable key storage. A host compromise that captures the passphrase or destination process memory can recover the key.

## Remaining non-goals

- protection from a fully compromised source or destination operating system
- hostile parser containment in v0.3
- hardware-backed signing or recipient keys in the built-in implementation
- traffic-analysis resistance for routing metadata and ciphertext sizes
- arbitrary undocumented API exploration
- automatic resolution of genuinely ambiguous business semantics
- distributed consensus across multiple concurrently writable systems
