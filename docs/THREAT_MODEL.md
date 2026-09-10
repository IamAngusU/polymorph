# Threat model

## Protected assets

- record payload values
- passwords, tokens and connector credentials
- destination recipient private keys
- destination identity-signing private keys
- source record-signing keys
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

Current checks include traversal paths, archived symlinks, duplicate normalized members, encrypted members, entry count, total expansion, individual member size, suspicious compression ratios, VBA projects and external workbook-link and data-connection parts. JSON item counts and XML element, depth and per-element attribute counts are bounded before recursive or attribute-materializing parsers run.

Excel uses `defusedxml` hardening through openpyxl. This addresses XML entity-expansion classes that plain openpyxl does not guard against by default. Formula results are still a semantic freshness problem rather than an XML problem: openpyxl does not calculate formulas, so cached results are marked unproven and require review before automatic promotion.

Magika can add independent local classification evidence. A confident disagreement is a veto signal, not permission to trust Magika over deterministic structure.

These measures reduce parser attack surface but are not complete OS-level containment. The optional
content-inspection worker can enforce a strict Linux boundary around deterministic detection,
archive inspection and Magika. Schema parsers and record iteration still run in the local process,
so a malicious parser implementation, native dependency bug or novel parser vulnerability can
still affect that process. Moving the remaining parser stages behind the snapshot worker remains a
roadmap item.

## Control-plane or relay compromise

A relay that only receives `BlindTransportRecord` objects can observe routing metadata and ciphertext but cannot recover payload plaintext without a destination recipient private key. Relay persistence is ciphertext-only.

Protocol v3 records carry an Ed25519 signature from a key independently bound to their tenant and
source connector. The destination repeats verification, so a relay cannot invent source provenance
or bypass a hard-revoked source key. Unsigned v2 acceptance is a temporary, explicit migration
exception and removes this property for the affected route.

A control plane could otherwise replace the destination X25519 public key and make an honest
source encrypt correctly signed records to an attacker. Protocol-v3 sources now reject raw
recipient keys by default. They accept only a certificate signed by a separately pinned Ed25519
destination identity and bound to the exact tenant and destination connector. Certificate
generations form an exact predecessor chain. A compromised control plane can withhold a valid
rotation and cause an availability failure, but cannot forge a replacement key without the
destination identity signer.

The identity trust anchor must be provisioned independently. If it is fetched from the same
compromised control plane as the certificate, the authenticity property collapses. A durable local
head rejects ordinary replay after restart, but rollback of that host state itself is not detectable
without an external monotonic checkpoint or hardware-backed counter.

This property depends on deployment separation. Running source, relay and destination in one compromised process collapses those host-level trust boundaries even though the APIs remain separated.

## Source compromise

The source connector and source agent observe values before sealing. A compromised source can leak
or alter those values and can produce valid records under its own authorized identity. Source
authentication prevents another source or a relay from impersonating that identity, but does not
make a compromised source honest. Preventing upstream compromise is outside the transport protocol.

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
- hostile containment of schema parsing and record iteration in the current alpha
- hardware-backed signing or recipient keys in the built-in implementation
- authenticated distribution and rollback protection for source trust bundles
- external monotonic checkpoints for recipient trust-state rollback
- destination identity-key rotation and emergency recipient revocation without a replacement
- traffic-analysis resistance for routing metadata and ciphertext sizes
- arbitrary undocumented API exploration
- automatic resolution of genuinely ambiguous business semantics
- distributed consensus across multiple concurrently writable systems
