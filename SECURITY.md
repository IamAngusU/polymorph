# Security

Polymorph is security-sensitive infrastructure. Do not place production credentials, plaintext payloads, private keys or customer data in issues, commits, fixtures or debug output.

## Reporting

Report security issues privately through the contact channel published at https://angusu.de. Avoid opening a public issue for a suspected vulnerability until a coordinated disclosure path has been agreed.

## Security invariants

1. The control plane does not require record payload values to create or validate a mapping plan.
2. File names, extensions and caller-provided MIME labels are never parser-selection authority.
3. Blocking content risks stop a file before a supported parser is invoked. High-confidence disagreement between independent content detectors blocks automatic parser selection by default.
4. ZIP and OOXML inspection rejects traversal, archived symlinks, duplicate normalized members, encrypted members, suspicious expansion, macros and external workbook-link and data-connection parts by default.
5. Excel parsing requires openpyxl XML hardening through `defusedxml`. Formula caches are freshness-unproven and cannot silently auto-promote a new route.
6. Secret and opaque values cannot be routed into lower-sensitivity destinations by policy.
7. Semantic encoders and rerankers accept descriptor text only. They have no connector, credential or record-value interface.
8. Model evidence cannot independently authorize an `AUTO` mapping. Automatic mapping requires independently strong deterministic evidence and margin.
9. Executable transformations come from a fixed registry. Input content cannot add code or SQL.
10. Recipes are candidate memory, not authorization. Every activation is rebound to current exact schemas, receives a new plan digest and passes validation and preflight again.
11. A sampled preflight cannot automatically promote or remember a route. Automatic promotion requires a complete no-write preflight.
12. Blind transport authenticates route, record, field, transfer, schema and plan metadata together with the ciphertext.
13. The sealed relay queue has no recipient private-key parameter or decrypt method.
14. Schema drift cannot silently change sensitivity or invalidate an approved foreign-key lookup proof.
15. A write with unknown durability is never treated as safely retryable merely because an exception occurred.
16. Exact duplicate deliveries are detected before a second decrypt/write attempt once a commit is recorded.
17. Quarantine and audit persistence accept machine-readable metadata and sealed records, not arbitrary payload-bearing exception text.
18. Connector credentials are represented by references when a secret provider is used and are never serialized into mapping plans.
19. Recipient private-key files are encrypted and created with restrictive POSIX permissions where supported.

## Parser containment

The v0.3 content gate and contract preflight are not a claim of hostile-code operating-system containment. Supported parsers execute in the local Polymorph process after the input gate accepts them. Resource limits, archive checks and hardened XML parsing reduce risk but do not replace a process sandbox.

`polymorph doctor` reports whether Bubblewrap or Firejail is available but does not treat their presence as an active security boundary. Parser-worker isolation is planned as a separate, explicit capability so unsupported hosts do not receive a false security claim.

## Key material

The built-in encrypted recipient key file is a software key store, not an HSM. Its protection depends on the passphrase, host security and the availability of Argon2id in the deployed cryptographic backend. Deployments that require hardware-backed keys should provide a destination process that obtains private-key operations from an OS keystore, HSM or equivalent trusted component.

## Dependencies

Optional semantic models are not redistributed in this repository. Their installers pin upstream revisions and verify selected ONNX model hashes. Runtime dependencies retain their upstream security and patch requirements.
