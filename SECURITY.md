# Security

Polymorph is security-sensitive infrastructure. Do not place production credentials, plaintext payloads, private keys or customer data in issues, commits, fixtures or debug output.

See [Security coverage and resource boundaries](docs/SECURITY_COVERAGE.md) for the enforced
defaults, their automated evidence and the aggregate limits that are still open.

## Reporting

Report security issues privately to [hello@angusu.de](mailto:hello@angusu.de) or through the contact
form at https://angusu.de. Avoid opening a public issue for a suspected vulnerability until a
coordinated disclosure path has been agreed.

## Supported versions

Only the current `main` branch and the newest published alpha receive security fixes. Older alpha
snapshots, including 0.3.x and earlier, are unsupported and should not be deployed.

## Security invariants

1. The control plane does not require record payload values to create or validate a mapping plan.
2. File names, extensions and caller-provided MIME labels are never parser-selection authority.
3. Blocking content risks stop a file before a supported parser is invoked. High-confidence disagreement between independent content detectors blocks automatic parser selection by default.
4. ZIP and OOXML inspection rejects traversal, archived symlinks, duplicate normalized members, encrypted members, suspicious expansion, macros and external workbook-link and data-connection parts by default.
5. Accepted CSV, JSON and Excel input is bound to the device, inode, size and nanosecond modification time of the actual opened handle before parser handoff.
6. Excel parsing requires openpyxl XML hardening through `defusedxml`. Formula caches are freshness-unproven and cannot silently auto-promote a new route.
7. Secret and opaque values cannot be routed into lower-sensitivity destinations by policy.
8. Semantic encoders and rerankers accept descriptor text only. They have no connector, credential or record-value interface.
9. Model evidence cannot independently authorize an `AUTO` mapping. Automatic mapping requires independently strong deterministic evidence and margin.
10. Executable transformations come from a fixed registry. Input content cannot add code or SQL.
11. Recipes are candidate memory, not authorization. Every activation is rebound to current exact schemas, receives a new plan digest and passes validation and preflight again.
12. A sampled preflight cannot automatically promote or remember a route. Automatic promotion requires a complete no-write preflight.
13. Blind transport authenticates route, record, field, transfer, schema and plan metadata together with the ciphertext.
14. Protocol v3 additionally authenticates the source with an Ed25519 key independently bound to its tenant and connector. Unsigned v2 intake is fail-closed unless every boundary explicitly enables migration mode.
15. Protocol-v3 sources reject unauthenticated destination recipient keys by default. Accepted keys are signed by an independently pinned destination identity, bound to the route and advanced through an exact monotonic predecessor chain.
16. The sealed relay queue has no recipient private-key parameter or decrypt method. Ack and release require the current unexpired random lease token.
17. Schema drift cannot silently change sensitivity or invalidate an approved foreign-key lookup proof.
18. The destination runtime checks the exact plan and target schema plus required fields, nullability and runtime types before writing.
19. A write with unknown durability is never treated as safely retryable merely because an exception occurred.
20. Exact duplicate deliveries are detected before a second decrypt/write attempt once a commit is recorded.
21. Quarantine and audit persistence accept machine-readable metadata and sealed records, not arbitrary payload-bearing exception text.
22. CSV destinations reject spreadsheet formula-like values by default. Enabling them is an explicit connector policy.
23. Connector credentials are represented by references when a secret provider is used and are never serialized into mapping plans.
24. Recipient private-key files are encrypted, created without overwriting an existing key and use restrictive POSIX permissions where supported.

## Parser containment

The content gate and contract preflight are not by themselves a claim of hostile-code
operating-system containment. Polymorph now has a fail-closed worker for the content-inspection
stage. It parses an exact-byte snapshot under an explicitly reported containment level. The strict
Linux backend uses Bubblewrap; a plain child process is never labelled as a filesystem or network
sandbox.

The Bubblewrap backend requires a non-setuid and non-setgid Bubblewrap 0.12.0 or newer. Older
versions are rejected because 0.12.0 fixes an upstream sandbox-setup
[symlink escape](https://github.com/containers/bubblewrap/security/advisories/GHSA-pxhw-h44j-8pfx).
Run Polymorph under a dedicated unprivileged service account. Binary discovery and a version check
are not treated as proof that the host kernel permits the requested namespace boundary; the worker
must launch successfully.

Supported schema parsers and record iterators still run in the local Polymorph process. Resource
limits, archive checks, hardened XML parsing and isolated content detection reduce risk but do not
yet contain that complete path. `polymorph doctor` reports concrete worker capabilities and keeps
binary presence distinct from a successfully exercised security boundary. See
[Parser isolation](docs/PARSER_ISOLATION.md).

## Key material

The built-in encrypted recipient key file is a software key store, not an HSM. Its protection depends on the passphrase, host security and the availability of Argon2id in the deployed cryptographic backend. Deployments that require hardware-backed keys should provide a destination process that obtains private-key operations from an OS keystore, HSM or equivalent trusted component.

## Dependencies

Optional semantic models are not redistributed in this repository. Their installers pin upstream revisions and verify every required model, tokenizer and configuration asset against a built-in SHA-256 digest. Runtime dependencies retain their upstream security and patch requirements.

## Known alpha limitations

- Only content inspection has a separately enforced worker; schema parsing and record iteration are
  not isolated yet.
- Source trust keys are in-memory primitives. Durable authenticated trust-bundle distribution is not implemented.
- Recipient certificate heads can be persisted locally, but source-host state rollback needs an
  independent checkpoint. Destination identity rotation and replacement-free emergency revocation
  are not implemented.
- Queue limits are per record and message, not cumulative per tenant or disk.
- The local audit chain has no external checkpoint, so an attacker with storage access may truncate a valid suffix.
- CLI database URLs may be exposed by shell history. Use structured endpoints and secret providers in automation.
- The project has not received an independent security assessment.
