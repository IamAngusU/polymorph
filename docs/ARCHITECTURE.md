# Architecture

## 0. Untrusted input gate

File connectors start from bytes, not the filename, extension or caller-provided MIME label. `ContentInspector` performs bounded content identification and rejects blocking risks before a format parser is selected.

For ZIP and OOXML inputs, the gate inspects the central directory without extraction. It limits entry count, total expansion, individual member size and suspicious compression ratios. It blocks traversal paths, archived symlinks, duplicate normalized member names, encrypted members, VBA projects and external workbook-link and data-connection parts by default.

Magika may be enabled as an independent local classifier. Its result is evidence only. A high-confidence disagreement with the deterministic detector reduces trust and blocks parser selection by default.

The Excel path additionally requires openpyxl's `defusedxml` hardening. Formula cells are detected independently from cached values because openpyxl does not calculate formulas.

## 1. Schema plane

A connector exposes a `SchemaDescriptor`. Descriptors contain field identity, name, aliases,
declared type, nullability, destination-generated status, sensitivity, field role and relationship
metadata. They intentionally contain no property for sample payload values.

For spreadsheets and delimited files, field IDs are positional (`c1`, `c2`, ...) while names are semantic descriptors. This distinction matters during drift repair: a positional ID is not proof that a moved column still represents the same business field.

Database connectors introspect primary keys, foreign keys and single-column unique constraints. A foreign-key target may expose referenced unique business keys as aliases, allowing the matcher to recognize relationships without pretending the business key is the internal foreign-key value.

## 2. Mapping plane

The matcher aggregates bounded evidence from normalized names and aliases, token overlap, string similarity, declared type compatibility, field roles, sensitivity compatibility and verified relationship aliases. Optional local descriptor embeddings and a cross-encoder reranker can improve candidate ordering.

Model evidence is advisory. An `AUTO` decision requires the selected target to also be the independently strongest deterministic target, to clear the deterministic score floor and deterministic margin, and to satisfy the final policy thresholds. If model evidence changes the winner away from the deterministic winner, the decision requires review.

Any target collision between plausible source mappings is conservatively demoted to review. A high score never overrides an information-flow conflict, required-target failure or relationship proof.

`build_plan()` converts accepted decisions into registered operations. A business key targeting a database foreign key becomes `lookup_foreign_key` only when the target relationship exposes an actual unique lookup column. Secret and opaque routes use transport semantics rather than value transforms.

A `MappingPlan` binds source and target schema fingerprints, rules, version and plan ID into a canonical SHA-256 digest. Delivery envelopes authenticate that digest. Repair therefore creates a new plan version and digest instead of mutating the semantics behind an existing authorization.

## 3. Recipe plane

A recipe stores previously approved mapping knowledge by structural source and target fingerprints. Structural fingerprints are deliberately weaker than exact fingerprints and are only used to locate a candidate recipe.

Activation always rebinds the stored rules to the current exact schema IDs and fingerprints, produces a new plan ID and digest, and runs full plan validation again. A recipe is never a capability grant and never bypasses current policies.

Automatic recipe remembering is allowed only after a complete no-write preflight. Sampled preflight is diagnostic only.

## 4. Preflight contract sandbox

Before a new or rebound plan is promotable, preflight walks source records without calling a destination write method. It checks record shape, required values, registered transformations, output types and optional read-only foreign-key resolution against the exact immutable plan.

Secret and opaque payloads are not interpreted. Preflight checks only presence and nullability where required.

Formula-bearing spreadsheets are marked review-required because cached workbook results have unproven freshness. A complete scan is required for automatic promotion.

This contract sandbox is distinct from hostile-code OS containment. In the current alpha, supported parsers still execute in the local process after the content gate accepts the file. Process-level parser isolation is a separate deployment capability planned for the agent runtime.

## 5. Source trust boundary

`BlindSourceAgent` validates the plan before touching payload data. Source-stage deterministic transforms run here because they require plaintext. Destination-stage operations such as foreign-key lookup are deferred.

Every mapped field is then encoded canonically and encrypted to the destination X25519 public key. The source process does not need the destination private key.

Protocol v3 signs the complete encrypted record with a separate Ed25519 source identity. The
verification key is independently bound to one tenant and source connector. Recipient encryption
keys, source signing keys and capability signing keys are distinct roles.

## 6. Opaque relay boundary

`SealedRelayQueue` verifies the source signature before route policy, then persists only canonical
wire records that already contain encrypted fields. It can validate authenticated expiration
metadata, deduplicate transfer identities, reject identity reuse with different ciphertext, queue
records, lease them to workers, and acknowledge or release a lease. Signature and revocation are
checked again when a record is leased so a revoked queued record cannot pass silently.

It cannot decrypt a record because its API has no private-key dependency.

The relay still learns metadata required for routing, including tenant, connector IDs, record ID, transfer ID, plan digest and field IDs. Payload confidentiality does not imply metadata confidentiality.

## 7. Destination trust boundary

`BlindDestinationAgent` independently re-verifies source identity and revocation, then verifies
tenant, destination and allowed plan digests before opening envelopes. `DestinationRuntime` then:

1. verifies that the plan supplies every required, non-generated target field
2. claims the delivery identity in the ledger
3. skips already committed duplicates
4. decrypts locally
5. checks the exact mapped field set and conservative runtime types
6. performs destination-stage relationship resolution and rechecks its result
7. invokes the destination connector with a deterministic idempotency key
8. records the durability result
9. removes successful records from sealed quarantine

A natural key is resolved to an internal foreign key only through database metadata. The caller chooses a previously approved unique match column but cannot select an arbitrary table or return column.

## 8. Delivery state and replay

The ledger records `claimed`, `write_started`, `committed`, `uncertain` and `quarantined` states.
`claimed` has a bounded lease and random fencing token. The token must still be current when the
runtime durably enters `write_started`, immediately before the connector call. Only stale
pre-write claims can be recovered automatically. It stores identifiers and cryptographic digests,
not payload values.

Connector failures may carry a `WriteOutcome`:

- `NOT_COMMITTED`: the connector has proof that the operation did not commit. Replay is safe after remediation.
- `UNKNOWN`: the connector cannot prove whether a side effect occurred. Non-idempotent replay is blocked unless explicitly forced by an authorized capability.

Unknown exceptions are classified conservatively as `UNKNOWN`.

## 9. Capabilities and audit

Capability grants are Ed25519 signed and scope a subject to tenant, connector, operation and optionally specific plan digests. Force-replaying an uncertain non-idempotent write is a separate capability from ordinary replay.

Audit events have a fixed metadata schema. Events form a SHA-256 hash chain and may additionally be Ed25519 signed. Audit failure after a successful destination write does not make the delivery appear failed because that could trigger an unsafe duplicate write.

## 10. Connector boundaries

Excel is content-verified before openpyxl is invoked, requires XML hardening, reads with VBA disabled and external link preservation disabled, and surfaces formula-cache uncertainty. CSV parsing is streaming and dialect detection is local. JSON5 is parsed as data and non-finite values are rejected before transport. HTTP connectors require HTTPS, disable redirects and environment proxy inheritance, enforce the configured host and port, and bound response sizes. Database writes target reflected tables and columns through SQLAlchemy parameterization.
