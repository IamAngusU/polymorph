# Metadata Firewall

The Metadata Firewall is a policy boundary for metadata attempting to cross a
Polymorph trust boundary. It is not a generic `strip_metadata=True` switch.

The initial implementation defines the policy, evidence and adapter contracts.
It does not yet claim format-level sanitization coverage.

## Boundary

```text
source artifact
  -> format-specific metadata inventory
  -> value-free metadata observations
  -> versioned policy
  -> preserve / strip / review / block
  -> format-specific sanitizer
  -> provenance receipt
```

Metadata observations contain category, presence, occurrence count, encoded
size and removal impact. They cannot contain the original GPS coordinate,
author name, comment or other metadata value. This keeps audit evidence from
becoming a second data leak.

## Built-in policies

`preserve` makes no metadata changes.

`privacy` strips location, device identifiers, person identity, editor history,
comments, document identifiers and embedded thumbnails. It preserves technical
rendering metadata and requires review for business-ambiguous timestamps and
copyright fields.

`strict` strips all known non-required metadata. Unknown metadata still requires
review rather than being silently discarded.

## Integrity behavior

If a policy would strip metadata from a signed artifact, the evaluation is
blocked. If signature state is unknown, mutation requires review. Polymorph does
not claim that privacy improvement is safe when it would silently invalidate a
source signature.

Removal impact is authoritative. `NONE` and `REPRESENTATION` may proceed to a
sanitizer, but a representation-changing adapter cannot claim byte-preserved
output. `RENDERING` and `UNKNOWN` require review. `SIGNATURE` blocks mutation.

Before mutation, format adapters must call the exact-byte source digest guard.
A changed path, identity, size, timestamp or SHA-256 digest fails with
`source_changed_after_metadata_inspection`.

A successful sanitizer must return both source and output SHA-256 digests, the
exact policy version, removed and preserved metadata keys, and explicit claims
about representation and rendering changes. A receipt cannot approve an
invalidated signature.

## Metadata is not active content

Office macros, PDF JavaScript, external links and embedded executables remain in
the existing content-security gate. They are not treated as metadata.

## Content classifiers remain optional

Probabilistic NSFW or other media classification is deliberately not a core
Metadata Firewall dependency. A future adapter may provide versioned advisory
signals to a separate Content Policy Gate, but it must not provide raw content,
previews or model inputs to the metadata audit record.

No latency claim is made for such a classifier until cold and warm p50/p95
measurements identify the model version, model digest, hardware, runtime,
preprocessing time, inference time and complete end-to-end time.

## Format adapter requirements

JPEG, PNG, WebP, PDF and Office support must be implemented independently and
tested against malformed, oversized, signed and adversarial fixtures. An adapter
is not covered merely because the policy interface exists.

Every inspector must use bounded reads and preserve file identity between
inspection and sanitization. Every writer must use a temporary file, flush and
fsync it, and atomically replace the destination. Lossless metadata removal must
not be described as lossless unless encoded content preservation is proven for
that specific format and operation.
