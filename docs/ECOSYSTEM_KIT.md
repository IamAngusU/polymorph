# Ecosystem and operations kit

Polymorph 0.4.0a5 adds practical integration surfaces without weakening its conservative write
contract. The toolkit is local-first and does not activate GitHub Actions or any hosted service.

```powershell
polymorph-kit --help
polymorph-kit connector scaffold "Acme CRM" --output .\acme-connector
polymorph-kit quality inspect .\incoming.csv --output .\quality.json
polymorph-kit ui export .\review-ui
polymorph-kit review finalize .\review-draft.json --output .\review.json
polymorph-kit sync inspect .\.polymorph\sync.sqlite3
```

## What is implemented

| Area | Implemented boundary |
|---|---|
| Connector builder | A no-overwrite, source-only starter with manifest, test, packaging, security checklist, and no CI workflow |
| Data quality | Streaming inspection with bounded issue groups and row-number samples; reports never contain row values |
| Cleaning | Lazy, immutable, schema-bound plans for NFC normalization, trimming, and empty-to-null; every rule requires explicit construction |
| Review handoff | Versioned artifacts bound to exact source and destination schema fingerprints with a canonical content digest |
| Review UI | Dependency-free EN/DE Web Component that emits drafts but has no destination credentials or write authority |
| OAuth lifecycle | Thread-safe in-memory access-token cache using a trusted-host refresh callback and redacted representations |
| Recurring runs | Durable local compare-and-swap checkpoints plus fenced, expiring single-host run leases |
| Schedule policy | Deterministic next-run calculation for an external scheduler; no background daemon is installed |

## Deliberate non-claims

- The connector starter is not a connector marketplace and does not create a working provider
  implementation by itself.
- The OAuth adapter is not an authorization server, redirect handler, or refresh-token vault.
- The local lease is not a distributed lock and cannot coordinate independent hosts.
- Checkpoints are incremental-run infrastructure, not CDC. A source connector must define cursor
  semantics and prove that reads are replay-safe.
- The Web Component is asynchronous review handoff, not authenticated real-time collaboration.
- A SHA-256 content digest detects accidental changes; it is not an identity signature.

These distinctions are part of the product contract, not missing fine print.
