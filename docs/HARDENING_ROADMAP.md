# Security hardening roadmap

This document separates implemented boundaries from infrastructure-dependent work. A design entry is
not a security claim.

## Implemented in 0.4.0a3

- finite shared connector work budgets for records, bytes, wall time, nesting, nodes and values
- Parquet metadata, row, row-group, uncompressed and decoded-batch limits
- HTTP JSON complexity and aggregate cross-page record limits
- streaming atomic CSV rewrites
- Windows Job Object CPU, memory, process-tree and kill-on-close limits
- streaming audit verification/export and finite no-deletion admission quotas
- local CycloneDX SBOM and hashed release manifests

## Next host-backed boundaries

1. Move full CSV, JSON, Excel and Parquet decoding into the isolated worker. The parent protocol must
   use bounded typed frames with sequence numbers, schema hashes and backpressure; it must reject
   unknown fields, oversized frames, count mismatches and incomplete terminal frames.
2. Add Windows AppContainer or a restricted-token equivalent with no network capability and a
   snapshot-only filesystem grant. Job Objects are resource containment, not an OS sandbox.
3. Add delegated cgroup v2 memory, CPU and PID limits around Bubblewrap. POSIX rlimits remain useful
   defense in depth but are not aggregate tree accounting.
4. Implement one transactional quota authority shared by relay, outbox and quarantine stores. It must
   reserve rows and bytes before admission, release reservations only after durable deletion, expose
   pressure metrics and never silently evict old evidence.
5. Add signed audit archive manifests and externally witnessed checkpoints. TPM, HSM and transparency
   services require deployment-specific keys and availability policy.
6. Build a trust-bundle control plane with monotonic bundle versions, overlapping rotations,
   revocation, stale-bundle fail-closed policy and rollback/fork detection.
7. Package source, destination and relay agents only after configuration validation, secret-provider
   integration, health checks, updates, rollback and least-privilege service identities have real
   Windows and Linux installation tests.
8. Run PostgreSQL and MySQL encrypted-path labs through a real fault proxy. Local SQLite and mocked
   failures remain valuable but are not substitutes for server commit and acknowledgement behavior.

## Required evidence before promoting a boundary

- Windows and Linux hostile-input tests at the claimed containment level
- parser and protocol fuzzing with retained crashing seeds
- mutation testing around fail-closed policy branches
- measured CPU, RSS, disk, row and byte pressure at exact limits and one-over cases
- operator recovery drill showing that backpressure preserves old evidence
- release manifest, SBOM, dependency scan and independently verifiable artifact signatures
