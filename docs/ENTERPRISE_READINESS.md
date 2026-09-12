# Enterprise readiness and procurement facts

This document separates available evidence from certifications Polymorph does not have. It is a
self-assessment aid, not an audit report, legal advice, an SLA, or a compliance certificate.

## Evidence available today

| Procurement question | Current evidence | Status |
|---|---|---|
| Can writes fail closed? | Commit-state model, schema recheck, preflight gates, partial HTTP outcome tests | Implemented and locally tested |
| Are customer rows required in telemetry? | Product events and quality/review metrics are metadata-only | Not required |
| Can the package be inspected offline? | Wheel, sdist, SHA-256 manifest, CycloneDX SBOM, source release | Available per release |
| Is a hosted control plane required? | Core, lab, review UI, metrics, and sync state run locally | No |
| Are secrets embedded in route specs? | SecretProvider references, OS keyring option, in-memory OAuth refresh adapter | Avoided by supported design |
| Is CI automatically enabled? | Repository Actions are disabled; connector scaffold emits no workflow | No |
| Is there an independent security audit? | No independent assessment is published | Not available |
| SOC 2 / ISO 27001 certification? | No organizational certification is claimed | Not available |
| HIPAA eligibility or BAA? | No BAA or HIPAA service claim | Not available |
| Contractual SLA and support response? | Community pre-release; no standard SLA | Not available |
| Multi-host distributed scheduling? | Local checkpoint and lease only | Not available |

## Deployment checklist

1. Pin the exact wheel and verify its SHA-256 against the release manifest.
2. Review the SBOM and transitive dependencies for the selected optional extras.
3. Keep state, plans, review artifacts, and cursors in an access-controlled local directory.
4. Use OS credential storage or a trusted host callback; do not place secrets in connector specs.
5. Set source, response, record, memory, time, and destination quotas for the real workload.
6. Run `validate_local.py`, the relevant connector conformance tests, and destination integration
   tests on the actual deployment host.
7. Treat AppContainer, Windows Job Objects, cgroup v2, Kubernetes policies, and external witnessing
   as unverified until tested on the target host.
8. Preserve evidence bundles and review metrics under the organization's retention policy.
9. Define operator responsibility for `UNKNOWN` and partial outcomes before enabling writes.
10. Obtain an independent assessment before making regulated or certified deployment claims.
