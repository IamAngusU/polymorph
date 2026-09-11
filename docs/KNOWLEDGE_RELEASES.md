# Versioned advisory knowledge

A public package is a learned lexical ranking artifact plus a signed, minimal
provenance statement. It cannot carry executable code, change policies, authorize
AUTO, install transforms or import private recipes.

## Versions and ownership

Use a new ID and increasing sequence for every released training artifact, for
example `2026.09.11.1`, sequence `1`. Keep prior packages at
`knowledge/packs/<version>.json`. `knowledge/latest.json` is a small discovery
pointer to the chosen package. It is not an authority: the client verifies the
package against a publisher key approved through a separate channel.

All published metadata describes ONE model version. Training the same pairs for
another epoch does not increase unique evidence. The example lab candidate has
365 training queries, 1,656 unique positive/negative preference comparisons,
19 synthetic training source groups and 13,248 weight updates. These are four
separate counts. Its 53-query synthetic holdout is not 53 independent customers.

The repository currently ships no signed general release and no publisher key.
The example counts in the README are explicitly labeled **lab candidate**.
A signature verifies publisher authorization, not semantic correctness or license
clearance. Only publish data and weights you have reviewed and may distribute.

## Separate stores

```text
<data-home>/recipes.sqlite           existing private recipes, never opened here
<data-home>/models/                  existing locally managed models, never opened here
<data-home>/knowledge/general.sqlite downloaded versions and active general pointer
```

Public updates have no merge operation with local data. A caller may consult
`KnowledgeStore(...).active_ranker()` for additional review suggestions. Existing
recipes, pins, user choices and policies retain their existing authority and
revalidation requirements. A public ranking disagreement never overwrites them.
There is not an existing automatically personalized neural model that this feature
secretly merges. Local recipes and explicitly managed local models are distinct.

`KnowledgeStore` is opt-in; it is not installed into the ordinary `HybridMatcher`
path. For observable A/B comparisons use `scripts/knowledge_learning_probe.py`.
It retains the deterministic decisions and returns a separate recommendation list.
`parse_map` uses the real connector to infer the source schema from a file.

## Important compatibility fix

The existing `matching/learned.py` uses `angusu.bridge.advisory-ranker/1` and
`bounded-token-cross/1`. Lab 0.2 writes `angusu.bridge.lexical-ranker/1` with
`token-cross/1` and 16,384 weights. Those are different contracts.

The compatible implementation is added as `matching/lexical.py`; the old loader
is NOT overwritten. Packages bind the model format, feature version, dimensions,
model SHA-256 and exact feature-runtime source SHA-256. An incompatible model is
rejected before activation. Ordinary platform line-ending conversion therefore
needs attention: the repository should retain LF source bytes when publishing;
train against the same runtime bytes. A future semantic feature ABI may reduce
this conservative invalidation requirement.

## Prepare a release in the separate lab

The publisher uses the existing `cryptography` dependency in the project Python.
It does not install dependencies, push Git, upload to a service or generate an
unprotected long-term signing key.

```powershell
# Keep this key outside Git and outside the ZIP you share with reviewers.
D:\polymorph\.venv\Scripts\python.exe publish_knowledge.py keygen --out D:\private-keys\knowledge-publisher.pem

D:\polymorph\.venv\Scripts\python.exe publish_knowledge.py prepare `
  --model learning\candidate\model.json `
  --training learning\candidate\training.json `
  --evaluation learning\evaluation\evaluation.json `
  --corpus learning\corpus `
  --key D:\private-keys\knowledge-publisher.pem `
  --version 2026.09.11.1 --sequence 1 --valid-days 90 `
  --confirm-public-synthetic --out releases\2026.09.11.1
```

The initial publisher supports reviewed **synthetic** corpora only. It verifies
retained input, epoch, prediction and model hashes; recomputes unique training
comparisons; checks source/query split separation; and reproduces the holdout
ranking before preparing an advisory preview. It does not certify an independent
customer benchmark or prove training history from a report alone.

The staged output contains the signed package, public evidence counters, latest
pointer and public key. It excludes training inputs, detailed device reports,
paths, model-training query signatures and the private key. Review even synthetic
model artifacts: public weights are public, and hashes do not anonymize metadata.

Copy only the staged `knowledge/` files into the repository; keep old pack files.
Run `python scripts/render_evidence.py`, review the diff, then commit/push or open a
PR. The client can use a pinned commit with `fetch --ref COMMIT` before merge.
There is no Actions dependency.

For small JSON rankers the repository is adequate. Large model weights should be
release assets or a model registry, not repeated Git blobs. GitHub immutable
releases can protect published assets and tags; their `latest` designation can
still change. The current downloader intentionally supports only the small,
fixed-repository raw-JSON path, NOT arbitrary release-asset URLs.

## Install and activate

First approve `publisher.pub` out of band. Do not accept a replacement public key
just because the server included it alongside the model.

```powershell
python scripts\knowledge.py --trusted-key D:\trusted\publisher.pub fetch
python scripts\knowledge.py --trusted-key D:\trusted\publisher.pub status
python scripts\knowledge.py --trusted-key D:\trusted\publisher.pub activate 2026.09.11.1
```

Offline installation accepts the same signed package:

```powershell
python scripts\knowledge.py --trusted-key D:\trusted\publisher.pub install knowledge\packs\2026.09.11.1.json --activate
```

Installation normally does not activate. Package storage, high-water state and
optional activation share one `FULL` SQLite transaction. Failed updates keep the
previous active selection. Repeating the exact same package is idempotent;
reusing a version or sequence for different bytes is rejected. History is bounded
to 128 MiB of package content, and is not silently deleted to make an update fit.

An explicit activation of an older, still valid installed package needs
`--allow-rollback`. It does not lower the highest accepted sequence. Expired,
tampered or incompatible active models fail closed; callers can keep deterministic
mapping available without granting the rejected model any authority.

## Scope and remaining limits

This is a narrow, single-publisher advisory-artifact mechanism, **not a full TUF
implementation**. The pinned publisher key and local host are trusted. Publisher
rotation needs an explicit migration. Multi-key thresholds, delegated roles,
external monotonic witnesses and full-host snapshot rollback resistance are not
implemented. Expiry depends on the local clock and does not prove that a newer
release exists. Denial of service and freezing a still-valid version remain
possible. No claim of protection against a malicious local administrator or
malicious trained semantics is made.

Filesystem checks reject observed links/reparse points; they are not an OS sandbox
or proof against every concurrent local path replacement. SQLite provides update
serialization and transactions, not immunity from disk faults or a hostile database.

References: [TUF specification](https://theupdateframework.github.io/specification/latest/),
[Ed25519 API](https://cryptography.io/en/latest/hazmat/primitives/asymmetric/ed25519/),
[GitHub immutable releases](https://docs.github.com/en/code-security/concepts/supply-chain-security/immutable-releases).
