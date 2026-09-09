# Recipes

Recipes preserve approved mapping knowledge without turning historical success into permanent trust.

## Stored data

The local SQLite recipe store keeps:

- source structural fingerprint
- target structural fingerprint
- immutable approved plan
- exact plan digest
- recipe version
- approval identity label
- creation timestamp
- metadata-only run outcomes

It does not store record payloads.

## Activation

A recipe is selected only when both structural fingerprints match. The stored plan is then rebound to the current exact schema identities and full fingerprints.

The rebound plan receives a new plan ID and digest. `PlanValidator` rechecks transforms, information-flow policy, current field existence, target uniqueness and current required-target coverage.

If the current route needs review, recipe activation stops.

## Automatic remembering

`polymorph prepare ... --remember` stores a fresh recipe only when the full preflight report is promotable. A sampled scan is never sufficient.

Manual `polymorph recipe remember` is a separate operator action. It validates the plan but represents explicit operator approval rather than automatic promotion.

## Drift behavior

Recipes do not use file path, workbook name or display name as their primary identity. This allows the same approved structure to be reused for periodic imports whose filenames change.

At the same time, a changed field structure or relationship graph changes the structural fingerprint and prevents automatic reuse.
