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

Every real `prepare` reuse records the metadata-only preflight outcome. A newly remembered recipe
also starts with its successful full-scan observation. Inspect the history-derived status with:

```bash
polymorph recipe health --store ./recipes.sqlite3
polymorph recipe health RECIPE_ID --store ./recipes.sqlite3
```

`recipe find` also reports the matched recipe's health and whether automatic reuse is allowed. It
still permits exporting a rebound plan for manual inspection; `prepare` is the command that
enforces the automatic-reuse circuit.

Health is `unobserved`, `healthy`, `degraded` or `suspended`. Review and sampled outcomes are
visible as degraded health, but do not open the automatic-reuse circuit. Three consecutive
rejected runs suspend reuse by default. `prepare` then falls back to a fresh conservative mapping
instead of trusting the unhealthy recipe. The threshold is configurable, and a successful
observation or a newly approved recipe version provides a recovery path.

Parser iteration and destination-probe availability failures are recorded as quarantined
observations, not recipe rejections. They remain visible but do not poison the reuse circuit.

This adaptation only reduces automation. It does not mutate a mapping from production data,
raise confidence scores or approve a replacement plan by itself.

## Drift behavior

Recipes do not use file path, workbook name or display name as their primary identity. This allows the same approved structure to be reused for periodic imports whose filenames change.

At the same time, a changed field structure or relationship graph changes the structural fingerprint and prevents automatic reuse.
