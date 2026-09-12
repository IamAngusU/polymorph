# Polymorph Review Desk

`polymorph-review.js` is a dependency-free Web Component. It displays schema-level mapping
evidence, records explicit decisions, emits `polymorph-review-change` and
`polymorph-review-submit`, and downloads a versioned review draft. It never receives record values
and has no write authority.

```html
<script type="module" src="./polymorph-review.js"></script>
<polymorph-review locale="de"></polymorph-review>
```

Generate the JSON model directly from `RoutePreparation` with
`review_model_from_preparation(...)`, or assign the contract demonstrated in `example.html`.
Evidence classes remain prominent while advisory numeric scores stay in a technical drilldown:
confidence is never presented as write authority. Send the downloaded draft through
`polymorph-kit review finalize DRAFT --output REVIEW.json`, then validate and apply the resulting
schema-bound artifact in the trusted host process. A draft is not a signed authorization token.
