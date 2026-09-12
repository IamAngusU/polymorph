# Embedded review UI and portable review evidence

Export the framework-neutral component:

```powershell
polymorph-kit ui export .\public\polymorph-review
```

Open `example.html` or import `polymorph-review.js` into any browser application. Set the
component's `model` property to schema metadata and evidence only. Listen for
`polymorph-review-change` for host-managed state and `polymorph-review-submit` for a complete draft.

```javascript
const review = document.querySelector("polymorph-review");
review.model = modelFromTrustedBackend;
review.addEventListener("polymorph-review-submit", event => {
  sendDraftToTrustedBackend(event.detail);
});
```

Finalize outside the browser:

```powershell
polymorph-kit review finalize review-draft.json --output review.json
polymorph-kit review validate review.json `
  --source-fingerprint SOURCE_SHA256 `
  --destination-fingerprint DESTINATION_SHA256
```

Python hosts can load and apply reviewed mappings:

```python
from polymorph.review_artifacts import ReviewArtifact, apply_review_artifact

artifact = ReviewArtifact.load("review.json")
prepared_again = apply_review_artifact(session, artifact)
result = session.execute()
```

`apply_review_artifact` only records mapping choices. `session.execute()` still rechecks schema,
capabilities, preflight evidence, and write policy. Neither a draft nor an artifact grants write
authority.

## Privacy and collaboration boundary

Artifacts contain field identifiers, reviewer labels, dispositions, timestamps, and schema
fingerprints. They contain no row values. Field identifiers can still be sensitive business
metadata, so share artifacts only with authorized reviewers. The versioned artifact supports
asynchronous review handoff; authentication, access control, concurrent editing, and electronic
signatures belong to the embedding application.
