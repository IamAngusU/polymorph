# Local learned advice

The external Polymorph Lab can now fit a small pairwise ranking model from reviewed
schema-descriptor labels. It exports a data-only JSON weight artifact. This repository
contains only the optional loader and a read-only shadow probe, not the corpus factory,
training code, raw datasets or generated weights.

## Explicit use

```python
from polymorph.matching.hybrid import HybridMatcher
from polymorph.matching.learned import AdvisoryRanker

advisor = AdvisoryRanker.load(
    ".polymorph/models/review-advisor/model.json",
    expected_sha256="<64 lowercase hex digits approved by the operator>",
)
matcher = HybridMatcher(reranker=advisor)
```

This is the existing reranker extension point. No default changes. No fitting in
production. No downloads, remote code, pickle, threshold changes or permissions in
the artifact. The pin must come from a reviewed configuration, not an untrusted
payload claiming its own hash is approved. A hash verifies content identity, not
model quality or the trustworthiness of its creator.

The current HybridMatcher may only consult a reranker for selected ambiguous
shortlists. Better standalone ranking therefore need not improve the complete
matcher. Automatic authorization remains subject to its independent deterministic
prerequisites; learned scores are not calibrated probabilities or safety proofs.

## Run through the actual matcher before deployment

With the external Lab v0.2:

```powershell
py learn.py check-core --corpus corpora/frozen-v1 --model runs/advisor-v1 `
  --project D:\polymorph --python D:\polymorph\.venv\Scripts\python.exe `
  --out reports/core-advisor-v1
```

The lab invokes `scripts/learned_probe.py`, which evaluates the baseline matcher
and the explicitly pinned advisor on the same requests. Expected answers remain
outside that process. The probe accepts mapping descriptors only, not production
write requests, parser paths, executable transforms or training labels. It uses
`scripts/lab_probe.py` for the already bounded descriptor/wire parsing contract.
A model or source change during the local run invalidates the evidence.

The comparison is a local developer test, not an OS sandbox or a certification of
all current database/relay behavior. Run the existing fixed safety corpus and full
local validator before merging or activating a trained artifact.

## The separate optional encoder profile

The external lab also has a fine-tuning path for the pinned IBM Granite 97M
multilingual R2 encoder. That trainer is not invoked or loaded by this module.
The portable JSON advisor and Granite safetensors are different model formats.
Neural candidates currently stay in the external evaluation workflow; they are
not automatically converted to this CPU model or installed into Polymorph.

## Privacy and releases

Training descriptors, validation sets, hardware reports and weights stay local by
default. The external package command excludes training rows and full logs, but
weights can still memorize information about their training source. Hashed sparse
features are not anonymization. Review data permissions and model contents before
sharing, including learned artifacts in a release, or adding a model pin to Git.

No claim is made that more processed rows automatically train Polymorph, that the
current synthetic catalog covers arbitrary ERP systems, or that an improved
standalone ranker improves live AUTO precision. A release's runtime code, candidate
hash, fixed corpus and local test evidence need review together.
