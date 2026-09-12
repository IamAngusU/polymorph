# Learned review recommendations

Polymorph can load the small JSON model produced by Polymorph Run as an optional
lexical ranker. The model may reorder review suggestions only. It cannot create,
replace, or upgrade an `auto`, `review`, or `blocked` decision and cannot execute
writes, train inside the application, upload data, or activate itself.

## Safe boundary

- `scripts/knowledge_learning_probe.py` always runs the unchanged `HybridMatcher`
  first for authoritative decisions.
- `src/polymorph/matching/lexical.py` reads descriptor text only: names, aliases,
  and descriptions. Field IDs, cell values, expected labels, and secrets are not
  model features.
- Candidate files are data-only JSON, limited to 2 MiB, and require an explicitly
  supplied SHA-256. Links and reparse points are rejected.
- Rankings always carry `authority: advisory_only` and `requires_review: true`.

## Use with Polymorph Run

From the extracted Polymorph Run folder, use the menu or these Windows commands:

```powershell
Weiterlernen.cmd --project "D:\polymorph" --no-prompt --no-open
Pause.cmd --project "D:\polymorph" --no-prompt --no-open
```

The campaign stores checkpoints below `D:\polymorph\.polymorph` and resumes from
the latest validated boundary. These local runtime files, models, raw logs, and
training rows are intentionally not uploaded to GitHub.

Run `Polymorph-Run.cmd --project "D:\polymorph" --mode all --no-prompt --no-open`
to compare the validated campaign candidate with the real checkout. Passing this
comparison proves protocol compatibility and unchanged deterministic authority;
it is not a production certification or an independent real-world holdout.

## Local acceptance snapshot

The full Windows acceptance run on 2026-09-12 evaluated 84 fixed-validation queries. The untrained advisory ranker placed 47 targets first; the trained candidate placed 61 first, with 14 paired gains, zero paired regressions, zero unsafe automatic decisions, and identical deterministic authority. This is a repeatable synthetic validation result, not an unseen final holdout.
