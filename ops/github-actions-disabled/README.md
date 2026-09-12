# Inactive GitHub Actions templates

Nothing in this directory is recognized or executed by GitHub Actions. This is deliberate: local
runs must not create cloud billing or upload evidence as a side effect.

The current template is also `workflow_dispatch` only. Activation requires all of these explicit
steps:

1. Review GitHub Actions billing and repository spending limits.
2. Review every third-party action version and requested permission.
3. Decide whether generated evidence is safe to retain as an artifact.
4. Copy the selected file into `.github/workflows/`.
5. Start it manually from GitHub when evidence is wanted.

Do not add `push`, `pull_request` or `schedule` triggers until recurring cost is intentionally
accepted. The workflow uses no AI service, but hosted runner minutes and artifact storage can still
have billing consequences.
