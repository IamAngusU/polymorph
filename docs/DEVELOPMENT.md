# Development setup

The repository keeps its virtual environment, model cache and local state beside the checkout.
All three directories are ignored by Git.

From the repository root:

```bash
python scripts/bootstrap.py
python scripts/dev.py doctor
```

Bootstrap creates `.venv`, installs the core runtime plus the development, file-identification,
CSV-detection and benchmark extras, then executes the core development checks: compile, Ruff lint
and format, strict mypy, pytest, mapping safety smoke and dependency consistency. It does not
download a model. The optional PostgreSQL driver is not installed. Package build, metadata and
clean-install checks remain release gates in CI.

The model-free default can also be stated explicitly for older automation:

```bash
python scripts/bootstrap.py --skip-models
```

Both current model profiles are research-only for product use because their training provenance
reaches MS MARCO. After reviewing `docs/MODEL_PROFILE.md`, a lab can opt in explicitly:

```bash
python scripts/bootstrap.py --include-research-encoder
python scripts/bootstrap.py --include-research-reranker
```

Use `scripts/dev.py` when working from the checkout. It pins `POLYMORPH_HOME` to the local
`.polymorph` directory, so recipes, models and other runtime state do not silently land on another
drive. A normal installed package still follows the operating system's data-directory convention
unless `POLYMORPH_HOME` is set explicitly. `ANGUSU_BRIDGE_HOME` remains a lower-priority legacy
alias for existing alpha installations. Without either variable, an existing legacy platform
directory is reused until the operator moves it; a new install uses the product-named directory.

An existing v0.3 model directory lacks the new ownership marker and compact SentencePiece asset.
Run `polymorph model install --profile multilingual-cpu` once after upgrading. The installer
migrates only a directory whose old manifest identifies the same exact pinned profile.
