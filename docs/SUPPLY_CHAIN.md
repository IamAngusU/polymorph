# Supply-chain evidence

Polymorph releases should carry evidence that can be checked without trusting GitHub Actions.
The repository-wide Actions switch may remain disabled; the local commands below are authoritative.

```powershell
python -m build
python scripts/build_release_evidence.py --artifact dist/package.whl --artifact dist/package.tar.gz
python scripts/verify_release_evidence.py dist/release-manifest.json
```

The builder emits a CycloneDX 1.5 SBOM, source commit, source-tree digest, dirty-tree flag, sizes and
SHA-256 hashes. It does not claim a signature. Sigstore keyless signing requires an external identity
flow, and GPG signing requires an operator-controlled key; either can sign the generated manifest
without changing its artifact hashes. Release publication must fail if the manifest says the tree was
dirty, if verification fails, or if the release tag does not equal the packaged version.

The manual-only workflow is preparation, not authority. GitHub Actions are currently disabled at the
repository level and no workflow is required to build or verify a release locally.
