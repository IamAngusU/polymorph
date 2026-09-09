# csv-spectrum fixture provenance

These regression fixtures come from the official csv-spectrum repository:

- Source: https://github.com/max-mapper/csv-spectrum
- Version: 2.0.0
- Commit: `d30e80f8b99d2eecb3778f1d7b9ed1cb425502ec`
- Commit date: 2024-07-04
- Retrieved: 2026-09-09
- Upstream license declaration: BSD-2-Clause in `package.json`
- Upstream author: Max Ogden
- Integrity: every redistributed data file is listed in `SHA256SUMS`

Only the 11 internally consistent CSV and expected-JSON pairs are copied. No
JavaScript, package metadata, npm dependency, or executable code is vendored.

`location_coordinates.csv` and `location_coordinates.json` are deliberately
excluded. At the pinned commit, the CSV contains phone number `2095257564`, while
the expected JSON contains `1234567890`. Its JSON top level is also an object,
unlike the arrays used by the other expected-result files. That is an upstream
fixture mismatch, not a parser result that Polymorph should bend to fit.

The upstream repository stores `*_crlf.csv` through a Git `eol=crlf` attribute.
Polymorph preserves the same checkout behavior in its root `.gitattributes`.
The SHA-256 values cover the materialized bytes, including the intended line
endings.

The upstream repository does not contain a standalone license file at the pinned
commit. Its `package.json` declares `BSD-2-Clause` and names Max Ogden as author.
The standard BSD-2-Clause terms and that attribution are preserved in `LICENSE.txt`.
