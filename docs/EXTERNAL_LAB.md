# External laboratory probe

The corpus factory, oracle, resource monitor, history and HTML reports live in a
separate local tool, not in this repository. `scripts/lab_probe.py` is the only
bridge-specific integration entry point. It is inactive during normal production
runs and adds no dependency, resident worker or background telemetry.

## Protocol and authority

Run the selected checkout's Python with `-I` and the probe script. Supply one
bounded JSON request on stdin and an explicit `--input-root`. The probe imports
`src/polymorph` from its own checkout, not an unrelated globally installed version.

The protocol is `angusu.bridge.lab-probe/1`. Supported operations are:

- `facts`: Python, Polymorph and dependency versions, model profile and probe hash.
- `map`: source and target descriptors into the real `HybridMatcher` with models off.
- `transform`: a small allowlist of the real source transform functions.
- `parse`: actual CSV/TSV, JSON/JSON5 and XLSX connectors, including their existing
  content gates. Returns count and typed ordered-row SHA-256, never the row payload.

A request contains IDs and inputs, not expected mappings, expected rows, labels,
credentials or destination URLs. Unknown object fields are rejected. There are no
training, arbitrary-code, production-write or model-install operations.

`oracle_received: false` means no oracle was in the request protocol. This is
logical separation, not an OS privacy boundary: a malicious program running as
the same user could read other files. Only run trusted checkout code and locally
generated fixtures with this probe. It is explicitly not a hostile-parser sandbox.

## Bounds and output

Requests are capped at 16 MiB, 128 cases, 128 fields per schema, 32 nesting levels
and 200,000 JSON nodes. File inputs are capped at 64 MiB. Existing connector limits
are not relaxed. A valid fixture exceeding a connector's configured operating
envelope is not silently skipped; it produces a failed or rejected observation.

Rows are consumed incrementally from the connector. A row's evidence encoding is
capped at 1 MiB, with a request-specific total logical output budget no larger than
512 MiB. Note that a connector itself may materialize a file before yielding rows;
this probe does not make a nonstreaming implementation streaming.

Typed evidence distinguishes null, bool, integer, string, decimal, float, temporal
values, binary, lists and objects. Object keys are sorted. Each encoded row is
prefixed with its 8-byte length before hashing. Count, order and multiplicity all
matter. SHA-256 is a compact integrity check, not a proof against hash collisions
or a dishonest target process.

Errors from the target, expected target rejections, invalid protocol requests and
probe observation failures are different. In particular, rejecting an invalid
output in the probe must not be reported as the target having rejected the input.
Messages contain error classes, not raw exception strings or source values.

Wall and current-process CPU time are collected per operation. Fresh-process
startup, process-tree RSS and I/O are measured by the external parent. Cold OS
cache is not claimed. GPU discovery is inventory, not evidence of GPU execution.

## Corpus and improvement policy

The local factory creates canonical synthetic business data, then source layouts,
target contracts and a separate oracle. Labels are derived from the factory's
world, not from Polymorph's answers. Mutations belong to one synthetic source group
and stay in the same train/validation/holdout split. Generator templates still
share assumptions, so the synthetic holdout is not an independent customer corpus.

Report unique cases, families, source groups, rows, AUTO decisions and repeated
executions separately. Do not calculate production confidence bounds from repeated
rows. A coverage floor prevents an always-abstain system from looking useful.

No model training or recipe promotion happens automatically. Training export is
restricted to the synthetic training split. Improvements require a deliberate code
or model change and a comparable rerun; runtime code/version is the experimental
variable, while corpus, hardware profile, Python/dependencies, probe and measurement
mode are held constant. Faster failing runs are not improvements.

## Validation performed for this change

38 focused probe tests passed under Linux/Python 3.13.5, including the actual
HybridMatcher and transform functions from a hash-verified source subset of
`df17b2f1a5b5bad469f93c33b714aaa7fee2fd2b`. Package facades in that test subset were
minimal test namespaces; this was not a full checkout or installed-release test.
The mapping and transform implementation bytes matched their Git blobs.

The external lab additionally exercised 42 synthetic mapping cases and 18 transform
cases through fresh probe processes. The mapping run observed 183 correct AUTO
choices, zero unsafe AUTO, and 183/198 safe automation coverage. These are synthetic
observations on this subset, not independent quality estimates. The external tool
has its own self-tests; those counts are not Polymorph's full test-suite count.

Native Windows, the complete CSV/JSON/XLSX connector pipeline and the encrypted
workflow on the full checkout must still be run locally. No GitHub Actions result,
full-project performance figure or production certification is claimed here.

Example project-side regression command:

```powershell
.\.venv\Scripts\python.exe -W error -m pytest tests\test_lab_probe.py -q
```

The external laboratory package is delivered separately. It is not vendored into
this source tree and no test corpus or machine report is uploaded automatically.
