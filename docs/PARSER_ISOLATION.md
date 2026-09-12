# Parser isolation

Untrusted files are code-adjacent input. Content detection reduces parser confusion, but it does
not make a native library or complex document parser safe. Polymorph therefore treats process
containment as a separate, explicit boundary.

## Current scope

The v0.4 worker isolates content inspection first. It runs deterministic file identification,
archive metadata checks and optional Magika classification against a private snapshot. CSV, JSON
and Excel schema parsing and record iteration are not routed through this worker yet. The normal
`inspect auto`, `prepare` and `preflight` paths therefore remain in-process until their streaming
worker contract is implemented.

This distinction is deliberate. A process around content detection is useful crash and resource
containment, but it is not honest to call every downstream parser sandboxed because one earlier
stage ran in a worker.

## Containment levels

Every result names the level actually used:

- `PROCESS`: a separate child process with a clean environment, parent wall timeout and bounded
  protocol output. It has the host user's filesystem and network authority.
- `RESOURCE_LIMITED_PROCESS`: `PROCESS` plus required POSIX CPU, address-space, open-file,
  real-UID-scoped process-count and output-file limits. Core-dump suppression is best effort.
  These limits are not a filesystem or network sandbox. A privileged process worker is reported
  only as `PROCESS`, because it can override those limits.
- `OS_SANDBOX`: an operating-system boundary that also removes network access and exposes only the
  staged input, Polymorph package and required read-only runtime paths.

The default policy requires `OS_SANDBOX`. It never silently falls back. Local operators can
explicitly request `PROCESS` for trusted files when they only need crash separation. On Windows a
normal subprocess is reported as `PROCESS`, not as a sandbox. A strict Windows backend still needs
an AppContainer or equivalent boundary. Job Objects alone would improve resource and descendant
control but would not remove filesystem or network authority.

Linux Bubblewrap is the first strict backend. The worker requires a non-setuid and non-setgid
Bubblewrap 0.12.0 or newer, and Polymorph should run as a dedicated unprivileged service account.
Older releases are rejected because upstream fixed a
sandbox-setup [symlink escape](https://github.com/containers/bubblewrap/security/advisories/GHSA-pxhw-h44j-8pfx)
only in 0.12.0. The command drops Linux capabilities, disables nested user namespaces and asks
Bubblewrap to assert that this restriction took effect. It keeps the sandbox root, application and
working directory read-only, and bounds its private temporary filesystems.

Finding a compatible executable is still only configuration evidence. A successful worker launch
proves that the requested invocation ran, while the dedicated Linux integration lab also attacks
host-file visibility, root/application/work-directory writes, network access, nested user
namespaces, temporary-filesystem exhaustion and descendant-held pipes on the actual kernel. The
command builder owns the security policy because Bubblewrap itself is a low-level sandbox toolkit,
not a complete policy.

The ephemeral GitHub Actions security lab relaxes Ubuntu's AppArmor restriction on unprivileged
user namespaces so it can exercise this boundary. That global sysctl change is CI scaffolding, not
a production installation instruction. A shared or production host needs an intentionally scoped
user-namespace and AppArmor policy instead of blindly changing the host-wide setting.

The strict backend still trusts the host kernel, the selected Bubblewrap binary, the Python
runtime, installed parser dependencies and the Polymorph package. Inside the namespace the worker
can see private `/proc`, `/dev` and bounded `/tmp` mounts plus the staged input, Polymorph package
and broad Python runtime roots such as `/usr` and `/lib*` read-only. It does not receive host home,
application state, credential directories or arbitrary input directories.

POSIX CPU and address-space limits apply per process, not to an aggregate cgroup. `RLIMIT_NPROC` is
shared across the real user ID and is not an exact per-worker descendant quota. The parent wall
timeout and process-group termination add another guard, while the Bubblewrap `/tmp` size is an
aggregate mount limit. This boundary reduces resource abuse but is not a complete defense against
kernel bugs or every multi-process denial-of-service strategy. There is no project-owned seccomp
allowlist or cgroup-v2 aggregate quota yet.

On Windows, the process backend now enters a Job Object before importing the parser worker. The job
enforces aggregate memory, CPU time, active-process count and kill-on-close descendant cleanup, so the
backend is reported as `RESOURCE_LIMITED_PROCESS`. This still does not deny network or filesystem
access and therefore is not reported as `OS_SANDBOX`; AppContainer or an equivalent restricted-token
boundary remains required for hostile structured parsing.

## Exact-byte snapshot

The parent rejects links or Windows reparse points in the leaf and supplied parent path components,
plus non-regular inputs. It compares path metadata
with the opened handle, copies no more than the configured byte limit into a private temporary
directory and hashes the bytes while copying. Source and opened-handle identity are checked again
after the copy.

The worker receives only the snapshot path. Both parent and worker verify its size and SHA-256
before accepting a result, and the parent verifies the snapshot again after worker exit. The result
contains the digest and timing evidence, not the original path. Temporary plaintext is removed when
the call ends. Secure erasure is not promised, especially on SSD and copy-on-write storage.

## Protocol and resource guards

Parent and worker exchange one bounded JSON object using `polymorph.parser-worker` version 1. The
contract rejects unknown fields, duplicate keys, non-finite numbers, invalid types, excess nesting,
oversized strings and mismatched request or input identities. Pickle and arbitrary Python object
deserialization are not used.

The worker starts with an allowlisted environment that excludes home, proxy, cloud, Git, SSH and
application credential variables. Parser-facing imports happen after POSIX limits are installed.
Python-level parser logs go to a counting discard sink instead of an unbounded memory buffer. Native
stdout or stderr writes remain bounded by the supervisor and invalidate the protocol if they add
unexpected output.

The supervisor independently enforces wall time and output size, records only a digest of stderr on
failure and tears down the worker before temporary files are removed. On POSIX, a separate process
group supports descendant cleanup. On Windows, the Job Object process backend supplies descendant
cleanup and aggregate resource limits, but not filesystem or network isolation.

## Operator commands

Strict content inspection is the default:

```bash
polymorph inspect isolated-content ./incoming-file
```

An operator can explicitly request process-only inspection for a trusted local file:

```bash
polymorph inspect isolated-content ./incoming-file \
  --backend process --require-containment process
```

`polymorph doctor` reports the configured worker backends and their concrete capabilities.
`polymorph benchmark parser-worker` measures snapshot, worker and exact end-to-end time without
pretending that the normal structured parsers are already isolated. In benchmark mode it also
samples aggregate child and descendant RSS, CPU time and I/O when `psutil` is installed. Sampling
has observer effect and short process exits can make these resource values conservative.

## Next boundary

The next protocol revision must move schema inspection and bounded record streaming behind the same
snapshot. Record transport needs backpressure, per-frame and total limits, explicit encodings for
date, datetime, decimal and bytes, and no in-process fallback. Only after `inspect auto`, `prepare`,
`preflight` and the workflow benchmark all use that path can Polymorph claim structured parser
containment for those workflows.
