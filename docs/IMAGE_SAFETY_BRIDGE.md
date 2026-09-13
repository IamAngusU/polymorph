# Optional image safety bridge

Polymorph can call the separately installed NSFW Guard through its versioned
`safety-bridge/v1` JSONL process protocol. It does not import model code, share an
environment, or pretend that an image classifier is a tabular connector. Names still mean things.

```powershell
python -m pip install "https://github.com/IamAngusU/polymorph/releases/download/v0.4.0a11/polymorph_bridge-0.4.0a11-py3-none-any.whl" "https://github.com/IamAngusU/nsfw-guard/releases/download/v0.1.0a3/nsfw_guard-0.1.0a3-py3-none-any.whl"
polymorph guard --doctor
polymorph guard C:\data\first.jpg C:\data\second.webp --no-download
```

Once both console commands are on `PATH`, there is no adapter package or application glue to
write. `POLYMORPH_NSFW_GUARD` or `--executable` can point at a specific executable when multiple
environments are installed.

## Boundary

The integration starts one persistent child process, passes one bounded JSON object per image,
and validates the protocol version, request id, outcome flag and response size. Every request
contains the source path and a SHA-256 claim that NSFW Guard binds to the scanned artifact.
Requests are not retried automatically.

CPU is the default because allocating somebody's GPU without being asked is not a convenience.
Select DirectML explicitly with `--provider directml`. CUDA additionally requires an explicit
arena limit:

```powershell
polymorph guard image.jpg --provider cuda --cuda-arena-limit-mib 768
```

NSFW Guard owns image policy and inference evidence. Polymorph owns process discovery and protocol
validation. Neither product turns the other's score into write authority.

Measured on the release host with 200 private, SHA-256-unique real screenshots: CPU 24.89 images/s,
DirectML 84.07 images/s and CUDA 83.87 images/s. See the NSFW Guard benchmark record for RSS,
VRAM, runtime versions and limitations. A naked number without its workload is decorative, not a
benchmark.
