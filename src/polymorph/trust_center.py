# ruff: noqa: E501
from __future__ import annotations

import argparse
import html
import json
import os
import shutil
import statistics
import sys
import tempfile
import webbrowser
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import cast


class TrustCenterError(RuntimeError):
    """Raised when evidence cannot support a release trust statement."""


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="polymorph trust",
        description="Build a static Trust Center from commit-bound local evidence.",
    )
    parser.add_argument("release_manifest", type=Path)
    parser.add_argument("validation_summary", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--open", action="store_true")
    return parser


def _mapping(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise TrustCenterError(f"{label} must be a JSON object")
    return cast(dict[str, object], value)


def _load(path: Path, label: str) -> dict[str, object]:
    try:
        if path.stat().st_size > 16 * 1024 * 1024:
            raise TrustCenterError(f"{label} exceeds 16 MiB")
        parsed: object = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise TrustCenterError(f"could not read {label}") from exc
    return _mapping(parsed, label)


def _required_text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise TrustCenterError(f"{label} must be a non-empty string")
    return value


def _release_value(
    document: dict[str, object],
    nested: dict[str, object],
    *names: str,
) -> object:
    for name in names:
        if name in nested:
            return nested[name]
        if name in document:
            return document[name]
    return None


def _integer(value: object, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise TrustCenterError(f"{label} must be a non-negative integer")
    return value


def _number(value: object, label: str) -> float:
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        raise TrustCenterError(f"{label} must be numeric")
    return float(value)


def _artifacts(document: dict[str, object]) -> list[dict[str, object]]:
    value = document.get("artifacts")
    if not isinstance(value, list) or not value:
        raise TrustCenterError("release manifest must contain artifacts")
    result: list[dict[str, object]] = []
    for index, item in enumerate(value):
        artifact = _mapping(item, f"artifact {index}")
        raw_name = artifact.get("name", artifact.get("filename", artifact.get("path")))
        name = Path(_required_text(raw_name, f"artifact {index} name")).name
        sha256 = _required_text(artifact.get("sha256"), f"artifact {index} sha256")
        raw_size = artifact.get("size_bytes", artifact.get("bytes", artifact.get("size")))
        result.append(
            {
                "name": name,
                "sha256": sha256,
                "size_bytes": _integer(raw_size, f"artifact {index} size"),
            }
        )
    return result


def _workflow_summary(validation: dict[str, object]) -> dict[str, object]:
    raw = _mapping(validation.get("workflow_measurements"), "workflow measurements")
    throughput: list[float] = []
    peak_rss: list[float] = []
    wall: list[float] = []
    for name, value in raw.items():
        measurement = _mapping(value, f"workflow measurement {name}")
        throughput.append(_number(measurement.get("throughput_per_second"), "throughput"))
        peak_rss.append(_number(measurement.get("peak_rss_mib"), "peak RSS"))
        wall.append(_number(measurement.get("wall_seconds"), "wall time"))
    if not throughput:
        raise TrustCenterError("validation has no workflow measurements")
    return {
        "peak_rss_mib_max": max(peak_rss),
        "runs": len(throughput),
        "throughput_per_second_max": max(throughput),
        "throughput_per_second_median": statistics.median(throughput),
        "throughput_per_second_min": min(throughput),
        "wall_seconds_median": statistics.median(wall),
    }


def _bounded_strings(value: object, label: str) -> list[str]:
    if not isinstance(value, list) or len(value) > 128:
        raise TrustCenterError(f"{label} must be a bounded JSON array")
    result: list[str] = []
    for item in value:
        result.append(_required_text(item, label))
    return result


def build_evidence(manifest: dict[str, object], validation: dict[str, object]) -> dict[str, object]:
    project_value = manifest.get("project")
    project = project_value if isinstance(project_value, dict) else {}
    source_value = manifest.get("source")
    source = source_value if isinstance(source_value, dict) else {}
    project_mapping = cast(dict[str, object], project)
    source_mapping = cast(dict[str, object], source)
    version = _required_text(
        project_mapping.get("version", manifest.get("project_version")),
        "project version",
    )
    commit = _required_text(
        _release_value(manifest, source_mapping, "commit", "source_commit"),
        "source commit",
    )
    clean = _release_value(
        manifest,
        source_mapping,
        "working_tree_clean",
        "source_working_tree_clean",
    )
    if clean is not True:
        raise TrustCenterError("release manifest is not bound to a clean tree")
    tree_sha256 = _required_text(
        _release_value(
            manifest,
            source_mapping,
            "tree_sha256",
            "source_tree_sha256",
        ),
        "source tree SHA-256",
    )

    if validation.get("status") != "passed":
        raise TrustCenterError("validation status is not passed")
    if validation.get("source_unchanged") is not True:
        raise TrustCenterError("validation source changed during the run")
    before = _mapping(validation.get("source_before"), "source before")
    after = _mapping(validation.get("source_after"), "source after")
    for label, snapshot in (("before", before), ("after", after)):
        if snapshot.get("dirty") is not False:
            raise TrustCenterError(f"validation source {label} was dirty")
        if snapshot.get("commit") != commit:
            raise TrustCenterError(f"validation source {label} commit does not match")
    if before.get("source_sha256") != after.get("source_sha256"):
        raise TrustCenterError("validation source digest changed")

    tests = _mapping(validation.get("tests"), "tests")
    passed = _integer(tests.get("passed"), "passed tests")
    failed = _integer(tests.get("failed"), "failed tests")
    errors = _integer(tests.get("errors"), "test errors")
    skipped = _integer(tests.get("skipped"), "skipped tests")
    if failed or errors:
        raise TrustCenterError("validation contains failed tests")

    host = _mapping(validation.get("host"), "host")
    limits = _bounded_strings(validation.get("not_covered"), "not covered")
    return {
        "generated_at": datetime.now(UTC).isoformat(),
        "provenance": {
            "external_audit": False,
            "github_actions_used": False,
            "independent": False,
            "origin": "local_maintainer_machine",
        },
        "release": {
            "artifacts": _artifacts(manifest),
            "source_commit": commit,
            "source_tree_sha256": tree_sha256,
            "version": version,
            "working_tree_clean": True,
        },
        "schema": "polymorph.trust-center",
        "validation": {
            "host": {
                "machine": _required_text(host.get("machine"), "host machine"),
                "os": _required_text(host.get("os"), "host OS"),
                "python": _required_text(host.get("python"), "Python version"),
            },
            "not_covered": limits,
            "run_id": _required_text(validation.get("run_id"), "validation run ID"),
            "source_sha256": _required_text(
                after.get("source_sha256"), "validation source SHA-256"
            ),
            "status": "passed",
            "tests": {
                "errors": errors,
                "failed": failed,
                "passed": passed,
                "skipped": skipped,
            },
            "workflow": _workflow_summary(validation),
        },
        "version": 1,
    }


def _render(evidence: dict[str, object]) -> str:
    release = _mapping(evidence.get("release"), "release")
    validation = _mapping(evidence.get("validation"), "validation")
    tests = _mapping(validation.get("tests"), "tests")
    workflow = _mapping(validation.get("workflow"), "workflow")
    host = _mapping(validation.get("host"), "host")
    artifacts_value = release.get("artifacts")
    if not isinstance(artifacts_value, list):
        raise TrustCenterError("release artifacts must be an array")
    artifact_rows = []
    for item in artifacts_value:
        artifact = _mapping(item, "artifact")
        artifact_rows.append(
            "<tr>"
            f"<td><strong>{html.escape(str(artifact['name']))}</strong></td>"
            f"<td>{int(cast(int, artifact['size_bytes'])):,}</td>"
            f"<td><code>{html.escape(str(artifact['sha256']))}</code></td>"
            "</tr>"
        )
    limits = _bounded_strings(validation.get("not_covered"), "not covered")
    limit_items = "".join(f"<li>{html.escape(item)}</li>" for item in limits)
    version = html.escape(str(release["version"]))
    commit = html.escape(str(release["source_commit"]))
    median = _number(workflow.get("throughput_per_second_median"), "throughput")
    peak = _number(workflow.get("peak_rss_mib_max"), "peak RSS")
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
  <title>Polymorph {version} Trust Center</title>
  <style>
    :root {{ --paper:#f3f1e8; --ink:#142c30; --muted:#607476; --line:#c5d0ca; --green:#167451; --lime:#d8f09d; --white:#fffefa; --amber:#efb45c; }}
    * {{ box-sizing:border-box; }} body {{ margin:0; background:linear-gradient(120deg,#f3f1e8 0 72%,#e1eadf 72%); color:var(--ink); font-family:"Aptos", "Trebuchet MS", sans-serif; }}
    main {{ width:min(1120px,calc(100% - 32px)); margin:auto; padding:52px 0 72px; }}
    header {{ display:grid; grid-template-columns:1fr auto; gap:28px; border-bottom:3px solid var(--ink); padding-bottom:28px; align-items:end; }}
    .kicker {{ color:var(--green); font-weight:800; letter-spacing:.16em; text-transform:uppercase; font-size:.75rem; }}
    h1 {{ font-family:Georgia,serif; font-size:clamp(3rem,8vw,6.8rem); line-height:.88; letter-spacing:-.06em; font-weight:500; margin:.4rem 0 .7rem; }}
    .commit {{ font-family:Consolas,monospace; background:var(--ink); color:var(--lime); padding:16px; max-width:28rem; overflow-wrap:anywhere; }}
    .stamp {{ background:var(--lime); border:2px solid var(--ink); padding:20px; transform:rotate(1.5deg); box-shadow:8px 8px 0 var(--ink); font-weight:800; text-transform:uppercase; letter-spacing:.08em; }}
    .grid {{ display:grid; grid-template-columns:repeat(4,1fr); gap:14px; margin:30px 0; }}
    .metric,section {{ background:rgba(255,254,250,.92); border:1px solid var(--line); }}
    .metric {{ padding:20px; }} .metric b {{ display:block; font-family:Georgia,serif; font-weight:500; font-size:2.15rem; }} .metric span {{ color:var(--muted); font-size:.75rem; text-transform:uppercase; letter-spacing:.08em; }}
    section {{ padding:clamp(18px,4vw,32px); margin-top:18px; }} h2 {{ font-family:Georgia,serif; font-weight:500; font-size:1.7rem; margin:0 0 14px; }}
    table {{ border-collapse:collapse; width:100%; font-size:.86rem; }} th,td {{ padding:12px 9px; border-bottom:1px solid var(--line); text-align:left; vertical-align:top; }} th {{ color:var(--muted); text-transform:uppercase; letter-spacing:.08em; font-size:.7rem; }} code {{ font-size:.76rem; overflow-wrap:anywhere; }}
    .warning {{ border-left:8px solid var(--amber); }} li {{ margin:.55rem 0; }} a {{ color:var(--ink); text-decoration-thickness:2px; text-underline-offset:3px; }}
    @media(max-width:800px) {{ header {{ grid-template-columns:1fr; }} .grid {{ grid-template-columns:repeat(2,1fr); }} section {{ overflow-x:auto; }} }}
    @media(max-width:480px) {{ .grid {{ grid-template-columns:1fr; }} h1 {{ font-size:3.2rem; }} }}
  </style>
</head>
<body><main>
  <header><div><div class="kicker">Polymorph / release evidence</div><h1>Trust,<br>with limits.</h1><p>Release <strong>{version}</strong> is bound to a clean local validation of the exact commit below.</p><div class="commit">{commit}</div></div><div class="stamp">Commit matched<br>Tree clean<br>Validation passed</div></header>
  <div class="grid">
    <div class="metric"><b>{int(cast(int, tests["passed"])):,}</b><span>tests passed</span></div>
    <div class="metric"><b>{int(cast(int, tests["skipped"]))}</b><span>explicitly skipped</span></div>
    <div class="metric"><b>{median:.2f}</b><span>median rows/s locally</span></div>
    <div class="metric"><b>{peak:.2f}</b><span>max peak RSS MiB</span></div>
  </div>
  <section><h2>Release artifacts</h2><table><thead><tr><th>Artifact</th><th>Bytes</th><th>SHA-256</th></tr></thead><tbody>{"".join(artifact_rows)}</tbody></table></section>
  <section><h2>Measurement context</h2><p>{html.escape(str(host["os"]))} / {html.escape(str(host["machine"]))} / Python {html.escape(str(host["python"]))}. The workflow figure is the median of {int(cast(int, workflow["runs"]))} local runs. It is reproducible evidence for this host and run, not a universal speed claim.</p><p><a href="evidence.json">Machine-readable evidence.json</a></p></section>
  <section class="warning"><h2>What this does not prove</h2><p>This is maintainer-controlled local evidence. It is not an independent audit, external witness, GitHub Actions run or cross-platform certification.</p><ul>{limit_items}</ul></section>
</main></body></html>
"""


def _write(path: Path, payload: bytes) -> None:
    with path.open("xb") as handle:
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())
    if os.name != "nt":
        path.chmod(0o600)


def build_trust_center(
    release_manifest: Path,
    validation_summary: Path,
    output: Path,
) -> dict[str, object]:
    resolved_output = output.expanduser().resolve()
    if resolved_output.exists():
        raise TrustCenterError("output directory already exists")
    evidence = build_evidence(
        _load(release_manifest.expanduser().resolve(strict=True), "release manifest"),
        _load(validation_summary.expanduser().resolve(strict=True), "validation summary"),
    )
    resolved_output.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(
        tempfile.mkdtemp(
            prefix=f".{resolved_output.name}.",
            dir=resolved_output.parent,
        )
    )
    try:
        encoded = (
            json.dumps(
                evidence,
                ensure_ascii=True,
                indent=2,
                sort_keys=True,
            ).encode("utf-8")
            + b"\n"
        )
        _write(temporary / "evidence.json", encoded)
        _write(temporary / "index.html", _render(evidence).encode("utf-8"))
        os.replace(temporary, resolved_output)
        temporary = Path()
    finally:
        if temporary != Path() and temporary.exists():
            shutil.rmtree(temporary, ignore_errors=True)
    release = _mapping(evidence.get("release"), "release")
    return {
        "output": str(resolved_output),
        "source_commit": release["source_commit"],
        "status": "passed",
        "version": release["version"],
    }


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        result = build_trust_center(
            cast(Path, args.release_manifest),
            cast(Path, args.validation_summary),
            cast(Path, args.output),
        )
    except (OSError, TrustCenterError) as exc:
        print(f"trust center failed: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, ensure_ascii=True, sort_keys=True))
    if cast(bool, args.open):
        report = Path(cast(str, result["output"])) / "index.html"
        webbrowser.open(report.as_uri())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
