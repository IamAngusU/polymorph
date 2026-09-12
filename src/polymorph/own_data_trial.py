# ruff: noqa: E501
from __future__ import annotations

import argparse
import html
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import webbrowser
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import cast


class TrialError(RuntimeError):
    """Raised when a local no-write trial cannot produce trustworthy output."""


def _positive_int(value: str) -> int:
    parsed = int(value)
    if parsed < 1:
        raise argparse.ArgumentTypeError("must be at least 1")
    return parsed


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="polymorph trial",
        description=(
            "Inspect one supported local file and build a metadata-only, no-write report."
        ),
    )
    parser.add_argument("source", type=Path, help="local source file to inspect")
    parser.add_argument(
        "--output",
        type=Path,
        help="new report directory (default: .polymorph/trials/<timestamp>-<file>)",
    )
    parser.add_argument("--max-records", type=_positive_int, default=10_000)
    parser.add_argument("--max-samples", type=_positive_int, default=32)
    parser.add_argument("--max-groups", type=_positive_int, default=128)
    parser.add_argument(
        "--open",
        action="store_true",
        help="open the finished local report in the default browser",
    )
    return parser


def _mapping(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise TrialError(f"{label} must be a JSON object")
    return cast(dict[str, object], value)


def _load_json(path: Path, label: str) -> dict[str, object]:
    try:
        if path.stat().st_size > 16 * 1024 * 1024:
            raise TrialError(f"{label} exceeds the 16 MiB report limit")
        parsed: object = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise TrialError(f"could not read {label}") from exc
    return _mapping(parsed, label)


def _write_bytes(path: Path, payload: bytes) -> None:
    with path.open("xb") as handle:
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())
    if os.name != "nt":
        path.chmod(0o600)


def _write_json(path: Path, payload: object) -> None:
    encoded = (
        json.dumps(
            payload,
            ensure_ascii=True,
            indent=2,
            sort_keys=True,
        ).encode("utf-8")
        + b"\n"
    )
    _write_bytes(path, encoded)


def _run(command: list[str], phase: str) -> None:
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            check=False,
            text=True,
        )
    except OSError as exc:
        raise TrialError(f"{phase} could not start") from exc
    if completed.returncode != 0:
        raise TrialError(f"{phase} failed with exit code {completed.returncode}")


def _scrub(value: object, replacements: tuple[str, ...], label: str) -> object:
    if isinstance(value, str):
        scrubbed = value
        for replacement in replacements:
            scrubbed = scrubbed.replace(replacement, label)
        return scrubbed
    if isinstance(value, list):
        return [_scrub(item, replacements, label) for item in value]
    if isinstance(value, dict):
        return {str(key): _scrub(item, replacements, label) for key, item in value.items()}
    return value


def _sanitize_schema(document: dict[str, object], source: Path) -> dict[str, object]:
    content = _mapping(document.get("content"), "schema content")
    content["path"] = source.name
    identity = content.get("identity")
    if isinstance(identity, dict):
        content["identity"] = {"size_bytes": identity.get("size_bytes")}

    schema = _mapping(document.get("schema"), "schema")
    metadata = schema.get("metadata")
    if isinstance(metadata, dict):
        metadata["path"] = source.name

    resolved = str(source)
    replacements = tuple(item for item in {resolved, resolved.replace("\\", "/")} if item)
    scrubbed = _scrub(document, replacements, source.name)
    return _mapping(scrubbed, "sanitized schema")


def _fields(document: dict[str, object]) -> list[dict[str, object]]:
    schema = _mapping(document.get("schema"), "schema")
    value = schema.get("fields")
    if not isinstance(value, list):
        raise TrialError("schema fields must be a JSON array")
    fields: list[dict[str, object]] = []
    for index, item in enumerate(value):
        fields.append(_mapping(item, f"schema field {index}"))
    return fields


def _text(value: object, fallback: str = "unknown") -> str:
    if value is None:
        return fallback
    return str(value)


def _integer(value: object, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise TrialError(f"{label} must be a non-negative integer")
    return value


def _render_html(
    *,
    source_name: str,
    kind: str,
    fields: list[dict[str, object]],
    records_scanned: int,
    issue_count: int,
    complete: bool,
) -> str:
    rows = []
    for field in fields:
        nullable = "yes" if field.get("nullable") is True else "no"
        rows.append(
            "<tr>"
            f"<td><strong>{html.escape(_text(field.get('name')))}</strong></td>"
            f"<td>{html.escape(_text(field.get('data_type')))}</td>"
            f"<td>{html.escape(_text(field.get('role')))}</td>"
            f"<td>{html.escape(_text(field.get('sensitivity')))}</td>"
            f"<td>{nullable}</td>"
            "</tr>"
        )
    field_rows = "".join(rows)
    completion = "complete bounded scan" if complete else "bounded partial scan"
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'">
  <title>Polymorph local trial</title>
  <style>
    :root {{ --paper:#f5f2ea; --ink:#102a2b; --muted:#587071; --line:#c9d3cc; --mint:#d9f3df; --coral:#ef6a4b; --white:#fffefa; }}
    * {{ box-sizing:border-box; }}
    body {{ margin:0; color:var(--ink); background:radial-gradient(circle at 92% 4%, #d9f3df 0, transparent 28rem), var(--paper); font-family:"Aptos", "Trebuchet MS", sans-serif; }}
    main {{ width:min(1080px, calc(100% - 32px)); margin:0 auto; padding:56px 0 72px; }}
    header {{ display:grid; grid-template-columns:1.45fr .75fr; gap:28px; align-items:end; border-bottom:2px solid var(--ink); padding-bottom:28px; }}
    .kicker {{ text-transform:uppercase; letter-spacing:.16em; font-size:.76rem; font-weight:800; color:#287252; }}
    h1 {{ margin:.35rem 0 .5rem; font-family:Georgia, serif; font-size:clamp(2.8rem, 8vw, 6.3rem); font-weight:500; line-height:.88; letter-spacing:-.055em; }}
    .lede {{ max-width:58ch; color:var(--muted); font-size:1.08rem; line-height:1.6; }}
    .boundary {{ background:var(--ink); color:var(--white); padding:20px; border-radius:2px; box-shadow:9px 9px 0 var(--coral); }}
    .boundary strong {{ display:block; font-family:Georgia, serif; font-size:1.35rem; margin-bottom:8px; }}
    .boundary span {{ display:block; margin-top:7px; }}
    .metrics {{ display:grid; grid-template-columns:repeat(3,1fr); gap:14px; margin:30px 0; }}
    .metric {{ background:var(--white); border:1px solid var(--line); padding:20px; }}
    .metric b {{ display:block; font-family:Georgia, serif; font-size:2.35rem; font-weight:500; }}
    .metric span {{ color:var(--muted); font-size:.84rem; text-transform:uppercase; letter-spacing:.08em; }}
    section {{ background:rgba(255,254,250,.82); border:1px solid var(--line); padding:clamp(18px,4vw,32px); margin-top:18px; }}
    h2 {{ margin:0 0 16px; font-family:Georgia, serif; font-size:1.65rem; font-weight:500; }}
    table {{ width:100%; border-collapse:collapse; font-size:.92rem; }}
    th,td {{ padding:12px 10px; text-align:left; border-bottom:1px solid var(--line); }}
    th {{ color:var(--muted); text-transform:uppercase; letter-spacing:.08em; font-size:.72rem; }}
    .files {{ display:flex; flex-wrap:wrap; gap:10px; }}
    a {{ color:var(--ink); text-decoration-thickness:2px; text-underline-offset:3px; }}
    footer {{ color:var(--muted); margin-top:24px; font-size:.86rem; }}
    @media (max-width:720px) {{ header {{ grid-template-columns:1fr; }} .metrics {{ grid-template-columns:1fr; }} section {{ overflow-x:auto; }} h1 {{ font-size:3.4rem; }} }}
  </style>
</head>
<body>
<main>
  <header>
    <div>
      <div class="kicker">Polymorph / local evidence trial</div>
      <h1>Your data.<br>No write.</h1>
      <p class="lede"><strong>{html.escape(source_name)}</strong> was inspected locally as <strong>{html.escape(kind)}</strong>. This report contains schema descriptors and bounded quality metadata, not record values.</p>
    </div>
    <aside class="boundary">
      <strong>Boundary held</strong>
      <span>NO DESTINATION</span>
      <span>NO WRITE AUTHORITY</span>
      <span>NO NETWORK REQUEST</span>
    </aside>
  </header>
  <div class="metrics">
    <div class="metric"><b>{len(fields)}</b><span>fields described</span></div>
    <div class="metric"><b>{records_scanned}</b><span>records scanned</span></div>
    <div class="metric"><b>{issue_count}</b><span>quality issues</span></div>
  </div>
  <section>
    <h2>Observed schema</h2>
    <table>
      <thead><tr><th>Field</th><th>Type</th><th>Role</th><th>Sensitivity</th><th>Nullable</th></tr></thead>
      <tbody>{field_rows}</tbody>
    </table>
  </section>
  <section>
    <h2>Evidence files</h2>
    <p>The quality phase reports a {completion}. Inspect the machine-readable artifacts without granting any connector credentials.</p>
    <div class="files"><a href="schema.json">schema.json</a><a href="quality.json">quality.json</a><a href="trial-summary.json">trial-summary.json</a></div>
  </section>
  <footer>Generated locally by Polymorph. A trial report is evidence about this input and this bounded scan, not a promise about every future file.</footer>
</main>
</body>
</html>
"""


def _slug(value: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9]+", "-", value).strip("-").lower()
    return slug[:48] or "data"


def _default_output(source: Path) -> Path:
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    return Path.cwd() / ".polymorph" / "trials" / f"{stamp}-{_slug(source.stem)}"


def build_trial(
    source: Path,
    output: Path,
    *,
    max_records: int,
    max_samples: int,
    max_groups: int,
) -> dict[str, object]:
    try:
        resolved_source = source.expanduser().resolve(strict=True)
    except OSError as exc:
        raise TrialError("source must be an existing local file") from exc
    if not resolved_source.is_file():
        raise TrialError("source must be an existing local file")

    resolved_output = output.expanduser().resolve()
    if resolved_output.exists():
        raise TrialError("output directory already exists")
    resolved_output.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(
        tempfile.mkdtemp(
            prefix=f".{resolved_output.name}.",
            dir=resolved_output.parent,
        )
    )
    try:
        raw_schema_path = temporary / "schema.raw.json"
        quality_path = temporary / "quality.json"
        _run(
            [
                sys.executable,
                "-m",
                "polymorph",
                "inspect",
                "auto",
                str(resolved_source),
                "--output",
                str(raw_schema_path),
            ],
            "schema inspection",
        )
        _run(
            [
                sys.executable,
                "-m",
                "polymorph.toolkit",
                "quality",
                "inspect",
                str(resolved_source),
                "--max-records",
                str(max_records),
                "--max-samples",
                str(max_samples),
                "--max-groups",
                str(max_groups),
                "--output",
                str(quality_path),
            ],
            "quality inspection",
        )

        raw_schema = _load_json(raw_schema_path, "schema report")
        quality = _load_json(quality_path, "quality report")
        if quality.get("privacy") != "metadata_only_no_record_values":
            raise TrialError("quality report did not prove metadata-only privacy")
        sanitized_schema = _sanitize_schema(raw_schema, resolved_source)
        fields = _fields(sanitized_schema)
        records_scanned = _integer(quality.get("records_scanned"), "records_scanned")
        issue_count = _integer(quality.get("issue_count"), "issue_count")
        complete = quality.get("complete") is True
        content = _mapping(sanitized_schema.get("content"), "schema content")
        kind = _text(content.get("kind"))

        raw_schema_path.unlink()
        _write_json(temporary / "schema.json", sanitized_schema)
        summary: dict[str, object] = {
            "complete": complete,
            "field_count": len(fields),
            "format": kind,
            "generated_at": datetime.now(UTC).isoformat(),
            "issue_count": issue_count,
            "network_used": False,
            "privacy": "metadata_only_no_record_values",
            "records_scanned": records_scanned,
            "schema": "polymorph.local-trial",
            "source": resolved_source.name,
            "version": 1,
            "write_authority": False,
        }
        _write_json(temporary / "trial-summary.json", summary)
        _write_bytes(
            temporary / "index.html",
            _render_html(
                source_name=resolved_source.name,
                kind=kind,
                fields=fields,
                records_scanned=records_scanned,
                issue_count=issue_count,
                complete=complete,
            ).encode("utf-8"),
        )
        os.replace(temporary, resolved_output)
        temporary = Path()
        return {**summary, "output": str(resolved_output), "status": "passed"}
    finally:
        if temporary != Path() and temporary.exists():
            shutil.rmtree(temporary, ignore_errors=True)


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    source = cast(Path, args.source)
    output_value = cast(Path | None, args.output)
    output = output_value if output_value is not None else _default_output(source)
    try:
        result = build_trial(
            source,
            output,
            max_records=cast(int, args.max_records),
            max_samples=cast(int, args.max_samples),
            max_groups=cast(int, args.max_groups),
        )
    except TrialError as exc:
        print(f"trial failed: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, ensure_ascii=True, sort_keys=True))
    if cast(bool, args.open):
        report = Path(cast(str, result["output"])) / "index.html"
        webbrowser.open(report.as_uri())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
