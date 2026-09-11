"""Render local README evidence and SVG badges. GitHub Markdown does not execute Python."""
from __future__ import annotations

import argparse
import base64
import hashlib
import html
import json
import math
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
START, END = "<!-- EVIDENCE:START -->", "<!-- EVIDENCE:END -->"


def read(path: Path) -> dict:
    raw = path.read_bytes()
    if len(raw) > 4 * 1024 * 1024:
        raise ValueError("public evidence exceeds byte limit")
    def unique(pairs):
        d = {}
        for k,v in pairs:
            if k in d:
                raise ValueError("duplicate public evidence key")
            d[k] = v
        return d
    obj = json.loads(raw, object_pairs_hook=unique)
    if not isinstance(obj, dict):
        raise ValueError("public evidence must be an object")
    return obj


def count(value: object) -> int:
    if type(value) is not int or value < 0:
        raise ValueError("public counter must be a non-negative integer")
    return value


def clean(value: object) -> str:
    if value is None:
        return "not recorded"
    return html.escape(str(value)).replace("|", "&#124;").replace("\n", " ").replace("\r", " ").replace("[", "&#91;").replace("]", "&#93;").replace("`", "&#96;")[:300]


def badge(label: str, value: str) -> str:
    left = max(64, len(label) * 7 + 14)
    right = max(42, len(value) * 7 + 14)
    width = left + right
    return (f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="22" role="img" '
            f'aria-label="{html.escape(label + ": " + value)}"><rect width="{width}" height="22" rx="4" fill="#e9edf1"/>'
            f'<path d="M{left} 0h{right}v22H{left}z" fill="#dde9e4"/>'
            f'<g fill="#24302b" font-family="Verdana,sans-serif" font-size="11" text-anchor="middle">'
            f'<text x="{left/2}" y="15">{html.escape(label)}</text>'
            f'<text x="{left+right/2}" y="15">{html.escape(value)}</text></g></svg>\n')


def render(root: Path, *, check: bool = False) -> list[str]:
    latest = read(root / "knowledge/latest.json")
    demo = read(root / "knowledge/evidence/lab-0.2-demo.json")
    general = "none published"
    examples = count(demo["evidence"]["unique_train_queries"])
    comparisons = count(demo["evidence"]["unique_train_comparisons"])
    if latest.get("package"):
        path = latest["package"]
        if not re.fullmatch(r"packs/[a-z0-9][a-z0-9.-]{0,63}\.json", path):
            raise ValueError("unsafe public package path")
        pack = root / "knowledge" / path
        if hashlib.sha256(pack.read_bytes()).hexdigest() != latest.get("sha256"):
            raise ValueError("latest package hash differs")
        signed = read(pack)["signed"]
        if signed["sequence"] != latest["sequence"] or signed["authority"] != "advisory_only":
            raise ValueError("invalid public knowledge identity")
        model = base64.b64decode(signed["model_b64"], validate=True)
        if hashlib.sha256(model).hexdigest() != signed["model_sha256"]:
            raise ValueError("published model digest differs")
        general = signed["version"]
        examples = count(signed["evidence"]["unique_train_queries"])
        comparisons = count(signed["evidence"]["unique_train_comparisons"])
    scope = "general pack" if latest.get("package") else "lab candidate"
    outputs = {
        "docs/assets/knowledge.svg": badge("general knowledge", general),
        "docs/assets/training.svg": badge(f"{scope} queries", f"{examples:,}"),
        "docs/assets/comparisons.svg": badge(f"{scope} comparisons", f"{comparisons:,}"),
    }
    rows = []
    for path in sorted((root / "knowledge/benchmarks").glob("*.json")):
        v = read(path)
        if v.get("format") != "angusu.bridge.public-workflow/1":
            raise ValueError("unknown public benchmark format")
        rate = v["median_records_per_second"]
        if type(rate) not in (int,float) or not math.isfinite(rate) or rate <= 0:
            raise ValueError("invalid throughput")
        rows.append((path, v))
    table = ["| Date / evidence | CPU / RAM / storage | OS / Python | Workload / knowledge | Records/s | Peak RSS |",
             "| --- | --- | --- | --- | ---: | ---: |"]
    for path, v in rows:
        h, w = v["hardware"], v["workload"]
        ram = f'{h["ram_total_bytes"]/1024**3:.1f} GiB' if h.get("ram_total_bytes") else "RAM not recorded"
        spec = f'{clean(h.get("cpu_model"))}; {ram}; {clean(h.get("storage_operator_supplied"))}'
        work = f'{count(w["records"]):,} rows; batch {count(w["batch_size"])}; {count(w["repeats"])} runs; {clean(v.get("model_profile"))}'
        rss = f'{v["max_peak_rss_mib"]:.2f} MiB max' if v.get("max_peak_rss_mib") is not None else "not recorded"
        if v.get("median_peak_rss_mib") is not None:
            rss = f'{v["median_peak_rss_mib"]:.2f} MiB median'
        link = path.relative_to(root).as_posix()
        table.append(f'| [{clean(v["date"][:10])}]({link}) / {clean(v["status"])} | {spec} | '
                     f'{clean(h.get("os"))} / {clean(v.get("python"))} | {work} | {v["median_records_per_second"]:.2f} | {rss} |')
    for name, german in (("README.md", False), ("README.de.md", True)):
        label = (f"**Allgemeines Wissenspaket:** {general}. **Trainingsaufgaben:** {examples:,}. "
                 f"**Eindeutige Präferenzvergleiche:** {comparisons:,}. Geltungsbereich: `{scope}`."
                 if german else f"**General knowledge package:** {general}. **Training queries:** {examples:,}. "
                 f"**Unique preference comparisons:** {comparisons:,}. Scope: `{scope}`.")
        note = ("Diese Zähler beschreiben den ausgewählten Stand, nicht die Summe aller Epochen oder wiederholten Tests. "
                "Parserzeilen sind keine gelernten Mapping-Entscheidungen."
                if german else "Counters describe the selected artifact, not all epochs or repeated tests added together. "
                "Parsed rows are not learned mapping decisions.")
        footer = ("Eine gemeinsame Tabelle für alle Messrechner. Fehlende CPU-, RAM- und Datenträgerangaben werden nicht geraten. "
                  "Die beiden Zeilen unten stammen vom selben Windows-Rechner. Der neue Stand braucht eine neue vollständige Messung."
                  if german else "One table across measurement machines. Missing CPU, RAM and storage details are not guessed. "
                  "The two historical entries below are from the same Windows host. The new code needs a new complete measurement.")
        rendered_table = "\n".join(table)
        if german:
            rendered_table = rendered_table.replace("| Date / evidence | CPU / RAM / storage | OS / Python | Workload / knowledge | Records/s | Peak RSS |", "| Datum / Nachweis | CPU / RAM / Datenträger | OS / Python | Arbeitslast / Wissen | Records/s | Peak RSS |")
            rendered_table = rendered_table.replace("not recorded", "nicht erfasst").replace("RAM not recorded", "RAM nicht erfasst")
        content = label + "\n\n" + note + "\n\n" + footer + "\n\n" + rendered_table
        original = (root / name).read_text(encoding="utf-8")
        if original.count(START) != 1 or original.count(END) != 1 or original.index(START) > original.index(END):
            raise ValueError("README evidence markers are missing or ambiguous")
        outputs[name] = original.split(START)[0] + START + "\n" + content + "\n" + END + original.split(END)[1]
    changed = []
    for relative, text in outputs.items():
        dest = root / relative
        if not dest.exists() or dest.read_bytes() != text.encode("utf-8"):
            changed.append(relative)
            if not check:
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes(text.encode("utf-8"))
    return changed


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--check", action="store_true")
    args = p.parse_args()
    differences = render(ROOT, check=args.check)
    print(json.dumps({"changed" if not args.check else "stale": differences}))
    raise SystemExit(1 if args.check and differences else 0)
