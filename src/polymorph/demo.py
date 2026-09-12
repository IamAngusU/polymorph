# ruff: noqa: E501

from __future__ import annotations

import html
import json
import os
import uuid
import webbrowser
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from decimal import Decimal
from pathlib import Path
from typing import cast

from .connectors.base import ConnectorCapabilities, DeliveryContext
from .domain_events import PolymorphEvent
from .embed import MoveSession
from .models.schema import FieldDescriptor, SchemaDescriptor
from .models.types import DataType


@dataclass(slots=True)
class _DemoSource:
    schema: SchemaDescriptor
    rows: tuple[Mapping[str, object], ...]
    capabilities = ConnectorCapabilities(read_schema=True, read_records=True)

    def inspect_schema(self) -> SchemaDescriptor:
        return self.schema

    def iter_records(self) -> Iterable[Mapping[str, object]]:
        return iter(self.rows)


@dataclass(slots=True)
class _DemoDestination:
    schema: SchemaDescriptor
    capabilities = ConnectorCapabilities(read_schema=True, write_records=True)

    def inspect_schema(self) -> SchemaDescriptor:
        return self.schema

    def write_records(
        self,
        records: Iterable[Mapping[str, object]],
        *,
        context: DeliveryContext | None = None,
    ) -> int:
        del records, context
        raise RuntimeError("the product demo never crosses the destination write boundary")


def _demo_schemas() -> tuple[SchemaDescriptor, SchemaDescriptor]:
    fields = (
        FieldDescriptor("customer_id", "Customer ID", DataType.STRING, nullable=False),
        FieldDescriptor("invoice_total", "Invoice Total", DataType.DECIMAL, nullable=False),
        FieldDescriptor("tax_rate", "Tax Rate", DataType.DECIMAL, nullable=False),
        FieldDescriptor("unit_code", "Unit Code", DataType.STRING, nullable=False),
    )
    destination_fields = tuple(
        FieldDescriptor(
            item.id,
            item.name,
            item.data_type,
            nullable=item.nullable,
            aliases=(item.id.replace("_", " "),),
        )
        for item in fields
    )
    return SchemaDescriptor("demo-source", fields), SchemaDescriptor(
        "demo-destination", destination_fields
    )


def build_demo_payload(*, locale: str = "en") -> dict[str, object]:
    if locale not in {"de", "en"}:
        raise ValueError("demo locale must be 'en' or 'de'")
    source_schema, destination_schema = _demo_schemas()
    source = _DemoSource(
        source_schema,
        (
            {
                "customer_id": "C-1042",
                "invoice_total": Decimal("1240.50"),
                "tax_rate": Decimal("19.0"),
                "unit_code": "EA",
            },
            {
                "customer_id": "C-1043",
                "invoice_total": Decimal("78.90"),
                "tax_rate": Decimal("7.0"),
                "unit_code": "KG",
            },
        ),
    )
    destination = _DemoDestination(destination_schema)
    events: list[PolymorphEvent] = []
    session = MoveSession(source, destination, max_input_records=100)
    session.on("*", events.append)
    preparation = session.prepare()
    event_payloads: list[dict[str, object]] = []
    for event in events:
        item = event.as_dict()
        item["message"] = event.localized_message(locale)
        event_payloads.append(item)
    decision_counts = {"auto": 0, "review": 0, "blocked": 0}
    for decision in preparation.decisions:
        decision_counts[decision.status.value] += 1
    return {
        "contract_version": 1,
        "demo_mode": "synthetic_no_write",
        "locale": locale,
        "network_used": False,
        "account_required": False,
        "destination_write_called": False,
        "synthetic_records_checked": (
            preparation.preflight.records_checked if preparation.preflight is not None else 0
        ),
        "decision_counts": decision_counts,
        "route": preparation.as_dict(),
        "events": event_payloads,
        "trust_facts": [
            "Source content and schema are inspected before mapping.",
            "Only deterministic contract evidence can authorize an automatic rule.",
            "A complete preflight reads every synthetic record without destination writes.",
            "Execution remains a separate explicit method call.",
            "Domain events contain control metadata, not record payload values.",
        ],
    }


def _mapping(value: object, *, label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise ValueError(f"invalid demo payload section: {label}")
    return cast(Mapping[str, object], value)


def _sequence(value: object, *, label: str) -> list[object]:
    if not isinstance(value, list):
        raise ValueError(f"invalid demo payload section: {label}")
    return value


def _float_value(value: object, *, default: float = 0.0) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return default
    return float(value)


def _int_value(value: object, *, default: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        return default
    return value


def render_demo_html(payload: Mapping[str, object]) -> str:
    locale = str(payload.get("locale", "en"))
    german = locale == "de"
    words = {
        "eyebrow": "LOKALE PRODUKT-DEMO" if german else "LOCAL PRODUCT DEMO",
        "title": "Eine Datenroute, bevor sie schreiben darf."
        if german
        else "A data route before it earns the right to write.",
        "subtitle": (
            "Echte Mapping- und Preflight-Entscheidungen auf synthetischen Daten. Kein Account, "
            "kein Netzwerk, kein Ziel-Write."
            if german
            else "Real mapping and preflight decisions on synthetic data. No account, no network, no destination write."
        ),
        "status": "Routenstatus" if german else "Route status",
        "checked": "Records geprueft" if german else "Records checked",
        "automatic": "Automatische Regeln" if german else "Automatic rules",
        "review": "Review-Regeln" if german else "Review rules",
        "route": "Entscheidungsoberflaeche" if german else "Decision surface",
        "events": "Produkt-Event-Timeline" if german else "Product event timeline",
        "trust": "Was diese Demo beweist" if german else "What this demo proves",
        "failure": "Failure Lab" if german else "Failure lab",
        "failure_text": (
            "In echten Runs werden Ambiguitaet, Schema-Drift und unbekannte Write-Outcomes als "
            "eigene Zustaende sichtbar, nicht als optimistische Retries."
            if german
            else "In real runs, ambiguity, schema drift and unknown write outcomes become explicit states, not optimistic retries."
        ),
        "download": "Evidence JSON laden" if german else "Download evidence JSON",
        "no_write": "ZIEL-WRITE NICHT AUFGERUFEN" if german else "DESTINATION WRITE NOT CALLED",
    }
    route = _mapping(payload.get("route"), label="route")
    decisions = _sequence(route.get("decisions"), label="decisions")
    decision_counts = _mapping(payload.get("decision_counts"), label="decision_counts")
    events = _sequence(payload.get("events"), label="events")
    trust_facts = _sequence(payload.get("trust_facts"), label="trust_facts")
    decision_rows: list[str] = []
    for raw_decision in decisions:
        decision = _mapping(raw_decision, label="decision")
        status = html.escape(str(decision.get("status", "unknown")))
        source = html.escape(str(decision.get("source_field_id", "")))
        target = html.escape(str(decision.get("target_field_id", "unmapped")))
        score = _float_value(decision.get("score"))
        decision_rows.append(
            f'<article class="decision" data-status="{status}">'
            f'<span class="status status-{status}">{status}</span>'
            f'<div><strong>{source}</strong><span class="arrow">-&gt;</span><strong>{target}</strong></div>'
            f'<meter min="0" max="1" value="{score:.6f}">{score:.2f}</meter>'
            f"<small>{score:.3f} evidence score</small></article>"
        )
    event_rows: list[str] = []
    for index, raw_event in enumerate(events, start=1):
        event = _mapping(raw_event, label="event")
        event_type = html.escape(str(event.get("event_type", "unknown")))
        message = html.escape(str(event.get("message", event.get("default_message", ""))))
        severity = html.escape(str(event.get("severity", "info")))
        event_rows.append(
            f'<li><span class="event-index">{index:02d}</span><div><code>{event_type}</code>'
            f'<p>{message}</p></div><span class="severity severity-{severity}">{severity}</span></li>'
        )
    facts = "".join(f"<li>{html.escape(str(item))}</li>" for item in trust_facts)
    evidence_json = json.dumps(payload, ensure_ascii=False, sort_keys=True).replace("<", "\\u003c")
    return f'''<!doctype html>
<html lang="{locale}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Polymorph local product demo</title>
<style>
:root {{ --paper:#f7f4eb; --ink:#102b2a; --muted:#5b6d68; --line:#c9d4ca; --green:#0b7a53; --lime:#d8f08a; --orange:#e97837; --red:#b9382f; --white:#fffdf7; }}
* {{ box-sizing:border-box; }}
body {{ margin:0; color:var(--ink); background:radial-gradient(circle at 12% 5%,#e8f5c9 0,transparent 26rem),linear-gradient(135deg,var(--paper),#eef3ea 68%,#f8eadc); font-family:"Avenir Next","Trebuchet MS",sans-serif; min-height:100vh; }}
body::before {{ content:""; position:fixed; inset:0; pointer-events:none; opacity:.25; background-image:linear-gradient(rgba(16,43,42,.08) 1px,transparent 1px),linear-gradient(90deg,rgba(16,43,42,.08) 1px,transparent 1px); background-size:36px 36px; mask-image:linear-gradient(to bottom,black,transparent 70%); }}
.shell {{ width:min(1180px,calc(100% - 32px)); margin:auto; padding:54px 0 72px; position:relative; }}
.hero {{ display:grid; grid-template-columns:1.45fr .55fr; gap:34px; align-items:end; border-bottom:2px solid var(--ink); padding-bottom:32px; }}
.eyebrow {{ letter-spacing:.18em; font-weight:800; font-size:.72rem; color:var(--green); }}
h1,h2 {{ font-family:"Iowan Old Style","Palatino Linotype",Georgia,serif; letter-spacing:-.035em; }}
h1 {{ font-size:clamp(3rem,7vw,6.7rem); line-height:.88; max-width:900px; margin:16px 0 22px; }}
.subtitle {{ max-width:720px; font-size:1.08rem; line-height:1.65; color:var(--muted); }}
.stamp {{ justify-self:end; width:190px; aspect-ratio:1; border:2px solid var(--ink); border-radius:50%; display:grid; place-items:center; text-align:center; transform:rotate(6deg); font-weight:900; background:var(--lime); box-shadow:8px 8px 0 var(--ink); }}
.metrics {{ display:grid; grid-template-columns:repeat(4,1fr); gap:12px; margin:24px 0 42px; }}
.metric {{ background:rgba(255,253,247,.82); border:1px solid var(--line); padding:20px; min-height:120px; }}
.metric strong {{ display:block; font-family:"Iowan Old Style",Georgia,serif; font-size:2.3rem; margin-top:18px; }}
.metric span {{ color:var(--muted); font-size:.82rem; text-transform:uppercase; letter-spacing:.09em; }}
.flow {{ background:var(--ink); color:var(--white); padding:25px; overflow:hidden; position:relative; margin-bottom:42px; }}
.flow svg {{ width:100%; height:130px; display:block; }}
.flow path {{ fill:none; stroke:var(--lime); stroke-width:3; stroke-dasharray:700; animation:draw 1.5s ease-out both; }}
.flow circle {{ fill:var(--white); stroke:var(--lime); stroke-width:5; }}
.flow text {{ fill:var(--white); font-size:13px; font-weight:700; }}
@keyframes draw {{ from {{ stroke-dashoffset:700; }} to {{ stroke-dashoffset:0; }} }}
.grid {{ display:grid; grid-template-columns:1.12fr .88fr; gap:18px; }}
.panel {{ background:rgba(255,253,247,.9); border:1px solid var(--line); padding:26px; box-shadow:0 16px 55px rgba(16,43,42,.08); }}
.panel h2 {{ font-size:2rem; margin:0 0 20px; }}
.filters {{ display:flex; gap:8px; margin-bottom:16px; flex-wrap:wrap; }}
button {{ border:1px solid var(--ink); background:transparent; color:var(--ink); padding:9px 13px; font:inherit; font-weight:800; cursor:pointer; }}
button:hover,button.active {{ background:var(--ink); color:var(--white); }}
.decision {{ display:grid; grid-template-columns:80px 1fr 110px; align-items:center; gap:14px; border-top:1px solid var(--line); padding:16px 0; animation:rise .5s ease both; }}
.decision small {{ color:var(--muted); text-align:right; }}
.arrow {{ padding:0 9px; color:var(--orange); }}
.status,.severity {{ text-transform:uppercase; font-size:.65rem; letter-spacing:.1em; font-weight:900; }}
.status-auto {{ color:var(--green); }} .status-review {{ color:var(--orange); }} .status-blocked {{ color:var(--red); }}
meter {{ width:100%; accent-color:var(--green); }}
.timeline {{ list-style:none; margin:0; padding:0; }}
.timeline li {{ display:grid; grid-template-columns:38px 1fr auto; gap:12px; padding:13px 0; border-top:1px solid var(--line); }}
.timeline p {{ margin:5px 0 0; color:var(--muted); line-height:1.4; }}
.event-index {{ font-family:monospace; color:var(--orange); }}
code {{ color:var(--green); font-size:.75rem; }}
.trust {{ margin-top:18px; display:grid; grid-template-columns:1fr 1fr; gap:18px; }}
.trust ul {{ padding-left:20px; line-height:1.7; }}
.failure {{ background:var(--lime); border:2px solid var(--ink); padding:26px; }}
.failure p {{ line-height:1.6; }}
.download {{ margin-top:18px; background:var(--orange); box-shadow:4px 4px 0 var(--ink); }}
.foot {{ margin-top:28px; color:var(--muted); font-size:.78rem; display:flex; justify-content:space-between; gap:20px; }}
@keyframes rise {{ from {{ opacity:0; transform:translateY(10px); }} to {{ opacity:1; transform:none; }} }}
@media (max-width:780px) {{ .hero,.grid,.trust {{ grid-template-columns:1fr; }} .stamp {{ justify-self:start; width:135px; }} .metrics {{ grid-template-columns:1fr 1fr; }} .decision {{ grid-template-columns:70px 1fr; }} .decision meter,.decision small {{ grid-column:2; text-align:left; }} h1 {{ font-size:3.35rem; }} }}
</style>
</head>
<body><main class="shell">
<section class="hero"><div><div class="eyebrow">{words["eyebrow"]}</div><h1>{words["title"]}</h1><p class="subtitle">{words["subtitle"]}</p></div><div class="stamp">{words["no_write"]}</div></section>
<section class="metrics">
<div class="metric"><span>{words["status"]}</span><strong>{html.escape(str(route.get("status", "unknown")))}</strong></div>
<div class="metric"><span>{words["checked"]}</span><strong>{_int_value(payload.get("synthetic_records_checked"))}</strong></div>
<div class="metric"><span>{words["automatic"]}</span><strong>{_int_value(decision_counts.get("auto"))}</strong></div>
<div class="metric"><span>{words["review"]}</span><strong>{_int_value(decision_counts.get("review"))}</strong></div>
</section>
<section class="flow"><svg viewBox="0 0 1000 130" role="img" aria-label="inspect map review preflight execute evidence"><path d="M45 72 C180 8 250 118 390 57 S650 105 805 48 S920 42 962 72"/><g><circle cx="45" cy="72" r="9"/><circle cx="250" cy="72" r="9"/><circle cx="455" cy="72" r="9"/><circle cx="660" cy="72" r="9"/><circle cx="850" cy="72" r="9"/><text x="20" y="110">INSPECT</text><text x="227" y="110">MAP</text><text x="423" y="110">PREFLIGHT</text><text x="633" y="110">EXECUTE</text><text x="820" y="110">EVIDENCE</text></g></svg></section>
<section class="grid"><div class="panel"><h2>{words["route"]}</h2><div class="filters"><button class="active" data-filter="all">ALL</button><button data-filter="auto">AUTO</button><button data-filter="review">REVIEW</button><button data-filter="blocked">BLOCKED</button></div>{"".join(decision_rows)}</div>
<div class="panel"><h2>{words["events"]}</h2><ol class="timeline">{"".join(event_rows)}</ol></div></section>
<section class="trust"><div class="panel"><h2>{words["trust"]}</h2><ul>{facts}</ul><button class="download" id="download">{words["download"]}</button></div><div class="failure"><h2>{words["failure"]}</h2><p>{words["failure_text"]}</p><p><strong>REVIEW_REQUIRED</strong> / <strong>BLOCKED</strong> / <strong>UNKNOWN</strong> / <strong>PARTIAL</strong></p></div></section>
<div class="foot"><span>Polymorph domain event contract v1</span><span>synthetic_no_write</span></div>
<script id="evidence" type="application/json">{evidence_json}</script>
<script>
const buttons=document.querySelectorAll('[data-filter]'); const cards=document.querySelectorAll('.decision');
buttons.forEach(button=>button.addEventListener('click',()=>{{buttons.forEach(x=>x.classList.remove('active'));button.classList.add('active');const filter=button.dataset.filter;cards.forEach(card=>card.hidden=filter!=='all'&&card.dataset.status!==filter);}}));
document.getElementById('download').addEventListener('click',()=>{{const text=document.getElementById('evidence').textContent;const link=document.createElement('a');link.href=URL.createObjectURL(new Blob([text],{{type:'application/json'}}));link.download='polymorph-demo-evidence.json';link.click();URL.revokeObjectURL(link.href);}});
</script></main></body></html>'''


def write_demo(
    path: str | Path = "polymorph-demo.html",
    *,
    locale: str = "en",
    open_browser: bool = False,
) -> dict[str, object]:
    output = Path(path).expanduser().resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    payload = build_demo_payload(locale=locale)
    rendered = render_demo_html(payload)
    temporary = output.with_name(f".{output.name}.{uuid.uuid4().hex}.tmp")
    try:
        with temporary.open("x", encoding="utf-8", newline="\n") as handle:
            handle.write(rendered)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, output)
    finally:
        temporary.unlink(missing_ok=True)
    if open_browser:
        webbrowser.open(output.as_uri())
    route = _mapping(payload["route"], label="route")
    return {
        "demo_mode": payload["demo_mode"],
        "output": str(output),
        "opened": open_browser,
        "route_status": route["status"],
        "records_checked": payload["synthetic_records_checked"],
        "destination_write_called": False,
        "network_used": False,
        "account_required": False,
    }
