const TEXT = {
  en: {
    eyebrow: "POLYMORPH REVIEW DESK",
    title: "Resolve the uncertain fields.",
    subtitle: "Evidence helps. Only your explicit review changes the mapping.",
    unresolved: "Unresolved",
    accepted: "Accepted",
    corrected: "Corrected",
    abstained: "Abstained",
    all: "All",
    suggestion: "Suggested target",
    evidenceClass: "Evidence class",
    details: "Technical evidence",
    scoreDetail: "Advisory score, not authority",
    signals: "Signals",
    accept: "Accept suggestion",
    correct: "Use selected target",
    abstain: "Abstain",
    reviewer: "Reviewer label",
    reviewerPlaceholder: "team or operator id",
    export: "Export review draft",
    exportHint: "Exports schema metadata only. It cannot execute a write.",
    noRows: "No review items match this filter.",
    select: "Choose a target",
    ready: "Draft ready",
    reviewerNeeded: "Add a reviewer label before export.",
  },
  de: {
    eyebrow: "POLYMORPH REVIEW DESK",
    title: "Klaere die unsicheren Felder.",
    subtitle: "Evidenz hilft. Nur deine explizite Pruefung aendert das Mapping.",
    unresolved: "Offen",
    accepted: "Akzeptiert",
    corrected: "Korrigiert",
    abstained: "Enthalten",
    all: "Alle",
    suggestion: "Vorgeschlagenes Ziel",
    evidenceClass: "Evidenzklasse",
    details: "Technische Evidenz",
    scoreDetail: "Advisory Score, keine Autoritaet",
    signals: "Signale",
    accept: "Vorschlag akzeptieren",
    correct: "Ausgewaehltes Ziel nutzen",
    abstain: "Enthalten",
    reviewer: "Reviewer-Kennung",
    reviewerPlaceholder: "Team- oder Operator-ID",
    export: "Review-Entwurf exportieren",
    exportHint: "Exportiert nur Schema-Metadaten. Kann keinen Write ausfuehren.",
    noRows: "Keine Review-Felder entsprechen diesem Filter.",
    select: "Ziel waehlen",
    ready: "Entwurf bereit",
    reviewerNeeded: "Vor dem Export eine Reviewer-Kennung angeben.",
  },
};

const STATIC_TEMPLATE = `
  <style>
    :host {
      --paper: #f5f7f6;
      --paper-raised: #ffffff;
      --ink: #17201e;
      --muted: #66716d;
      --line: #dce2df;
      --accent: #285d52;
      --accent-soft: #edf3f1;
      --review: #846a35;
      --danger: #8c4f48;
      display: block;
      color: var(--ink);
      font-family: "Geist", "Sohne", "Aptos", sans-serif;
    }
    * { box-sizing: border-box; }
    .shell {
      overflow: hidden;
      border: 1px solid #cbc5b7;
      border-radius: 20px;
      background: var(--paper);
      box-shadow: 0 1px 2px rgba(23, 32, 30, .06);
    }
    header { padding: clamp(24px, 5vw, 54px); border-bottom: 1px solid var(--line); }
    .eyebrow { color: var(--accent); font-size: 11px; font-weight: 750; letter-spacing: .15em; }
    h1 { max-width: 760px; margin: 14px 0 10px; font-size: clamp(34px, 6vw, 64px); font-weight: 620; line-height: 1; letter-spacing: -.045em; }
    .subtitle { max-width: 690px; margin: 0; color: var(--muted); font-size: 17px; line-height: 1.55; }
    .summary { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 10px; margin-top: 28px; }
    .metric { padding: 14px; border: 1px solid var(--line); border-radius: 12px; background: var(--paper-raised); }
    .metric strong { display: block; font-size: 25px; font-weight: 650; line-height: 1; }
    .metric span { color: var(--muted); font-size: 12px; }
    nav { display: flex; gap: 8px; overflow-x: auto; padding: 18px clamp(20px, 5vw, 54px); border-bottom: 1px solid var(--line); }
    nav button, .action, .export {
      appearance: none; border: 1px solid var(--line); border-radius: 999px; background: var(--paper-raised);
      color: var(--ink); cursor: pointer; font: 680 13px/1 "Geist", "Aptos", sans-serif; padding: 11px 16px;
    }
    nav button[aria-pressed="true"] { border-color: var(--accent); background: var(--accent); color: white; }
    main { display: grid; gap: 14px; padding: clamp(20px, 5vw, 54px); }
    .card { border: 1px solid var(--line); border-left: 3px solid transparent; border-radius: 14px; background: var(--paper-raised); padding: 20px; transition: border-color .22s ease, background-color .22s ease; }
    .card[data-state="accepted"] { border-left-color: var(--accent); background: #fbfdfc; }
    .card[data-state="corrected"] { border-left-color: var(--review); }
    .card[data-state="abstained"] { border-left-color: var(--danger); }
    .route { display: grid; grid-template-columns: minmax(0, 1fr) auto minmax(0, 1fr); align-items: center; gap: 16px; }
    .field small { display: block; color: var(--muted); font-size: 11px; text-transform: uppercase; letter-spacing: .1em; }
    .field strong { display: block; margin-top: 5px; font-size: 20px; font-weight: 620; line-height: 1.2; overflow-wrap: anywhere; }
    .arrow { color: var(--muted); font-size: 20px; }
    select, input { width: 100%; min-height: 44px; border: 1px solid var(--line); border-radius: 12px; background: white; color: var(--ink); padding: 9px 11px; font: inherit; }
    .evidence { display: grid; grid-template-columns: minmax(145px, .65fr) 1fr auto; gap: 16px; align-items: center; margin-top: 18px; padding-top: 16px; border-top: 1px solid var(--line); }
    .evidence-class small { display: block; color: var(--muted); font-size: 10px; text-transform: uppercase; letter-spacing: .1em; }
    .evidence-class strong { display: block; margin-top: 4px; font-size: 13px; font-weight: 720; }
    .chips { display: flex; flex-wrap: wrap; gap: 6px; }
    .chip { border-radius: 99px; background: var(--accent-soft); color: #315a51; padding: 5px 9px; font-size: 11px; }
    details { color: var(--muted); font-size: 11px; }
    details summary { cursor: pointer; white-space: nowrap; font-weight: 680; }
    details p { max-width: 220px; margin: 8px 0 0; line-height: 1.4; }
    .actions { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 18px; }
    .action[data-kind="accept"] { border-color: var(--accent); color: var(--accent); }
    .action[data-kind="correct"] { border-color: var(--review); color: #725b2e; }
    .action[data-kind="abstain"] { color: var(--danger); }
    .status { margin-left: auto; align-self: center; color: var(--muted); font-size: 12px; font-weight: 700; text-transform: uppercase; }
    footer { display: grid; grid-template-columns: minmax(0, 1fr) auto; gap: 18px; align-items: end; padding: 24px clamp(20px, 5vw, 54px) 34px; border-top: 1px solid var(--line); background: var(--paper-raised); }
    label { display: grid; gap: 7px; max-width: 440px; color: var(--muted); font-size: 12px; font-weight: 700; }
    .export { border-color: var(--accent); background: var(--accent); color: white; padding: 14px 20px; }
    .hint { grid-column: 1 / -1; margin: 0; color: var(--muted); font-size: 12px; }
    .empty { color: var(--muted); text-align: center; padding: 35px; }
    .notice { min-height: 18px; color: var(--danger); font-size: 12px; }
    @media (max-width: 680px) {
      .summary { grid-template-columns: repeat(2, minmax(0, 1fr)); }
      .route, .evidence, footer { grid-template-columns: 1fr; }
      .arrow { transform: rotate(90deg); }
      .status { margin-left: 0; }
    }
    @media (prefers-reduced-motion: reduce) { .card { transition: none; } }
  </style>
  <section class="shell">
    <header>
      <div class="eyebrow"></div><h1></h1><p class="subtitle"></p><div class="summary"></div>
    </header>
    <nav aria-label="Review filter"></nav>
    <main></main>
    <footer>
      <label><span class="reviewer-label"></span><input class="reviewer" maxlength="256" /></label>
      <button class="export" type="button"></button>
      <div class="notice" role="status"></div><p class="hint"></p>
    </footer>
  </section>`;

class PolymorphReview extends HTMLElement {
  static get observedAttributes() { return ["locale"]; }

  constructor() {
    super();
    this.attachShadow({ mode: "open" });
    this.shadowRoot.innerHTML = STATIC_TEMPLATE;
    this._model = null;
    this._decisions = new Map();
    this._filter = "all";
    this.shadowRoot.querySelector(".export").addEventListener("click", () => this.exportDraft());
  }

  set model(value) {
    this._model = value && typeof value === "object" ? value : null;
    this._decisions.clear();
    this.render();
  }

  get model() { return this._model; }

  connectedCallback() { this.render(); }
  attributeChangedCallback() { this.render(); }
  get locale() { return this.getAttribute("locale") === "de" ? "de" : "en"; }

  render() {
    const t = TEXT[this.locale];
    const root = this.shadowRoot;
    root.querySelector(".eyebrow").textContent = t.eyebrow;
    root.querySelector("h1").textContent = t.title;
    root.querySelector(".subtitle").textContent = t.subtitle;
    root.querySelector(".reviewer-label").textContent = t.reviewer;
    root.querySelector(".reviewer").placeholder = t.reviewerPlaceholder;
    root.querySelector(".export").textContent = t.export;
    root.querySelector(".hint").textContent = t.exportHint;
    this.renderSummary();
    this.renderFilters();
    this.renderCards();
  }

  counts() {
    const result = { unresolved: 0, accepted: 0, corrected: 0, abstained: 0 };
    const suggestions = Array.isArray(this._model?.suggestions) ? this._model.suggestions : [];
    for (const item of suggestions) {
      const disposition = this._decisions.get(String(item.source_field))?.disposition || "unresolved";
      result[disposition] += 1;
    }
    return result;
  }

  renderSummary() {
    const t = TEXT[this.locale];
    const counts = this.counts();
    const summary = this.shadowRoot.querySelector(".summary");
    summary.replaceChildren();
    for (const key of ["unresolved", "accepted", "corrected", "abstained"]) {
      const box = document.createElement("div");
      box.className = "metric";
      const strong = document.createElement("strong");
      strong.textContent = String(counts[key]);
      const label = document.createElement("span");
      label.textContent = t[key];
      box.append(strong, label);
      summary.append(box);
    }
  }

  renderFilters() {
    const t = TEXT[this.locale];
    const nav = this.shadowRoot.querySelector("nav");
    nav.replaceChildren();
    for (const key of ["all", "unresolved", "accepted", "corrected", "abstained"]) {
      const button = document.createElement("button");
      button.type = "button";
      button.textContent = t[key];
      button.setAttribute("aria-pressed", String(this._filter === key));
      button.addEventListener("click", () => { this._filter = key; this.render(); });
      nav.append(button);
    }
  }

  renderCards() {
    const t = TEXT[this.locale];
    const main = this.shadowRoot.querySelector("main");
    main.replaceChildren();
    const suggestions = Array.isArray(this._model?.suggestions) ? this._model.suggestions : [];
    const targets = Array.isArray(this._model?.target_fields) ? this._model.target_fields : [];
    let visible = 0;
    suggestions.forEach((item, index) => {
      const source = String(item.source_field || "");
      const decision = this._decisions.get(source);
      const state = decision?.disposition || "unresolved";
      if (this._filter !== "all" && this._filter !== state) return;
      visible += 1;
      const card = document.createElement("article");
      card.className = "card";
      card.dataset.state = state;
      const route = document.createElement("div"); route.className = "route";
      const sourceBox = this.fieldBox("Source", source);
      const arrow = document.createElement("div"); arrow.className = "arrow"; arrow.textContent = "→"; arrow.setAttribute("aria-hidden", "true");
      const targetBox = document.createElement("div"); targetBox.className = "field";
      const targetLabel = document.createElement("small"); targetLabel.textContent = t.suggestion;
      const select = document.createElement("select"); select.setAttribute("aria-label", t.select);
      const empty = document.createElement("option"); empty.value = ""; empty.textContent = t.select; select.append(empty);
      for (const target of targets) {
        const option = document.createElement("option"); option.value = String(target); option.textContent = String(target); select.append(option);
      }
      select.value = decision?.target_field || String(item.target_field || "");
      targetBox.append(targetLabel, select); route.append(sourceBox, arrow, targetBox);
      const evidence = document.createElement("div"); evidence.className = "evidence";
      const confidence = Math.max(0, Math.min(1, Number(item.confidence || 0)));
      const classification = document.createElement("div"); classification.className = "evidence-class";
      const classLabel = document.createElement("small"); classLabel.textContent = t.evidenceClass;
      const classValue = document.createElement("strong"); classValue.textContent = String(item.evidence_class || "unclassified").replaceAll("_", " ").toUpperCase();
      classification.append(classLabel, classValue);
      const chips = document.createElement("div"); chips.className = "chips"; chips.setAttribute("aria-label", t.signals);
      for (const reason of (Array.isArray(item.reasons) ? item.reasons : []).slice(0, 12)) { const chip = document.createElement("span"); chip.className = "chip"; chip.textContent = String(reason); chips.append(chip); }
      const details = document.createElement("details"); const detailSummary = document.createElement("summary"); detailSummary.textContent = t.details;
      const detailText = document.createElement("p"); detailText.textContent = `${t.scoreDetail}: ${Math.round(confidence * 100)}%.`;
      details.append(detailSummary, detailText); evidence.append(classification, chips, details);
      const actions = document.createElement("div"); actions.className = "actions";
      actions.append(
        this.action(t.accept, "accept", () => this.decide(source, "accepted", String(item.target_field || ""))),
        this.action(t.correct, "correct", () => this.decide(source, "corrected", select.value)),
        this.action(t.abstain, "abstain", () => this.decide(source, "abstained", null)),
      );
      const status = document.createElement("span"); status.className = "status"; status.textContent = t[state]; actions.append(status);
      card.append(route, evidence, actions); main.append(card);
    });
    if (!visible) { const empty = document.createElement("p"); empty.className = "empty"; empty.textContent = t.noRows; main.append(empty); }
  }

  fieldBox(label, value) {
    const box = document.createElement("div"); box.className = "field";
    const small = document.createElement("small"); small.textContent = label;
    const strong = document.createElement("strong"); strong.textContent = value;
    box.append(small, strong); return box;
  }

  action(label, kind, callback) {
    const button = document.createElement("button"); button.type = "button"; button.className = "action"; button.dataset.kind = kind; button.textContent = label; button.addEventListener("click", callback); return button;
  }

  decide(source, disposition, target) {
    if ((disposition === "accepted" || disposition === "corrected") && !target) return;
    this._decisions.set(source, { source_field: source, target_field: target, disposition });
    this.dispatchEvent(new CustomEvent("polymorph-review-change", { bubbles: true, composed: true, detail: this.draft(false) }));
    this.render();
  }

  draft(includeReviewer = true) {
    const reviewer = includeReviewer ? this.shadowRoot.querySelector(".reviewer").value.trim() : "";
    const suggestions = Array.isArray(this._model?.suggestions) ? this._model.suggestions : [];
    return {
      schema: "polymorph.review-draft",
      version: 1,
      session_id: String(this._model?.session_id || "local-review"),
      source_schema_fingerprint: String(this._model?.source_schema_fingerprint || ""),
      destination_schema_fingerprint: String(this._model?.destination_schema_fingerprint || ""),
      reviewed_by: reviewer,
      reviewed_at: new Date().toISOString(),
      decisions: suggestions.map(item => this._decisions.get(String(item.source_field)) || { source_field: String(item.source_field), target_field: null, disposition: "abstained" }),
      privacy: "schema_metadata_only_no_record_values",
    };
  }

  exportDraft() {
    const t = TEXT[this.locale];
    const notice = this.shadowRoot.querySelector(".notice");
    const reviewer = this.shadowRoot.querySelector(".reviewer").value.trim();
    if (!reviewer) { notice.textContent = t.reviewerNeeded; return; }
    const draft = this.draft(true);
    this.dispatchEvent(new CustomEvent("polymorph-review-submit", { bubbles: true, composed: true, detail: draft }));
    const blob = new Blob([`${JSON.stringify(draft, null, 2)}\n`], { type: "application/json" });
    const url = URL.createObjectURL(blob); const link = document.createElement("a"); link.href = url; link.download = "polymorph-review-draft.json"; link.click(); URL.revokeObjectURL(url); notice.textContent = t.ready;
  }
}

if (!customElements.get("polymorph-review")) customElements.define("polymorph-review", PolymorphReview);

export { PolymorphReview };
