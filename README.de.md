<p align="center">
  <img src="https://raw.githubusercontent.com/IamAngusU/polymorph/main/docs/assets/brand-mark.webp" width="116" alt="Polymorph Logo">
</p>

<p align="center">
  <strong>Deutsch</strong> · <a href="README.md">English</a>
</p>

<h1 align="center">Polymorph</h1>

<p align="center">
  <strong>Daten zwischen inkompatiblen Systemen bewegen. Die Route beweisen, bevor geschrieben wird.<br>Plaintext bleibt an den Endpunkten. Wenn die Evidenz nicht reicht, wird sauber gestoppt.</strong>
</p>

<p align="center">
  <a href="docs/PERFORMANCE_BASELINE.md#file-inspection"><img src="docs/assets/badges/fixture-rows.svg" height="42" alt="Datei-Fixtures mit je 50.000 Zeilen"></a>
  <a href="#gemessene-lokale-baseline"><img src="docs/assets/badges/workflow.svg" height="42" alt="Sicherer Workflow mit 1.000 Records"></a>
  <a href="#gemessene-lokale-baseline"><img src="docs/assets/badges/throughput.svg" height="42" alt="Median 52,41 Records pro Sekunde lokal"></a>
  <a href="#optionale-modell-evidenz"><img src="docs/assets/badges/auto-precision.svg" height="42" alt="17 von 17 beobachteten automatischen Entscheidungen korrekt"></a>
</p>

<p align="center"><sub>Gemessene Baselines, keine universellen Versprechen. Ein Klick führt zum Kontext.</sub></p>

Polymorph ist eine local-first, policy-driven Data Bridge für wiederkehrende Imports und Integrationen, die zu wichtig für ein hoffnungsvolles Skript und zu speziell für eine riesige Integrationsplattform sind.

System A nennt ein Feld `customer_no`. System B erwartet `account_id`. Dann verschiebt jemand eine Spreadsheet-Spalte, benennt einen Header um, fügt eine Formel hinzu, ändert einen Foreign-Key-Vertrag oder schickt denselben Report mit anderem Layout.

Die traditionelle Lösung ist häufig eine Variante von: einmal mappen und hoffen, dass danach bitte niemand mehr irgendetwas anfasst.

Polymorph hat stattdessen Vertrauensprobleme.

Die zentrale Zuverlässigkeitsregel ist einfach:

**Unsicherheit muss Automation reduzieren, niemals Raten erhöhen.**

Ein Dateiname ist Evidenz. Ein erfolgreicher Parser-Aufruf ist Evidenz. Ein Model-Score ist Evidenz. Eine Recipe, die gestern funktioniert hat, ist Evidenz.

Gestern war übrigens auch ein anderer Tag.

Automatische Freigabe braucht unabhängig starke deterministische Evidenz, einen unveränderlichen validierten Plan und einen vollständigen No-write-Preflight. Kann Polymorph eine Route innerhalb des erklärten Betriebsbereichs nicht beweisen, verlangt es Review, statt Selbstbewusstsein zu erfinden.

Stabile Protocol- und Persistenz-Namespaces sind absichtlich vom Produktnamen getrennt. Ein späteres Rebranding darf verschlüsselte Envelopes, Delivery-State oder Recipe-Historie nicht ungültig machen. Branding darf eine Midlife-Crisis haben. Persistierter kryptografischer Zustand eher nicht.

## Warum Polymorph existiert

Noch ein AI-Column-Mapper ist kein besonders interessantes Produkt. Das ist eine Funktion, und mehrere Anbieter haben sie bereits.

Polymorph soll die Vertrauensschicht zwischen Systemen sein, die nie dafür gebaut wurden, sich gegenseitig zu verstehen.

Die nützliche Version macht vier Dinge gut:

1. **Die Quelle konservativ verstehen.** Bytes, Struktur, Schema, Beziehungen und Policy prüfen, bevor Labels geglaubt werden.
2. **Die Route vor dem Schreiben beweisen.** Mapping, Transformationen und Foreign-Key-Auflösung werden gegen genau einen Plan validiert.
3. **Plaintext an den Endpunkten halten.** Das Relay bekommt Ciphertext und Routing-Metadaten, nicht die Payload-Werte, die es transportiert.
4. **Langweilig scheitern.** Mehrdeutige Mappings brauchen Review. Unbekannte Write-Outcomes bleiben unbekannt. Ein Retry ist kein Optimismus mit Schleife drumherum.

Die ersten Nutzer sind Entwickler und technische Operatoren mit wiederkehrenden Imports, bei denen ein falscher Identifier, Betrag, Credential oder Foreign Key teuer wird:

- Agenturen, die Kundenexports in unterschiedliche Kundensysteme bewegen
- kleine Operations-Teams, die Excel-, CSV- oder API-Daten in ERP oder Datenbank importieren
- sicherheitsbewusste Teams, die Payloads nicht an einen gehosteten Mapping-Service schicken können
- Softwareanbieter, die eine self-hosted Ingestion-Kante für Kundendaten brauchen
- regulierte Teams, die einen prüfbaren Plan und ehrliche Zustände für unsichere Writes brauchen

## Evidenz ist keine Autorität

Polymorph trennt bewusst hilfreiche Signale von Signalen, die Automation autorisieren dürfen.

| Signal | Hilfreich? | Darf allein einen Write autorisieren? |
| --- | --- | --- |
| Dateiendung oder Anzeigename | Ja | Nein |
| Erfolgreicher Parser-Aufruf | Ja | Nein |
| Magika-Klassifikation | Ja | Nein |
| Alte Recipe | Ja | Nein |
| Embedding-Ähnlichkeit | Ja | Nein |
| Cross-Encoder-Score | Ja | Nein |
| Aktuelles Schema, Policy und deterministische Contract-Evidenz | Ja | Ja, wenn alle Gates bestehen |

**Hilfreich ist nicht autorisiert.**

Ein Modell darf Kandidaten besser sortieren. Einen Stift bekommt es trotzdem nicht.

Wenn ein hochkonfidentes Modellresultat einem unabhängig stärksten deterministischen Ziel widerspricht, wird das Mapping review-required. Eine größere Zahl hinter dem Komma ist keine neue Trust Boundary.

## Was v0.4 alpha bereits macht

### Input Trust

- Content-first-Dateiinspektion. Parserauswahl vertraut weder Dateiendung noch Anzeigename.
- Opened-handle Identity Binding für CSV, JSON und Excel schließt gewöhnliche Path-Swap-Lücken zwischen Inspektion und Parsing.
- ZIP- und OOXML-Central-Directory-Prüfungen blockieren Traversal, Symlinks, doppelte oder verschlüsselte Member, verdächtige Expansion, übergroße Member, Makros sowie externe Workbook-Links und Datenverbindungen, bevor ein Workbook-Parser geöffnet wird.
- GZIP-Member werden bounded gestreamt und mit Member-Limits validiert.
- JSON und XML haben explizite Budgets für Parse-Größe, Tiefe, Items, Elemente und Attribute je Tag, bevor teurere Verarbeitung beginnt.
- Optionale lokale Magika-Evidenz kann die deterministische Erkennung challengen. Ein starker Konflikt blockiert automatische Parserauswahl, statt einen Confidence-Beliebtheitswettbewerb zu starten.
- Eine fail-closed Parser-Worker-Basis kann einen Exact-byte-Snapshot prüfen. Unter Linux ist nicht-setid Bubblewrap 0.12.0 oder neuer das strikte Backend. Ein normaler Windows-Child-Process wird nur als Process Separation bezeichnet.
- Excel-Parsing verlangt XML-Härtung über `defusedxml` und erkennt danach unter anderem Title Rows, verschobene Spalten, wiederholte Header und Fixed-width-Identifier wie `000042`.
- Spreadsheet-Formeln werden separat erkannt. Cached Formula Results haben keine bewiesene Frische und blockieren daher automatische Recipe-Promotion.
- CSV-Dialekte werden über ein deterministisches Candidate-Ensemble gewählt und können CleverCSV einbeziehen. Ein knappes Unentschieden wird abgelehnt statt geraten. Revolutionär, offenbar.

### Mapping und Preflight

- Deterministisches Schema-Matching ist die automatische Autorität.
- Matching nutzt Namen, Aliases, deklarierte Typen, Nullability, Sensitivity, Field Roles und verifizierte Relationship-Evidenz.
- Optionale lokale Embeddings und ein multilingualer Cross-Encoder-Reranker dürfen die Candidate-Reihenfolge verbessern, aber kein Mapping allein autorisieren.
- Target-Kollisionen, gerichtete Typ-Probleme, Sensitivity-Konflikte und schwache Relationship-Beweise reduzieren oder blockieren Automation auch dann, wenn ein Score hübsch aussieht.
- Versionierte Recipes speichern wiederverwendbares Gedächtnis, keine Erlaubnis. Jede Wiederverwendung wird an aktuelle exakte Schemas gebunden, bekommt einen neuen Plan-Digest, wird erneut validiert und muss erneut durch Preflight.
- Wiederholt abgelehnte Recipe-Runs reduzieren Vertrauen und suspendieren automatische Wiederverwendung, statt den Matcher kreativer werden zu lassen.
- `prepare` kombiniert Content Inspection, Mapping, Recipe-Reuse und vollständigen No-write-Preflight.
- Full-scan-Preflight übt Source-Transforms und optionale read-only Foreign-Key-Auflösung aus, ohne Destination-Writes auszuführen.
- Sampled Scans sind Diagnose. Sie dürfen keine Recipe automatisch promoten.
- `--max-input-records` ist ein hartes Blast-Radius-Budget pro Run. Der erste Record über dem Limit blockiert Readiness, statt eine Quelle stillschweigend freizugeben, die über Mittag zwei Größenordnungen gewachsen ist.

### Blinder Transport und Delivery

- Full-record Blind Transport nutzt X25519, HKDF-SHA256 und ChaCha20-Poly1305.
- Source-Records werden mit Ed25519-Identitäten authentifiziert, die an Tenant und Connector gebunden sind, inklusive begrenztem Rotation-Drain und Hard Revocation.
- Destination Recipient Keys stammen aus separat gepinnten Ed25519-Destination-Identitäten und nicht allein aus Control-Plane-Behauptungen.
- Signierte route-bound Recipient Certificates bilden eine monotone Rotation Chain. Ein optionaler lokaler Checkpoint weist veraltete Generationen und konkurrierende Forks zurück.
- Eine durable Source Outbox persistiert exakt den signierten Ciphertext des ersten Sends. Ack verloren? Exakt diese Bytes erneut senden. Denselben logischen Record neu zu versiegeln erzeugt anderen authentifizierten Ciphertext, weil Kryptografie nicht verpflichtet ist, eine bequeme Retry-Implementierung zu unterstützen.
- Das Relay speichert Ciphertext plus erforderliche Routing-Metadaten, nutzt fenced Leases und ein persistentes Idempotency-Ledger.
- Destination Delivery unterscheidet bewiesenes `NOT_COMMITTED` von `UNKNOWN`. Unbekannt wird nicht retry-safe, nur weil eine Exception sich entschuldigend angehört hat.
- Capability-gated Atomic Batches behalten per-Record Authentication, Ledger-, Audit- und Replay-Evidenz und nutzen für unterstützte SQLite- und PostgreSQL-Writes eine Transaktion.
- Jeder Batch ist nach Record-Anzahl und Sealed-wire-Größe begrenzt.
- Der Destination Runtime ist an genau einen Plan und Target Contract gepinnt und prüft Field Set, Required Values, Nullability und Typen erneut, bevor der Connector-Write beginnt.
- CSV-Exports blockieren spreadsheet-formula-artige Werte standardmäßig.
- HTTP-Redirects zählen niemals als committed Write.

### Betrieb und Diagnose

- Ed25519-signierte Capabilities begrenzen privilegierte Operationen.
- Metadata-only Audit Events bilden eine SHA-256-Hash-Chain und können zusätzlich signiert werden.
- Reason Codes erklären, warum etwas blockiert oder herabgestuft wurde.
- Recipe-Health-Zusammenfassungen machen wiederholte Ablehnung sichtbar.
- Payload-freie Operational Events tragen Run- und Correlation-IDs für den aktuell instrumentierten Workflow.
- Credential References und verschlüsselte Destination-Recipient-Key-Dateien vermeiden die kreative Annahme, rohe Connection Strings seien bereits Secret Management.

## Trust Model

```text
              schema + policy + exact plan
                         |
                         v
                 +---------------+
                 | control plane |
                 +---------------+
                         |
                    plan digest
                         |
      source trust      |                 destination trust
         boundary       |                    boundary
            |           |                       |
            v           |                       v
     +--------------+   |              +------------------+
     | source agent |   |              | destination agent|
     +--------------+   |              +------------------+
       | plaintext       |                    ^ plaintext
       | local transforms|                    | FK lookup
       v                 |                    |
    seal to destination public key            |
       |                                      |
       v                                      |
    +--------------------------------------------------+
    |        ciphertext-only relay / data plane        |
    | route metadata, leases, digests, no private key  |
    +--------------------------------------------------+
```

Das Relay sieht weiterhin die Metadaten, die es zum Routen eines Records braucht, darunter Tenant, Connector-IDs, Record- und Transfer-IDs, Plan-Digest und Field-IDs. Payload-Vertraulichkeit ist keine Traffic-Analysis-Resistenz. Source und Destination sehen Plaintext notwendigerweise an ihren jeweiligen Trust Boundaries.

Der öffentliche Destination-Identity-Key muss die Source über einen operator-kontrollierten Kanal erreichen, der unabhängig von der Control Plane ist. Die Control Plane darf signierte Recipient-Key-Certificates verteilen, kann aber deren Tenant-, Destination-, Key-, Validity- oder Rotation-Metadaten nicht ersetzen.

Siehe [Authentizität und Rotation von Recipient Keys](docs/RECIPIENT_KEY_ROTATION.md).

## Schnellstart

Python 3.11 bis 3.14 wird in CI ausgeführt.

Für einen Development-Checkout mit dem deterministischen modellfreien Pfad:

```bash
git clone https://github.com/IamAngusU/polymorph.git
cd polymorph
python scripts/bootstrap.py
python scripts/dev.py doctor
```

Optionale Research-Modelle werden für den Core nicht benötigt:

```bash
python scripts/bootstrap.py --skip-models
```

`python examples.py` startet ein kleines deterministisches Mapping-Beispiel ohne Modelle oder externe Services.

Siehe [Development setup](docs/DEVELOPMENT.md) für das absichtlich lokale Datenlayout.

## Der einfachste sichere Workflow

Zielschema inspizieren, dann `prepare` die Source inspizieren, eine Recipe finden oder einen Mapping-Plan bauen lassen und den vollständigen No-write-Preflight ausführen:

```bash
polymorph inspect db 'sqlite:///target.sqlite' --table orders -o target.schema.json
polymorph prepare ./incoming-file target.schema.json --output-plan orders.plan.json --remember \
  --max-input-records 5000
```

Ein Plan wird nur geschrieben, wenn die Route promotable ist.

Reicht die Evidenz nicht, beendet sich `prepare` als review-required, statt ein selbstbewusst aussehendes JSON zu erzeugen und Future-you herausfinden zu lassen, was es eigentlich meinte.

Für eine Foreign-Key-Route kommt ein read-only Destination Resolver dazu, damit der Preflight den Natural-Key-Lookup vor Promotion beweisen kann:

```bash
polymorph prepare ./orders-upload target.schema.json \
  --resolver-db-url 'sqlite:///target.sqlite' \
  --resolver-db-table orders
```

## Manueller Plan-Workflow

Wenn jede Stufe einzeln gebraucht wird:

```bash
polymorph inspect auto ./upload.bin -o source.schema.json
polymorph map source.schema.json target.schema.json
polymorph plan create source.schema.json target.schema.json -o route.plan.json
polymorph plan validate route.plan.json source.schema.json target.schema.json
polymorph preflight ./upload.bin target.schema.json route.plan.json
```

Review-Level-Entscheidungen werden standardmäßig nicht in einen Plan geschrieben. `--allow-review` ist für eine explizite Operator-Entscheidung da, nicht um den Matcher höflich zu bitten, endlich weniger schwierig zu sein.

## Optionale Modell-Evidenz

Der Core funktioniert vollständig ohne Modell.

Der optionale CPU-Descriptor-Encoder läuft zur Runtime lokal, ist auf eine Upstream-Revision gepinnt und wird bei Installation hash-verifiziert. Der native SentencePiece-Tokenizer vermeidet das Laden der deutlich größeren JSON-Vokabular-Repräsentation.

```bash
pip install -e ".[semantic]"
polymorph model install --profile multilingual-cpu
polymorph prepare ./incoming-file target.schema.json --models
```

Beide aktuellen Model-Profile sind für Product Use research-only. Provenance und Dataset Terms stehen unter [Model profiles](docs/MODEL_PROFILE.md). Der Standard-Bootstrap lädt keines davon herunter.

Modelle bekommen Schema-Deskriptoren, keine Record-Payload-Werte. Ihre Evidenz darf Ordering verbessern und Review-Arbeit reduzieren. Automatische Promotion braucht weiterhin unabhängig starke deterministische Evidenz.

Auf dem eingecheckten synthetischen Regression-Corpus treffen die Modellpfade aktuell dieselben automatischen Entscheidungen wie das deterministische Profil.

| Profil | Ergebnis | Wall Time | Peak RSS |
| --- | --- | ---: | ---: |
| Deterministisch | Gleiche Entscheidungen | 4,02 ms | 73,30 MiB |
| Encoder | Gleiche Entscheidungen | 0,926 s | 284,52 MiB |
| Encoder + Reranker | Gleiche Entscheidungen | 2,325 s | 437,87 MiB |

Der Encoder-Run erreichte 100% beobachtete automatische Precision bei 17 von 17 automatischen Entscheidungen und 89,47% Automation Coverage unter explizit eligible Fields. Das ist Regression-Evidenz auf einem synthetischen Corpus, keine Behauptung universeller Mapping-Genauigkeit.

Ja, der Modell-Stack funktioniert also.

Auf diesem Corpus wandelt er aktuell vor allem mehr Strom in Wärme um, ohne das Decision Set zu verbessern. Wir messen weiter, statt Lüftergeräuschen architektonische Bedeutung zu verleihen.

Siehe [Gemessene Performance-Baseline](docs/PERFORMANCE_BASELINE.md).

## Diagnose und Benchmarks

```bash
pip install -e ".[fileid,csv-detection,benchmark]"
polymorph inspect auto ./unknown-upload --magika

# Strikte Linux-Grenze. Fail-closed, wenn kompatibles Bubblewrap fehlt.
polymorph inspect isolated-content ./unknown-upload

polymorph doctor
polymorph benchmark inspect ./unknown-upload --records 10000 --magika
polymorph benchmark parser-worker ./unknown-upload --runs 5
polymorph benchmark mapping ./benchmarks/safety-regression.json \
  --require-auto-precision 1.0 \
  --require-automation-coverage 0.70
polymorph benchmark workflow --records 1000 --batch-size 100 \
  --work-dir ./workflow-run --output workflow.json
polymorph recipe health
polymorph audit summary ./audit.sqlite
polymorph events check ./workflow-run/operational-events.jsonl --run-id RUN_ID
polymorph explain write_outcome_unknown
```

`RUN_ID` ist der Wert von `workflow.observability.run_id` aus `workflow.json`.

Die Benchmark-Kommandos sind explizite Diagnostik. Normale Production-Pfade schalten nicht CPython Allocation Tracing oder RSS Polling ein, nur damit sich ein Graph beteiligt fühlt.

## Gemessene lokale Baseline

Der vollständig durable, signierte und auditierte lokale Transport bewegte 1.000 Records mit jeweils fünf String-Feldern bei einem Median von **52,41 Records/s** zu einer SQLite-Destination und **85,42 MiB** medianem Peak RSS auf der dokumentierten Windows-Entwicklungsmaschine.

Jeder Run enthielt Recipient-Certificate-Verifikation, X25519- und ChaCha20-Poly1305-Sealing, Ed25519-Source-Signaturen, durable Source Outbox, Relay-Validation und fenced Leases, Destination Authentication und Decryption, Contract Validation, SQLite-Writes, Sealed-spool-Cleanup, signiertes Hash-chain-Audit und Acknowledgements.

In jedem aufbewahrten Run wurden alle 1.000 Records genau einmal zugestellt.

Separate durable SQLite-Commits dominieren dieses Profil. Sinnvolle Optimierungsziele sind Transaction Batching, Connection Reuse und Batch Acknowledgements. Durability abzuschalten würde den Benchmark ebenfalls schneller machen. Bremsen ausbauen macht ein Auto auch leichter.

Siehe [Performance baseline](docs/PERFORMANCE_BASELINE.md) für Maschine, Methodik und Einschränkungen.

## Dokumentation

- [Architektur](docs/ARCHITECTURE.md)
- [Reliability Model](docs/RELIABILITY.md)
- [Product Direction](docs/PRODUCT.md)
- [File Trust Gate](docs/FILE_TRUST.md)
- [Parser Isolation](docs/PARSER_ISOLATION.md)
- [Recipes](docs/RECIPES.md)
- [Benchmarking](docs/BENCHMARKING.md)
- [Workflow und Failure Lab](docs/WORKFLOW_LAB.md)
- [Gemessene Performance-Baseline](docs/PERFORMANCE_BASELINE.md)
- [Protocol](docs/PROTOCOL.md)
- [Threat Model](docs/THREAT_MODEL.md)
- [Operations und Replay Safety](docs/OPERATIONS.md)
- [Operational Visibility](docs/OBSERVABILITY.md)
- [Recipient-Key-Authentizität und Rotation](docs/RECIPIENT_KEY_ROTATION.md)
- [Security Coverage](docs/SECURITY_COVERAGE.md)
- [Ecosystem und Dataset Review](docs/ECOSYSTEM_REVIEW.md)
- [Operator Workflows](docs/WORKFLOWS.md)
- [Test Strategy](docs/TEST_STRATEGY.md)
- [Roadmap](docs/ROADMAP.md)
- [Security melden](SECURITY.de.md)
- [Beitragen](CONTRIBUTING.de.md)
- [Lizenzierung erklärt](LICENSING.de.md)

## Status: Alpha heißt Alpha

Polymorph bleibt Alpha.

Inspection, Mapping, Planning und Preflight sind über die CLI verfügbar. Source Transport, Relay und Destination Delivery sind getestete Python-APIs. Long-running Agent Services, ein authentifizierter Control Channel und ein Deployment Supervisor sind weiterhin Roadmap-Arbeit.

Wichtige aktuelle Grenzen:

- Strikte Linux-Containment deckt derzeit nur den Content-Inspection-Worker ab.
- Strukturierte Schema-Parser und Record-Iteration laufen nach akzeptiertem Content Gate weiterhin im lokalen Polymorph-Prozess.
- Windows Process Mode ist Process Separation, keine Filesystem- oder Network-Containment.
- Durable Trust-Bundle-Distribution existiert noch nicht.
- Es gibt noch kein kumulatives per-Tenant Relay-Queue-Quota.
- Es gibt noch keinen externen Audit-Checkpoint gegen Log-Suffix-Truncation.
- Rohe Database-URLs können Credentials über Shell History leaken. Production-Automation sollte `DatabaseEndpoint` plus Secret Provider nutzen.
- Automatic-Promotion-Policy braucht weiterhin einen großen source-separated adversarial Corpus und unabhängige Security Review.
- Operational-Event-Coverage außerhalb des aktuell instrumentierten Workflows ist unvollständig.
- Destination Audit bleibt optional.
- Notification Service und Queue Metric Exporter existieren noch nicht.

Diese Grenzen stehen hier, weil „Alpha“ ein Software-Reifegrad ist und kein Deko-Badge, das verschwindet, sobald die README teuer aussieht.

## Lizenz

Polymorph ist unter der **PolyForm Noncommercial License 1.0.0** source-available. Es ist nicht OSI Open Source.

Die tatsächlichen Nutzungsrechte stehen in [`LICENSE`](LICENSE). Kommerzielle Nutzung benötigt eine separate Lizenz von Angus Uelsmann.

Eine menschlich lesbare Einordnung steht in [LICENSING.de.md](LICENSING.de.md). Kommerzielle Konditionen, einschließlich möglicher Revenue Participation oder White-label-Rechte, werden nur in einer separaten schriftlichen Vereinbarung festgelegt. Siehe [kommerzielle Lizenzierung](COMMERCIAL.de.md).

Required Notices referenzieren [angusu.de](https://angusu.de) und dieses Repository. Third-party-Komponenten behalten ihre jeweiligen Lizenzen; siehe [THIRD_PARTY.md](THIRD_PARTY.md).
