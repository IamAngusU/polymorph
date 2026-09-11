<p align="center"><img src="docs/assets/brand-mark.webp" width="100" alt="Polymorph Logo"></p>

# Polymorph

[English](README.md) · [Deutsch](README.de.md)

![Wissensversion](docs/assets/knowledge.svg) ![Trainingsaufgaben](docs/assets/training.svg) ![Trainingsvergleiche](docs/assets/comparisons.svg)

**System A nennt es `customer_no`. System B erwartet `account_id`.
Die Datei sieht schon wieder anders aus. Niemand sollte raten.**

Polymorph ist eine lokale Datenbrücke für Entwickler, die CSV-, Excel-, JSON-, API-
oder Datenbankdaten in andere Strukturen überführen müssen, ohne das Ziel still zu
beschädigen. Es untersucht Eingaben, schlägt Zuordnungen vor, prüft Pläne und
verhindert, dass ein unklarer Schreibausgang zu einem motivierten Duplikat wird.

**Unsicherheit reduziert Automatisierung.**

Eine Dateiendung ist ein Vorschlag. Ein Modellscore ist ein Hinweis, keine
Schreibberechtigung. Das Recipe hat gestern funktioniert? Gestern war auch ein
anderer Tag.

## Zuerst das eigentliche Importproblem

```text
Kundenexport → untersuchen → zuordnen → No-Write-Preflight → prüfen oder freigeben
                                                                  ↓
                                        Quelle → verschlüsseltes Relay → Ziel
```

`prepare` untersucht und plant. Es schreibt **nicht** nebenbei ins produktive Ziel.
Der verschlüsselte Zustellpfad ist derzeit eine Python-API mit explizitem Benchmark,
kein dauerhaft laufender Deployment-Dienst.

```bash
git clone https://github.com/IamAngusU/polymorph.git
cd polymorph
python scripts/bootstrap.py
python scripts/dev.py doctor

# Zielmetadaten lesen; die Dateiendung bleibt anschließend ohne Autorität.
python scripts/dev.py inspect db 'sqlite:///target.sqlite' --table orders -o target.schema.json
python scripts/dev.py prepare ./incoming-file target.schema.json --output-plan orders.plan.json --remember --max-input-records 5000
```

Benötigt wird Python 3.11+. Der Bootstrap installiert lokale Abhängigkeiten, aber
standardmäßig kein Modell. Siehe [Entwicklungsumgebung](docs/DEVELOPMENT.md) und
[Bedienabläufe](docs/WORKFLOWS.md). Die ursprüngliche CI-Matrix ist für Python
3.11–3.14 unter Linux und Windows konfiguriert. Konfiguriert heißt nicht bestanden:
GitHub Actions ist für diesen Account nicht verfügbar. Dafür gibt es die
[lokale Validierung](docs/LOCAL_VALIDATION.md).

## Was die Arbeit übernimmt

| Grenze | Vertrag |
| --- | --- |
| Eingabe | Inhaltsprüfung, ZIP-/OOXML-Limits, XML-Härtung, begrenzte JSON-/GZIP-Verarbeitung und konservative CSV-Dialekterkennung. Dateinamen-Optimismus ist kein Parser. |
| Mapping | Namen, Typen, Beziehungen, Sensitivität und Mehrdeutigkeit prüfen. Gelernte Hinweise vergeben keine AUTO-Berechtigung. |
| Recipes | Lokales Gedächtnis. Gegen aktuelle Schemas neu binden, neuen Plan-Digest erzeugen und erneut prüfen. Erinnerung, keine Erlaubnis. |
| Transport | Quelle und Ziel sehen Klartext an ihren Vertrauensgrenzen. Das Relay erhält signierten Ciphertext und Routing-Metadaten, nicht den privaten Entschlüsselungsschlüssel. |
| Vertrauen | Ed25519-Quellenauthentifizierung, an die Zielidentität gebundene Empfängerzertifikate, planbezogene Verschlüsselung und Capability-Prüfungen. |
| Zustellung | Leases mit Fencing, persistente Outbox, Ledger, Quarantäne und getrennte Zustände `NOT_COMMITTED` / `UNKNOWN`. Ein Timeout ist keine Empfangsbestätigung des Universums. |
| Batching | Nur mit geeignetem atomarem Connector-Vertrag. Authentifizierung und Replay-Nachweise bleiben; Transaktionen werden zusammengefasst, nicht Ehrlichkeit. |

Ein Audit- oder Aufräumfehler nach bestätigtem Commit wird nicht zur Aufforderung,
noch einmal zu schreiben. Das sind die langweiligen Unterschiede, die spannende
Postmortems verhindern.

### Grenzen, bevor das Marketing schneller wird als der Code

Dies ist eine **Alpha**, kein universell sicherer Upload-Dienst. Der isolierte
Worker schützt derzeit **nur die Inhaltsprüfung**. CSV-/JSON-/XLSX-Schema-Parsing
und Record-Iteration laufen weiterhin im Hauptprozess. Linux nutzt kompatibles
Bubblewrap; Windows-Prozesstrennung ist **keine** Dateisystem- oder Netzwerk-Sandbox.

Endpunkte sowie Datenbank und Treiber bleiben Vertrauensgrenzen. Verschlüsselung
versteckt weder Routing-Metadaten noch Verkehrsmuster. Ein lokaler Trust-Checkpoint
schützt nicht vor dem Zurücksetzen des gesamten Hosts. Dauerhafte Agenten, globale
Queue-Backpressure, vollständige Betriebsüberwachung und große unabhängige
Kundenkorpora sind noch Arbeit.

Kein SOC-2-Audit, keine ISO-Zertifizierung, universelle Genauigkeit oder dauerhaft
unveränderliche Zielzeile wird behauptet. Siehe [Threat Model](docs/THREAT_MODEL.md),
[Security-Matrix](docs/SECURITY_COVERAGE.md) und [Parser-Isolation](docs/PARSER_ISOLATION.md).

## Allgemeines Wissen, ohne dein Wissen zu überschreiben

Das separate Labor trainiert Zuordnungshilfen. Ein Release ist ein **versioniertes,
signiertes Datenpaket**, kein heruntergeladenes Python, keine Recipe-Migration und
keine neue Sicherheitsrichtlinie. Alte Versionen bleiben erhalten. Aktiviert wird
bewusst.

```text
Allgemeines Wissen: <data-home>/knowledge/general.sqlite
Private Recipes:    <data-home>/recipes.sqlite              ← Updates fassen diese nicht an
Private Modelle:    vom Betreiber verwaltet                ← weder vermischt noch hochgeladen
```

Ein unabhängig bestätigter öffentlicher Publisher-Schlüssel prüft jedes Paket. Ein
persistenter Sequenzhöchststand weist alte Updates und wiederverwendete
Versionsidentitäten zurück. Rollback ist ausdrücklich und senkt den Höchststand
nicht. Das Modell bleibt beratend. Kein privater Publisher-Schlüssel wird
mitgeliefert; der Downloadkanal bestätigt nicht seine eigene Vertrauenswürdigkeit.

```bash
# Nach einem veröffentlichten Paket und unabhängiger Prüfung von publisher.pub:
python scripts/knowledge.py --trusted-key publisher.pub fetch
python scripts/knowledge.py --trusted-key publisher.pub status
python scripts/knowledge.py --trusted-key publisher.pub activate VERSION
```

Der erste Befehl installiert, aktiviert aber nicht. Noch wurde kein allgemeines
Wissenspaket veröffentlicht. [Wissens-Releases](docs/KNOWLEDGE_RELEASES.md) erklärt
Publisher-Ablauf, Kompatibilität, Ablaufzeit und API. Private Recipes benötigen
weiterhin ihre normalen Prüfungen. Ein öffentliches Modell steht nie über der Policy.

## Messdaten statt dekorativer Zahlen

<!-- EVIDENCE:START -->
**Allgemeines Wissenspaket:** none published. **Trainingsaufgaben:** 365. **Eindeutige Präferenzvergleiche:** 1,656. Geltungsbereich: `lab candidate`.

Diese Zähler beschreiben den ausgewählten Stand, nicht die Summe aller Epochen oder wiederholten Tests. Parserzeilen sind keine gelernten Mapping-Entscheidungen.

Eine gemeinsame Tabelle für alle Messrechner. Fehlende CPU-, RAM- und Datenträgerangaben werden nicht geraten. Die beiden Zeilen unten stammen vom selben Windows-Rechner. Der neue Stand braucht eine neue vollständige Messung.

| Datum / Nachweis | CPU / RAM / Datenträger | OS / Python | Arbeitslast / Wissen | Records/s | Peak RSS |
| --- | --- | --- | --- | ---: | ---: |
| [2026-09-10](knowledge/benchmarks/20260910-batch-checkpoint.json) / provisional batch checkpoint | nicht erfasst; RAM nicht erfasst; nicht erfasst | Windows build 26200 / nicht erfasst | 1,000 rows; batch 100; 7 runs; none | 353.52 | 95.23 MiB max |
| [2026-09-10](knowledge/benchmarks/20260910-legacy.json) / historical documented baseline | nicht erfasst; RAM nicht erfasst; nicht erfasst | Windows build 26200 / 3.11.9 | 1,000 rows; batch 100; 3 runs; none | 52.41 | 85.42 MiB median |
<!-- EVIDENCE:END -->

52,41 Records/s ist die **historische Messung vor dem Batching**, nicht die aktuelle
Geschwindigkeitsbehauptung. 353,52 Records/s ist ein **Entwicklungszwischenstand aus
sieben Läufen**, vor weiteren Sicherheitsänderungen. Ein späteres Protokoll nennt
rund 381 Records/s aus drei Vorläufen. Beides ersetzt keine vollständige Messung des
finalen Codes. Ein zweites oder drittes Hardwareprofil wurde hier nicht erfunden,
damit die Tabelle voller aussieht.

[Messnachweise und Herkunft](docs/PERFORMANCE_EVIDENCE.md) dokumentiert die alten
Werte, fehlende Gerätedetails und den Weg für neue Messreihen. Die historische
[Baseline](docs/PERFORMANCE_BASELINE.md) bleibt erhalten. CPU, nutzbare Kerne und
Quotas, Datenträger-/fsync-Latenz, RAM, Betriebssystem/Python, Treiber, Durability,
Record-Aufbau und Batchgröße sind relevant. Eine GPU hilft nur, wenn der gemessene
Pfad sie tatsächlich verwendet.

Badges und dieser Abschnitt entstehen lokal aus versioniertem JSON, ohne externen
Badge-Dienst und ohne Actions:

```bash
python scripts/render_evidence.py
python scripts/render_evidence.py --check
```

Der Laborkandidat nutzte 365 eindeutige Aufgaben und 1.656 Präferenzvergleiche.
Auf dem synthetischen Holdout verbesserte er seine eigene Basis von 32/53 auf 44/53
korrekte Erstvorschläge. Das ist **kein** Vergleich mit Polymorph-AUTO, keine 1.656
unabhängigen Kunden und keine Zahl importierter Tabellenzeilen.

Auf dem älteren Mapping-Korpus trafen Deterministik und optionale Forschungsmodelle
dieselben Entscheidungen. Encoder plus Reranker benötigten deutlich mehr Zeit und
Speicher. Zusätzliche AI wandelte dort hauptsächlich Strom in Wärme um. Ein guter
Benchmark darf uns sagen, etwas nicht auszuliefern. Siehe [Modellprofil](docs/MODEL_PROFILE.md).

## Lokal messen

```bash
python scripts/validate_local.py
python scripts/dev.py benchmark mapping benchmarks/safety-regression.json --require-auto-precision 1.0 --max-unsafe-auto 0
python scripts/dev.py benchmark workflow --records 1000 --batch-size 100 --work-dir workflow-run --output workflow.json
```

Das separate Labor bietet feste Referenzkorpora, Exploration, Training und gepaarte
Auswertung. Wiederholte Zeilen prüfen Volumen; unterschiedliche beschriftete
Zuordnungen lehren einen Ranker. Diese Zähler sind nicht austauschbar. Öffentliche
Beiträge gehören zuerst in eine geprüfte Corpus-Inbox, nicht unmittelbar ins
Training oder in einen produktiven Ausführungsplan.

## Technische Dokumentation

[Architektur](docs/ARCHITECTURE.md) · [Zuverlässigkeit](docs/RELIABILITY.md) ·
[Recipes](docs/RECIPES.md) · [Dateivertrauen](docs/FILE_TRUST.md) ·
[Empfängerschlüssel](docs/RECIPIENT_KEY_ROTATION.md) · [Write-Nachweis](docs/DATABASE_WRITE_PROOF.md) ·
[Betrieb](docs/OPERATIONS.md) · [Observability](docs/OBSERVABILITY.md) ·
[Benchmarking](docs/BENCHMARKING.md) · [Externes Labor](docs/EXTERNAL_LAB.md) ·
[Roadmap](docs/ROADMAP.md) · [Security](SECURITY.md)

## Lizenz

Source-available unter **PolyForm Noncommercial 1.0.0**, nicht OSI Open Source.
Kommerzielle Nutzung benötigt eine separate Lizenz von Angus Uelsmann. Maßgeblich
ist der Lizenztext. [Kommerzielle Konditionen](COMMERCIAL.md) · [Drittanbieter](THIRD_PARTY.md).

Entwickelt von [angusu.de](https://angusu.de). Namen dürfen wechseln. Protokollidentitäten sollten dafür nicht umziehen müssen.
