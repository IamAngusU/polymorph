# Beitragen

<p align="center">
  <a href="CONTRIBUTING.md">English</a> · <strong>Deutsch</strong>
</p>

Polymorph ist sicherheitsrelevante Infrastruktur. Beiträge sind willkommen, aber die Messlatte liegt absichtlich etwas höher als „der Happy Path lief auf meinem Rechner“.

Eine Änderung sollte explizite Trust Boundaries erhalten, Unsicherheit sichtbar lassen und lieber fail-closed reagieren, als Datenbedeutung still zu verändern. Wenn ein Patch das System hilfreicher macht, indem es mehr rät, hilft es wahrscheinlich in die falsche Richtung.

## Externe Beiträge

Issues, Design-Feedback, reproduzierbare Testfälle und verantwortungsvolle Security Reports sind willkommen.

Polymorph wird öffentlich unter AGPL-3.0-only lizenziert und kann zusätzlich unter separaten kommerziellen Bedingungen angeboten werden. Damit dieses Dual-Licensing-Modell sauber erhalten bleibt, werden substantielle Third-party-Codebeiträge erst gemerged, wenn eine Contributor-Vereinbarung dem Maintainer ausreichende Rechte gibt, den Beitrag unter AGPL zu veröffentlichen und in alternative kommerzielle Lizenzen einzubeziehen.

Bevor du Code beiträgst, öffne bitte zuerst ein Issue oder kontaktiere den Maintainer.

Diese Datei ist nicht die Contributor-Vereinbarung. Ein Pull Request ist ebenfalls kein überraschendes Copyright Assignment. Solange dieser Prozess für einen Beitrag nicht existiert und akzeptiert wurde, können unaufgeforderte PRs für die Diskussion nützlich sein, sollten aber nicht automatisch mit einem Merge rechnen.

## Vor einer Änderung

- Ergänze oder aktualisiere Tests für jedes sicherheits-, persistenz- oder delivery-relevante Verhalten.
- Halte semantisches Matching und Ausführungsautorisierung getrennt.
- Model-Scores, Dateiendungen, MIME-Labels, erfolgreicher Parser-Lauf oder Recipe-Historie dürfen niemals alleinige Autorisierungsevidenz werden.
- Kein dynamischer Code, kein `eval`, keine beliebige SQL-Generierung und kein payload-definiertes Connector-Verhalten.
- Keine echten Credentials, Private Keys, Access Tokens oder Kundendaten in Fixtures, Logs, Issues oder Commits.
- Jeder neue Datei-Parser muss seine Content-Identification-Regel, Resource Limits, Hostile-input-Risiken und Containment-Erwartungen dokumentieren.
- Jedes neue Retry-Verhalten muss sagen, ob ein fehlgeschlagener Write bewiesen `NOT_COMMITTED`, bekannt committed oder `UNKNOWN` ist.
- Jede neue Destination-side Relationship-Transformation muss ihren erlaubten Lookup-Pfad aus Destination-Metadaten oder einem explizit reviewten Contract beweisen.
- Jeder neue persistente Store muss dokumentieren, ob er Plaintext-Werte enthalten kann.
- Jede neue automatische Promotion-Regel muss die unabhängige Evidenz benennen, die sie autorisiert. „Der Score war hoch“ ist keine unabhängige Evidenz. Es ist eine Zahl mit guter Haltung.
- Benchmark-Daten müssen nach ursprünglicher Source, Template oder Organisation getrennt werden, bevor synthetische Varianten entstehen. Near-duplicate Leakage macht Charts glücklicher und Schlussfolgerungen schlechter.

## Änderungen an Trust Boundaries

Wenn eine Änderung Encryption, Signaturen, Identity Binding, Replay, Leases, Capabilities, Parser Containment, Secret Handling oder Destination Writes betrifft, dokumentiere:

1. was vor der Änderung vertraut wird
2. was nach der Änderung vertraut wird
3. welche Evidenz die Grenze überschreitet
4. was bei fehlender, veralteter oder widersprüchlicher Evidenz passiert
5. wie der Failure Path getestet wird

Eine neue Abstraktion ist kein Security-Argument. Eine Klasse namens `SafeSomething` übrigens auch nicht.

## Parser und feindliche Inputs

Datei-Parsing ist Angriffsfläche.

Ein Parser-Beitrag sollte, wo sinnvoll, malformed und resource-hostile Fixtures enthalten, explizite Byte- oder Record-Budgets haben und seinen Containment-Grad klar benennen. Ein Parser in einem anderen Prozess ist Process Separation. Sandbox wird daraus erst, wenn die Betriebssystemgrenze diese Behauptung tatsächlich durchsetzt.

Dateiendungen bleiben dekorative Metadaten. Sie dürfen korrekt sein. Verpflichtet sind sie dazu nicht.

## Mapping und Modelle

Modelle dürfen Retrieval, Ranking und Operator-Ergonomie verbessern. Sie dürfen nicht still zur Autorität werden.

Eine `AUTO`-Entscheidung muss weiterhin die aktuellen deterministischen und Policy-Gates erfüllen. Wenn Model-Evidenz den Gewinner vom unabhängig stärksten deterministischen Target wegändert, ist Review das erwartete Ergebnis. Nicht die Einladung, den Threshold so lange zu senken, bis CI wieder grün aussieht.

## Delivery- und Retry-Semantik

Externe Side Effects verdienen langweilige State Machines.

Kann ein Connector nicht beweisen, ob ein Write committed wurde, ist das Ergebnis `UNKNOWN`. Daraus wird nicht retry-safe, nur weil eine Exception geworfen wurde, ein Socket geschlossen ist oder Retry gerade praktisch wäre.

Jede Änderung am Replay-Verhalten muss durable Provenance und Idempotency-Annahmen über Restarts hinweg erhalten. Der erfolgreiche Retry-Pfad von gestern war übrigens auch ein anderer Tag.

## Benchmarks

Performance-Änderungen sollten Correctness Assertions im Benchmark behalten.

Bitte Connector, Durability Mode, Batch Size, Record Shape, Record Count und Machine Context für aufbewahrte Messungen dokumentieren. `--tracemalloc`-Runs nicht mit normalen Runs vergleichen, als hätte Instrumentation Overhead höflich beschlossen, heute nicht teilzunehmen.

Schneller durch Entfernen von Durability, Validation oder Evidence Checks ist keine Optimierung. Bremsen ausbauen verbessert ebenfalls die Fahrzeugmasse.

## Lokale Checks

Der normale modellfreie Development-Pfad ist:

```bash
python scripts/bootstrap.py --skip-models
```

Der Befehl installiert den Development-Stack und führt Compile Checks, Ruff Lint und Formatting, strict mypy, pytest mit Warnings als Errors, den Mapping Safety Smoke und `pip check` aus.

Das Repository enthält eine vorbereitete Python-Version-Matrix und Package-Release-Gates, aber GitHub Actions sind derzeit repositoryweit deaktiviert. Veröffentlichte Alpha-Evidenz entsteht durch die dokumentierte lokale Validierung und den manuellen Release-Prozess. Eine Workflow-Datei ist kein Beweis für einen öffentlichen Lauf.

Vor einem PR ist die Erwartung ziemlich simpel: relevante Tests bestehen, neues Verhalten ist abgedeckt und die Dokumentation erzählt weiterhin die Wahrheit.

## Security melden

Für vermutete Schwachstellen bitte kein öffentliches Issue eröffnen. Nutze den privaten Meldeweg in [SECURITY.de.md](SECURITY.de.md).

## Lizenz

Die öffentliche Projektlizenz ist AGPL-3.0-only. Eine Contributor-Vereinbarung kann dem Maintainer zusätzlich die Rechte geben, die für alternative kommerzielle Lizenzierung des Beitrags nötig sind; ein PR allein erledigt diese Aufgabe nicht.

Siehe [LICENSING.de.md](LICENSING.de.md) und [`LICENSE`](LICENSE).
