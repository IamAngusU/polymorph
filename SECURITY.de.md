# Sicherheit

<p align="center">
  <a href="SECURITY.md">English</a> · <strong>Deutsch</strong>
</p>

Polymorph ist sicherheitsrelevante Infrastruktur. Security Claims haben deshalb Geltungsbereiche, Voraussetzungen und bekannte Grenzen. „Läuft meistens“ gehört nicht dazu.

Keine Production-Credentials, Plaintext-Payloads, Private Keys, Access Tokens oder Kundendaten in Issues, Commits, Fixtures oder Debug Output. GitHub Issues sind durchsuchbare Kollaborationstools, kein Secret Manager mit Kommentarfeld.

Siehe [Security Coverage und Resource Boundaries](docs/SECURITY_COVERAGE.md) für enforced Defaults, automatisierte Evidenz und noch offene Aggregate Limits.

## Schwachstellen melden

Vermutete Security-Probleme bitte privat an [hello@angusu.de](mailto:hello@angusu.de) oder über das Kontaktformular auf [angusu.de](https://angusu.de) melden.

Bitte kein öffentliches Issue für eine vermutete Schwachstelle eröffnen, bevor ein koordinierter Disclosure-Pfad abgestimmt wurde.

Ein hilfreicher Report enthält, soweit möglich:

- betroffene Komponente und Version oder Commit
- Reproduktionsschritte oder einen minimalen Proof of Concept
- erwartete gegenüber beobachteter Trust Boundary
- Security Impact
- relevante Logs, aus denen Secrets und Payload-Werte entfernt wurden

Wenn der Report eine feindliche Datei braucht, bitte die kleinste reproduzierbare Fixture über einen abgestimmten privaten Kanal teilen. Kundendaten werden nicht dadurch zu Testdaten, dass sie den Bug besonders zuverlässig auslösen.

## Unterstützte Versionen

Nur der aktuelle `main`-Branch und die neueste veröffentlichte Alpha erhalten Security Fixes.

Ältere Alpha-Stände, einschließlich 0.3.x und früher, sind unsupported und sollten nicht deployed werden.

## Security-Invarianten

Das sind Design Constraints. Sie werden nicht optional, nur weil eine Funktion ohne sie bequemer wäre.

1. Die Control Plane benötigt keine Record-Payload-Werte, um einen Mapping-Plan zu erstellen oder zu validieren.
2. Dateinamen, Endungen und caller-provided MIME-Labels sind niemals Autorität für Parserauswahl.
3. Blocking Content Risks stoppen eine Datei, bevor ein unterstützter Parser aufgerufen wird. Ein hochkonfidenter Widerspruch zwischen unabhängigen Content-Detectors blockiert standardmäßig die automatische Parserauswahl.
4. ZIP- und OOXML-Inspection blockiert standardmäßig Traversal, archivierte Symlinks, doppelte normalisierte Member, verschlüsselte Member, verdächtige Expansion, Makros und externe Workbook-Link- oder Data-Connection-Parts.
5. Akzeptierte CSV-, JSON- und Excel-Inputs werden vor Parser-Handoff an Device, Inode, Size und nanosekündliche Modification Time des tatsächlich geöffneten Handles gebunden.
6. Excel-Parsing verlangt openpyxl-XML-Härtung über `defusedxml`. Formula Caches haben keine bewiesene Frische und dürfen keine neue Route still automatisch promoten.
7. Secret- und Opaque-Werte dürfen per Policy nicht in Destinationen mit niedrigerer Sensitivity geroutet werden.
8. Semantic Encoder und Reranker bekommen ausschließlich Descriptor-Text. Sie haben keine Connector-, Credential- oder Record-Value-Schnittstelle.
9. Model-Evidenz darf ein `AUTO`-Mapping nicht unabhängig autorisieren. Automatisches Mapping braucht unabhängig starke deterministische Evidenz und Margin.
10. Ausführbare Transformationen stammen aus einer festen Registry. Input Content kann weder Code noch SQL hinzufügen.
11. Recipes sind Candidate Memory, keine Autorisierung. Jede Aktivierung wird an aktuelle exakte Schemas gebunden, erhält einen neuen Plan-Digest und läuft erneut durch Validation und Preflight.
12. Ein gesampelter Preflight darf eine Route weder automatisch promoten noch merken. Automatische Promotion verlangt einen vollständigen No-write-Preflight.
13. Blind Transport authentifiziert Route-, Record-, Field-, Transfer-, Schema- und Plan-Metadaten zusammen mit dem Ciphertext.
14. Protocol v3 authentifiziert zusätzlich die Source mit einem Ed25519-Key, der unabhängig an Tenant und Connector gebunden ist. Unsigned-v2-Intake ist fail-closed, sofern nicht jede Boundary explizit Migration Mode aktiviert.
15. Protocol-v3-Sources lehnen nicht authentifizierte Destination-Recipient-Keys standardmäßig ab. Akzeptierte Keys sind von einer unabhängig gepinnten Destination Identity signiert, an die Route gebunden und werden über eine exakte monotone Predecessor Chain fortgeschrieben.
16. Die Sealed Relay Queue hat weder Recipient-Private-Key-Parameter noch Decrypt-Methode. Ack und Release benötigen den aktuellen nicht abgelaufenen zufälligen Lease Token.
17. Schema Drift darf Sensitivity nicht still ändern oder einen genehmigten Foreign-Key-Lookup-Beweis ungültig machen.
18. Der Destination Runtime prüft vor dem Write den exakten Plan und das Target Schema sowie Required Fields, Nullability und Runtime Types.
19. Ein Write mit unbekannter Durability wird niemals nur deshalb als sicher retrybar behandelt, weil eine Exception aufgetreten ist.
20. Exakte Duplicate Deliveries werden nach aufgezeichnetem Commit vor einem zweiten Decrypt-/Write-Versuch erkannt.
21. Quarantine- und Audit-Persistenz akzeptieren maschinenlesbare Metadaten und Sealed Records, keine beliebigen Exception-Texte mit Payload-Werten.
22. CSV-Destinationen blockieren spreadsheet-formula-artige Werte standardmäßig. Freigabe ist explizite Connector Policy.
23. Connector-Credentials werden bei Nutzung eines Secret Providers als Referenzen dargestellt und niemals in Mapping Plans serialisiert.
24. Recipient-Private-Key-Dateien sind verschlüsselt, überschreiben keinen bestehenden Key und verwenden restriktive POSIX Permissions, wo unterstützt.
25. Die eingebettete Convenience-API kann erst nach einer expliziten vollständigen Vorbereitung schreiben. Ihr lokaler Write-Pfad akzeptiert nur content-geprüfte unveränderliche Dateien, prüft Destination Schema und Capabilities erneut und verweigert Secret- oder Opaque-Forwarding.
26. Produkt-Events sind begrenzte payload-freie Hinweise. Consumer-Fehler können ein Destination-Outcome weder unterbrechen noch stärker darstellen, und Produkt-Events ersetzen nicht die signierte Audit Chain.
27. Third-Party-Connector-Entry-Points werden beim normalen Registry-Aufbau niemals importiert. Sie zu laden ist eine explizite Trusted-Code-Aktion; Destination-Ressourcen bleiben danach weiterhin explizit.

Unbekannt heißt unbekannt. Das ist lästig. Es ist immer noch besser, als einen Write selbstbewusst zu replayen, der bereits committed sein könnte.

## Parser Containment

Content Gate und Contract Preflight sind keine Behauptung von hostile-code Operating-System Containment.

Polymorph hat einen fail-closed Worker für die Content-Inspection-Stufe. Er parst einen Exact-byte-Snapshot unter einem explizit gemeldeten Containment-Level. Das strikte Linux-Backend nutzt Bubblewrap. Ein normaler Child Process wird als Process Separation bezeichnet, weil ein zweiter PID nicht automatisch eine Sandbox erzeugt.

Das Bubblewrap-Backend verlangt nicht-setuid und nicht-setgid Bubblewrap 0.12.0 oder neuer. Ältere Versionen werden abgelehnt, weil 0.12.0 einen Upstream-Sandbox-Setup-[Symlink Escape](https://github.com/containers/bubblewrap/security/advisories/GHSA-pxhw-h44j-8pfx) behebt.

Polymorph sollte unter einem dedizierten unprivilegierten Service Account laufen. Binary Discovery und Versionsprüfung gelten nicht als Beweis, dass der Host Kernel die angeforderte Namespace Boundary erlaubt; der Worker muss erfolgreich starten.

Unterstützte Schema Parser und Record Iterators laufen weiterhin im lokalen Polymorph-Prozess. Resource Limits, Archive Checks, gehärtetes XML-Parsing und isolierte Content Detection reduzieren Risiko, enthalten diesen vollständigen Pfad aber noch nicht.

`polymorph doctor` meldet konkrete Worker-Capabilities und trennt bloße Binary-Präsenz von einer tatsächlich erfolgreich ausgeübten Boundary. Siehe [Parser Isolation](docs/PARSER_ISOLATION.md).

## Key Material

Die eingebaute verschlüsselte Recipient-Key-Datei ist ein Software Key Store, kein HSM.

Ihr Schutz hängt von Passphrase, Host Security und der Verfügbarkeit von Argon2id im eingesetzten Crypto Backend ab. Deployments mit Hardware-backed Keys sollten einen Destination Process verwenden, der Private-Key-Operationen über OS Keystore, HSM oder eine vergleichbare vertrauenswürdige Komponente bezieht.

Verschlüsselt auf Disk ist eine Eigenschaft. Hardware Isolation ist eine andere. Die beiden werden nicht synonym, nur weil im Dateinamen `key` steht.

## Dependencies und optionale Modelle

Optionale Semantic Models werden in diesem Repository nicht redistribuiert. Ihre Installer pinnen Upstream-Revisions und verifizieren jedes benötigte Model-, Tokenizer- und Configuration-Asset gegen eingebaute SHA-256-Digests.

Runtime Dependencies behalten ihre Upstream-Security- und Patch-Anforderungen. Optionale Model Profiles haben zusätzlich Provenance- und Dataset-Term-Grenzen, dokumentiert unter [Model Profiles](docs/MODEL_PROFILE.md).

Modelle erhalten Schema-Deskriptoren, keine Record-Payload-Werte, und dürfen ein Write-Mapping nicht unabhängig autorisieren.

## Bekannte Alpha-Grenzen

Polymorph ist Alpha. Folgende Lücken sind bekannt und absichtlich dokumentiert:

- Nur Content Inspection hat einen separat enforced Worker. Schema Parsing und Record Iteration sind noch nicht isoliert.
- Source Trust Keys sind In-memory-Primitives. Durable authenticated Trust-Bundle-Distribution ist nicht implementiert.
- Recipient-Certificate-Heads können lokal persistiert werden, aber Source-host State Rollback braucht einen unabhängigen Checkpoint. Destination-Identity-Rotation und replacement-free Emergency Revocation sind nicht implementiert.
- Queue Limits gelten pro Record und Message, nicht kumulativ pro Tenant oder Disk.
- Die lokale Audit Chain hat keinen externen Checkpoint. Ein Angreifer mit Storage-Zugriff könnte einen gültigen Suffix abschneiden.
- CLI-Database-URLs können über Shell History sichtbar werden. In Automation strukturierte Endpoints und Secret Providers verwenden.
- Destination Audit bleibt optional.
- Operational-Event-Coverage ist außerhalb des aktuell instrumentierten Workflows unvollständig.
- Der eingebettete `execute()`-Convenience-Pfad läuft im selben Prozess und ist auf unveränderliche Datei-Sources begrenzt. Er ist nicht das ciphertext-only Relay und macht Database- oder HTTP-Source-Snapshots nicht atomar.
- Produkt-Event-Delivery ist Best Effort. Third-Party-Event-Sinks verantworten Authentication, Transport-Durability, Backpressure und Access Control selbst.
- Connector Conformance validiert den erklärten Python-Contract, beweist aber weder einen Third-Party-Service noch dessen Transaktionen, Idempotency-Implementierung oder Plugin-Paket als vertrauenswürdig.
- Notification Service und Queue Metric Exporter existieren noch nicht.
- Das Projekt hatte noch kein unabhängiges Security Assessment.

Das sind Grenzen, keine TODOs hinter optimistischer Formulierung. Alpha ist ein Reifegrad, kein Deko-Badge.

## Security-relevante Dokumentation

- [Security Coverage](docs/SECURITY_COVERAGE.md)
- [Threat Model](docs/THREAT_MODEL.md)
- [Parser Isolation](docs/PARSER_ISOLATION.md)
- [Recipient-Key-Authentizität und Rotation](docs/RECIPIENT_KEY_ROTATION.md)
- [Protocol](docs/PROTOCOL.md)
- [Operations und Replay Safety](docs/OPERATIONS.md)
- [Reliability Model](docs/RELIABILITY.md)

## Lizenz

Eine Security-Meldung gewährt keine zusätzlichen Rechte unter der Repository-Lizenz. Siehe [`LICENSE`](LICENSE) und [LICENSING.de.md](LICENSING.de.md).
