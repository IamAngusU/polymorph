# Hier starten

Polymorph ist ein lokaler Trust-Layer fuer die Zuordnung und Uebertragung von Daten zwischen
inkompatiblen Systemen. Lernende Komponenten duerfen Vorschlaege verbessern, aber keine Writes
autorisieren.

## Windows: Nachweis in fuenf Minuten

Voraussetzung: Python 3.11 oder neuer. Eine GPU ist nicht erforderlich.

```powershell
git clone https://github.com/IamAngusU/polymorph.git
cd polymorph
py -3.11 -m venv .venv
.venv\Scripts\python -m pip install ".[benchmark]"
World-Benchmark.cmd
```

Der Lauf erzeugt lokale Nachweise unter `.polymorph/evidence/`. Er laedt nichts hoch, pusht nichts,
aktiviert kein Modell und startet keine GitHub Action.

## Daten ohne Write pruefen

```powershell
polymorph inspect auto .\eingang.csv --output .\schema-und-inhalt.json
polymorph inspect excel .\eingang.xlsx --output .\excel-schema.json
polymorph inspect parquet .\eingang.parquet --output .\parquet-schema.json
```

Fuer Parquet:

```powershell
python -m pip install ".[parquet]"
```

Fuer einen echten PostgreSQL-Connector-Nachweis:

```powershell
python -m pip install ".[postgres]"
$env:POLYMORPH_TEST_POSTGRES_URL = "postgresql+psycopg://USER:PASSWORD@HOST/DB"
python scripts\postgres_lab.py --output .polymorph\postgres-lab.json
```

Die URL wird nicht protokolliert. Das Lab erstellt eine zufaellig benannte Testtabelle, beweist
Write und Rollback und entfernt sie danach.

## Echte Review-Zeit messen

```powershell
polymorph-review start --fields 40 --suggestions 32 --corpus kundenimport
polymorph-review finish SESSION_ID --accepted 25 --corrected 10 --abstained 5
polymorph-review summary
```

Gespeichert werden nur Zaehler und Zeiten, keine Feldnamen oder Datenwerte.
