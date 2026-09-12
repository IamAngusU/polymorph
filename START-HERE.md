# Start here

Polymorph is a local-first trust layer for mapping and moving data between incompatible systems.
Learned components may improve suggestions but cannot authorize writes.

## Windows: five-minute proof

Requirements: Python 3.11 or newer. No GPU is required.

```powershell
git clone https://github.com/IamAngusU/polymorph.git
cd polymorph
py -3.11 -m venv .venv
.venv\Scripts\python -m pip install ".[benchmark]"
World-Benchmark.cmd
```

The command creates local evidence below `.polymorph/evidence/`. It does not upload, push, activate
a model or start GitHub Actions.

## Install the small package

```powershell
py -3.11 -m venv .venv
.venv\Scripts\python -m pip install polymorph_bridge-0.4.0a2-py3-none-any.whl
.venv\Scripts\polymorph doctor
```

## Inspect data without writing

```powershell
polymorph inspect auto .\incoming.csv --output .\schema-and-content.json
polymorph inspect excel .\incoming.xlsx --output .\excel-schema.json
polymorph inspect parquet .\incoming.parquet --output .\parquet-schema.json
polymorph inspect db "postgresql+psycopg://USER@HOST/DB" --table orders --output db-schema.json
```

Parquet is optional:

```powershell
python -m pip install ".[parquet]"
```

PostgreSQL is optional:

```powershell
python -m pip install ".[postgres]"
$env:POLYMORPH_TEST_POSTGRES_URL = "postgresql+psycopg://USER:PASSWORD@HOST/DB"
python scripts\postgres_lab.py --output .polymorph\postgres-lab.json
```

The PostgreSQL URL is never written to the report. The lab creates a random temporary table, proves
a real write and transaction rollback, and removes the table afterward.

## Measure real review work

```powershell
polymorph-review start --fields 40 --suggestions 32 --corpus customer-import
polymorph-review finish SESSION_ID --accepted 25 --corrected 10 --abstained 5
polymorph-review summary
```

Only counts and timing are stored. Field names and row values are not recorded.

## Safety expectations

- Start with inspection and mapping; do not point the first experiment at a production destination.
- Keep benchmark and customer data separate.
- Review every generated plan before allowing writes.
- Treat `REVIEW` and `BLOCKED` as useful safety outcomes, not failures to hide.
- Never publish local evidence without checking it for paths and environment details.
