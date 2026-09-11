# Resumable local training and reviewed publication

The external Polymorph Run 1.1 / Lab 0.3 is a local training controller. It is not
an agent that rewrites this repository or grants itself production authority.
The new campaign path is separate from the repeatable reference-training command.

## Operator workflow

1. Run `Start.cmd` once to check the local checkout and initialize a CPU campaign.
2. Use `Weiterlernen.cmd` to continue the existing campaign. `Pause.cmd` requests
   a checkpoint boundary; `Status.cmd` prints the retained progress.
3. Use `Freigabe.cmd` only after reviewing a candidate. It asks for approval and a
   locally encrypted publisher key, performs a final synthetic evaluation and
   prepares the signed knowledge package.
4. Review the exact file list before selecting `BEREITSTELLEN`. Only the package,
   its evidence/pointer and the generated README/badge sections are written.
5. Review `git diff`, then commit/push yourself. No script calls `git add`, commit,
   push, pull, merge, or force-push. No SSH key is needed for local training.

General updates retain the separate `knowledge/general.sqlite` model store. The
publisher never opens `recipes.sqlite`, local model directories, credentials or
customer datasets. The package remains advisory; installation and activation are
separate choices governed by the existing knowledge contract.

## Checkpoint contract

The CPU trainer commits last weights, selected best weights, next input cursor,
round/epoch counters, learning-rate settings and dataset identity in one SQLite
transaction with FULL synchronous durability. It retains the three latest
checkpoints. A deterministic permutation is derived from the saved seed,
dataset digest, round and epoch; pause/resume does not start from baseline.

A normal pause saves at a safe update boundary. Killing the process or losing
power cannot be relied upon to invoke an exit handler. Restart uses the last
complete checkpoint and may repeat only the uncommitted interval. The SQLite
and filesystem durability assumptions still apply. Checksums are corruption
detection, not authentication against a malicious local administrator.

A changed trainer/feature implementation or Python version blocks exact resume.
It does not silently discard training or interpret old state under new code.
Reference experiments still deliberately start from baseline and remain separate.

## New tasks without a moving finish line

Exploration adds unseen training queries and replays the previous training pool.
Validation and holdout remain frozen within a campaign. Matching source groups
and exact reserved queries cannot cross into the training pool. A candidate only
replaces the selected best when its validation metrics improve without losing
previously correct validation queries. This is a corpus-specific selection rule,
not a guarantee of general correctness.

The generator has a finite synthetic business ontology. The campaign stops at
its round/query/pair budget or when no new training queries are found. Another
epoch is not another independent example. A larger checkpoint is not proof of a
better model. The optional GPU projection trainer is not covered by CPU resume.

## Candidate interchange

The local exporter writes four files: `manifest.json`, `model.json`,
`evidence.json`, `evaluation.json`. The manifest binds the other three exact byte
streams. Last unselected weights, RNG/checkpoint state, raw data, descriptors,
private paths and hardware inventory do not belong in the public candidate.

Check it against this checkout:

```powershell
.\.venv\Scripts\python.exe scripts\check_campaign_candidate.py D:\candidate-folder
```

A successful check is `verified: true` with `publication_approved: false`.
It verifies structure and consistency, NOT that the reported training took place
or that a model is useful in production. The local publisher recreates candidates
from the retained campaign rather than trusting an arbitrary model/report pair.

Training evidence describes the *selected* model's training population and update
count. Data added after that model was selected does not inflate its badge.
The model's feature implementation is compared by Python AST for inference
compatibility; its signed package still binds the exact product runtime bytes
expected by the current `KnowledgeStore`. This only tolerates representation
changes such as blank lines. A changed AST is not silently declared equivalent.

## Publication boundaries

Checkpoint, candidate and released knowledge are three distinct states. The final
holdout is evaluated explicitly for release preparation and cached per model;
repeated exports are not new independent tests. The report records the number of
holdout evaluations in the campaign. Repeated human inspection can still turn it
into a development set, so independent final customer evidence remains necessary.

The publisher's private Ed25519 key is encrypted PKCS8 outside Git. Passphrases
are prompted, not placed in command arguments, environment variables or logs.
A signature proves publisher authorization, not semantic correctness.

Preparation uses an explicit synthetic-data approval. Staging uses a file
allowlist plus Git's ignore policy; `.gitignore` alone is not a privacy boundary.
The new package is written before `knowledge/latest.json`. Existing releases are
not overwritten and unrelated working-tree files remain untouched. A local
journal and backups remain after an interrupted multi-file stage. This is NOT an
atomic repository transaction; inspect a partial-stage result before committing.
No automatically accepted production knowledge or publisher key ships with this
change. The normal mapper and write/replay contracts are unchanged.

## Deutsche Kurzfassung

`Start.cmd` prueft das Projekt und startet beziehungsweise setzt die lokale
Kampagne fort. `Weiterlernen.cmd` trainiert weiter, `Pause.cmd` fordert einen
sauberen Haltepunkt an. Nach hartem Abbruch wird der letzte vollstaendige
Checkpoint geladen, nicht wieder mit Ausgangsgewichten begonnen.

Neue Aufgaben stammen ausschliesslich aus dem Trainingssplit. Die alte
Trainingsmenge bleibt als Wiederholung enthalten; Validation und Holdout werden
nicht heimlich verschoben. Der Fortschrittsbericht trennt neue Aufgaben,
Gewichtsaktualisierungen und die Zaehler des ausgewaehlten Modells.

`Freigabe.cmd` ist eine separate Entscheidung mit Vorschau. Das Werkzeug bereitet
nur freigegebene Wissensdateien und README-Bereiche im lokalen Projekt vor. Danach
pruefst du den Diff und committest selbst. Private Recipes und lokale Modelle
bleiben getrennt. GPU-Training, Produktionsfreigabe und eine vollstaendige
Windows-/PostgreSQL-Zertifizierung sind damit nicht behauptet.
