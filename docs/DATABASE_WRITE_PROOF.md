# Database write postconditions

## Contract

`DatabaseConnector` checks the supplied values before it acknowledges a successful
INSERT transaction. A matching driver `rowcount` is necessary on the ordinary
insert path, but it is not evidence that an AFTER trigger left the intended rows
and values in the table.

The write path now performs these steps in a single transaction:

1. Validate a homogeneous set of known columns and freeze typed expectations.
2. Select a complete, non-null supplied primary or globally unique key. Partial
   and expression indexes are not proof keys. Alternatively, obtain generated
   primary keys from the driver, using RETURNING for a generated-key batch.
3. Insert all rows and validate the row count or generated identity count.
4. On PostgreSQL, make deferred constraints immediate before verification so
   pending constraint triggers run before the read-back.
5. Read back the supplied columns by their row identities in bounded query chunks.
   Compare the identity set, values and multiplicities, not just their count.
6. Commit only after that postcondition holds.

RETURNING is an identity source, not the final value proof. SQLite explicitly
excludes subsequent AFTER-trigger modifications from its returned values and does
not guarantee result order. The generated-key path therefore makes no assumption
about RETURNING order. For rows with supplied keys, those keys remain part of the
value comparison. For wholly generated keys, the postcondition is the exact
multiset of supplied values across the returned identities.

## Failure semantics

A failed postcondition causes rollback. Only a confirmed rollback under the
captured transactional contract produces `NOT_COMMITTED`. A failed rollback or an
uncertain commit remains `UNKNOWN`; the connector does not retry either path.
A connection-close error after a confirmed commit cannot turn success into a
retry signal. Driver exceptions are not included in public error messages.

Known SQLite/DBAPI autocommit configurations are rejected before insertion. The
configured database, driver and connector host remain trusted dependencies.
This is not protection against a malicious database server, forged read results,
external effects of user-defined functions, or later independent transactions.
In particular, it is not a guarantee that rows can never change after commit.

## Compatibility and limits

- Writes need SELECT permission on the identity and supplied columns as well as
  INSERT permission. RLS that prevents verification makes the operation fail.
- Tables without a usable key are rejected. No full-table count or payload-only
  matching fallback silently weakens the proof.
- Mixed column sets in one call are rejected. Missing and explicitly null fields
  are not silently made equivalent. Split such inputs into explicit batches.
- Unmapped default/generated columns may be filled by the database. Changes to
  supplied values require an explicit transformation before this connector call.
- Finite numeric values compare by value; booleans stay distinct from numbers.
  Decimal rounding, string/numeric coercion, lost timezones and altered JSON or
  binary values cannot silently pass. Nested comparison depth is limited to 64.
- A call to `write_records` accepts at most 1,000 rows, matching the existing batch
  ceiling. It reads at most one additional item to detect an oversized iterable
  and performs no inserts on that admission failure. This API does not split an
  oversized call into separately committed transactions.
- Existing batch wire-byte limits and delivery identities remain unchanged.
  Read-back uses at most 500 identity bind parameters per query for normal key
  widths. The extra SELECT work is deliberately inside the same transaction.
- These checks cover the inserted rows and supplied columns. They do not enumerate
  arbitrary trigger side effects on unrelated rows or tables.

## Validation in this change

The focused suite `tests/test_database_postconditions.py` was run against the
actual DatabaseConnector and its exact upstream dependencies from commit
`928b268d5a3931419fbbb44ea49579c18ad5294e` in a source subset, not a full checkout.

- Before the change: 57 tests, 34 failures, 23 passes.
- With the change: 57 tests passed, no skips.
- Python 3.13.5, SQLAlchemy 2.0.50, pytest 9.0.2, Linux.
- SQLite files used `/dev/shm`; these are correctness tests, not disk-durability
  or throughput measurements. No end-to-end performance claim is made.
- Real SQLite triggers exercise deletion, rewriting and earlier-row corruption.
- Tests cover generated/composite keys, value coercion, mutation during execution,
  commit/rollback acknowledgement loss, cleanup errors, bounded iteration and a
  1,000-row batch retaining one transaction with two read-back queries.
- The PostgreSQL test checks statement ordering with an instrumented connection;
  it is not a live PostgreSQL test.

A full-project run, native Windows run, live PostgreSQL validation, Ruff and mypy
remain required before merging. The first GitHub branch-validation job stopped
before executing any step, so it supplied no test result. The draft pull request
must not be treated as a release certification.

## References

- SQLite RETURNING: https://www.sqlite.org/lang_returning.html
- PostgreSQL SET CONSTRAINTS: https://www.postgresql.org/docs/current/sql-set-constraints.html
