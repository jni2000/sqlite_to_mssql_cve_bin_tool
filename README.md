# cve-bin-tool SQLite → Microsoft SQL Server migration utility v0.3.4

Standalone migration utility for the `jni2000/cve-bin-tool` `sodiacs` deployment architecture.

## Supported source databases

- `--kind cve`: migrates the seven tables from `cve.db` into the target SQL Server database.
- `--kind version-map`: migrates `version_map.db` (`latest_update_sqlite` and `sqlite`) into a separate SQL Server database.
- `--kind generic`: schema-discovered fallback for other SQLite files; not needed for the production scanner design.

The downloaded `purl2cpe/purl2cpe.db` is intentionally not a production migration target: cve-bin-tool uses it while building `cve.db`, and the resulting `purl2cpe` table is already migrated as part of `cve.db`.

## Requirements

```powershell
py -m pip install pyodbc
```

## SQL Server Express example

Create two databases first: `cvedb` and `version_map`.

Migrate CVE data:

```powershell
py .\sqlite_to_mssql.py `
  --source .\cve.db `
  --kind cve `
  --connection-string "DRIVER={ODBC Driver 18 for SQL Server};SERVER=localhost\SQLEXPRESS;DATABASE=cvedb;Trusted_Connection=yes;TrustServerCertificate=yes" `
  --create-tables --replace-data --verify
```

Migrate version map:

```powershell
py .\sqlite_to_mssql.py `
  --source .\version_map.db `
  --kind version-map `
  --connection-string "DRIVER={ODBC Driver 18 for SQL Server};SERVER=localhost\SQLEXPRESS;DATABASE=version_map;Trusted_Connection=yes;TrustServerCertificate=yes" `
  --create-tables --replace-data --verify
```

Use `--dry-run` first if desired. `--replace-data` deletes existing rows from the selected target tables before inserting source rows.

`version_map.db` stores its update timestamp in SQLite in a form that can be an epoch number; the migrator converts numeric epoch values to SQL Server `DATETIME2` values.

## v0.3.1 migration reliability fix

- `fast_executemany` is now **off by default**. ODBC array binding can infer an unsuitable parameter type when SQLite columns contain mixed Python types.
- `cve_metrics.metric_id` and `metrics.metrics_id` are normalized explicitly to Python `int` before binding.
- `cve_metrics.metric_score` and `cve_severity.score` are normalized to `float`/`NULL`; nonnumeric SQLite values such as `unknown` become `NULL`.
- On a batch failure the migrator rolls back, probes rows individually, and reports the exact source row plus values and Python types.
- Use `--fast-executemany` only after a successful safe migration if you want to benchmark the faster path.


## v0.3.3 cve_metrics compatibility

The upstream SQLite `cve_metrics` table is heterogeneous: `metric_id`, `metric_score`, and `metric_field` can contain the literal text sentinel `unknown`. v0.3.3 preserves those values losslessly in SQL Server text columns. `cve_metrics` automatically uses `pyodbc.fast_executemany` after normalization to homogeneous parameter types; use `--safe-executemany` only as a slow diagnostic fallback.

Because v0.3.1 created `cve_metrics.metric_id` as `INT`, upgrading an existing target requires `--create-tables --drop-tables --replace-data` once so the SQL Server schema is recreated.


## v0.3.3 cve_metrics compatibility
Preserves duplicate cve_metrics rows with a SQL-Server-only row_id identity. The SQLite-facing compatibility layer hides row_id and emulates the scanner loose GROUP BY by choosing the earliest stored row per metric_id.

## v0.3.4: scanner lookup indexes and bounded key columns

For **newly created** `--kind cve` target tables, `cve_range.vendor`,
`cve_range.product`, and `cve_range.version` are now nullable
`NVARCHAR(128)`, `NVARCHAR(256)`, and `NVARCHAR(128)`, respectively.
`purl2cpe.purl` is nullable `NVARCHAR(256)`; `purl2cpe.cpe` stays
`NVARCHAR(MAX)`. The utility creates the following indexes **after loading**:

```sql
CREATE NONCLUSTERED INDEX IX_cve_range_vendor_product_version
ON dbo.cve_range (vendor, product, version) INCLUDE (cve_number);
CREATE NONCLUSTERED INDEX IX_purl2cpe_purl
ON dbo.purl2cpe (purl) INCLUDE (cpe);
```

The existing `cve_metrics` nonunique runtime index and duplicate/sentinel
preservation remain unchanged. Before any SQL Server changes, the utility
checks source values against the new column limits, counting UTF-16 code
units. Oversize source values cause an explicit error instead of truncation.
The current limits were selected using the observed source maximums, not as
universal guarantees for future upstream database snapshots.

**Existing successfully migrated databases:** Do not re-migrate solely to
apply this update. If you have already altered the columns and created both
indexes in SSMS, your database is ready. This utility does not automatically
alter pre-existing `NVARCHAR(MAX)` columns. When rebuilding a database later,
use the normal `--create-tables --drop-tables --replace-data --verify` command
against a backup/test target first. `--drop-tables` destroys the selected
existing SQL Server tables and their data.

Note: a `LIKE '%substring%'` predicate generally cannot seek an ordinary
B-tree index. Compare real scanner runtime and execution plans to validate
performance improvements.
