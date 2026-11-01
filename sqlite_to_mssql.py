#!/usr/bin/env python3
from __future__ import annotations

import argparse
from version import __version__
import contextlib
from datetime import datetime
import re
import sqlite3
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Iterator, Sequence

try:
    import pyodbc
except ImportError:  # allow --dry-run without pyodbc installed
    pyodbc = None


VERSION_MAP_TABLES = {
    "latest_update_sqlite": """
    IF OBJECT_ID(N'dbo.latest_update_sqlite', N'U') IS NULL
    BEGIN
        CREATE TABLE dbo.latest_update_sqlite (datestamp DATETIME2 NULL);
    END
    """,
    "sqlite": """
    IF OBJECT_ID(N'dbo.sqlite', N'U') IS NULL
    BEGIN
        CREATE TABLE dbo.sqlite (
            version NVARCHAR(255) NULL,
            sourceId NVARCHAR(2048) NOT NULL,
            CONSTRAINT PK_version_map_sqlite PRIMARY KEY (sourceId)
        );
    END
    """,
}

CVE_TABLE_ORDER = [
    "metrics",
    "cve_severity",
    "cve_range",
    "cve_exploited",
    "cve_metrics",
    "mismatch",
    "purl2cpe",
]

# DDL is intentionally SQL Server-native instead of mechanically translating
# SQLite CREATE TABLE statements. Foreign keys are omitted because the current
# cve-bin-tool SQLite schema contains relationships that are not valid SQL
# Server candidate-key references (notably cve_metrics -> cve_severity(cve_number)).
CVE_DDL = {
    "metrics": """
CREATE TABLE {table} (
    metrics_id INT NOT NULL,
    metrics_name NVARCHAR(128) NULL,
    CONSTRAINT {pk} PRIMARY KEY (metrics_id)
)
""",
    "cve_severity": """
CREATE TABLE {table} (
    cve_number NVARCHAR(128) NOT NULL,
    severity NVARCHAR(64) NULL,
    description NVARCHAR(MAX) NULL,
    score FLOAT NULL,
    cvss_version NVARCHAR(32) NULL,
    cvss_vector NVARCHAR(2048) NULL,
    data_source NVARCHAR(128) NOT NULL,
    last_modified NVARCHAR(128) NULL,
    CONSTRAINT {pk} PRIMARY KEY (cve_number, data_source)
)
""",
    "cve_range": """
CREATE TABLE {table} (
    cve_number NVARCHAR(128) NULL,
    vendor NVARCHAR(128) NULL,
    product NVARCHAR(256) NULL,
    version NVARCHAR(128) NULL,
    versionStartIncluding NVARCHAR(MAX) NULL,
    versionStartExcluding NVARCHAR(MAX) NULL,
    versionEndIncluding NVARCHAR(MAX) NULL,
    versionEndExcluding NVARCHAR(MAX) NULL,
    data_source NVARCHAR(128) NULL
)
""",
    "cve_exploited": """
CREATE TABLE {table} (
    cve_number NVARCHAR(128) NOT NULL,
    product NVARCHAR(MAX) NULL,
    description NVARCHAR(MAX) NULL,
    CONSTRAINT {pk} PRIMARY KEY (cve_number)
)
""",
    "cve_metrics": """
CREATE TABLE {table} (
    row_id BIGINT IDENTITY(1,1) NOT NULL,
    cve_number NVARCHAR(128) NOT NULL,
    metric_id NVARCHAR(32) NOT NULL,
    metric_score NVARCHAR(128) NULL,
    metric_field NVARCHAR(2048) NULL,
    CONSTRAINT {pk} PRIMARY KEY (row_id)
)
""",
    "mismatch": """
CREATE TABLE {table} (
    purl NVARCHAR(2048) NOT NULL,
    vendor NVARCHAR(MAX) NOT NULL
)
""",
    "purl2cpe": """
CREATE TABLE {table} (
    purl NVARCHAR(256) NULL,
    cpe NVARCHAR(MAX) NULL
)
""",
}

# Validated against the September 2026 cve.db snapshot. These limits are
# checked before loading and on every normalized row to prevent truncation.
CVE_INDEX_KEY_LIMITS = {
    "cve_range": {"vendor": 128, "product": 256, "version": 128},
    "purl2cpe": {"purl": 256},
}


def validate_index_key_lengths(table: str, names: Sequence[str], row: Sequence[object]) -> None:
    limits = CVE_INDEX_KEY_LIMITS.get(table, {})
    for name, value in zip(names, row):
        if name in limits and value is not None:
            # SQL Server NVARCHAR(n) counts UTF-16 code units, not code points.
            units = len(str(value).encode("utf-16-le")) // 2
            if units > limits[name]:
                raise ValueError(
                    f"{table}.{name} requires {units} UTF-16 units, "
                    f"exceeding NVARCHAR({limits[name]}). "
                    "Review the source and revise the schema/index before migration."
                )


def preflight_index_key_lengths(sqlite_conn: sqlite3.Connection, tables: set[str]) -> None:
    """Check the source before any target rows are deleted or inserted."""
    for table, limits in CVE_INDEX_KEY_LIMITS.items():
        if table not in tables:
            continue
        cols = list(limits)
        sql = (f"SELECT {', '.join(sqlite_qi(c) for c in cols)} "
               f"FROM {sqlite_qi(table)}")
        for row in sqlite_conn.execute(sql):
            validate_index_key_lengths(table, cols, row)


SQLITE_TYPE_RE = re.compile(r"^\s*([A-Z]+)", re.I)


@dataclass(frozen=True)
class Column:
    name: str
    sqlite_type: str
    not_null: bool
    pk_order: int


def qi(name: str) -> str:
    """Quote a SQL Server identifier."""
    return "[" + name.replace("]", "]]" ) + "]"


def sqlite_qi(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


def safe_constraint_name(prefix: str, schema: str, table: str) -> str:
    raw = f"{prefix}_{schema}_{table}"
    return re.sub(r"[^A-Za-z0-9_]", "_", raw)[:120]


def discover_tables(conn: sqlite3.Connection) -> list[str]:
    rows = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
    ).fetchall()
    return [r[0] for r in rows]


def discover_columns(conn: sqlite3.Connection, table: str) -> list[Column]:
    rows = conn.execute(f"PRAGMA table_info({sqlite_qi(table)})").fetchall()
    return [
        Column(name=r[1], sqlite_type=r[2] or "", not_null=bool(r[3]), pk_order=int(r[5] or 0))
        for r in rows
    ]


def sqlite_type_to_mssql(sqlite_type: str) -> str:
    """Conservative SQLite affinity -> SQL Server type mapping."""
    t = (sqlite_type or "").upper()
    if "INT" in t:
        return "BIGINT"
    if any(x in t for x in ("REAL", "FLOA", "DOUB")):
        return "FLOAT"
    if any(x in t for x in ("NUM", "DEC")):
        return "DECIMAL(38, 10)"
    if "BOOL" in t:
        return "BIT"
    if any(x in t for x in ("DATE", "TIME")):
        return "NVARCHAR(128)"  # SQLite dates can be text/number; preserve exactly.
    if "BLOB" in t or t == "":
        return "VARBINARY(MAX)"
    return "NVARCHAR(MAX)"


def generic_table_ddl(schema: str, table: str, columns: Sequence[Column]) -> str:
    defs = []
    for c in columns:
        nullability = "NOT NULL" if c.not_null or c.pk_order else "NULL"
        defs.append(f"    {qi(c.name)} {sqlite_type_to_mssql(c.sqlite_type)} {nullability}")
    # Generic importer deliberately omits PKs if their inferred SQL Server types
    # are MAX types, which cannot participate in ordinary keys/indexes.
    return f"CREATE TABLE {qi(schema)}.{qi(table)} (\n" + ",\n".join(defs) + "\n)"


def table_exists_sql() -> str:
    return """
SELECT 1
FROM sys.tables t
JOIN sys.schemas s ON s.schema_id = t.schema_id
WHERE s.name = ? AND t.name = ?
"""


def schema_exists_sql() -> str:
    return "SELECT 1 FROM sys.schemas WHERE name = ?"


def ensure_schema(cursor, schema: str) -> None:
    if cursor.execute(schema_exists_sql(), schema).fetchone() is None:
        # Schema name cannot be parameterized as an identifier.
        cursor.execute(f"CREATE SCHEMA {qi(schema)}")


def mssql_table_exists(cursor, schema: str, table: str) -> bool:
    return cursor.execute(table_exists_sql(), schema, table).fetchone() is not None


def create_cve_tables(cursor, schema: str, source_tables: set[str], drop: bool) -> None:
    ensure_schema(cursor, schema)
    for table in reversed(CVE_TABLE_ORDER):
        if table in source_tables and drop and mssql_table_exists(cursor, schema, table):
            cursor.execute(f"DROP TABLE {qi(schema)}.{qi(table)}")
    for table in CVE_TABLE_ORDER:
        if table not in source_tables:
            continue
        if mssql_table_exists(cursor, schema, table):
            continue
        ddl = CVE_DDL[table].format(
            table=f"{qi(schema)}.{qi(table)}",
            pk=qi(safe_constraint_name("PK", schema, table)),
        )
        cursor.execute(ddl)


def ensure_cve_runtime_indexes(cursor, schema: str, tables: set[str]) -> None:
    """Create non-unique indexes needed by the runtime shim after bulk loading."""
    for table_name, idx, keys, included in (
        ("cve_range", "IX_cve_range_vendor_product_version",
         "[vendor], [product], [version]", "[cve_number]"),
        ("purl2cpe", "IX_purl2cpe_purl", "[purl]", "[cpe]"),
    ):
        if table_name in tables:
            table_ref = f"{qi(schema)}.{qi(table_name)}"
            cursor.execute(
                "IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name=? "
                "AND object_id=OBJECT_ID(?)) "
                f"CREATE NONCLUSTERED INDEX {qi(idx)} ON {table_ref} "
                f"({keys}) INCLUDE ({included})",
                idx, f"{qi(schema)}.{qi(table_name)}",
            )
    if "cve_metrics" in tables:
        table = f"{qi(schema)}.[cve_metrics]"
        idx = safe_constraint_name("IX", schema, "cve_metrics_cve_metric")
        cursor.execute(
            f"IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name=N'{idx}' "
            f"AND object_id=OBJECT_ID(N'{schema}.cve_metrics')) "
            f"CREATE INDEX {qi(idx)} ON {table} ([cve_number], [metric_id], [row_id]) "
            "INCLUDE ([metric_score], [metric_field])"
        )


def create_version_map_tables(cursor, schema: str, source_tables: set[str], drop: bool) -> None:
    ensure_schema(cursor, schema)
    order = ["latest_update_sqlite", "sqlite"]
    for table in reversed(order):
        if table in source_tables and drop and mssql_table_exists(cursor, schema, table):
            cursor.execute(f"DROP TABLE {qi(schema)}.{qi(table)}")
    if "latest_update_sqlite" in source_tables and not mssql_table_exists(cursor, schema, "latest_update_sqlite"):
        cursor.execute(
            f"CREATE TABLE {qi(schema)}.[latest_update_sqlite] ([datestamp] DATETIME2 NULL)"
        )
    if "sqlite" in source_tables and not mssql_table_exists(cursor, schema, "sqlite"):
        cursor.execute(
            f"CREATE TABLE {qi(schema)}.[sqlite] ("
            "[version] NVARCHAR(255) NULL, "
            "[sourceId] NVARCHAR(2048) NOT NULL, "
            f"CONSTRAINT {qi(safe_constraint_name('PK', schema, 'sqlite'))} PRIMARY KEY ([sourceId]))"
        )


def create_generic_tables(
    cursor, schema: str, sqlite_conn: sqlite3.Connection, tables: Sequence[str], drop: bool
) -> None:
    ensure_schema(cursor, schema)
    for table in reversed(tables):
        if drop and mssql_table_exists(cursor, schema, table):
            cursor.execute(f"DROP TABLE {qi(schema)}.{qi(table)}")
    for table in tables:
        if mssql_table_exists(cursor, schema, table):
            continue
        columns = discover_columns(sqlite_conn, table)
        cursor.execute(generic_table_ddl(schema, table, columns))


def chunks(cursor: sqlite3.Cursor, batch_size: int) -> Iterator[list[tuple]]:
    while True:
        rows = cursor.fetchmany(batch_size)
        if not rows:
            return
        yield rows


def normalize_value(value):
    # pyodbc accepts bytes, strings, ints, floats, None and datetime values.
    if isinstance(value, memoryview):
        return bytes(value)
    return value


def _number_or_none(value):
    if value is None or value == "":
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def normalize_row(table: str, names: Sequence[str], row: Sequence[object]) -> tuple:
    values = [normalize_value(v) for v in row]

    # cve_metrics is intentionally heterogeneous in the upstream SQLite DB.
    # Real source data contains millions of rows where metric_id, metric_score
    # and metric_field are the literal text sentinel "unknown", while normal
    # rows contain numeric metric IDs/scores. Preserve those SQLite values
    # losslessly as text in SQL Server; the runtime shim restores SQLite-like
    # Python numeric values for numeric strings when rows are fetched.
    if table == "cve_metrics":
        for i, name in enumerate(names):
            if name.lower() in {"metric_id", "metric_score", "metric_field"}:
                value = values[i]
                values[i] = None if value is None else str(value)

    # Other numeric columns have stable numeric semantics.
    numeric_float_columns = {("cve_severity", "score")}
    numeric_int_columns = {("metrics", "metrics_id")}
    for i, name in enumerate(names):
        if (table, name.lower()) in numeric_float_columns:
            values[i] = _number_or_none(values[i])
        if (table, name.lower()) in numeric_int_columns:
            value = values[i]
            if value is None or value == "":
                values[i] = None
            else:
                try:
                    number = float(value)
                    if not number.is_integer():
                        raise ValueError(f"non-integral value {value!r}")
                    values[i] = int(number)
                except (TypeError, ValueError) as exc:
                    raise ValueError(
                        f"Cannot convert {table}.{name}={value!r} to SQL Server INT"
                    ) from exc
        if table.startswith("latest_update_") and name.lower() == "datestamp":
            value = values[i]
            if isinstance(value, (int, float)):
                values[i] = datetime.fromtimestamp(value)
    return tuple(values)


def migrate_table(
    sqlite_conn: sqlite3.Connection,
    mssql_conn,
    schema: str,
    table: str,
    batch_size: int,
    replace_data: bool,
    fast_executemany: bool = False,
) -> tuple[int, float]:
    columns = discover_columns(sqlite_conn, table)
    if not columns:
        raise RuntimeError(f"No columns discovered for SQLite table {table!r}")

    names = [c.name for c in columns]
    source_sql = f"SELECT {', '.join(sqlite_qi(n) for n in names)} FROM {sqlite_qi(table)}"
    target = f"{qi(schema)}.{qi(table)}"
    placeholders = ",".join("?" for _ in names)
    insert_sql = (
        f"INSERT INTO {target} ({', '.join(qi(n) for n in names)}) "
        f"VALUES ({placeholders})"
    )

    target_cursor = mssql_conn.cursor()
    if replace_data:
        target_cursor.execute(f"DELETE FROM {target}")
        mssql_conn.commit()

    source_cursor = sqlite_conn.execute(source_sql)
    # pyodbc fast_executemany can infer an unsuitable parameter type from an
    # early row (especially when SQLite columns contain mixed Python types).
    # Keep the safe row-binding path as the default; it is opt-in via CLI.
    with contextlib.suppress(Exception):
        target_cursor.fast_executemany = fast_executemany

    count = 0
    started = time.monotonic()
    for batch in chunks(source_cursor, batch_size):
        converted = [normalize_row(table, names, row) for row in batch]
        for values in converted:
            validate_index_key_lengths(table, names, values)
        try:
            target_cursor.executemany(insert_sql, converted)
            mssql_conn.commit()
        except Exception as exc:
            mssql_conn.rollback()
            # Re-run one row at a time only to identify the exact offending
            # source row/column. Roll back all diagnostic inserts afterwards.
            for offset, values in enumerate(converted):
                try:
                    target_cursor.execute(insert_sql, values)
                except Exception as row_exc:
                    mssql_conn.rollback()
                    details = ", ".join(
                        f"{name}={value!r}<{type(value).__name__}>"
                        for name, value in zip(names, values)
                    )
                    source_row = count + offset + 1
                    raise RuntimeError(
                        f"SQL Server insert failed for table {table!r}, "
                        f"source row {source_row}: {details}"
                    ) from row_exc
            mssql_conn.rollback()
            raise RuntimeError(
                f"Batch insert failed for table {table!r}, but every row "
                "succeeded individually. Re-run without --fast-executemany; "
                "this indicates an ODBC array-binding/type-inference issue."
            ) from exc
        count += len(converted)
        print(f"  {table}: {count:,} rows", file=sys.stderr, flush=True)
    return count, time.monotonic() - started


def sqlite_count(conn: sqlite3.Connection, table: str) -> int:
    return int(conn.execute(f"SELECT COUNT(*) FROM {sqlite_qi(table)}").fetchone()[0])


def mssql_count(conn, schema: str, table: str) -> int:
    cur = conn.cursor()
    return int(cur.execute(f"SELECT COUNT_BIG(*) FROM {qi(schema)}.{qi(table)}").fetchone()[0])


def validate_cve_source(tables: set[str]) -> None:
    missing_core = {"cve_severity", "cve_range"} - tables
    if missing_core:
        raise RuntimeError(
            "Source does not look like cve-bin-tool cve.db; missing: "
            + ", ".join(sorted(missing_core))
        )


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Migrate cve-bin-tool SQLite databases to Microsoft SQL Server"
    )
    p.add_argument("--source", required=True, type=Path, help="SQLite source file")
    p.add_argument("--kind", required=True, choices=("cve", "version-map", "generic"))
    p.add_argument(
        "--connection-string",
        help="pyodbc SQL Server connection string; not needed with --dry-run",
    )
    p.add_argument("--schema", default="dbo", help="Target SQL Server schema (default: dbo)")
    p.add_argument("--batch-size", type=int, default=5000)
    p.add_argument("--create-tables", action="store_true")
    p.add_argument("--drop-tables", action="store_true")
    p.add_argument("--replace-data", action="store_true")
    p.add_argument("--verify", action="store_true")
    p.add_argument(
        "--fast-executemany",
        action="store_true",
        help="Enable pyodbc array binding for all tables. cve_metrics uses it automatically.",
    )
    p.add_argument(
        "--safe-executemany",
        action="store_true",
        help="Disable pyodbc fast_executemany everywhere (diagnostic fallback; much slower).",
    )
    p.add_argument("--dry-run", action="store_true")
    p.add_argument(
        "--tables",
        help="Comma-separated subset of source tables to migrate (default: all applicable)",
    )
    p.add_argument(
        "--version",
        action="version",
        version=f"sqlite-to-mssql-cve-bin-tool {__version__}",
    )
    return p.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    if args.batch_size <= 0:
        raise SystemExit("--batch-size must be > 0")
    if args.drop_tables and not args.create_tables:
        raise SystemExit("--drop-tables requires --create-tables")
    if not args.source.is_file():
        raise SystemExit(f"SQLite source does not exist: {args.source}")

    sqlite_conn = sqlite3.connect(f"file:{args.source}?mode=ro", uri=True)
    try:
        all_tables = discover_tables(sqlite_conn)
        if args.tables:
            requested = [t.strip() for t in args.tables.split(",") if t.strip()]
            unknown = set(requested) - set(all_tables)
            if unknown:
                raise SystemExit(f"Unknown SQLite table(s): {', '.join(sorted(unknown))}")
            tables = requested
        elif args.kind == "cve":
            validate_cve_source(set(all_tables))
            tables = [t for t in CVE_TABLE_ORDER if t in all_tables]
        elif args.kind == "version-map":
            expected = ["latest_update_sqlite", "sqlite"]
            tables = [t for t in expected if t in all_tables]
            if not tables:
                raise RuntimeError("Source does not look like version_map.db")
        else:
            tables = all_tables

        print(f"Source: {args.source}")
        print(f"Kind:   {args.kind}")
        print("Tables:")
        for table in tables:
            cols = discover_columns(sqlite_conn, table)
            print(
                f"  {table}: {sqlite_count(sqlite_conn, table):,} rows; "
                + ", ".join(f"{c.name} {c.sqlite_type or '(untyped)'}" for c in cols)
            )

        if args.kind == "cve":
            print("Validating bounded index-key lengths against SQLite source...")
            preflight_index_key_lengths(sqlite_conn, set(tables))

        if args.dry_run:
            print("Dry run only; SQL Server was not modified.")
            return 0
        if not args.connection_string:
            raise SystemExit("--connection-string is required unless --dry-run is used")
        if pyodbc is None:
            raise SystemExit("pyodbc is not installed; run: python -m pip install pyodbc")

        mssql_conn = pyodbc.connect(args.connection_string, autocommit=False)
        try:
            if args.create_tables:
                cur = mssql_conn.cursor()
                if args.kind == "cve":
                    create_cve_tables(cur, args.schema, set(tables), args.drop_tables)
                elif args.kind == "version-map":
                    create_version_map_tables(cur, args.schema, set(tables), args.drop_tables)
                else:
                    create_generic_tables(cur, args.schema, sqlite_conn, tables, args.drop_tables)
                mssql_conn.commit()

            print("Migrating:")
            for table in tables:
                if not mssql_table_exists(mssql_conn.cursor(), args.schema, table):
                    raise RuntimeError(
                        f"Target table {args.schema}.{table} does not exist; use --create-tables"
                    )
                count, seconds = migrate_table(
                    sqlite_conn,
                    mssql_conn,
                    args.schema,
                    table,
                    args.batch_size,
                    args.replace_data,
                    fast_executemany=(
                        False if args.safe_executemany else
                        (args.fast_executemany or (args.kind == "cve" and table == "cve_metrics"))
                    ),
                )
                rate = count / seconds if seconds else float("inf")
                print(f"  {table}: loaded {count:,} rows in {seconds:.1f}s ({rate:,.0f} rows/s)")

            if args.kind == "cve":
                print("Creating runtime indexes:")
                ensure_cve_runtime_indexes(mssql_conn.cursor(), args.schema, set(tables))
                mssql_conn.commit()
                print("  runtime indexes: OK")

            if args.verify:
                print("Verification:")
                failures = []
                for table in tables:
                    src = sqlite_count(sqlite_conn, table)
                    dst = mssql_count(mssql_conn, args.schema, table)
                    ok = src == dst
                    print(f"  {table}: SQLite={src:,}, SQL Server={dst:,} -> {'OK' if ok else 'MISMATCH'}")
                    if not ok:
                        failures.append(table)

                # cve_metrics has SQLite mixed-type sentinel rows. Verify that
                # the three literal "unknown" values survived migration intact.
                if args.kind == "cve" and "cve_metrics" in tables:
                    src_unknown = int(sqlite_conn.execute(
                        "SELECT COUNT(*) FROM cve_metrics "
                        "WHERE metric_id='unknown' AND metric_score='unknown' AND metric_field='unknown'"
                    ).fetchone()[0])
                    dst_unknown = int(mssql_conn.cursor().execute(
                        f"SELECT COUNT_BIG(*) FROM {qi(args.schema)}.[cve_metrics] "
                        "WHERE metric_id=N'unknown' AND metric_score=N'unknown' AND metric_field=N'unknown'"
                    ).fetchone()[0])
                    sentinel_ok = src_unknown == dst_unknown
                    print(
                        f"  cve_metrics unknown sentinel: SQLite={src_unknown:,}, "
                        f"SQL Server={dst_unknown:,} -> {'OK' if sentinel_ok else 'MISMATCH'}"
                    )
                    if not sentinel_ok:
                        failures.append("cve_metrics:unknown-sentinel")
                if failures:
                    print("Verification failed for: " + ", ".join(failures), file=sys.stderr)
                    return 2
        finally:
            mssql_conn.close()
    finally:
        sqlite_conn.close()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
