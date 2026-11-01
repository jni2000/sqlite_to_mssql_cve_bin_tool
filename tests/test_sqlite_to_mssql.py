import importlib.util
import sqlite3
import sys
from pathlib import Path

MODULE = Path(__file__).parents[1] / "sqlite_to_mssql.py"
spec = importlib.util.spec_from_file_location("migrator", MODULE)
m = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = m
spec.loader.exec_module(m)


def test_type_mapping():
    assert m.sqlite_type_to_mssql("INTEGER") == "BIGINT"
    assert m.sqlite_type_to_mssql("REAL") == "FLOAT"
    assert m.sqlite_type_to_mssql("TEXT") == "NVARCHAR(MAX)"
    assert m.sqlite_type_to_mssql("BLOB") == "VARBINARY(MAX)"


def test_discover(tmp_path):
    db = tmp_path / "x.db"
    c = sqlite3.connect(db)
    c.execute("CREATE TABLE purl2cpe (purl TEXT, cpe TEXT)")
    c.executemany("INSERT INTO purl2cpe VALUES (?,?)", [("pkg:a", "cpe:a"), ("pkg:b", "cpe:b")])
    c.commit()
    assert m.discover_tables(c) == ["purl2cpe"]
    cols = m.discover_columns(c, "purl2cpe")
    assert [x.name for x in cols] == ["purl", "cpe"]
    assert m.sqlite_count(c, "purl2cpe") == 2
    c.close()


def test_cve_validation():
    m.validate_cve_source({"cve_severity", "cve_range"})


def test_generic_ddl():
    cols = [m.Column("purl", "TEXT", False, 0), m.Column("cpe", "TEXT", False, 0)]
    ddl = m.generic_table_ddl("dbo", "purl2cpe", cols)
    assert "CREATE TABLE [dbo].[purl2cpe]" in ddl
    assert "[purl] NVARCHAR(MAX)" in ddl


def test_unknown_score_becomes_null():
    row = m.normalize_row("cve_severity", ["cve_number", "score"], ["CVE-1", "unknown"])
    assert row == ("CVE-1", None)
    row2 = m.normalize_row("cve_severity", ["cve_number", "score"], ["CVE-2", "7.5"])
    assert row2 == ("CVE-2", 7.5)


def test_version_map_epoch_normalization():
    names = ["datestamp"]
    row = m.normalize_row("latest_update_sqlite", names, (1700000000.0,))
    from datetime import datetime
    assert isinstance(row[0], datetime)


def test_version_map_kind_is_accepted(tmp_path):
    db = tmp_path / "version_map.db"
    conn = sqlite3.connect(db)
    conn.execute("CREATE TABLE latest_update_sqlite(datestamp DATETIME)")
    conn.execute("CREATE TABLE sqlite(version TEXT, sourceId TEXT PRIMARY KEY)")
    conn.execute("INSERT INTO latest_update_sqlite VALUES (?)", (1700000000.0,))
    conn.execute("INSERT INTO sqlite VALUES (?, ?)", ("3.0", "src"))
    conn.commit(); conn.close()
    assert m.main(["--source", str(db), "--kind", "version-map", "--dry-run"]) == 0


def test_normalize_cve_metrics_numeric_strings():
    row = m.normalize_row(
        "cve_metrics",
        ["cve_number", "metric_id", "metric_score", "metric_field"],
        ("CVE-1", "3", "9.8", "CVSS:3.1/test"),
    )
    assert row == ("CVE-1", "3", "9.8", "CVSS:3.1/test")


def test_normalize_cve_metrics_unknown_score_to_null():
    row = m.normalize_row(
        "cve_metrics",
        ["cve_number", "metric_id", "metric_score", "metric_field"],
        ("CVE-1", 0, "unknown", "unknown"),
    )
    assert row == ("CVE-1", "0", "unknown", "unknown")


def test_cve_lookup_schema_is_bounded():
    assert "vendor NVARCHAR(128) NULL" in m.CVE_DDL["cve_range"]
    assert "product NVARCHAR(256) NULL" in m.CVE_DDL["cve_range"]
    assert "version NVARCHAR(128) NULL" in m.CVE_DDL["cve_range"]
    assert "purl NVARCHAR(256) NULL" in m.CVE_DDL["purl2cpe"]
    assert "cpe NVARCHAR(MAX) NULL" in m.CVE_DDL["purl2cpe"]


def test_index_key_length_validation():
    m.validate_index_key_lengths("cve_range", ["vendor", "product", "version"],
                                 ["v" * 128, "p" * 256, "1" * 128])
    m.validate_index_key_lengths("purl2cpe", ["purl"], ["p" * 256])
    import pytest
    with pytest.raises(ValueError, match="purl2cpe.purl"):
        m.validate_index_key_lengths("purl2cpe", ["purl"], ["p" * 257])
    with pytest.raises(ValueError, match="cve_range.vendor"):
        m.validate_index_key_lengths("cve_range", ["vendor"], ["😀" * 65])


def test_preflight_rejects_oversize_source():
    import pytest
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE purl2cpe(purl TEXT, cpe TEXT)")
    conn.execute("INSERT INTO purl2cpe VALUES (?, ?)", ("x" * 257, "cpe"))
    with pytest.raises(ValueError, match="purl2cpe.purl"):
        m.preflight_index_key_lengths(conn, {"purl2cpe"})
    conn.close()


class RecordingCursor:
    def __init__(self):
        self.statements = []
    def execute(self, sql, *args):
        self.statements.append((sql, args))
        return self


def test_runtime_indexes_include_both_lookup_indexes():
    cursor = RecordingCursor()
    m.ensure_cve_runtime_indexes(cursor, "dbo", {"cve_range", "purl2cpe", "cve_metrics"})
    combined = "\n".join(sql for sql, _ in cursor.statements)
    assert "IX_cve_range_vendor_product_version" in combined
    assert "([vendor], [product], [version]) INCLUDE ([cve_number])" in combined
    assert "IX_purl2cpe_purl" in combined
    assert "([purl]) INCLUDE ([cpe])" in combined
    assert "[cve_number], [metric_id], [row_id]" in combined
