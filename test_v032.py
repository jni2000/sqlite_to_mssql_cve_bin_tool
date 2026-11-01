import importlib.util
from pathlib import Path
p=Path(__file__).with_name('sqlite_to_mssql.py')
spec=importlib.util.spec_from_file_location('m',p); m=importlib.util.module_from_spec(spec); import sys; sys.modules['m']=m; spec.loader.exec_module(m)

def test_unknown_preserved():
    names=['cve_number','metric_id','metric_score','metric_field']
    assert m.normalize_row('cve_metrics', names, ('CVE-X','unknown','unknown','unknown')) == ('CVE-X','unknown','unknown','unknown')

def test_numeric_metrics_normalized_to_text():
    names=['cve_number','metric_id','metric_score','metric_field']
    assert m.normalize_row('cve_metrics', names, ('CVE-X',2,9.8,'baseScore')) == ('CVE-X','2','9.8','baseScore')

def test_cve_metrics_ddl_is_mixed_type_safe():
    ddl=m.CVE_DDL['cve_metrics']
    assert 'metric_id NVARCHAR(32)' in ddl
    assert 'metric_score NVARCHAR(128)' in ddl


def test_cve_metrics_ddl_preserves_duplicates():
    ddl=m.CVE_DDL['cve_metrics']
    assert 'row_id BIGINT IDENTITY(1,1)' in ddl
    assert 'PRIMARY KEY (row_id)' in ddl
    assert 'PRIMARY KEY (cve_number, metric_id)' not in ddl
