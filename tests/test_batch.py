from core.batch import batch_summary_rows, parse_ip_file, parse_ip_text
from core.investigator import investigate_ip


def test_parse_ip_text_deduplicates_and_reports_invalid():
    valid, invalid = parse_ip_text("8.8.8.8\n8.8.8.8\n2001:4860:4860::8888\nnot-an-ip")
    assert valid == ["8.8.8.8", "2001:4860:4860::8888"]
    assert invalid == ["not-an-ip"]


def test_parse_csv_ip_column():
    content = b"ip,label\n1.1.1.1,a\n8.8.8.8,b\n"
    valid, invalid = parse_ip_file(content, "targets.csv")
    assert valid == ["1.1.1.1", "8.8.8.8"]
    assert invalid == []


def test_batch_summary_offline():
    bundles = [investigate_ip("10.0.0.1", enabled_sources=set())]
    rows = batch_summary_rows(bundles)
    assert rows[0]["IP"] == "10.0.0.1"
    assert rows[0]["Uso especial"] == "IPv4 privado"
