from core.investigator import investigate_ip
from core.pdf_report import build_case_pdf, build_single_pdf


def test_single_pdf_is_valid_pdf_bytes():
    bundle = investigate_ip("10.1.2.3", enabled_sources=set())
    pdf = build_single_pdf(bundle)
    assert pdf.startswith(b"%PDF")
    assert len(pdf) > 1000


def test_case_pdf_is_valid_pdf_bytes():
    bundle = investigate_ip("2001:db8::1", enabled_sources=set())
    case = {
        "name": "Caso teste",
        "description": "Teste de relatório consolidado",
        "status": "Aberto",
        "created_at_utc": "2026-10-27T10:00:00+00:00",
        "updated_at_utc": "2026-10-27T10:00:00+00:00",
    }
    pdf = build_case_pdf(case, [bundle])
    assert pdf.startswith(b"%PDF")
    assert len(pdf) > 1000
