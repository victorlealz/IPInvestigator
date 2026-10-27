from datetime import date, time

from core.investigator import investigate_ip
from core.report import build_markdown_report


def test_offline_private_analysis_has_conclusion_and_no_sources():
    bundle = investigate_ip(
        "10.1.2.3",
        response_mode="Investigativo",
        incident={"enabled": True, "date": date(2026, 1, 2), "time": time(12, 30), "timezone": "America/Fortaleza"},
        enabled_sources=set(),
    )
    assert bundle["sources"] == []
    assert bundle["conclusion"]["headline"]
    assert bundle["query"]["incident"]["utc"].endswith("+00:00")


def test_markdown_contains_sources_section():
    bundle = investigate_ip("100.64.10.1", enabled_sources=set())
    report = build_markdown_report(bundle)
    assert "Conclusão investigativa" in report
    assert "Fontes e proveniência" in report
    assert "CGNAT" in report
