from __future__ import annotations

import html
from io import BytesIO
from typing import Any, Iterable

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    BaseDocTemplate,
    Frame,
    KeepTogether,
    PageTemplate,
    Paragraph,
    PageBreak,
    Spacer,
    Table,
    TableStyle,
)


PAGE_W, PAGE_H = A4


def _clean(value: Any) -> str:
    if value is None or value == "":
        return "-"
    if isinstance(value, bool):
        return "Sim" if value else "Não"
    if isinstance(value, (list, tuple, set)):
        value = ", ".join(str(x) for x in value) if value else "-"
    text = str(value)
    replacements = {
        "—": "-",
        "–": "-",
        "“": '"',
        "”": '"',
        "’": "'",
        "•": "-",
        "→": "->",
        "✓": "Sim",
        "✗": "Não",
    }
    for src, dst in replacements.items():
        text = text.replace(src, dst)
    return text.encode("cp1252", errors="replace").decode("cp1252")


def _p(value: Any, style: ParagraphStyle) -> Paragraph:
    safe = html.escape(_clean(value)).replace("\n", "<br/>")
    return Paragraph(safe, style)


def _styles() -> dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle(
            "IPTitle",
            parent=base["Title"],
            fontName="Helvetica-Bold",
            fontSize=20,
            leading=24,
            textColor=colors.HexColor("#1f2933"),
            alignment=TA_LEFT,
            spaceAfter=10,
        ),
        "subtitle": ParagraphStyle(
            "IPSubtitle",
            parent=base["Normal"],
            fontName="Helvetica",
            fontSize=9.5,
            leading=13,
            textColor=colors.HexColor("#52606d"),
            spaceAfter=12,
        ),
        "h1": ParagraphStyle(
            "IPH1",
            parent=base["Heading2"],
            fontName="Helvetica-Bold",
            fontSize=13,
            leading=16,
            textColor=colors.HexColor("#243b53"),
            spaceBefore=9,
            spaceAfter=7,
        ),
        "h2": ParagraphStyle(
            "IPH2",
            parent=base["Heading3"],
            fontName="Helvetica-Bold",
            fontSize=10.5,
            leading=13,
            textColor=colors.HexColor("#334e68"),
            spaceBefore=6,
            spaceAfter=5,
        ),
        "body": ParagraphStyle(
            "IPBody",
            parent=base["BodyText"],
            fontName="Helvetica",
            fontSize=9.2,
            leading=13,
            textColor=colors.HexColor("#263238"),
            spaceAfter=5,
        ),
        "small": ParagraphStyle(
            "IPSmall",
            parent=base["BodyText"],
            fontName="Helvetica",
            fontSize=7.8,
            leading=10.5,
            textColor=colors.HexColor("#52606d"),
            wordWrap="CJK",
        ),
        "table": ParagraphStyle(
            "IPTable",
            parent=base["BodyText"],
            fontName="Helvetica",
            fontSize=8,
            leading=10,
            textColor=colors.HexColor("#263238"),
            wordWrap="CJK",
        ),
        "center": ParagraphStyle(
            "IPCenter",
            parent=base["BodyText"],
            fontName="Helvetica-Bold",
            fontSize=8.5,
            leading=10.5,
            alignment=TA_CENTER,
        ),
    }


def _page_header_footer(canvas, doc) -> None:
    canvas.saveState()
    canvas.setStrokeColor(colors.HexColor("#d9e2ec"))
    canvas.setLineWidth(0.5)
    canvas.line(18 * mm, 13 * mm, PAGE_W - 18 * mm, 13 * mm)
    canvas.setFont("Helvetica", 7.5)
    canvas.setFillColor(colors.HexColor("#627d98"))
    canvas.drawString(18 * mm, 8.5 * mm, "IP Investigator - relatório local de apoio investigativo")
    canvas.drawRightString(PAGE_W - 18 * mm, 8.5 * mm, f"Página {doc.page}")
    canvas.restoreState()


def _doc(buffer: BytesIO) -> BaseDocTemplate:
    doc = BaseDocTemplate(
        buffer,
        pagesize=A4,
        leftMargin=18 * mm,
        rightMargin=18 * mm,
        topMargin=18 * mm,
        bottomMargin=18 * mm,
        title="IP Investigator",
        author="IP Investigator",
    )
    frame = Frame(doc.leftMargin, doc.bottomMargin, doc.width, doc.height, id="normal")
    doc.addPageTemplates([PageTemplate(id="main", frames=[frame], onPage=_page_header_footer)])
    return doc


def _kv_table(rows: list[tuple[Any, Any]], styles: dict[str, ParagraphStyle]) -> Table:
    data = [[_p(label, styles["table"]), _p(value, styles["table"])] for label, value in rows]
    table = Table(data, colWidths=[48 * mm, 112 * mm], repeatRows=0, hAlign="LEFT")
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f0f4f8")),
                ("TEXTCOLOR", (0, 0), (-1, -1), colors.HexColor("#263238")),
                ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("LEFTPADDING", (0, 0), (-1, -1), 7),
                ("RIGHTPADDING", (0, 0), (-1, -1), 7),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#d9e2ec")),
            ]
        )
    )
    return table


def _bundle_story(bundle: dict[str, Any], styles: dict[str, ParagraphStyle], *, include_title: bool = True) -> list[Any]:
    q = bundle.get("query") or {}
    local = bundle.get("local") or {}
    facts = bundle.get("facts") or {}
    conclusion = bundle.get("conclusion") or {}
    network = facts.get("network") or {}
    rdap = facts.get("rdap") or {}
    incident = q.get("incident") or {}

    story: list[Any] = []
    if include_title:
        story.append(_p(f"Análise do IP {q.get('ip', '')}", styles["h1"]))

    asns = [f"AS{str(x).replace('AS', '')}" for x in (network.get("asns") or [])]
    holders = [x.get("holder") for x in (facts.get("asn_overviews") or []) if isinstance(x, dict) and x.get("holder")]
    rows = [
        ("Endereço", q.get("ip")),
        ("Versão", f"IPv{local.get('version')}" if local.get("version") else None),
        ("Globalmente roteável", local.get("is_global")),
        ("Uso especial", local.get("special_use") or "Não identificado"),
        ("Prefixo BGP", network.get("prefix")),
        ("ASN(s)", ", ".join(asns)),
        ("Organização/holder", "; ".join(holders) or rdap.get("name")),
        ("Papel provável", conclusion.get("network_role")),
        ("Confiança do papel", conclusion.get("network_role_confidence")),
    ]
    if incident.get("enabled"):
        rows.extend(
            [
                ("Data/hora informada", f"{incident.get('local_date')} {incident.get('local_time')} ({incident.get('timezone')})"),
                ("Instante UTC", incident.get("utc")),
                ("Porta de origem", incident.get("source_port")),
                ("Protocolo", incident.get("protocol")),
            ]
        )
    story.append(_kv_table(rows, styles))
    story.append(Spacer(1, 7))

    story.append(_p("Conclusão investigativa", styles["h2"]))
    story.append(_p(conclusion.get("headline") or "Sem conclusão gerada.", styles["body"]))
    for paragraph in conclusion.get("paragraphs") or []:
        story.append(_p(paragraph, styles["body"]))

    limitations = conclusion.get("limitations") or []
    if limitations:
        story.append(_p("Limitações", styles["h2"]))
        for item in limitations:
            story.append(_p(f"- {item}", styles["body"]))

    next_steps = conclusion.get("next_steps") or []
    if next_steps:
        story.append(_p("Providências e checagens sugeridas", styles["h2"]))
        for item in next_steps:
            story.append(_p(f"- {item}", styles["body"]))

    scorecard = conclusion.get("scorecard") or {}
    if scorecard:
        story.append(_p("Valor investigativo", styles["h2"]))
        story.append(_kv_table(list(scorecard.items()), styles))
        story.append(Spacer(1, 7))

    sources = bundle.get("sources") or []
    story.append(_p("Referências e proveniência", styles["h2"]))
    story.append(_p(bundle.get("source_disclosure_notice") or "", styles["small"]))
    if not sources:
        story.append(_p("Nenhuma fonte externa foi consultada.", styles["small"]))
    else:
        source_data = [[
            _p("Fonte", styles["center"]),
            _p("Estado", styles["center"]),
            _p("Consulta / documentação", styles["center"]),
            _p("UTC / SHA-256", styles["center"]),
        ]]
        for src in sources:
            status = "OK" if src.get("ok") else f"Falha: {src.get('error') or 'indisponível'}"
            urls = _clean(src.get("url"))
            if src.get("documentation_url"):
                urls += "\nDoc: " + _clean(src.get("documentation_url"))
            provenance = _clean(src.get("retrieved_at_utc"))
            if src.get("sha256"):
                provenance += "\n" + _clean(src.get("sha256"))
            source_data.append([
                _p(src.get("name"), styles["small"]),
                _p(status, styles["small"]),
                _p(urls, styles["small"]),
                _p(provenance, styles["small"]),
            ])
        table = Table(source_data, colWidths=[34 * mm, 25 * mm, 65 * mm, 36 * mm], repeatRows=1, hAlign="LEFT")
        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#d9e2ec")),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                    ("LEFTPADDING", (0, 0), (-1, -1), 4),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                    ("TOPPADDING", (0, 0), (-1, -1), 4),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                    ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#cbd5e1")),
                ]
            )
        )
        story.append(table)
    return story


def build_single_pdf(bundle: dict[str, Any]) -> bytes:
    styles = _styles()
    buffer = BytesIO()
    doc = _doc(buffer)
    q = bundle.get("query") or {}
    story: list[Any] = [
        _p("IP Investigator", styles["title"]),
        _p(f"Relatório técnico-investigativo - {q.get('ip', '')}", styles["subtitle"]),
        _p(
            "Ferramenta de apoio investigativo. Resultados de APIs e bases OSINT devem ser confirmados nas fontes originais e correlacionados com outros elementos probatórios.",
            styles["body"],
        ),
        Spacer(1, 4),
    ]
    story.extend(_bundle_story(bundle, styles, include_title=False))
    doc.build(story)
    return buffer.getvalue()


def build_case_pdf(case: dict[str, Any], bundles: Iterable[dict[str, Any]]) -> bytes:
    bundle_list = [b for b in bundles if isinstance(b, dict)]
    styles = _styles()
    buffer = BytesIO()
    doc = _doc(buffer)
    story: list[Any] = [
        _p("IP Investigator", styles["title"]),
        _p(f"Relatório do caso: {case.get('name', '')}", styles["subtitle"]),
        _kv_table(
            [
                ("Caso", case.get("name")),
                ("Descrição", case.get("description")),
                ("Status", case.get("status")),
                ("Criado em UTC", case.get("created_at_utc")),
                ("Atualizado em UTC", case.get("updated_at_utc")),
                ("Análises incluídas", len(bundle_list)),
            ],
            styles,
        ),
        Spacer(1, 9),
        _p(
            "Este relatório consolida análises armazenadas localmente no caso. O grafo interativo de relações permanece disponível no aplicativo e não é convertido automaticamente em imagem no PDF.",
            styles["body"],
        ),
    ]

    if bundle_list:
        summary_data = [[
            _p("IP", styles["center"]),
            _p("Prefixo", styles["center"]),
            _p("ASN", styles["center"]),
            _p("Papel provável", styles["center"]),
        ]]
        for bundle in bundle_list:
            q = bundle.get("query") or {}
            facts = bundle.get("facts") or {}
            network = facts.get("network") or {}
            conclusion = bundle.get("conclusion") or {}
            asns = ", ".join(f"AS{str(x).replace('AS', '')}" for x in (network.get("asns") or []))
            summary_data.append([
                _p(q.get("ip"), styles["table"]),
                _p(network.get("prefix"), styles["table"]),
                _p(asns, styles["table"]),
                _p(conclusion.get("network_role"), styles["table"]),
            ])
        table = Table(summary_data, colWidths=[40 * mm, 46 * mm, 32 * mm, 42 * mm], repeatRows=1)
        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#d9e2ec")),
                    ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#cbd5e1")),
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                    ("LEFTPADDING", (0, 0), (-1, -1), 5),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                    ("TOPPADDING", (0, 0), (-1, -1), 5),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ]
            )
        )
        story.extend([_p("Resumo das análises", styles["h1"]), table])

    for idx, bundle in enumerate(bundle_list, start=1):
        story.append(PageBreak())
        story.append(_p(f"Análise {idx} de {len(bundle_list)}", styles["subtitle"]))
        story.extend(_bundle_story(bundle, styles, include_title=True))

    doc.build(story)
    return buffer.getvalue()
