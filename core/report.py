from __future__ import annotations

from typing import Any


def _fmt(value: Any) -> str:
    if value is None or value == "":
        return "—"
    if isinstance(value, bool):
        return "Sim" if value else "Não"
    if isinstance(value, (list, tuple, set)):
        return ", ".join(str(x) for x in value) if value else "—"
    return str(value)


def build_markdown_report(bundle: dict[str, Any]) -> str:
    q = bundle.get("query", {})
    local = bundle.get("local", {})
    facts = bundle.get("facts", {})
    conclusion = bundle.get("conclusion", {})
    incident = q.get("incident", {})

    lines: list[str] = []
    lines.append(f"# Relatório de análise de IP — {q.get('ip', '')}")
    lines.append("")
    lines.append(f"Gerado em UTC: `{bundle.get('generated_at_utc', '')}`")
    lines.append("")
    lines.append("> Ferramenta de apoio investigativo. Os resultados devem ser confirmados nas fontes originais e correlacionados com outros elementos probatórios.")
    lines.append("")

    lines.append("## 1. Consulta")
    lines.append("")
    lines.append(f"- IP: `{q.get('ip', '')}`")
    lines.append(f"- Modo: {_fmt(q.get('response_mode'))}")
    if incident.get("enabled"):
        lines.append(f"- Data/hora informada: {incident.get('local_date')} {incident.get('local_time')} ({incident.get('timezone')})")
        lines.append(f"- Instante normalizado em UTC: `{incident.get('utc')}`")
    if incident.get("source_port"):
        lines.append(f"- Porta lógica de origem: `{incident.get('source_port')}`")
    if incident.get("protocol"):
        lines.append(f"- Protocolo: `{incident.get('protocol')}`")
    lines.append("")

    lines.append("## 2. Estrutura e classificação local")
    lines.append("")
    fields = [
        ("Versão", f"IPv{local.get('version')}") ,
        ("Forma comprimida", local.get("compressed")),
        ("Forma expandida", local.get("exploded")),
        ("Globalmente roteável", local.get("is_global")),
        ("Privado", local.get("is_private")),
        ("Loopback", local.get("is_loopback")),
        ("Link-local", local.get("is_link_local")),
        ("Multicast", local.get("is_multicast")),
        ("Uso especial", local.get("special_use")),
        ("Faixa especial", local.get("special_cidr")),
        ("Referência", local.get("special_reference")),
    ]
    for label, value in fields:
        lines.append(f"- **{label}:** {_fmt(value)}")
    if local.get("embedded_ipv4"):
        lines.append(f"- **IPv4 incorporado/transição:** `{local.get('embedded_ipv4')}`")
    lines.append("")

    network = facts.get("network") or {}
    lines.append("## 3. Registro e roteamento")
    lines.append("")
    lines.append(f"- Prefixo BGP atual: `{_fmt(network.get('prefix'))}`")
    lines.append(f"- ASN(s) de origem atuais: {_fmt(['AS' + str(x).replace('AS', '') for x in (network.get('asns') or [])])}")
    rdap = facts.get("rdap") or {}
    lines.append(f"- Nome do bloco no RDAP: {_fmt(rdap.get('name'))}")
    lines.append(f"- Handle RDAP: {_fmt(rdap.get('handle'))}")
    lines.append(f"- Intervalo RDAP: {_fmt(rdap.get('start_address'))} — {_fmt(rdap.get('end_address'))}")
    lines.append(f"- País administrativo RDAP: {_fmt(rdap.get('country'))}")
    if facts.get("asn_overviews"):
        for item in facts["asn_overviews"]:
            lines.append(f"- {_fmt(item.get('resource'))}: {_fmt(item.get('holder'))} (anunciando prefixos: {_fmt(item.get('announced'))})")
    if facts.get("rpki"):
        for item in facts["rpki"]:
            lines.append(f"- RPKI {_fmt(item.get('resource'))} / `{_fmt(item.get('prefix'))}`: **{_fmt(item.get('status'))}**")
    if facts.get("peeringdb"):
        for item in facts["peeringdb"]:
            lines.append(f"- PeeringDB AS{_fmt(item.get('asn'))}: {_fmt(item.get('name'))}; tipos: {_fmt(item.get('info_types'))}; IXs: {_fmt(item.get('ix_count'))}; facilities: {_fmt(item.get('fac_count'))}")
    lines.append("")

    if facts.get("historical_bgp"):
        h = facts["historical_bgp"]
        lines.append("## 4. BGP histórico")
        lines.append("")
        lines.append(f"- Instante consultado: `{_fmt(h.get('query_time'))}`")
        lines.append(f"- Rotas relevantes observadas: {_fmt(h.get('route_count'))}")
        lines.append(f"- Origens observadas: `{_fmt(h.get('origin_counts'))}`")
        lines.append(f"- Prefixos observados: `{_fmt(h.get('prefix_counts'))}`")
        lines.append("")

    lines.append("## 5. DNS, geolocalização e inteligência")
    lines.append("")
    dns = facts.get("reverse_dns") or {}
    lines.append(f"- PTR/hostname: {_fmt(dns.get('hostname'))}")
    if facts.get("geolocation"):
        lines.append(f"- Geolocalização estimada (primeiros resultados): `{facts.get('geolocation')[:5]}`")
    tor = facts.get("tor") or {}
    lines.append(f"- Tor relay atual detectado: {_fmt(tor.get('is_tor_relay'))}")
    lines.append(f"- Tor exit atual detectado: {_fmt(tor.get('is_tor_exit'))}")
    gn = facts.get("greynoise") or {}
    if gn:
        lines.append(f"- GreyNoise — noise: {_fmt(gn.get('noise'))}; RIOT: {_fmt(gn.get('riot'))}; classificação: {_fmt(gn.get('classification'))}")
    public_enrichment = facts.get("public_enrichment") or []
    if public_enrichment:
        for item in public_enrichment:
            lines.append(
                f"- {item.get('provider')} — ASN: {_fmt(item.get('asn'))}; org: {_fmt(item.get('organization'))}; "
                f"VPN: {_fmt(item.get('vpn'))}; proxy: {_fmt(item.get('proxy'))}; Tor: {_fmt(item.get('tor'))}; hosting: {_fmt(item.get('hosting'))}"
            )
    shodan = facts.get("shodan_internetdb") or {}
    if shodan:
        lines.append(f"- Shodan InternetDB — portas observadas: {_fmt(shodan.get('ports'))}; hostnames: {_fmt(shodan.get('hostnames'))}; CVEs: {_fmt(shodan.get('vulns'))}")
    abuse = facts.get("abuseipdb") or {}
    if abuse:
        lines.append(f"- AbuseIPDB — score: {_fmt(abuse.get('abuse_confidence_score'))}; reports: {_fmt(abuse.get('total_reports'))}; usage type: {_fmt(abuse.get('usage_type'))}")
    lines.append("")

    lines.append("## 6. Conclusão investigativa")
    lines.append("")
    lines.append(f"**{conclusion.get('headline', '')}**")
    lines.append("")
    for p in conclusion.get("paragraphs", []):
        lines.append(p)
        lines.append("")

    lines.append("### Limitações")
    lines.append("")
    for item in conclusion.get("limitations", []):
        lines.append(f"- {item}")
    lines.append("")

    lines.append("### Providências/checagens sugeridas")
    lines.append("")
    for item in conclusion.get("next_steps", []):
        lines.append(f"- {item}")
    lines.append("")

    lines.append("### Valor investigativo dos dados")
    lines.append("")
    for label, value in (conclusion.get("scorecard") or {}).items():
        lines.append(f"- **{label}:** {value}")
    lines.append("")

    lines.append("## 7. Fontes e proveniência")
    lines.append("")
    lines.append(bundle.get("source_disclosure_notice", ""))
    lines.append("")
    for source in bundle.get("sources", []):
        status = "OK" if source.get("ok") else f"Falha ({source.get('error') or 'indisponível'})"
        lines.append(f"### {source.get('name')}")
        lines.append(f"- Categoria: {_fmt(source.get('category'))}")
        lines.append(f"- Estado: {status}")
        lines.append(f"- Consultado em UTC: `{_fmt(source.get('retrieved_at_utc'))}`")
        lines.append(f"- URL da consulta: {source.get('url')}")
        if source.get("documentation_url"):
            lines.append(f"- Documentação: {source.get('documentation_url')}")
        if source.get("sha256"):
            lines.append(f"- SHA-256 da resposta normalizada: `{source.get('sha256')}`")
        lines.append("")

    return "\n".join(lines)
