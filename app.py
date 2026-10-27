from __future__ import annotations

import ipaddress
import json
import os
from datetime import date, time
from typing import Any

import streamlit as st
import streamlit.components.v1 as components
from dotenv import load_dotenv

from core.batch import batch_summary_rows, parse_ip_file, parse_ip_text
from core.cases import (
    add_analysis_to_case,
    create_case,
    delete_case,
    export_case,
    get_case,
    get_case_analyses,
    init_db,
    list_cases,
    remove_analysis,
    update_case,
)
from core.graph import build_graph_elements, cytoscape_html, graph_stats
from core.investigator import investigate_ip
from core.pdf_report import build_case_pdf, build_single_pdf
from core.report import build_markdown_report
from core.third_party import third_party_links


load_dotenv()
init_db()

st.set_page_config(
    page_title="IP Investigator",
    page_icon="🛰️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown(
    """
<style>
    .block-container {padding-top: 1.5rem; padding-bottom: 4rem; max-width: 1550px;}
    h1, h2, h3 {letter-spacing: -0.02em;}
    .hero {
        border: 1px solid rgba(128,128,128,.22);
        border-radius: 18px;
        padding: 1.25rem 1.45rem;
        margin-bottom: 1rem;
        background: linear-gradient(135deg, rgba(70,90,120,.10), rgba(120,120,120,.04));
    }
    .hero-title {font-size: 2rem; font-weight: 750; margin: 0;}
    .hero-sub {opacity: .76; margin-top: .35rem; margin-bottom: 0;}
    div[data-testid="stMetric"] {
        border: 1px solid rgba(128,128,128,.16);
        padding: .75rem .9rem;
        border-radius: 12px;
    }
</style>
""",
    unsafe_allow_html=True,
)

TIMEZONES = [
    "America/Fortaleza",
    "America/Sao_Paulo",
    "America/Manaus",
    "America/Rio_Branco",
    "UTC",
    "Europe/London",
    "Europe/Lisbon",
    "America/New_York",
]


def valid_ip(value: str) -> str | None:
    try:
        return str(ipaddress.ip_address(value.strip())) if value.strip() else None
    except ValueError:
        return None


def bool_label(value: Any) -> str:
    if value is True:
        return "Sim"
    if value is False:
        return "Não"
    return "—"


def render_key_values(items: list[tuple[str, object]], cols: int = 3) -> None:
    columns = st.columns(cols)
    for idx, (label, value) in enumerate(items):
        display = "—" if value is None or value == "" or value == [] else str(value)
        columns[idx % cols].metric(label, display)


def render_incident_inputs(prefix: str, *, allow_port: bool = True) -> tuple[dict[str, Any], str | None, str]:
    use_incident = st.checkbox("Informar data/hora do fato para análise histórica", value=False, key=f"{prefix}_use_incident")
    c1, c2, c3 = st.columns([1, 1, 1.35])
    with c1:
        incident_date = st.date_input("Data", value=date.today(), disabled=not use_incident, key=f"{prefix}_date")
    with c2:
        incident_time = st.time_input("Hora", value=time(12, 0), step=1, disabled=not use_incident, key=f"{prefix}_time")
    with c3:
        timezone_name = st.selectbox("Fuso horário", TIMEZONES, index=0, disabled=not use_incident, key=f"{prefix}_tz")

    source_port: str | None = None
    protocol = "Não informado"
    if allow_port:
        c4, c5 = st.columns(2)
        with c4:
            source_port = st.text_input("Porta lógica de origem", placeholder="Ex.: 51842", key=f"{prefix}_port")
        with c5:
            protocol = st.selectbox("Protocolo", ["Não informado", "TCP", "UDP", "QUIC/UDP", "Outro"], key=f"{prefix}_protocol")
    return {
        "enabled": use_incident,
        "date": incident_date,
        "time": incident_time,
        "timezone": timezone_name,
    }, source_port, protocol


def validate_port(source_port: str | None) -> bool:
    if not source_port:
        return True
    try:
        value = int(source_port)
        return 1 <= value <= 65535
    except ValueError:
        return False


def current_enabled_sources() -> set[str]:
    enabled: set[str] = set()
    if st.session_state.get("local_only", False):
        return enabled
    mapping = {
        "use_rdap": "rdap",
        "use_ripe": "ripe",
        "use_dns": "dns",
        "use_tor": "tor",
        "use_gn": "greynoise",
        "use_public": "public_enrichment",
        "use_abuse": "abuseipdb",
        "use_ipinfo": "ipinfo",
    }
    for state_key, source in mapping.items():
        if st.session_state.get(state_key, False):
            enabled.add(source)
    return enabled


def case_options() -> tuple[list[dict[str, Any]], dict[str, int]]:
    cases = list_cases()
    labels = {f"#{c['id']} - {c['name']} ({c['analysis_count']} análises)": int(c["id"]) for c in cases}
    return cases, labels


def save_bundles_to_case(bundles: list[dict[str, Any]], case_id: int, label_prefix: str = "") -> int:
    count = 0
    for bundle in bundles:
        ip = (bundle.get("query") or {}).get("ip", "")
        label = f"{label_prefix}{ip}".strip()
        add_analysis_to_case(case_id, bundle, label=label)
        count += 1
    return count


def render_bundle(bundle: dict[str, Any], response_mode: str) -> None:
    q = bundle["query"]
    local = bundle["local"]
    facts = bundle["facts"]
    conclusion = bundle["conclusion"]

    st.divider()
    st.subheader(f"Resultado para {q['ip']}")

    network = facts.get("network") or {}
    rdap = facts.get("rdap") or {}
    asn_overviews = facts.get("asn_overviews") or []
    asn_text = ", ".join("AS" + str(x).replace("AS", "") for x in (network.get("asns") or [])) or "—"
    holder_text = "; ".join(x.get("holder") or "" for x in asn_overviews if x.get("holder")) or rdap.get("name") or "—"

    top = st.columns(5)
    top[0].metric("Versão", f"IPv{local['version']}")
    top[1].metric("Global", bool_label(local.get("is_global")))
    top[2].metric("Prefixo BGP", network.get("prefix") or "—")
    top[3].metric("ASN", asn_text)
    top[4].metric("Papel provável", conclusion.get("network_role") or "—")
    st.caption(f"Organização/holder observado: {holder_text}")

    if response_mode == "Resumo":
        st.markdown("### Síntese")
        st.write(local.get("investigation_note"))
        if facts.get("reverse_dns"):
            st.write(f"**PTR:** {facts['reverse_dns'].get('hostname') or '—'}")
        if facts.get("tor"):
            st.write(
                f"**Tor atual:** relay={bool_label(facts['tor'].get('is_tor_relay'))}; "
                f"exit={bool_label(facts['tor'].get('is_tor_exit'))}"
            )
        if facts.get("greynoise"):
            st.write(
                f"**GreyNoise:** noise={bool_label(facts['greynoise'].get('noise'))}; "
                f"RIOT={bool_label(facts['greynoise'].get('riot'))}; "
                f"classificação={facts['greynoise'].get('classification') or '—'}"
            )
    else:
        tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs(
            ["Estrutura", "Registro / ASN", "BGP / RPKI", "DNS / Geo", "Threat / Tor", "Fontes / bruto"]
        )

        with tab1:
            render_key_values([
                ("IP comprimido", local.get("compressed")),
                ("IP expandido", local.get("exploded")),
                ("Uso especial", local.get("special_use") or "Não"),
                ("Faixa especial", local.get("special_cidr") or "—"),
                ("Privado", bool_label(local.get("is_private"))),
                ("Link-local", bool_label(local.get("is_link_local"))),
                ("Loopback", bool_label(local.get("is_loopback"))),
                ("Multicast", bool_label(local.get("is_multicast"))),
                ("Reverse pointer", local.get("reverse_pointer")),
            ])
            st.info(local.get("investigation_note"))
            if local.get("embedded_ipv4"):
                st.write("**Informação IPv4 incorporada/transição:**")
                st.json(local["embedded_ipv4"], expanded=True)

        with tab2:
            st.markdown("#### RDAP / registro")
            if rdap:
                render_key_values([
                    ("Nome", rdap.get("name")),
                    ("Handle", rdap.get("handle")),
                    ("País administrativo", rdap.get("country")),
                    ("Início", rdap.get("start_address")),
                    ("Fim", rdap.get("end_address")),
                    ("Tipo", rdap.get("type")),
                ])
                with st.expander("Entidades e contatos públicos do RDAP"):
                    st.json(rdap.get("entities", []), expanded=False)
            else:
                st.caption("Sem dados RDAP disponíveis nas fontes habilitadas.")

            st.markdown("#### ASN")
            if asn_overviews:
                st.dataframe(asn_overviews, use_container_width=True, hide_index=True)
            else:
                st.caption("Sem AS Overview disponível.")
            if facts.get("peeringdb"):
                st.markdown("#### PeeringDB")
                st.dataframe(facts["peeringdb"], use_container_width=True, hide_index=True)
                st.caption("PeeringDB descreve a rede/AS e sua presença declarada; não identifica usuário final.")

        with tab3:
            render_key_values([("Prefixo atual", network.get("prefix")), ("ASN(s) atuais", asn_text)], cols=2)
            if facts.get("rpki"):
                st.markdown("#### Validação RPKI atual")
                st.dataframe(facts["rpki"], use_container_width=True, hide_index=True)
                st.caption("O estado RPKI exibido é atual, salvo quando a fonte explicitamente fornecer histórico.")
            if facts.get("historical_bgp"):
                st.markdown("#### Estado BGP na data/hora informada")
                hist = facts["historical_bgp"]
                render_key_values([
                    ("Instante retornado", hist.get("query_time")),
                    ("Rotas relevantes", hist.get("route_count")),
                    ("Origens observadas", hist.get("origin_counts")),
                    ("Prefixos observados", hist.get("prefix_counts")),
                ], cols=2)
                with st.expander("Amostra de rotas históricas"):
                    st.json(hist.get("sample_routes", []), expanded=False)

        with tab4:
            dns = facts.get("reverse_dns") or {}
            render_key_values([
                ("PTR / hostname", dns.get("hostname")),
                ("Aliases", dns.get("aliases")),
                ("Endereços retornados", dns.get("addresses")),
            ])
            st.markdown("#### Geolocalização estimada")
            if facts.get("geolocation"):
                st.dataframe(facts["geolocation"], use_container_width=True, hide_index=True)
                st.warning("Cidade/coordenadas são estimativas GeoIP; não equivalem à localização física do usuário.")
            elif facts.get("ipinfo"):
                st.json(facts["ipinfo"], expanded=True)
            else:
                st.caption("Sem geolocalização disponível nas fontes habilitadas.")

        with tab5:
            tor = facts.get("tor") or {}
            render_key_values([
                ("Tor relay atual", bool_label(tor.get("is_tor_relay"))),
                ("Tor exit atual", bool_label(tor.get("is_tor_exit"))),
            ], cols=2)
            if tor.get("relays"):
                st.dataframe(tor["relays"], use_container_width=True, hide_index=True)
            if facts.get("greynoise"):
                st.markdown("#### GreyNoise")
                st.json(facts["greynoise"], expanded=True)
            if facts.get("public_enrichment"):
                st.markdown("#### Comparação entre provedores públicos")
                st.dataframe(facts["public_enrichment"], use_container_width=True, hide_index=True)
                st.caption("VPN/proxy/Tor/hosting e scores são indicadores dos fornecedores e podem divergir.")
            if facts.get("shodan_internetdb"):
                st.markdown("#### Shodan InternetDB - exposição observada")
                st.json(facts["shodan_internetdb"], expanded=True)
                st.caption("Portas/CVEs são observações de base de varredura e podem estar desatualizadas.")
            if facts.get("abuseipdb"):
                st.markdown("#### AbuseIPDB")
                st.json(facts["abuseipdb"], expanded=True)
            st.caption("Ausência de detecção não prova ausência de VPN, proxy, Tor ou atividade maliciosa.")

        with tab6:
            st.warning(bundle.get("source_disclosure_notice"))
            source_rows = [{
                "Fonte": s.get("name"),
                "Categoria": s.get("category"),
                "Status": "OK" if s.get("ok") else s.get("error") or "Falha",
                "UTC": s.get("retrieved_at_utc"),
                "SHA-256": s.get("sha256"),
            } for s in bundle.get("sources", [])]
            if source_rows:
                st.dataframe(source_rows, use_container_width=True, hide_index=True)
            for source in bundle.get("sources", []):
                with st.expander(f"{source.get('name')} - {'OK' if source.get('ok') else 'falha'}"):
                    st.markdown(f"**Consulta:** {source.get('url')}")
                    if source.get("documentation_url"):
                        st.markdown(f"**Documentação:** {source.get('documentation_url')}")
                    st.caption(f"Consultado em UTC: {source.get('retrieved_at_utc')} | SHA-256: {source.get('sha256') or '—'}")
                    st.json(source.get("data"), expanded=False)

    st.divider()
    st.markdown("## Conclusão")
    st.success(conclusion.get("headline"))
    for paragraph in conclusion.get("paragraphs", []):
        st.write(paragraph)

    if response_mode == "Investigativo":
        c_a, c_b = st.columns(2)
        with c_a:
            st.markdown("### Limitações da inferência")
            for item in conclusion.get("limitations", []):
                st.markdown(f"- {item}")
        with c_b:
            st.markdown("### Providências / checagens sugeridas")
            for item in conclusion.get("next_steps", []):
                st.markdown(f"- {item}")

        st.markdown("### Valor investigativo")
        st.dataframe(
            [{"Dimensão": k, "Avaliação": v} for k, v in conclusion.get("scorecard", {}).items()],
            use_container_width=True,
            hide_index=True,
        )

    st.markdown("### Referências da origem das respostas")
    if bundle.get("sources"):
        for idx, source in enumerate(bundle["sources"], 1):
            status = "OK" if source.get("ok") else f"falha: {source.get('error') or 'indisponível'}"
            st.markdown(
                f"{idx}. **{source.get('name')}** - {status} - [consulta]({source.get('url')})"
                + (f" - [documentação]({source.get('documentation_url')})" if source.get("documentation_url") else "")
            )
    else:
        st.caption("Nenhuma fonte externa foi consultada; a conclusão baseia-se apenas na classificação local do endereço.")

    report_md = build_markdown_report(bundle)
    report_json = json.dumps(bundle, ensure_ascii=False, indent=2, default=str)
    pdf_bytes = build_single_pdf(bundle)
    d1, d2, d3 = st.columns(3)
    safe_ip = q["ip"].replace(":", "_")
    d1.download_button("Baixar relatório Markdown", report_md, f"ip-investigator-{safe_ip}.md", "text/markdown", use_container_width=True)
    d2.download_button("Baixar evidências JSON", report_json, f"ip-investigator-{safe_ip}.json", "application/json", use_container_width=True)
    d3.download_button("Baixar relatório PDF", pdf_bytes, f"ip-investigator-{safe_ip}.pdf", "application/pdf", use_container_width=True)

    _, labels = case_options()
    if labels:
        c1, c2 = st.columns([3, 1])
        selected_label = c1.selectbox("Salvar esta análise em um caso", list(labels), key=f"save_single_case_{safe_ip}")
        if c2.button("Salvar no caso", use_container_width=True, key=f"save_single_btn_{safe_ip}"):
            add_analysis_to_case(labels[selected_label], bundle, label=f"Análise {q['ip']}")
            st.success("Análise salva no caso.")
    else:
        st.caption("Crie um caso na aba Casos para armazenar esta análise.")


# Sidebar: source control
with st.sidebar:
    st.header("Fontes e privacidade")
    st.caption("O programa roda localmente, mas APIs externas recebem o IP consultado quando habilitadas.")
    local_only = st.toggle("Modo estritamente local", value=False, help="Não envia o IP a nenhuma API externa.", key="local_only")
    st.divider()
    st.toggle("RDAP / RIR", value=True, disabled=local_only, key="use_rdap")
    st.toggle("RIPEstat / BGP / RPKI / GeoLite", value=True, disabled=local_only, key="use_ripe")
    st.toggle("DNS reverso", value=True, disabled=local_only, key="use_dns")
    st.toggle("Tor Metrics / Onionoo", value=True, disabled=local_only, key="use_tor")
    st.toggle("GreyNoise Community", value=True, disabled=local_only, key="use_gn")
    st.toggle("Enriquecimento público (ipctl / GeoIPHub / ipto / FFraud)", value=True, disabled=local_only, key="use_public")
    st.divider()
    st.subheader("Integrações opcionais")
    has_abuse = bool(os.getenv("ABUSEIPDB_API_KEY", "").strip())
    has_ipinfo = bool(os.getenv("IPINFO_TOKEN", "").strip())
    st.toggle("AbuseIPDB", value=has_abuse, disabled=local_only or not has_abuse, key="use_abuse")
    st.toggle("IPinfo", value=has_ipinfo, disabled=local_only or not has_ipinfo, key="use_ipinfo")
    st.caption(f"AbuseIPDB: {'chave detectada' if has_abuse else 'sem chave no .env'}")
    st.caption(f"IPinfo: {'token detectado' if has_ipinfo else 'sem token no .env'}")
    with st.expander("Como adicionar chaves"):
        st.code("ABUSEIPDB_API_KEY=sua_chave\nGREYNOISE_API_KEY=sua_chave_opcional\nIPINFO_TOKEN=seu_token", language="text")

st.markdown(
    """
<div class="hero">
  <p class="hero-title">IP Investigator</p>
  <p class="hero-sub">Enriquecimento técnico, análise em lote, grafos Cytoscape, casos locais e relatórios com proveniência.</p>
</div>
""",
    unsafe_allow_html=True,
)

main_single, main_batch, main_graph, main_cases = st.tabs(["Análise individual", "Análise em lote", "Grafo", "Casos"])

with main_single:
    left, right = st.columns([3.3, 1.2])
    with left:
        ip_input = st.text_input("Endereço IPv4 ou IPv6", placeholder="Ex.: 8.8.8.8 ou 2001:4860:4860::8888", key="single_ip")
    with right:
        response_mode = st.selectbox("Tipo de resposta", ["Investigativo", "Técnico", "Resumo"], index=0, key="single_mode")

    normalized_ip = valid_ip(ip_input)
    with st.expander("Contexto temporal e de conexão (opcional)", expanded=True):
        incident, source_port, protocol = render_incident_inputs("single", allow_port=True)

    with st.popover("Consultar em plataformas de terceiros", use_container_width=True):
        if normalized_ip:
            st.caption("Cada link envia o IP diretamente ao serviço escolhido.")
            incident_for_links = str(incident["date"]) if incident["enabled"] else None
            for item in third_party_links(normalized_ip, incident_for_links):
                st.link_button(item["name"], item["url"], use_container_width=True)
                st.caption(item["description"])
        else:
            st.info("Digite um IP válido para gerar links de consulta direta.")

    if st.button("Analisar IP", type="primary", use_container_width=True, key="single_analyze"):
        if not normalized_ip:
            st.error("Informe um endereço IPv4 ou IPv6 válido.")
        elif not validate_port(source_port):
            st.error("A porta lógica deve ser um número entre 1 e 65535.")
        else:
            with st.spinner("Consultando e correlacionando as fontes habilitadas..."):
                st.session_state.analysis_bundle = investigate_ip(
                    normalized_ip,
                    response_mode=response_mode,
                    incident=incident,
                    source_port=source_port,
                    protocol=protocol,
                    enabled_sources=current_enabled_sources(),
                )

    bundle = st.session_state.get("analysis_bundle")
    if bundle:
        render_bundle(bundle, (bundle.get("query") or {}).get("response_mode") or response_mode)

with main_batch:
    st.subheader("Análise em lote")
    st.caption("Aceita IPv4 e IPv6, um por linha. Também é possível importar TXT ou CSV com coluna `ip`/`address`/`indicador`.")
    c1, c2 = st.columns([2.4, 1])
    with c1:
        batch_text = st.text_area("IPs", height=180, placeholder="8.8.8.8\n1.1.1.1\n2001:4860:4860::8888", key="batch_text")
        batch_file = st.file_uploader("Ou importar arquivo", type=["txt", "csv"], key="batch_file")
    with c2:
        batch_mode = st.selectbox("Tipo de resposta", ["Investigativo", "Técnico", "Resumo"], key="batch_mode")
        max_batch = st.number_input("Máximo de IPs por execução", min_value=1, max_value=100, value=25, step=1)
        st.info("Em lote, as fontes habilitadas no menu lateral são consultadas para cada IP global. Use o modo local para casos sigilosos ou triagem inicial.")

    with st.expander("Contexto temporal comum ao lote (opcional)"):
        batch_incident, _, _ = render_incident_inputs("batch", allow_port=False)

    if st.button("Analisar lote", type="primary", use_container_width=True, key="batch_analyze"):
        valid: list[str] = []
        invalid: list[str] = []
        if batch_text.strip():
            v, i = parse_ip_text(batch_text, max_items=int(max_batch))
            valid.extend(v)
            invalid.extend(i)
        if batch_file is not None:
            remaining = max(0, int(max_batch) - len(valid))
            if remaining:
                v, i = parse_ip_file(batch_file.getvalue(), batch_file.name, max_items=remaining)
                valid.extend(ip for ip in v if ip not in valid)
                invalid.extend(i)
        valid = valid[: int(max_batch)]

        if invalid:
            st.warning("Entradas inválidas ignoradas: " + ", ".join(invalid[:20]) + (" ..." if len(invalid) > 20 else ""))
        if not valid:
            st.error("Nenhum IP válido foi informado.")
        else:
            bundles: list[dict[str, Any]] = []
            progress = st.progress(0, text="Iniciando análise em lote...")
            status = st.empty()
            for idx, ip in enumerate(valid, start=1):
                status.caption(f"Analisando {idx}/{len(valid)}: {ip}")
                try:
                    bundles.append(
                        investigate_ip(
                            ip,
                            response_mode=batch_mode,
                            incident=batch_incident,
                            enabled_sources=current_enabled_sources(),
                        )
                    )
                except Exception as exc:
                    st.warning(f"Falha ao analisar {ip}: {exc}")
                progress.progress(idx / len(valid), text=f"{idx}/{len(valid)} concluídos")
            status.empty()
            st.session_state.batch_bundles = bundles

    batch_bundles = st.session_state.get("batch_bundles") or []
    if batch_bundles:
        st.markdown("### Resumo do lote")
        st.dataframe(batch_summary_rows(batch_bundles), use_container_width=True, hide_index=True)
        batch_json = json.dumps(batch_bundles, ensure_ascii=False, indent=2, default=str)
        pseudo_case = {
            "name": "Análise em lote",
            "description": "Relatório consolidado da sessão atual.",
            "status": "Sessão",
            "created_at_utc": batch_bundles[0].get("generated_at_utc"),
            "updated_at_utc": batch_bundles[-1].get("generated_at_utc"),
        }
        batch_pdf = build_case_pdf(pseudo_case, batch_bundles)
        d1, d2 = st.columns(2)
        d1.download_button("Baixar lote em JSON", batch_json, "ip-investigator-lote.json", "application/json", use_container_width=True)
        d2.download_button("Baixar relatório PDF do lote", batch_pdf, "ip-investigator-lote.pdf", "application/pdf", use_container_width=True)

        _, labels = case_options()
        if labels:
            c1, c2 = st.columns([3, 1])
            selected_label = c1.selectbox("Salvar todo o lote em um caso", list(labels), key="batch_case_select")
            if c2.button("Salvar lote", use_container_width=True, key="batch_case_save"):
                saved = save_bundles_to_case(batch_bundles, labels[selected_label], label_prefix="Lote - ")
                st.success(f"{saved} análises salvas no caso.")

with main_graph:
    st.subheader("Grafo de relações")
    st.caption("Visualização interativa construída com Cytoscape.js. As arestas representam apenas relações presentes nos dados coletados.")
    source_options = []
    if st.session_state.get("analysis_bundle"):
        source_options.append("Análise individual atual")
    if st.session_state.get("batch_bundles"):
        source_options.append("Análise em lote atual")
    cases, labels = case_options()
    if labels:
        source_options.append("Caso salvo")

    if not source_options:
        st.info("Faça uma análise individual/lote ou crie um caso com análises para gerar o grafo.")
    else:
        graph_source = st.selectbox("Origem dos dados", source_options, key="graph_source")
        graph_bundles: list[dict[str, Any]] = []
        graph_title = graph_source
        if graph_source == "Análise individual atual":
            graph_bundles = [st.session_state["analysis_bundle"]]
        elif graph_source == "Análise em lote atual":
            graph_bundles = list(st.session_state["batch_bundles"])
        else:
            selected_case_label = st.selectbox("Caso", list(labels), key="graph_case")
            case_id = labels[selected_case_label]
            selected_case = get_case(case_id)
            graph_title = selected_case["name"] if selected_case else selected_case_label
            graph_bundles = [x["bundle"] for x in get_case_analyses(case_id) if x.get("bundle")]

        elements = build_graph_elements(graph_bundles)
        stats = graph_stats(elements)
        m1, m2, m3 = st.columns(3)
        m1.metric("Análises", len(graph_bundles))
        m2.metric("Nós", stats["nodes"])
        m3.metric("Relações", stats["edges"])
        if elements:
            components.html(cytoscape_html(elements, title=graph_title), height=900, scrolling=False)
            st.caption("Cytoscape.js é distribuído sob licença MIT; a cópia utilizada está versionada em `assets/vendor/` para funcionamento local.")
        else:
            st.info("Os resultados selecionados ainda não contêm relações suficientes para construir o grafo.")

with main_cases:
    st.subheader("Casos locais")
    st.caption("Os casos e análises são armazenados localmente em `data/ip_investigator.db` (SQLite). Esse arquivo está fora do Git por padrão.")

    with st.expander("Criar novo caso", expanded=not bool(list_cases())):
        new_case_name = st.text_input("Nome do caso", key="new_case_name")
        new_case_desc = st.text_area("Descrição", key="new_case_desc")
        if st.button("Criar caso", type="primary", key="create_case_btn"):
            try:
                case_id = create_case(new_case_name, new_case_desc)
                st.success(f"Caso #{case_id} criado.")
                st.rerun()
            except ValueError as exc:
                st.error(str(exc))

    cases, labels = case_options()
    if not labels:
        st.info("Nenhum caso criado ainda.")
    else:
        selected_label = st.selectbox("Selecionar caso", list(labels), key="case_manager_select")
        case_id = labels[selected_label]
        case = get_case(case_id)
        analyses = get_case_analyses(case_id)

        if case:
            with st.expander("Dados do caso", expanded=False):
                edit_name = st.text_input("Nome", value=case["name"], key=f"edit_name_{case_id}")
                edit_desc = st.text_area("Descrição", value=case["description"], key=f"edit_desc_{case_id}")
                edit_status = st.selectbox("Status", ["Aberto", "Em análise", "Concluído", "Arquivado"], index=["Aberto", "Em análise", "Concluído", "Arquivado"].index(case["status"]) if case["status"] in ["Aberto", "Em análise", "Concluído", "Arquivado"] else 0, key=f"edit_status_{case_id}")
                if st.button("Salvar alterações", key=f"update_case_{case_id}"):
                    update_case(case_id, name=edit_name, description=edit_desc, status=edit_status)
                    st.success("Caso atualizado.")
                    st.rerun()

            top = st.columns(4)
            top[0].metric("Caso", f"#{case_id}")
            top[1].metric("Status", case["status"])
            top[2].metric("Análises", len(analyses))
            top[3].metric("Atualizado UTC", case["updated_at_utc"])
            if case["description"]:
                st.write(case["description"])

            if analyses:
                rows = []
                for item in analyses:
                    bundle_item = item.get("bundle") or {}
                    conclusion = bundle_item.get("conclusion") or {}
                    network = (bundle_item.get("facts") or {}).get("network") or {}
                    rows.append({
                        "ID": item["id"],
                        "IP": item["ip"],
                        "Rótulo": item["label"],
                        "Prefixo": network.get("prefix"),
                        "Papel provável": conclusion.get("network_role"),
                        "Gerado UTC": item["generated_at_utc"],
                        "Salvo UTC": item["saved_at_utc"],
                        "SHA-256": item["bundle_sha256"],
                    })
                st.dataframe(rows, use_container_width=True, hide_index=True)

                export = export_case(case_id)
                export_json = json.dumps(export, ensure_ascii=False, indent=2, default=str)
                bundles = [item["bundle"] for item in analyses if item.get("bundle")]
                case_pdf = build_case_pdf(case, bundles)
                d1, d2 = st.columns(2)
                d1.download_button("Exportar caso em JSON", export_json, f"caso-{case_id}.json", "application/json", use_container_width=True)
                d2.download_button("Exportar relatório PDF", case_pdf, f"caso-{case_id}.pdf", "application/pdf", use_container_width=True)

                with st.expander("Remover uma análise do caso"):
                    analysis_labels = {f"#{a['id']} - {a['ip']} - {a['saved_at_utc']}": a["id"] for a in analyses}
                    remove_label = st.selectbox("Análise", list(analysis_labels), key=f"remove_analysis_select_{case_id}")
                    if st.button("Remover análise", key=f"remove_analysis_btn_{case_id}"):
                        remove_analysis(analysis_labels[remove_label])
                        st.success("Análise removida do caso.")
                        st.rerun()
            else:
                st.caption("Este caso ainda não possui análises.")

            with st.expander("Excluir caso"):
                confirm_delete = st.checkbox("Confirmo a exclusão definitiva deste caso e de suas análises locais.", key=f"confirm_delete_{case_id}")
                if st.button("Excluir caso", disabled=not confirm_delete, key=f"delete_case_{case_id}"):
                    delete_case(case_id)
                    st.success("Caso excluído.")
                    st.rerun()

st.divider()
st.caption("IP Investigator organiza dados públicos e inferências técnicas. Não substitui perícia, resposta oficial de provedor nem correlação com outras evidências.")
