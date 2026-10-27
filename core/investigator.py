from __future__ import annotations

import ipaddress
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import date, datetime, time, timezone
from typing import Any
from zoneinfo import ZoneInfo

from .local_analysis import analyze_local_ip, extract_embedded_ipv4
from .sources import (
    SourceResult,
    abuseipdb,
    ffraud_lookup,
    geoiphub_lookup,
    ipctl_lookup,
    ipto_lookup,
    peeringdb_network,
    shodan_internetdb,
    greynoise_community,
    ipinfo,
    rdap_lookup,
    reverse_dns,
    ripe_as_overview,
    ripe_bgp_state,
    ripe_geolocation,
    ripe_network_info,
    ripe_prefix_overview,
    ripe_routing_status,
    ripe_rpki,
    tor_onionoo,
)


INFRA_KEYWORDS = {
    "amazon", "aws", "google", "cloudflare", "microsoft", "azure", "digitalocean",
    "hetzner", "ovh", "akamai", "fastly", "linode", "leaseweb", "m247", "hosting",
    "datacenter", "data center", "cloud", "vultr", "oracle", "cdn", "colo",
}


def _source_payload(result: SourceResult | None) -> Any:
    if not result or not result.ok or not isinstance(result.data, dict):
        return None
    if "data" in result.data and isinstance(result.data.get("data"), (dict, list)):
        return result.data.get("data")
    return result.data


def _parse_vcard(entity: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {
        "handle": entity.get("handle"),
        "roles": entity.get("roles", []),
    }
    vcard = entity.get("vcardArray")
    if isinstance(vcard, list) and len(vcard) == 2 and isinstance(vcard[1], list):
        for row in vcard[1]:
            if not isinstance(row, list) or len(row) < 4:
                continue
            key, value = row[0], row[3]
            if key in {"fn", "org", "email", "tel", "url"}:
                out.setdefault(key, [])
                if isinstance(value, list):
                    out[key].extend(str(v) for v in value)
                else:
                    out[key].append(str(value))
    return out


def _parse_rdap(result: SourceResult | None) -> dict[str, Any] | None:
    data = _source_payload(result)
    if not isinstance(data, dict):
        return None
    entities = []
    for e in data.get("entities", []) or []:
        if isinstance(e, dict):
            entities.append(_parse_vcard(e))
    return {
        "name": data.get("name"),
        "handle": data.get("handle"),
        "start_address": data.get("startAddress"),
        "end_address": data.get("endAddress"),
        "ip_version": data.get("ipVersion"),
        "country": data.get("country"),
        "type": data.get("type"),
        "status": data.get("status"),
        "parent_handle": data.get("parentHandle"),
        "entities": entities[:12],
        "notices": [n.get("title") for n in (data.get("notices") or []) if isinstance(n, dict) and n.get("title")],
    }


def _parse_network_info(result: SourceResult | None) -> dict[str, Any] | None:
    data = _source_payload(result)
    if not isinstance(data, dict):
        return None
    return {"prefix": data.get("prefix"), "asns": data.get("asns") or []}


def _parse_as_overview(result: SourceResult | None) -> dict[str, Any] | None:
    data = _source_payload(result)
    if not isinstance(data, dict):
        return None
    return {
        "resource": data.get("resource"),
        "holder": data.get("holder"),
        "announced": data.get("announced"),
        "block": data.get("block"),
    }


def _parse_rpki(result: SourceResult | None) -> dict[str, Any] | None:
    data = _source_payload(result)
    if not isinstance(data, dict):
        return None
    return {
        "status": data.get("status"),
        "description": data.get("description"),
        "prefix": data.get("prefix"),
        "resource": data.get("resource"),
    }


def _flatten_locations(data: Any) -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = []
    if isinstance(data, dict):
        # RIPEstat MaxMind commonly nests locations in located_resources.
        if isinstance(data.get("located_resources"), list):
            for item in data["located_resources"]:
                if not isinstance(item, dict):
                    continue
                resource = item.get("resource")
                locs = item.get("locations") or []
                for loc in locs:
                    if isinstance(loc, dict):
                        found.append({"resource": resource, **loc})
        elif isinstance(data.get("locations"), list):
            for loc in data["locations"]:
                if isinstance(loc, dict):
                    found.append(loc)
        else:
            # Fallback for changing API shapes: keep only recognizable geo keys.
            geo_keys = {"country", "country_code", "city", "latitude", "longitude", "region", "timezone"}
            subset = {k: data.get(k) for k in geo_keys if data.get(k) is not None}
            if subset:
                found.append(subset)
    return found[:20]


def _parse_tor(result: SourceResult | None, ip: str) -> dict[str, Any] | None:
    data = _source_payload(result)
    if not isinstance(data, dict):
        return None
    relays = []
    for relay in data.get("relays", []) or []:
        if not isinstance(relay, dict):
            continue
        address_text = " ".join((relay.get("or_addresses") or []) + (relay.get("exit_addresses") or []))
        # Onionoo search allows prefix matching; require textual exact-ish containment bounded by common delimiters.
        exact = (
            f"{ip}:" in address_text
            or f"[{ip}]:" in address_text
            or ip in (relay.get("exit_addresses") or [])
        )
        if not exact:
            continue
        flags = relay.get("flags") or []
        relays.append({
            "nickname": relay.get("nickname"),
            "fingerprint": relay.get("fingerprint"),
            "running": relay.get("running"),
            "flags": flags,
            "is_exit": "Exit" in flags or ip in (relay.get("exit_addresses") or []),
            "first_seen": relay.get("first_seen"),
            "last_seen": relay.get("last_seen"),
            "country": relay.get("country_name") or relay.get("country"),
            "asn": relay.get("as"),
            "as_name": relay.get("as_name"),
            "hostnames": relay.get("verified_host_names") or [],
        })
    return {"is_tor_relay": bool(relays), "is_tor_exit": any(r["is_exit"] for r in relays), "relays": relays}


def _parse_greynoise(result: SourceResult | None) -> dict[str, Any] | None:
    data = _source_payload(result)
    if not isinstance(data, dict):
        return None
    return {
        "noise": data.get("noise"),
        "riot": data.get("riot"),
        "classification": data.get("classification"),
        "name": data.get("name"),
        "last_seen": data.get("last_seen"),
        "message": data.get("message"),
        "link": data.get("link"),
    }


def _parse_abuse(result: SourceResult | None) -> dict[str, Any] | None:
    data = _source_payload(result)
    if not isinstance(data, dict):
        return None
    return {
        "abuse_confidence_score": data.get("abuseConfidenceScore"),
        "total_reports": data.get("totalReports"),
        "last_reported_at": data.get("lastReportedAt"),
        "country_code": data.get("countryCode"),
        "usage_type": data.get("usageType"),
        "isp": data.get("isp"),
        "domain": data.get("domain"),
        "is_whitelisted": data.get("isWhitelisted"),
    }


def _parse_ipinfo(result: SourceResult | None) -> dict[str, Any] | None:
    data = _source_payload(result)
    if not isinstance(data, dict):
        return None
    keep = ["hostname", "city", "region", "country", "loc", "org", "postal", "timezone", "anycast", "asn", "is_anycast", "is_mobile", "is_anonymous", "is_hosting"]
    return {k: data.get(k) for k in keep if data.get(k) is not None}


def _parse_public_enrichment(name: str, result: SourceResult | None) -> dict[str, Any] | None:
    data = _source_payload(result)
    if not isinstance(data, dict):
        return None

    out: dict[str, Any] = {"provider": name}
    if name == "FFraud":
        out.update({
            "asn": data.get("ASN") or data.get("asn"),
            "organization": data.get("organization"),
            "country": (data.get("geo") or {}).get("country") if isinstance(data.get("geo"), dict) else None,
            "city": (data.get("geo") or {}).get("city") if isinstance(data.get("geo"), dict) else None,
            "vpn": data.get("vpn"),
            "proxy": data.get("proxy"),
            "tor": data.get("tor"),
            "hosting": data.get("hosting"),
            "fraud_score": data.get("fraud_score"),
            "risk": data.get("risk"),
            "connection_type": data.get("connection_type"),
            "is_abuser": data.get("is_abuser"),
            "recent_abuse": data.get("recent_abuse"),
            "threat_tags": data.get("threat_tags"),
        })
    elif name == "GeoIPHub":
        asn = data.get("asn") if isinstance(data.get("asn"), dict) else {}
        geo = data.get("geo") if isinstance(data.get("geo"), dict) else {}
        det = data.get("detection") if isinstance(data.get("detection"), dict) else {}
        scoring = data.get("scoring") if isinstance(data.get("scoring"), dict) else {}
        out.update({
            "asn": asn.get("asn"),
            "organization": asn.get("org") or asn.get("organization"),
            "asn_type": asn.get("connection_type") or asn.get("type"),
            "country": geo.get("country_code") or geo.get("country"),
            "city": geo.get("city"),
            "vpn": det.get("is_vpn"),
            "proxy": det.get("is_proxy"),
            "tor": det.get("is_tor"),
            "hosting": det.get("is_hosting"),
            "vpn_provider": det.get("vpn_provider"),
            "fraud_score": scoring.get("fraud_score"),
            "risk": scoring.get("recommended_action") or scoring.get("risk"),
        })
    elif name == "ipto.to":
        flags = data.get("flags") if isinstance(data.get("flags"), dict) else {}
        out.update({
            "asn": data.get("asn"),
            "organization": data.get("asn_org") or data.get("asn_name") or data.get("org"),
            "asn_type": data.get("asn_type"),
            "country": data.get("country_code") or data.get("country_name"),
            "city": data.get("city"),
            "vpn": flags.get("vpn"),
            "proxy": flags.get("proxy"),
            "tor": flags.get("tor"),
            "hosting": flags.get("hosting"),
            "bot": flags.get("bot"),
        })
    elif name == "ipctl.io":
        # Schema may evolve; extract common top-level and nested fields defensively.
        asn = data.get("asn") if isinstance(data.get("asn"), dict) else {}
        geo = data.get("geo") if isinstance(data.get("geo"), dict) else data.get("geolocation") if isinstance(data.get("geolocation"), dict) else {}
        threat = data.get("threat") if isinstance(data.get("threat"), dict) else {}
        out.update({
            "asn": asn.get("asn") or data.get("asn_number") or data.get("asn" if not isinstance(data.get("asn"), dict) else "_none"),
            "organization": asn.get("org") or asn.get("name") or data.get("organization"),
            "country": geo.get("country_code") or geo.get("country") or data.get("country_code"),
            "city": geo.get("city") or data.get("city"),
            "vpn": threat.get("vpn") if "vpn" in threat else data.get("is_vpn"),
            "proxy": threat.get("proxy") if "proxy" in threat else data.get("is_proxy"),
            "tor": threat.get("tor") if "tor" in threat else data.get("is_tor"),
            "hosting": threat.get("hosting") if "hosting" in threat else data.get("is_hosting"),
            "threat_score": threat.get("score") or data.get("threat_score"),
        })

    return {k: v for k, v in out.items() if v is not None}


def _parse_shodan_internetdb(result: SourceResult | None) -> dict[str, Any] | None:
    data = _source_payload(result)
    if not isinstance(data, dict):
        return None
    return {
        "ports": data.get("ports") or [],
        "hostnames": data.get("hostnames") or [],
        "cpes": data.get("cpes") or [],
        "vulns": data.get("vulns") or [],
        "tags": data.get("tags") or [],
    }


def _parse_peeringdb(result: SourceResult | None) -> dict[str, Any] | None:
    data = _source_payload(result)
    if not isinstance(data, dict):
        return None
    rows = data.get("data") or []
    if not isinstance(rows, list) or not rows:
        return None
    row = rows[0] if isinstance(rows[0], dict) else {}
    return {
        "id": row.get("id"),
        "asn": row.get("asn"),
        "name": row.get("name"),
        "aka": row.get("aka"),
        "website": row.get("website"),
        "info_types": row.get("info_types") or [],
        "info_prefixes4": row.get("info_prefixes4"),
        "info_prefixes6": row.get("info_prefixes6"),
        "info_traffic": row.get("info_traffic"),
        "info_scope": row.get("info_scope"),
        "ix_count": row.get("ix_count"),
        "fac_count": row.get("fac_count"),
        "looking_glass": row.get("looking_glass"),
        "route_server": row.get("route_server"),
        "irr_as_set": row.get("irr_as_set"),
        "status": row.get("status"),
    }


def _parse_historical_bgp(result: SourceResult | None, ip: str) -> dict[str, Any] | None:
    data = _source_payload(result)
    if not isinstance(data, dict):
        return None
    routes = data.get("bgp_state") or []
    ip_obj = ipaddress.ip_address(ip)
    relevant = []
    for row in routes:
        if not isinstance(row, dict):
            continue
        prefix = row.get("target_prefix")
        if not prefix:
            continue
        try:
            if ip_obj not in ipaddress.ip_network(prefix, strict=False):
                continue
        except ValueError:
            continue
        path = row.get("path") or []
        origin = path[-1] if path else None
        relevant.append({"prefix": prefix, "origin": origin, "path": path, "source_id": row.get("source_id")})
    origins = Counter(str(r["origin"]) for r in relevant if r.get("origin") is not None)
    prefixes = Counter(r["prefix"] for r in relevant)
    return {
        "query_time": data.get("query_time"),
        "route_count": len(relevant),
        "origin_counts": dict(origins.most_common(10)),
        "prefix_counts": dict(prefixes.most_common(10)),
        "sample_routes": relevant[:15],
    }


def _incident_to_utc(incident: dict[str, Any] | None) -> str | None:
    if not incident or not incident.get("enabled"):
        return None
    d = incident.get("date")
    t = incident.get("time")
    tz_name = incident.get("timezone") or "UTC"
    if not isinstance(d, date) or not isinstance(t, time):
        return None
    try:
        tz = ZoneInfo(tz_name)
    except Exception:
        tz = timezone.utc
    local_dt = datetime.combine(d, t, tzinfo=tz)
    return local_dt.astimezone(timezone.utc).isoformat(timespec="seconds")


def _network_role(facts: dict[str, Any]) -> tuple[str, str]:
    tor = facts.get("tor") or {}
    if tor.get("is_tor_exit"):
        return "Tor exit relay", "alta"
    if tor.get("is_tor_relay"):
        return "Tor relay", "alta"

    public_enrichment = facts.get("public_enrichment") or []
    if any(item.get("tor") is True for item in public_enrichment):
        return "Tor / infraestrutura de anonimização (indicadores de fornecedor)", "média-alta"
    if any(item.get("vpn") is True or item.get("proxy") is True for item in public_enrichment):
        return "VPN / proxy / infraestrutura de anonimização (indicadores de fornecedor)", "média-alta"
    if any(item.get("hosting") is True for item in public_enrichment):
        return "Infraestrutura / cloud / hosting", "média-alta"
    for item in public_enrichment:
        asn_type = str(item.get("asn_type") or item.get("connection_type") or "").lower()
        if "mobile" in asn_type:
            return "Operadora móvel", "média"
        if any(x in asn_type for x in ["isp", "residential", "fixed"]):
            return "ISP de acesso", "média"

    abuse = facts.get("abuseipdb") or {}
    usage = (abuse.get("usage_type") or "").lower()
    if "fixed line isp" in usage:
        return "ISP de acesso fixo", "alta"
    if "mobile isp" in usage:
        return "Operadora móvel", "alta"
    if any(x in usage for x in ["data center", "hosting", "transit", "content delivery"]):
        return "Infraestrutura / hosting / trânsito", "alta"

    text_parts = []
    rdap = facts.get("rdap") or {}
    text_parts.append(str(rdap.get("name") or ""))
    for asn in facts.get("asn_overviews") or []:
        text_parts.append(str(asn.get("holder") or ""))
    text = " ".join(text_parts).lower()
    if any(k in text for k in INFRA_KEYWORDS):
        return "Infraestrutura / cloud / hosting (heurística)", "média"

    return "Não determinado apenas pelas fontes consultadas", "baixa"


def _build_conclusion(local: dict[str, Any], facts: dict[str, Any], context: dict[str, Any]) -> dict[str, Any]:
    role, role_conf = _network_role(facts)
    paragraphs: list[str] = []
    limitations: list[str] = []
    next_steps: list[str] = []

    special = local.get("special_use")
    if special == "Shared Address Space / CGNAT":
        headline = "Endereço de CGNAT / Shared Address Space: não é um IPv4 público de assinante."
        paragraphs.append(
            "O endereço pertence à faixa 100.64.0.0/10. A atribuição depende dos registros internos da operadora que correlacionem endereço compartilhado, sessão e tradução NAT."
        )
        next_steps.append("Identificar a operadora/rede em cujo ambiente o endereço foi observado e requisitar os logs internos de CGNAT/NAT correspondentes.")
    elif not local.get("is_global"):
        headline = "Endereço não global: a atribuição depende do contexto da rede local onde foi registrado."
        paragraphs.append(local.get("investigation_note") or "")
        next_steps.append("Correlacionar o IP com DHCP, NAT, firewall, roteador, controladora Wi-Fi e demais logs da rede onde o endereço foi observado.")
    else:
        headline = f"IPv{local.get('version')} público/global; papel de rede: {role}."
        prefix = (facts.get("network") or {}).get("prefix")
        asns = (facts.get("network") or {}).get("asns") or []
        if prefix or asns:
            paragraphs.append(
                f"O roteamento atual observado associa o endereço ao prefixo {prefix or 'não determinado'}"
                f" e ao(s) ASN(s) {', '.join('AS'+str(x).replace('AS','') for x in asns) if asns else 'não determinado(s)'}."
            )
        if role.startswith("Tor"):
            paragraphs.append(
                "A presença em infraestrutura Tor reduz fortemente o valor do IP como indicador direto da origem do usuário; tráfego observado pode ter sido encaminhado por terceiros através do relay."
            )
        elif "VPN" in role or "proxy" in role.lower() or "anonimização" in role.lower():
            paragraphs.append(
                "Há indicadores de fornecedor compatíveis com VPN/proxy/anonimização. Esses sinais devem ser confirmados em mais de uma fonte e, se relevantes, por registros do serviço correspondente."
            )
        elif "Infraestrutura" in role:
            paragraphs.append(
                "O endereço aparenta estar ligado a infraestrutura intermediária/servidor, de modo que a geolocalização e o titular do bloco não devem ser confundidos com o usuário final."
            )
        else:
            paragraphs.append(
                "Mesmo quando o endereço está ligado a um ISP de acesso, ele identifica uma conexão/recurso de rede em determinado momento, não uma pessoa ou dispositivo por si só."
            )

    if facts.get("historical_bgp"):
        hist = facts["historical_bgp"]
        paragraphs.append(
            f"Foi realizada consulta histórica BGP para o instante informado (UTC), com {hist.get('route_count', 0)} rotas relevantes observadas pelos coletores RIPE RIS."
        )
        limitations.append("A consulta BGP histórica descreve roteamento observado, não a atribuição do endereço a um assinante naquele instante.")

    limitations.extend([
        "Geolocalização por IP é estimativa e não demonstra, isoladamente, a localização física do usuário.",
        "RDAP informa registro/administração do recurso numérico; não identifica quem utilizava o IP em um momento específico.",
        "ASN/BGP descrevem roteamento e origem de anúncios, não autoria de uma conduta.",
        "Ausência de sinal em bases de abuso, VPN, proxy ou Tor não prova que tais mecanismos não tenham sido usados.",
    ])

    port = context.get("source_port")
    protocol = context.get("protocol")
    if local.get("version") == 4 and local.get("is_global"):
        if port:
            next_steps.append(
                f"Preservar e informar ao provedor IP + data/hora + fuso + porta lógica de origem {port}"
                + (f" + protocolo {protocol}" if protocol and protocol != "Não informado" else "")
                + ", especialmente se houver CGNAT."
            )
        else:
            next_steps.append("Se houver possibilidade de CGNAT, obter/preservar a porta lógica de origem e o protocolo além de IP, data, hora e fuso.")
    elif local.get("version") == 6 and local.get("is_global"):
        next_steps.append("Preservar o IPv6 completo e o timestamp preciso; solicitar ao provedor a associação temporal do endereço/prefixo ao assinante ou sessão.")

    if role.startswith("Tor"):
        next_steps.append("Verificar o IP na base histórica ExoneraTor para a data do fato e buscar outros elementos de correlação fora do IP de saída.")
    elif "VPN" in role or "proxy" in role.lower() or "anonimização" in role.lower():
        next_steps.append("Identificar o provedor de VPN/proxy quando possível e correlacionar conta, sessão, timestamps e logs de entrada/saída, observando retenção e jurisdição.")
    elif "Infraestrutura" in role:
        next_steps.append("Identificar o serviço hospedado/conta/tenant e buscar logs de aplicação, autenticação, reverse proxy e conexões de origem.")
    elif local.get("is_global"):
        next_steps.append("Solicitar ao provedor responsável a associação temporal do recurso à conexão/assinante, sem tratar essa associação como prova suficiente de autoria.")

    scorecard = {
        "Atribuição da rede/bloco": "Alta" if facts.get("rdap") or facts.get("network") else "Indisponível",
        "ASN/roteamento": "Alta" if facts.get("network") else "Indisponível",
        "Papel da rede": f"{role} (confiança {role_conf})",
        "Geolocalização do país": "Indicativa" if facts.get("geolocation") or facts.get("ipinfo") else "Indisponível",
        "Geolocalização de cidade": "Baixa / não probatória" if facts.get("geolocation") or facts.get("ipinfo") else "Indisponível",
        "Identificação de assinante": "Depende de logs do provedor e correlação temporal",
        "Identificação de dispositivo": "Não determinável pelo IP isoladamente",
        "Identificação de pessoa/autoria": "Não determinável pelo IP isoladamente",
    }

    return {
        "headline": headline,
        "network_role": role,
        "network_role_confidence": role_conf,
        "paragraphs": paragraphs,
        "limitations": limitations,
        "next_steps": next_steps,
        "scorecard": scorecard,
    }


def investigate_ip(
    ip: str,
    *,
    response_mode: str = "Investigativo",
    incident: dict[str, Any] | None = None,
    source_port: str | None = None,
    protocol: str | None = None,
    enabled_sources: set[str] | None = None,
) -> dict[str, Any]:
    local_obj = analyze_local_ip(ip)
    local = local_obj.to_dict()
    local["embedded_ipv4"] = extract_embedded_ipv4(ip)
    enabled = {"rdap", "ripe", "dns", "tor", "greynoise", "public_enrichment", "abuseipdb", "ipinfo"} if enabled_sources is None else enabled_sources
    sources: list[SourceResult] = []
    facts: dict[str, Any] = {}
    timestamp_utc = _incident_to_utc(incident)

    context = {
        "source_port": source_port.strip() if isinstance(source_port, str) else source_port,
        "protocol": protocol,
        "incident_time_utc": timestamp_utc,
    }

    # Public enrichment is meaningful primarily for globally routable addresses.
    if local_obj.is_global:
        tasks: dict[str, Any] = {}
        if "rdap" in enabled:
            tasks["rdap"] = lambda: rdap_lookup(ip)
        if "ripe" in enabled:
            tasks["network"] = lambda: ripe_network_info(ip)
            tasks["geo"] = lambda: ripe_geolocation(ip)
            tasks["routing"] = lambda: ripe_routing_status(ip, timestamp_utc)
            if timestamp_utc:
                tasks["history"] = lambda: ripe_bgp_state(ip, timestamp_utc)
        if "dns" in enabled:
            tasks["dns"] = lambda: reverse_dns(ip)
        if "tor" in enabled:
            tasks["tor"] = lambda: tor_onionoo(ip)
        if "greynoise" in enabled and local_obj.version == 4:
            tasks["greynoise"] = lambda: greynoise_community(ip)
        if "public_enrichment" in enabled:
            tasks["ipctl"] = lambda: ipctl_lookup(ip)
            tasks["geoiphub"] = lambda: geoiphub_lookup(ip)
            tasks["ipto"] = lambda: ipto_lookup(ip)
            tasks["ffraud"] = lambda: ffraud_lookup(ip)
            if local_obj.version == 4:
                tasks["shodan_internetdb"] = lambda: shodan_internetdb(ip)
        if "abuseipdb" in enabled:
            maybe = abuseipdb
            tasks["abuseipdb"] = lambda: maybe(ip)
        if "ipinfo" in enabled:
            maybe_info = ipinfo
            tasks["ipinfo"] = lambda: maybe_info(ip)

        results: dict[str, SourceResult | None] = {}
        with ThreadPoolExecutor(max_workers=min(10, max(1, len(tasks)))) as pool:
            futures = {pool.submit(fn): key for key, fn in tasks.items()}
            for future in as_completed(futures):
                key = futures[future]
                try:
                    results[key] = future.result()
                except Exception as exc:
                    results[key] = None

        for result in results.values():
            if isinstance(result, SourceResult):
                sources.append(result)

        facts["rdap"] = _parse_rdap(results.get("rdap"))
        facts["network"] = _parse_network_info(results.get("network"))
        facts["geolocation"] = _flatten_locations(_source_payload(results.get("geo")))
        facts["reverse_dns"] = _source_payload(results.get("dns"))
        facts["tor"] = _parse_tor(results.get("tor"), ip)
        facts["greynoise"] = _parse_greynoise(results.get("greynoise"))
        facts["public_enrichment"] = [
            parsed for name, key in [("ipctl.io", "ipctl"), ("GeoIPHub", "geoiphub"), ("ipto.to", "ipto"), ("FFraud", "ffraud")]
            if (parsed := _parse_public_enrichment(name, results.get(key)))
        ]
        facts["shodan_internetdb"] = _parse_shodan_internetdb(results.get("shodan_internetdb"))
        facts["abuseipdb"] = _parse_abuse(results.get("abuseipdb"))
        facts["ipinfo"] = _parse_ipinfo(results.get("ipinfo"))
        facts["historical_bgp"] = _parse_historical_bgp(results.get("history"), ip)
        facts["routing_status"] = _source_payload(results.get("routing"))

        network = facts.get("network") or {}
        prefix = network.get("prefix")
        asns = network.get("asns") or []

        # Second wave depends on prefix/ASN discovered above.
        dependent: dict[str, Any] = {}
        if "ripe" in enabled and prefix:
            dependent["prefix_overview"] = lambda: ripe_prefix_overview(prefix, timestamp_utc)
            for asn in asns[:3]:
                dependent[f"asn_{asn}"] = lambda asn=asn: ripe_as_overview(asn)
                dependent[f"rpki_{asn}"] = lambda asn=asn: ripe_rpki(prefix, asn)
                if "public_enrichment" in enabled:
                    dependent[f"peering_{asn}"] = lambda asn=asn: peeringdb_network(asn)

        dep_results: dict[str, SourceResult | None] = {}
        if dependent:
            with ThreadPoolExecutor(max_workers=min(6, len(dependent))) as pool:
                futures = {pool.submit(fn): key for key, fn in dependent.items()}
                for future in as_completed(futures):
                    key = futures[future]
                    try:
                        dep_results[key] = future.result()
                    except Exception:
                        dep_results[key] = None
            for result in dep_results.values():
                if isinstance(result, SourceResult):
                    sources.append(result)

        facts["prefix_overview"] = _source_payload(dep_results.get("prefix_overview"))
        facts["asn_overviews"] = [
            parsed for key, result in dep_results.items()
            if key.startswith("asn_") and (parsed := _parse_as_overview(result))
        ]
        facts["rpki"] = [
            parsed for key, result in dep_results.items()
            if key.startswith("rpki_") and (parsed := _parse_rpki(result))
        ]
        facts["peeringdb"] = [
            parsed for key, result in dep_results.items()
            if key.startswith("peering_") and (parsed := _parse_peeringdb(result))
        ]
    else:
        facts.update({
            "rdap": None,
            "network": None,
            "geolocation": [],
            "reverse_dns": None,
            "tor": None,
            "greynoise": None,
            "public_enrichment": [],
            "shodan_internetdb": None,
            "abuseipdb": None,
            "ipinfo": None,
            "historical_bgp": None,
            "routing_status": None,
            "prefix_overview": None,
            "asn_overviews": [],
            "rpki": [],
            "peeringdb": [],
        })

    conclusion = _build_conclusion(local, facts, context)
    return {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "query": {
            "ip": str(ipaddress.ip_address(ip)),
            "response_mode": response_mode,
            "incident": {
                "enabled": bool(incident and incident.get("enabled")),
                "local_date": str(incident.get("date")) if incident and incident.get("enabled") else None,
                "local_time": str(incident.get("time")) if incident and incident.get("enabled") else None,
                "timezone": incident.get("timezone") if incident and incident.get("enabled") else None,
                "utc": timestamp_utc,
                "source_port": context.get("source_port") or None,
                "protocol": protocol if protocol != "Não informado" else None,
            },
        },
        "local": local,
        "facts": facts,
        "conclusion": conclusion,
        "sources": [s.to_dict() for s in sorted(sources, key=lambda x: (x.category, x.name))],
        "source_disclosure_notice": (
            "As consultas externas revelam às respectivas fontes o endereço IP pesquisado. "
            "O aplicativo registra as URLs consultadas e o horário UTC para fins de proveniência."
        ),
    }
