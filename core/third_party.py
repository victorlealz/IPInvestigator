from __future__ import annotations

from urllib.parse import quote


def third_party_links(ip: str, incident_date: str | None = None) -> list[dict[str, str]]:
    q = quote(ip, safe=':')
    links = [
        {
            "name": "ipctl.io",
            "url": f"https://ipctl.io/ip/{q}",
            "description": "BGP, RPKI, registro, geolocalização e threat intelligence.",
        },
        {
            "name": "GeoIPHub",
            "url": "https://geoiphub.com/tools/ip-lookup",
            "description": "GeoIP, ASN/WHOIS, VPN/proxy/Tor, threat e scoring.",
        },
        {
            "name": "IPDebrief",
            "url": f"https://ipdebrief.com/{q}",
            "description": "Dossiê público com ownership, infraestrutura, exposição e risco.",
        },
        {
            "name": "Max Intel",
            "url": "https://maxintel.org/ip.html",
            "description": "Agregador OSINT de geolocalização, ASN, ameaça e pivôs externos.",
        },
        {
            "name": "ipto.to",
            "url": f"https://ipto.to/{q}",
            "description": "ASN, organização, geolocalização e flags de infraestrutura/ameaça.",
        },
        {
            "name": "FFraud",
            "url": f"https://api.ffraud.com/public/ip/{q}",
            "description": "Resposta JSON gratuita com fraude, VPN/proxy/Tor/hosting e ASN.",
        },
        {
            "name": "RIPEstat",
            "url": "https://stat.ripe.net/",
            "description": "Roteamento, ASN, BGP, RPKI e dados de registro/infraestrutura.",
        },
        {
            "name": "AbuseIPDB",
            "url": f"https://www.abuseipdb.com/check/{q}",
            "description": "Reputação e denúncias de abuso associadas ao endereço.",
        },
        {
            "name": "GreyNoise Visualizer",
            "url": f"https://viz.greynoise.io/ip/{q}",
            "description": "Atividade de scanning/noise e classificação de infraestrutura observada.",
        },
        {
            "name": "IPinfo",
            "url": f"https://ipinfo.io/{q}",
            "description": "Dados de rede/ASN, hostname e geolocalização estimada.",
        },
        {
            "name": "Shodan InternetDB",
            "url": f"https://internetdb.shodan.io/{q}",
            "description": "Portas, hostnames, CPEs e CVEs observados, sem chave para uso compatível com o serviço.",
        },
    ]
    if incident_date:
        links.append({
            "name": "Tor ExoneraTor (histórico)",
            "url": f"https://metrics.torproject.org/exonerator.html?ip={q}&timestamp={quote(incident_date)}&lang=en",
            "description": "Verifica se o IP foi relay/exit Tor na data informada (janela aproximada do serviço).",
        })
    else:
        links.append({
            "name": "Tor Relay Search",
            "url": f"https://metrics.torproject.org/rs.html#search/{q}",
            "description": "Consulta relays Tor atuais por IP.",
        })
    return links
