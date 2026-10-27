from __future__ import annotations

import hashlib
import json
import os
import re
import socket
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any
from urllib.parse import parse_qsl, quote, urlencode, urlsplit, urlunsplit

import requests


USER_AGENT = "IP-Investigator-Local/0.1 (+local research tool)"
DEFAULT_TIMEOUT = float(os.getenv("REQUEST_TIMEOUT", "12"))
RIPE_SOURCEAPP = os.getenv("RIPESTAT_SOURCEAPP", "ip-investigator-local")


@dataclass
class SourceResult:
    name: str
    category: str
    url: str
    documentation_url: str | None
    retrieved_at_utc: str
    ok: bool
    http_status: int | None
    data: Any = None
    error: str | None = None
    sha256: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _hash_payload(payload: Any) -> str:
    raw = json.dumps(payload, ensure_ascii=False, sort_keys=True, default=str).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _redact_url(url: str) -> str:
    try:
        parts = urlsplit(url)
        sensitive = {"token", "key", "api_key", "apikey", "access_token"}
        query = []
        for k, v in parse_qsl(parts.query, keep_blank_values=True):
            query.append((k, "REDACTED" if k.lower() in sensitive else v))
        return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query, doseq=True), parts.fragment))
    except Exception:
        return url


def _safe_error(exc: Exception) -> str:
    """Return an exception string with known credentials and query tokens redacted."""
    message = f"{type(exc).__name__}: {exc}"
    for env_name in ("IPINFO_TOKEN", "ABUSEIPDB_API_KEY", "GREYNOISE_API_KEY"):
        secret = os.getenv(env_name, "").strip()
        if secret:
            message = message.replace(secret, "REDACTED")
    # Best-effort redaction for URLs embedded in requests exception messages.
    message = re.sub(
        r"(?i)([?&](?:token|key|api_key|apikey|access_token)=)[^&\s'\"]+",
        r"\1REDACTED",
        message,
    )
    return message


def _get_json(
    name: str,
    category: str,
    url: str,
    documentation_url: str | None = None,
    *,
    params: dict[str, Any] | None = None,
    headers: dict[str, str] | None = None,
    timeout: float = DEFAULT_TIMEOUT,
) -> SourceResult:
    req_headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    if headers:
        req_headers.update(headers)
    try:
        r = requests.get(url, params=params, headers=req_headers, timeout=timeout, allow_redirects=True)
        final_url = _redact_url(r.url)
        try:
            payload = r.json()
        except Exception:
            payload = {"text": r.text[:10000]}
        ok = 200 <= r.status_code < 300
        return SourceResult(
            name=name,
            category=category,
            url=final_url,
            documentation_url=documentation_url,
            retrieved_at_utc=_now(),
            ok=ok,
            http_status=r.status_code,
            data=payload,
            error=None if ok else f"HTTP {r.status_code}",
            sha256=_hash_payload(payload),
        )
    except Exception as exc:
        return SourceResult(
            name=name,
            category=category,
            url=_redact_url(url),
            documentation_url=documentation_url,
            retrieved_at_utc=_now(),
            ok=False,
            http_status=None,
            data=None,
            error=_safe_error(exc),
            sha256=None,
        )


def rdap_lookup(ip: str) -> SourceResult:
    return _get_json(
        "RDAP (bootstrap para RIR autoritativo)",
        "Registro",
        f"https://rdap.org/ip/{quote(ip, safe=':')}",
        "https://about.rdap.org/",
    )


def ripestat(endpoint: str, params: dict[str, Any], name: str, category: str, doc_url: str) -> SourceResult:
    full = dict(params)
    full.setdefault("sourceapp", RIPE_SOURCEAPP)
    return _get_json(
        name,
        category,
        f"https://stat.ripe.net/data/{endpoint}/data.json",
        doc_url,
        params=full,
    )


def ripe_network_info(ip: str) -> SourceResult:
    return ripestat(
        "network-info",
        {"resource": ip},
        "RIPEstat Network Info",
        "BGP",
        "https://stat.ripe.net/docs/data-api/api-endpoints/network-info",
    )


def ripe_prefix_overview(prefix: str, query_time: str | None = None) -> SourceResult:
    params: dict[str, Any] = {"resource": prefix}
    if query_time:
        params["query_time"] = query_time
    return ripestat(
        "prefix-overview",
        params,
        "RIPEstat Prefix Overview",
        "BGP",
        "https://stat.ripe.net/docs/data-api/api-endpoints/prefix-overview",
    )


def ripe_as_overview(asn: int | str) -> SourceResult:
    resource = str(asn)
    if not resource.upper().startswith("AS"):
        resource = f"AS{resource}"
    return ripestat(
        "as-overview",
        {"resource": resource},
        "RIPEstat AS Overview",
        "ASN",
        "https://stat.ripe.net/docs/data-api/api-endpoints/as-overview",
    )


def ripe_rpki(prefix: str, asn: int | str) -> SourceResult:
    resource = str(asn).upper().replace("AS", "")
    return ripestat(
        "rpki-validation",
        {"resource": resource, "prefix": prefix},
        "RIPEstat RPKI Validation",
        "RPKI",
        "https://stat.ripe.net/docs/data-api/api-endpoints/rpki-validation",
    )


def ripe_bgp_state(ip: str, timestamp_utc: str) -> SourceResult:
    return ripestat(
        "bgp-state",
        {"resource": ip, "timestamp": timestamp_utc},
        "RIPEstat BGP State (histórico)",
        "BGP histórico",
        "https://stat.ripe.net/docs/data-api/api-endpoints/bgp-state",
    )


def ripe_routing_status(resource: str, timestamp_utc: str | None = None) -> SourceResult:
    params: dict[str, Any] = {"resource": resource}
    if timestamp_utc:
        params["timestamp"] = timestamp_utc
    return ripestat(
        "routing-status",
        params,
        "RIPEstat Routing Status",
        "BGP",
        "https://stat.ripe.net/docs/data-api/api-endpoints/routing-status",
    )


def ripe_geolocation(ip: str) -> SourceResult:
    return ripestat(
        "maxmind-geo-lite",
        {"resource": ip},
        "RIPEstat / MaxMind GeoLite",
        "Geolocalização estimada",
        "https://stat.ripe.net/docs/data-api/api-endpoints/maxmind-geo-lite",
    )


def reverse_dns(ip: str) -> SourceResult:
    queried = _now()
    try:
        hostname, aliases, addresses = socket.gethostbyaddr(ip)
        payload = {"hostname": hostname, "aliases": aliases, "addresses": addresses}
        return SourceResult(
            name="DNS reverso (PTR via resolver local)",
            category="DNS",
            url=f"dns://PTR/{ip}",
            documentation_url="https://www.rfc-editor.org/rfc/rfc1035",
            retrieved_at_utc=queried,
            ok=True,
            http_status=None,
            data=payload,
            sha256=_hash_payload(payload),
        )
    except Exception as exc:
        return SourceResult(
            name="DNS reverso (PTR via resolver local)",
            category="DNS",
            url=f"dns://PTR/{ip}",
            documentation_url="https://www.rfc-editor.org/rfc/rfc1035",
            retrieved_at_utc=queried,
            ok=False,
            http_status=None,
            data=None,
            error=_safe_error(exc),
        )


def tor_onionoo(ip: str) -> SourceResult:
    return _get_json(
        "Tor Metrics Onionoo",
        "Tor",
        "https://onionoo.torproject.org/details",
        "https://metrics.torproject.org/onionoo.html",
        params={
            "search": ip,
            "type": "relay",
            "fields": "nickname,fingerprint,or_addresses,exit_addresses,flags,running,last_seen,first_seen,country,country_name,as,as_name,verified_host_names",
        },
    )


def greynoise_community(ip: str) -> SourceResult:
    key = os.getenv("GREYNOISE_API_KEY", "").strip()
    headers = {"key": key} if key else None
    return _get_json(
        "GreyNoise Community",
        "Threat Intelligence",
        f"https://api.greynoise.io/v3/community/{quote(ip, safe=':')}",
        "https://docs.greynoise.io/reference/getcommunityip",
        headers=headers,
    )


def abuseipdb(ip: str) -> SourceResult | None:
    key = os.getenv("ABUSEIPDB_API_KEY", "").strip()
    if not key:
        return None
    return _get_json(
        "AbuseIPDB",
        "Threat Intelligence",
        "https://api.abuseipdb.com/api/v2/check",
        "https://docs.abuseipdb.com/",
        params={"ipAddress": ip, "maxAgeInDays": 90},
        headers={"Key": key},
    )


def ipinfo(ip: str) -> SourceResult | None:
    token = os.getenv("IPINFO_TOKEN", "").strip()
    if not token:
        return None
    return _get_json(
        "IPinfo",
        "Geolocalização / ASN",
        f"https://ipinfo.io/{quote(ip, safe=':')}/json",
        "https://ipinfo.io/developers",
        params={"token": token},
    )


def ipctl_lookup(ip: str) -> SourceResult:
    return _get_json(
        "ipctl.io",
        "Enriquecimento público",
        f"https://api.ipctl.io/v1/ip/{quote(ip, safe=':')}",
        "https://ipctl.io/docs",
    )


def geoiphub_lookup(ip: str) -> SourceResult:
    return _get_json(
        "GeoIPHub",
        "Enriquecimento público",
        f"https://api.geoiphub.com/v1/lookup/{quote(ip, safe=':')}",
        "https://help.geoiphub.com/docs/api/lookup",
    )


def ipto_lookup(ip: str) -> SourceResult:
    return _get_json(
        "ipto.to",
        "Enriquecimento público",
        f"https://ipto.to/v1/ip/{quote(ip, safe=':')}",
        "https://ipto.to/docs",
    )


def ffraud_lookup(ip: str) -> SourceResult:
    return _get_json(
        "FFraud",
        "Enriquecimento público",
        f"https://api.ffraud.com/public/ip/{quote(ip, safe=':')}",
        "https://ffraud.com/docs",
    )


def shodan_internetdb(ip: str) -> SourceResult:
    return _get_json(
        "Shodan InternetDB",
        "Exposição observada",
        f"https://internetdb.shodan.io/{quote(ip, safe=':')}",
        "https://help.shodan.io/developer-fundamentals/looking-up-ip-info",
    )


def peeringdb_network(asn: int | str) -> SourceResult:
    resource = str(asn).upper().replace("AS", "")
    return _get_json(
        "PeeringDB",
        "Peering / ASN",
        "https://www.peeringdb.com/api/net",
        "https://www.peeringdb.com/apidocs/",
        params={"asn": resource},
    )
