from __future__ import annotations

import csv
import io
import ipaddress
from typing import Any, Iterable


def parse_ip_text(text: str, *, max_items: int = 100) -> tuple[list[str], list[str]]:
    raw_items: list[str] = []
    for line in (text or "").replace(",", "\n").replace(";", "\n").splitlines():
        value = line.strip()
        if value:
            raw_items.append(value)
    return _normalize_items(raw_items, max_items=max_items)


def parse_ip_file(content: bytes, filename: str = "", *, max_items: int = 100) -> tuple[list[str], list[str]]:
    text = content.decode("utf-8-sig", errors="replace")
    if filename.lower().endswith(".csv"):
        rows = list(csv.reader(io.StringIO(text)))
        if not rows:
            return [], []
        header = [c.strip().casefold() for c in rows[0]]
        preferred = ["ip", "address", "endereco", "endereço", "indicator", "indicador"]
        index = next((header.index(name) for name in preferred if name in header), 0)
        start = 1 if any(name in header for name in preferred) else 0
        items = [row[index].strip() for row in rows[start:] if len(row) > index and row[index].strip()]
        return _normalize_items(items, max_items=max_items)
    return parse_ip_text(text, max_items=max_items)


def _normalize_items(items: Iterable[str], *, max_items: int) -> tuple[list[str], list[str]]:
    valid: list[str] = []
    invalid: list[str] = []
    seen: set[str] = set()
    for raw in items:
        if len(valid) >= max_items:
            break
        try:
            normalized = str(ipaddress.ip_address(raw.strip()))
        except ValueError:
            invalid.append(raw.strip())
            continue
        if normalized not in seen:
            seen.add(normalized)
            valid.append(normalized)
    return valid, invalid


def batch_summary_rows(bundles: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for bundle in bundles:
        q = bundle.get("query") or {}
        local = bundle.get("local") or {}
        facts = bundle.get("facts") or {}
        conclusion = bundle.get("conclusion") or {}
        network = facts.get("network") or {}
        asns = [f"AS{str(x).replace('AS', '')}" for x in (network.get("asns") or [])]
        rdap = facts.get("rdap") or {}
        holders = [x.get("holder") for x in (facts.get("asn_overviews") or []) if isinstance(x, dict) and x.get("holder")]
        rows.append(
            {
                "IP": q.get("ip"),
                "Versão": f"IPv{local.get('version')}" if local.get("version") else None,
                "Global": local.get("is_global"),
                "Uso especial": local.get("special_use"),
                "Prefixo": network.get("prefix"),
                "ASN": ", ".join(asns) or None,
                "Organização": "; ".join(holders) or rdap.get("name"),
                "Papel provável": conclusion.get("network_role"),
                "Confiança": conclusion.get("network_role_confidence"),
                "Conclusão": conclusion.get("headline"),
            }
        )
    return rows
