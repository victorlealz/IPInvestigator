from __future__ import annotations

import hashlib
import html
import json
from pathlib import Path
from typing import Any, Iterable


VENDOR_PATH = Path(__file__).resolve().parent.parent / "assets" / "vendor" / "cytoscape.min.js"


def _stable_id(kind: str, value: Any) -> str:
    raw = f"{kind}:{value}".encode("utf-8", "replace")
    return f"{kind}-{hashlib.sha1(raw).hexdigest()[:14]}"


def _node(kind: str, value: str, label: str | None = None, **extra: Any) -> dict[str, Any]:
    return {
        "data": {
            "id": _stable_id(kind, value),
            "label": label or str(value),
            "kind": kind,
            "value": str(value),
            **{k: v for k, v in extra.items() if v is not None},
        }
    }


def _edge(source_id: str, target_id: str, relation: str) -> dict[str, Any]:
    edge_key = f"{source_id}|{relation}|{target_id}"
    return {
        "data": {
            "id": _stable_id("edge", edge_key),
            "source": source_id,
            "target": target_id,
            "relation": relation,
            "label": relation,
        }
    }


def _country_from_bundle(bundle: dict[str, Any]) -> str | None:
    facts = bundle.get("facts") or {}
    for loc in facts.get("geolocation") or []:
        if not isinstance(loc, dict):
            continue
        value = loc.get("country") or loc.get("country_code")
        if value:
            return str(value)
    ipinfo = facts.get("ipinfo") or {}
    if ipinfo.get("country"):
        return str(ipinfo["country"])
    rdap = facts.get("rdap") or {}
    if rdap.get("country"):
        return str(rdap["country"])
    for item in facts.get("public_enrichment") or []:
        if isinstance(item, dict) and item.get("country"):
            return str(item["country"])
    return None


def _org_candidates(bundle: dict[str, Any]) -> list[str]:
    facts = bundle.get("facts") or {}
    values: list[str] = []
    for item in facts.get("asn_overviews") or []:
        if isinstance(item, dict) and item.get("holder"):
            values.append(str(item["holder"]))
    rdap = facts.get("rdap") or {}
    if rdap.get("name"):
        values.append(str(rdap["name"]))
    for item in facts.get("public_enrichment") or []:
        if isinstance(item, dict) and item.get("organization"):
            values.append(str(item["organization"]))
    ipinfo = facts.get("ipinfo") or {}
    if ipinfo.get("org"):
        values.append(str(ipinfo["org"]))

    seen: set[str] = set()
    out: list[str] = []
    for value in values:
        cleaned = value.strip()
        key = cleaned.casefold()
        if cleaned and key not in seen:
            seen.add(key)
            out.append(cleaned)
    return out[:8]


def _indicator_nodes(bundle: dict[str, Any]) -> list[tuple[str, str]]:
    facts = bundle.get("facts") or {}
    indicators: list[tuple[str, str]] = []

    tor = facts.get("tor") or {}
    if tor.get("is_tor_exit"):
        indicators.append(("indicator", "Tor exit node"))
    elif tor.get("is_tor_relay"):
        indicators.append(("indicator", "Tor relay"))

    gn = facts.get("greynoise") or {}
    if gn.get("noise") is True:
        classification = gn.get("classification") or "observado"
        indicators.append(("indicator", f"GreyNoise: {classification}"))
    if gn.get("riot") is True:
        indicators.append(("indicator", "GreyNoise RIOT"))

    abuse = facts.get("abuseipdb") or {}
    score = abuse.get("abuse_confidence_score")
    if isinstance(score, (int, float)) and score >= 25:
        indicators.append(("indicator", f"AbuseIPDB score {score}"))

    for item in facts.get("public_enrichment") or []:
        if not isinstance(item, dict):
            continue
        provider = item.get("provider") or "provider"
        for field, label in (("vpn", "VPN"), ("proxy", "Proxy"), ("hosting", "Hosting/datacenter")):
            if item.get(field) is True:
                indicators.append(("indicator", f"{label} ({provider})"))

    seen: set[str] = set()
    out: list[tuple[str, str]] = []
    for kind, label in indicators:
        key = label.casefold()
        if key not in seen:
            seen.add(key)
            out.append((kind, label))
    return out[:10]


def build_graph_elements(bundles: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """Build a de-duplicated Cytoscape.js element list from investigation bundles."""
    nodes: dict[str, dict[str, Any]] = {}
    edges: dict[str, dict[str, Any]] = {}

    def add_node(kind: str, value: str, label: str | None = None, **extra: Any) -> str:
        n = _node(kind, value, label, **extra)
        node_id = n["data"]["id"]
        if node_id not in nodes:
            nodes[node_id] = n
        return node_id

    def add_edge(source: str, target: str, relation: str) -> None:
        e = _edge(source, target, relation)
        edges.setdefault(e["data"]["id"], e)

    for bundle in bundles:
        if not isinstance(bundle, dict):
            continue
        q = bundle.get("query") or {}
        facts = bundle.get("facts") or {}
        conclusion = bundle.get("conclusion") or {}
        ip = q.get("ip")
        if not ip:
            continue

        ip_id = add_node(
            "ip",
            str(ip),
            str(ip),
            title=f"IP: {ip}",
            role=conclusion.get("network_role"),
        )

        network = facts.get("network") or {}
        prefix = network.get("prefix")
        if prefix:
            prefix_id = add_node("prefix", str(prefix), str(prefix), title=f"Prefixo BGP: {prefix}")
            add_edge(ip_id, prefix_id, "pertence ao prefixo")
        else:
            prefix_id = None

        asn_ids: list[str] = []
        for raw_asn in network.get("asns") or []:
            asn_value = str(raw_asn).upper().replace("AS", "")
            asn_label = f"AS{asn_value}"
            asn_id = add_node("asn", asn_value, asn_label, title=f"ASN: {asn_label}")
            asn_ids.append(asn_id)
            add_edge(prefix_id or ip_id, asn_id, "originado por")

        orgs = _org_candidates(bundle)
        if orgs:
            for idx, org in enumerate(orgs):
                org_id = add_node("organization", org, org, title=f"Organização: {org}")
                if asn_ids:
                    # The first holder is generally the strongest ASN context; additional orgs are enrichment.
                    for asn_id in asn_ids if idx == 0 else asn_ids[:1]:
                        add_edge(asn_id, org_id, "associado a")
                else:
                    add_edge(ip_id, org_id, "registrado/associado a")

        dns = facts.get("reverse_dns") or {}
        hostname = dns.get("hostname")
        if hostname:
            host_id = add_node("hostname", str(hostname), str(hostname), title=f"PTR: {hostname}")
            add_edge(ip_id, host_id, "PTR")

        country = _country_from_bundle(bundle)
        if country:
            country_id = add_node("country", country, country, title=f"País indicativo: {country}")
            add_edge(ip_id, country_id, "geo/registro indicativo")

        for kind, indicator in _indicator_nodes(bundle):
            indicator_id = add_node(kind, indicator, indicator, title=indicator)
            add_edge(ip_id, indicator_id, "indicador")

    return [*nodes.values(), *edges.values()]


def graph_stats(elements: list[dict[str, Any]]) -> dict[str, int]:
    nodes = sum(1 for e in elements if "source" not in (e.get("data") or {}))
    edges = len(elements) - nodes
    return {"nodes": nodes, "edges": edges}


def cytoscape_html(
    elements: list[dict[str, Any]],
    *,
    height: int = 720,
    title: str = "Grafo de relações",
) -> str:
    """Return a self-contained HTML document using the vendored Cytoscape.js build."""
    if not VENDOR_PATH.exists():
        raise FileNotFoundError(f"Cytoscape.js não encontrado em {VENDOR_PATH}")

    cytoscape_js = VENDOR_PATH.read_text(encoding="utf-8")
    payload = json.dumps(elements, ensure_ascii=False).replace("</", "<\\/")
    safe_title = html.escape(title)

    return f"""<!doctype html>
<html lang=\"pt-BR\">
<head>
<meta charset=\"utf-8\">
<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">
<style>
  :root {{ color-scheme: light dark; }}
  body {{ margin:0; font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, \"Segoe UI\", sans-serif; background:transparent; color:#263238; }}
  .toolbar {{ display:flex; gap:8px; align-items:center; flex-wrap:wrap; padding:8px 4px 10px; }}
  .toolbar strong {{ margin-right:auto; font-size:14px; }}
  .toolbar input, .toolbar select, .toolbar button {{ font:inherit; border:1px solid #c8d0d7; border-radius:8px; background:#fff; color:#263238; padding:7px 9px; }}
  .toolbar input {{ min-width:220px; flex:1 1 220px; }}
  .toolbar button {{ cursor:pointer; }}
  #cy {{ height:{int(height)}px; min-height:480px; border:1px solid #d8dee4; border-radius:12px; background:#fbfcfd; }}
  #details {{ margin-top:8px; padding:9px 11px; min-height:20px; border:1px solid #e1e6ea; border-radius:10px; background:#fff; font-size:13px; line-height:1.45; }}
  .legend {{ display:flex; flex-wrap:wrap; gap:8px 12px; padding:8px 2px 0; font-size:12px; color:#54616a; }}
  .dot {{ display:inline-block; width:10px; height:10px; border-radius:50%; margin-right:4px; vertical-align:-1px; }}
  @media (prefers-color-scheme: dark) {{
    body {{ color:#e8edf1; }}
    .toolbar input, .toolbar select, .toolbar button, #details {{ background:#172025; color:#e8edf1; border-color:#3a474f; }}
    #cy {{ background:#11191e; border-color:#344149; }}
    .legend {{ color:#aebbc3; }}
  }}
</style>
</head>
<body>
<div class=\"toolbar\">
  <strong>{safe_title}</strong>
  <input id=\"search\" aria-label=\"Buscar nó\" placeholder=\"Buscar IP, ASN, organização...\">
  <select id=\"layout\" aria-label=\"Layout do grafo\">
    <option value=\"cose\">Cose</option>
    <option value=\"breadthfirst\">Hierárquico</option>
    <option value=\"concentric\">Concêntrico</option>
    <option value=\"circle\">Circular</option>
    <option value=\"grid\">Grade</option>
  </select>
  <button id=\"fit\" type=\"button\">Ajustar</button>
</div>
<div id=\"cy\" role=\"img\" aria-label=\"Grafo interativo de relações investigativas\"></div>
<div class=\"legend\">
 <span><i class=\"dot\" style=\"background:#2b6cb0\"></i>IP</span>
 <span><i class=\"dot\" style=\"background:#4a5568\"></i>Prefixo</span>
 <span><i class=\"dot\" style=\"background:#805ad5\"></i>ASN</span>
 <span><i class=\"dot\" style=\"background:#2f855a\"></i>Organização</span>
 <span><i class=\"dot\" style=\"background:#b7791f\"></i>Hostname</span>
 <span><i class=\"dot\" style=\"background:#718096\"></i>País</span>
 <span><i class=\"dot\" style=\"background:#c53030\"></i>Indicador</span>
</div>
<div id=\"details\">Clique em um nó para ver os detalhes.</div>
<script>{cytoscape_js}</script>
<script>
(function() {{
  const elements = {payload};
  const cy = window.cytoscape({{
    container: document.getElementById('cy'),
    elements,
    style: [
      {{ selector:'node', style:{{
        'background-color':'#607d8b', 'label':'data(label)', 'color':'#243038', 'font-size':11,
        'text-wrap':'wrap', 'text-max-width':'120px', 'text-valign':'bottom',
        'text-margin-y':7, 'text-background-color':'#ffffff', 'text-background-opacity':0.78,
        'text-background-padding':2, 'width':34, 'height':34, 'border-width':1,
        'border-color':'#ffffff'
      }} }},
      {{ selector:'node[kind = "ip"]', style:{{ 'background-color':'#2b6cb0', 'width':46, 'height':46, 'font-weight':'bold' }} }},
      {{ selector:'node[kind = "prefix"]', style:{{ 'background-color':'#4a5568' }} }},
      {{ selector:'node[kind = "asn"]', style:{{ 'background-color':'#805ad5' }} }},
      {{ selector:'node[kind = "organization"]', style:{{ 'background-color':'#2f855a' }} }},
      {{ selector:'node[kind = "hostname"]', style:{{ 'background-color':'#b7791f' }} }},
      {{ selector:'node[kind = "country"]', style:{{ 'background-color':'#718096' }} }},
      {{ selector:'node[kind = "indicator"]', style:{{ 'background-color':'#c53030', 'shape':'diamond' }} }},
      {{ selector:'edge', style:{{
        'width':1.5, 'line-color':'#a9b4bc', 'target-arrow-color':'#a9b4bc',
        'target-arrow-shape':'triangle', 'curve-style':'bezier', 'label':'data(relation)',
        'font-size':9, 'color':'#66737c', 'text-background-color':'#ffffff',
        'text-background-opacity':0.82, 'text-background-padding':2
      }} }},
      {{ selector:'.faded', style:{{ 'opacity':0.14 }} }},
      {{ selector:'.matched', style:{{ 'border-width':4, 'border-color':'#111827' }} }}
    ],
    layout: {{ name:'cose', animate:false, fit:true, padding:35, nodeRepulsion:450000, idealEdgeLength:110 }}
  }});

  const runLayout = () => {{
    const name = document.getElementById('layout').value;
    const opts = {{ name, animate:false, fit:true, padding:35 }};
    if (name === 'breadthfirst') opts.directed = true;
    cy.layout(opts).run();
  }};
  document.getElementById('layout').addEventListener('change', runLayout);
  document.getElementById('fit').addEventListener('click', () => cy.fit(undefined, 35));

  const details = document.getElementById('details');
  cy.on('tap', 'node', evt => {{
    const d = evt.target.data();
    const parts = [
      '<strong>' + escapeHtml(d.label || d.id) + '</strong>',
      'Tipo: ' + escapeHtml(d.kind || '—'),
      d.role ? 'Papel provável: ' + escapeHtml(d.role) : '',
      d.title ? escapeHtml(d.title) : ''
    ].filter(Boolean);
    details.innerHTML = parts.join(' &nbsp;·&nbsp; ');
  }});
  cy.on('tap', evt => {{ if (evt.target === cy) details.textContent = 'Clique em um nó para ver os detalhes.'; }});

  function escapeHtml(value) {{
    return String(value).replace(/[&<>\"']/g, ch => ({{'&':'&amp;','<':'&lt;','>':'&gt;','\"':'&quot;',"'":'&#39;'}}[ch]));
  }}

  const search = document.getElementById('search');
  search.addEventListener('input', () => {{
    const q = search.value.trim().toLowerCase();
    cy.elements().removeClass('faded matched');
    if (!q) return;
    const matches = cy.nodes().filter(n => String(n.data('label') || '').toLowerCase().includes(q) || String(n.data('value') || '').toLowerCase().includes(q));
    if (matches.length === 0) {{ cy.elements().addClass('faded'); return; }}
    const neighborhood = matches.closedNeighborhood();
    cy.elements().not(neighborhood).addClass('faded');
    matches.addClass('matched');
    cy.fit(neighborhood, 60);
  }});
}})();
</script>
</body>
</html>"""
