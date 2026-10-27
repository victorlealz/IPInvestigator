from core.graph import build_graph_elements, cytoscape_html, graph_stats
from core.investigator import investigate_ip


def test_graph_from_offline_bundle():
    bundle = investigate_ip("100.64.1.2", enabled_sources=set())
    elements = build_graph_elements([bundle])
    stats = graph_stats(elements)
    assert stats["nodes"] >= 1
    assert any(e.get("data", {}).get("kind") == "ip" for e in elements)
    rendered = cytoscape_html(elements, height=500)
    assert "window.cytoscape" in rendered
    assert "100.64.1.2" in rendered


def test_graph_deduplicates_shared_asn_across_ips():
    def bundle(ip):
        return {
            "query": {"ip": ip},
            "facts": {
                "network": {"prefix": "203.0.113.0/24", "asns": [64500]},
                "asn_overviews": [{"holder": "Example Network"}],
                "rdap": {"name": "Example Network", "country": "BR"},
                "reverse_dns": None,
                "geolocation": [],
                "public_enrichment": [],
                "tor": None,
                "greynoise": None,
                "abuseipdb": None,
            },
            "conclusion": {"network_role": "ISP/provedor de acesso"},
        }

    elements = build_graph_elements([bundle("203.0.113.10"), bundle("203.0.113.20")])
    asn_nodes = [e for e in elements if e.get("data", {}).get("kind") == "asn"]
    prefix_nodes = [e for e in elements if e.get("data", {}).get("kind") == "prefix"]
    ip_nodes = [e for e in elements if e.get("data", {}).get("kind") == "ip"]
    assert len(asn_nodes) == 1
    assert len(prefix_nodes) == 1
    assert len(ip_nodes) == 2
