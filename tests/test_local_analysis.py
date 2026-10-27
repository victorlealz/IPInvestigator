from core.local_analysis import analyze_local_ip, extract_embedded_ipv4


def test_private_ipv4():
    x = analyze_local_ip("192.168.1.10")
    assert x.version == 4
    assert x.is_private is True
    assert x.special_use == "IPv4 privado"


def test_cgnat():
    x = analyze_local_ip("100.64.1.2")
    assert x.special_use == "Shared Address Space / CGNAT"
    assert x.special_cidr == "100.64.0.0/10"


def test_ipv6_documentation():
    x = analyze_local_ip("2001:db8::1")
    assert x.version == 6
    assert x.special_use == "IPv6 de documentação"


def test_ipv4_mapped_ipv6():
    embedded = extract_embedded_ipv4("::ffff:192.0.2.1")
    assert embedded is not None
    assert embedded["ipv4"] == "192.0.2.1"
