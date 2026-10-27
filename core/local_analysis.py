from __future__ import annotations

import ipaddress
from dataclasses import dataclass, asdict
from typing import Any


@dataclass
class LocalIPAnalysis:
    ip: str
    version: int
    compressed: str
    exploded: str
    integer: int
    reverse_pointer: str
    is_global: bool
    is_private: bool
    is_loopback: bool
    is_link_local: bool
    is_multicast: bool
    is_reserved: bool
    is_unspecified: bool
    special_use: str | None
    special_cidr: str | None
    special_reference: str | None
    investigation_note: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# Specific ranges are intentionally ordered from most specific/meaningful to broad.
SPECIAL_RANGES: list[tuple[str, str, str, str]] = [
    ("255.255.255.255/32", "Limited broadcast", "RFC 919 / RFC 922", "Não representa um host remoto identificável."),
    ("192.0.2.0/24", "TEST-NET-1 (documentação)", "RFC 5737", "Faixa reservada para exemplos e documentação; não deve aparecer como origem pública real."),
    ("198.51.100.0/24", "TEST-NET-2 (documentação)", "RFC 5737", "Faixa reservada para exemplos e documentação; não deve aparecer como origem pública real."),
    ("203.0.113.0/24", "TEST-NET-3 (documentação)", "RFC 5737", "Faixa reservada para exemplos e documentação; não deve aparecer como origem pública real."),
    ("100.64.0.0/10", "Shared Address Space / CGNAT", "RFC 6598", "Endereço compartilhado usado entre cliente e operadora em cenários de CGNAT; não é um IPv4 público comum."),
    ("198.18.0.0/15", "Benchmarking de dispositivos de rede", "RFC 2544 / RFC 6890", "Faixa destinada a testes; não deve ser tratada como endereço público de assinante."),
    ("169.254.0.0/16", "IPv4 link-local", "RFC 3927", "Válido apenas no enlace local; não é roteável na Internet pública."),
    ("127.0.0.0/8", "Loopback", "RFC 1122 / RFC 6890", "Refere-se ao próprio host; não identifica equipamento remoto."),
    ("10.0.0.0/8", "IPv4 privado", "RFC 1918", "Endereço interno; precisa ser correlacionado com topologia/NAT local para atribuição."),
    ("172.16.0.0/12", "IPv4 privado", "RFC 1918", "Endereço interno; precisa ser correlacionado com topologia/NAT local para atribuição."),
    ("192.168.0.0/16", "IPv4 privado", "RFC 1918", "Endereço interno; precisa ser correlacionado com topologia/NAT local para atribuição."),
    ("224.0.0.0/4", "Multicast IPv4", "RFC 5771", "Não representa um host unicast individual."),
    ("240.0.0.0/4", "Reserved for future use", "RFC 1112 / RFC 6890", "Faixa reservada; não deve ser interpretada como endereço global comum."),
    ("0.0.0.0/8", "This network / special use", "RFC 1122 / RFC 6890", "Uso especial; não representa, em regra, um host público remoto."),
    ("::/128", "IPv6 unspecified", "RFC 4291", "Endereço não especificado; não identifica host remoto."),
    ("::1/128", "IPv6 loopback", "RFC 4291", "Refere-se ao próprio host."),
    ("::ffff:0:0/96", "IPv4-mapped IPv6", "RFC 4291", "Representação IPv6 de um endereço IPv4 em APIs/sockets; deve-se extrair o IPv4 incorporado."),
    ("64:ff9b::/96", "NAT64 Well-Known Prefix", "RFC 6052", "Pode conter um IPv4 embutido em cenário NAT64."),
    ("64:ff9b:1::/48", "NAT64 local-use prefix", "RFC 8215", "Pode ser usado em tradução IPv4/IPv6 dentro de um domínio administrativo."),
    ("100::/64", "Discard-only IPv6", "RFC 6666", "Prefixo especial para descarte de tráfego; não representa endpoint público comum."),
    ("2001:db8::/32", "IPv6 de documentação", "RFC 3849", "Faixa reservada para exemplos e documentação."),
    ("2001::/32", "Teredo", "RFC 4380", "Endereço associado ao mecanismo de transição Teredo; pode encapsular informações IPv4/porta."),
    ("2002::/16", "6to4", "RFC 3056", "Mecanismo legado de transição; os 32 bits seguintes podem incorporar um IPv4."),
    ("fc00::/7", "Unique Local Address (ULA)", "RFC 4193", "Endereço IPv6 interno; não é globalmente roteável."),
    ("fe80::/10", "IPv6 link-local", "RFC 4291", "Válido apenas no enlace local; não identifica localização global."),
    ("ff00::/8", "IPv6 multicast", "RFC 4291", "Não representa um host unicast individual."),
]


def _match_special(ip_obj: ipaddress._BaseAddress) -> tuple[str | None, str | None, str | None, str | None]:
    for cidr, label, ref, note in SPECIAL_RANGES:
        net = ipaddress.ip_network(cidr)
        if ip_obj.version == net.version and ip_obj in net:
            return label, cidr, ref, note
    return None, None, None, None


def analyze_local_ip(value: str) -> LocalIPAnalysis:
    ip_obj = ipaddress.ip_address(value.strip())
    special, cidr, ref, note = _match_special(ip_obj)

    if note is None:
        if ip_obj.is_global:
            note = (
                "Endereço globalmente roteável. Atribuição a assinante ou usuário exige correlação temporal "
                "com registros do provedor e, conforme o cenário, porta lógica/protocolo."
            )
        elif ip_obj.is_private:
            note = "Endereço não global; a atribuição depende do contexto da rede onde foi observado."
        else:
            note = "Endereço de uso especial ou não global; interpretar conforme o contexto de rede."

    return LocalIPAnalysis(
        ip=str(ip_obj),
        version=ip_obj.version,
        compressed=ip_obj.compressed,
        exploded=ip_obj.exploded,
        integer=int(ip_obj),
        reverse_pointer=ip_obj.reverse_pointer,
        is_global=ip_obj.is_global,
        is_private=ip_obj.is_private,
        is_loopback=ip_obj.is_loopback,
        is_link_local=ip_obj.is_link_local,
        is_multicast=ip_obj.is_multicast,
        is_reserved=ip_obj.is_reserved,
        is_unspecified=ip_obj.is_unspecified,
        special_use=special,
        special_cidr=cidr,
        special_reference=ref,
        investigation_note=note,
    )


def extract_embedded_ipv4(value: str) -> dict[str, str] | None:
    """Extract obvious IPv4 information from transition formats when possible."""
    ip_obj = ipaddress.ip_address(value)
    if ip_obj.version != 6:
        return None

    if ip_obj.ipv4_mapped:
        return {"mechanism": "IPv4-mapped IPv6", "ipv4": str(ip_obj.ipv4_mapped)}

    # 6to4: 2002:V4ADDR::/48
    if ip_obj in ipaddress.ip_network("2002::/16"):
        packed = ip_obj.packed
        embedded = ipaddress.IPv4Address(packed[2:6])
        return {"mechanism": "6to4", "ipv4": str(embedded)}

    # Teredo parser available in stdlib.
    if ip_obj in ipaddress.ip_network("2001::/32"):
        try:
            server, client = ip_obj.teredo
            return {
                "mechanism": "Teredo",
                "server_ipv4": str(server),
                "client_ipv4": str(client),
            }
        except Exception:
            return {"mechanism": "Teredo"}

    # RFC 6052 WKP /96: last 32 bits are IPv4.
    if ip_obj in ipaddress.ip_network("64:ff9b::/96"):
        embedded = ipaddress.IPv4Address(ip_obj.packed[-4:])
        return {"mechanism": "NAT64 WKP", "ipv4": str(embedded)}

    return None
