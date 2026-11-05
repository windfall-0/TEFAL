"""입력 검증 (8장): trace_id hex 32자, ip는 ipaddress 모듈, 사설 IP 판정 (5.4 TI 규칙)."""

import ipaddress
import re

from app.core.errors import ApiError

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address

_TRACE_ID_RE = re.compile(r"^[0-9a-f]{32}$")
_K8S_NAME_RE = re.compile(r"^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$")

# 문서에 명시된 대역. is_global 검사와 함께 이중으로 본다.
_NON_PUBLIC_NETS = [
    ipaddress.ip_network(n)
    for n in (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "100.64.0.0/10",
        "fc00::/7",  # IPv6 ULA
        "fe80::/10",  # IPv6 링크로컬
        "::1/128",
    )
]


def validate_trace_id(value: str) -> str:
    v = value.strip().lower()
    if not _TRACE_ID_RE.fullmatch(v):
        raise ApiError(400, "invalid_trace_id", "trace_id는 16진수 32자여야 합니다")
    return v


def parse_ip(value: str) -> IPAddress:
    try:
        ip = ipaddress.ip_address(value.strip())
    except ValueError:
        raise ApiError(400, "invalid_ip", f"IP 주소 형식이 아닙니다: {value[:64]}") from None
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        return ip.ipv4_mapped
    return ip


def is_public_ip(ip: IPAddress) -> bool:
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    if any(ip in net for net in _NON_PUBLIC_NETS if net.version == ip.version):
        return False
    return ip.is_global and not ip.is_multicast


def is_valid_k8s_name(value: str) -> bool:
    return bool(_K8S_NAME_RE.fullmatch(value))
