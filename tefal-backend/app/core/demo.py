"""시연 모드: 사건의 내부 출발지 IP를 정해진 공인 IP로 바꿔 보여 준다.

NodePort가 master에서 SNAT되어 출발지가 클러스터 내부 IP(10.233.x.x)로만 남는다. 그러면 TI·GeoIP 화면이
비므로, 시연할 때만 `DEMO_SRC_IP_POOL`의 공인 IP로 바꿔 내보낸다.

- 응답에 실을 때만 바꾼다. 사건 DB, Loki, Tempo에는 원래 값이 그대로 남는다.
- 같은 내부 IP는 항상 같은 공인 IP로 바뀐다(해시). 이미 공인 IP인 값은 그대로 둔다.
- 풀이 비어 있으면 아무것도 바꾸지 않는다(기본값, 꺼짐).
"""

import hashlib
import ipaddress


def parse_pool(raw: str) -> list[str]:
    """쉼표로 구분한 공인 IP 목록. 사설·예약 IP가 섞여 있으면 ValueError."""
    out: list[str] = []
    for part in raw.split(","):
        part = part.strip()
        if not part:
            continue
        addr = ipaddress.ip_address(part)  # 형식이 틀리면 ValueError
        if not addr.is_global:
            raise ValueError(f"DEMO_SRC_IP_POOL에는 공인 IP만 넣을 수 있습니다: {part}")
        out.append(str(addr))
    return list(dict.fromkeys(out))  # 순서 유지 중복 제거


def demo_ip(ip: str | None, pool: list[str]) -> str | None:
    """시연용으로 바꾼 IP. 바꿀 대상이 아니면 받은 값을 그대로 돌려준다."""
    if not ip or not pool:
        return ip
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return ip
    if addr.is_global:
        return ip
    idx = int.from_bytes(hashlib.sha256(str(addr).encode()).digest()[:8], "big") % len(pool)
    return pool[idx]
