"""위협 인텔리전스 API (5.4): ③ 위협 인텔리전스, ② 출발지 IP 요약."""

import ipaddress
import logging
from typing import Annotated

from fastapi import APIRouter, Query, Request

from app.core.demo import demo_ip
from app.core.errors import ApiError
from app.core.params import CommonFilters, parse_time_range
from app.core.timefmt import fmt_hm, fmt_md
from app.core.validators import is_public_ip, parse_ip
from app.ti.service import TiService

log = logging.getLogger(__name__)
router = APIRouter(tags=["ti"])

NEW_LOOKUPS_PER_REQUEST = 10  # 목록 한 번에 새로 외부 조회할 IP 수 (나머지는 캐시만, 다음 새로고침에 채운다)
ROLE_TEXT = {"src": "출발지", "demo": "출발지 (시연용)", "dst": "외부 연결"}
DEMO_NOTICE = "시연용 IP · 실제 출발지 아님"  # 선택 IP 상세 Stat 칸이 좁아 짧게


def _ti(request: Request) -> TiService:
    return request.app.state.ti


def _public(ip: str | None) -> str | None:
    if not ip:
        return None
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    return str(addr) if is_public_ip(addr) else None


def _mark_demo(request: Request, row: dict) -> None:
    demo = row["ip"] in request.app.state.settings.demo_src_ip_list
    row["demo"] = demo
    row["notice"] = DEMO_NOTICE if demo else None


def _checked(epoch_sec: float | None, tz: str) -> str | None:
    return fmt_hm(int(epoch_sec * 1000), tz) if epoch_sec else None


async def _targets(request: Request, from_ms: int, to_ms: int) -> dict[str, dict]:
    """시간 범위 안 TI 대상 IP: 사건 출발지 + 감시 pod의 외부 연결 목적지(공인 IP만)."""
    store = request.app.state.incidents
    pool = request.app.state.settings.demo_src_ip_list
    incs = await store.query(CommonFilters(from_ms, to_ms, None, None, None))
    out: dict[str, dict] = {}
    for inc in incs:
        shown = demo_ip(inc.src_ip, pool, inc.trace_id)  # 시연 모드면 사건 화면과 같은 IP를 쓴다
        ip = _public(shown)
        if ip:
            t = out.setdefault(ip, {"roles": set(), "incidents": set(), "pods": set()})
            t["roles"].add("demo" if shown != inc.src_ip else "src")
            t["incidents"].add(inc.trace_id)
            t["last_attack_ms"] = max(t.get("last_attack_ms", 0), inc.last_ms)  # 출발지 사건만 (외부 연결은 공격이 아니다)
    for r in await store.remote_ips(from_ms * 1_000_000, to_ms * 1_000_000):
        ip = _public(r["ip"])  # 수집기도 공인 IP만 쌓지만 외부로 나가기 전에 한 번 더 막는다
        if ip is None:
            continue
        t = out.setdefault(ip, {"roles": set(), "incidents": set(), "pods": set()})
        t["roles"].add("dst")
        t["pods"].add(r["pod"])
        # 그 pod의 사건 중 연결 시각 ±60초에 걸친 사건을 관련 사건으로 본다
        lo, hi = r["first_ns"] // 1_000_000 - 60_000, r["last_ns"] // 1_000_000 + 60_000
        t["incidents"].update(i.trace_id for i in incs if i.pod == r["pod"] and i.last_ms >= lo and i.start_ms <= hi)
    return out


async def _rows(request: Request, from_ms: int, to_ms: int) -> list[dict]:
    ti, tz = _ti(request), request.app.state.settings.display_tz
    rows, budget = [], NEW_LOOKUPS_PER_REQUEST
    for ip, t in sorted((await _targets(request, from_ms, to_ms)).items()):
        row = await ti.lookup(ip, allow_fetch=budget > 0)
        if not row["cached"]:
            budget -= 1
        row["role"] = " · ".join(ROLE_TEXT[r] for r in ("src", "demo", "dst") if r in t["roles"])
        _mark_demo(request, row)
        row["related_incidents"] = len(t["incidents"])
        row["related_pods"] = ", ".join(sorted(t["pods"]))
        row["last_checked"] = _checked(row.pop("checked_at"), tz)
        at = t.get("last_attack_ms")
        row["last_attack"] = f"{fmt_md(at, tz)} {fmt_hm(at, tz)}" if at else None
        rows.append(row)
    return rows


@router.get("/ti/ips")
async def ips(
    request: Request,
    from_: Annotated[int | None, Query(alias="from")] = None,
    to: int | None = None,
    min_abuse: Annotated[int, Query(ge=0, le=100)] = 0,
) -> list[dict]:
    from_ms, to_ms = parse_time_range(from_, to)
    rows = await _rows(request, from_ms, to_ms)
    rows = [r for r in rows if (r["abuse_score"] or 0) >= min_abuse]
    return sorted(rows, key=lambda r: (-(r["abuse_score"] or -1), r["ip"]))


@router.get("/ti/ip/{ip}")
async def ip_detail(request: Request, ip: str) -> dict:
    addr = parse_ip(ip)
    if not is_public_ip(addr):
        raise ApiError(400, "private_ip", "사설·예약 IP는 외부 평판 조회를 하지 않습니다")
    row = await _ti(request).lookup(str(addr))
    _mark_demo(request, row)
    row["last_checked"] = _checked(row.pop("checked_at"), request.app.state.settings.display_tz)
    row["vt_text"] = f"{row['vt_malicious']} / {row['vt_total']} 악성" if row["vt_total"] is not None else None
    return row


@router.get("/ti/summary")
async def summary(
    request: Request,
    from_: Annotated[int | None, Query(alias="from")] = None,
    to: int | None = None,
) -> dict:
    from_ms, to_ms = parse_time_range(from_, to)
    ti = _ti(request)
    targets = await _targets(request, from_ms, to_ms)
    high = 0
    for ip in targets:
        row = await ti.lookup(ip, allow_fetch=False)  # 요약은 외부 조회를 하지 않는다 (목록이 채운다)
        high += row["risk_level"] == "high"
    u = await ti.usage()
    looked = u["cache_hit"] + u["cache_miss"]
    return {
        "public_ip_count": len(targets),
        "high_risk_count": high,
        "abuseipdb_used": u["abuseipdb_used"], "abuseipdb_limit": u["abuseipdb_limit"],
        "virustotal_used": u["virustotal_used"], "virustotal_limit": u["virustotal_limit"],
        "ipinfo_used": u["ipinfo_used"], "ipinfo_limit": u["ipinfo_limit"], "ipinfo_enabled": u["ipinfo_enabled"],
        "cache_ttl_hours": request.app.state.settings.ti_cache_ttl_hours,
        "cache_hit_rate": round(u["cache_hit"] / looked, 3) if looked else None,
        "demo_mode": bool(request.app.state.settings.demo_src_ip_list),
        "demo_lookups": u["demo_lookups"],
    }


@router.get("/ti/files")
async def files(request: Request) -> list[dict]:
    # 파일 해시는 Tetragon 로그에 없다(미결정 1: IMA 해시 정책 필요). 수집 전까지 빈 목록.
    return []
