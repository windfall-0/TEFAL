"""Falco 루프백 오탐 (4.3.1).

Falco `outbound` 매크로는 IPv4 루프백(127.0.0.0/8)만 빼고 IPv6 루프백(::1)·IPv4-mapped(::ffff:127.0.0.1)는
외부 연결로 본다. Apache는 기동할 때(주소 확인용 UDP connect, 포트 0)와 자식 프로세스를 정리할 때
(internal dummy connection, ::1 → ::1:80) 자기 자신에게 연결하므로 "Outbound Connection" 경보가 난다.

- 새 경보: 웹훅(`ingest_falco`)과 탐지 수 수집기에서 버린다 (FALCO_IGNORE_LOOPBACK, 기본 켜짐).
- 지난 데이터: 기동할 때 한 번 Loki의 Falco 원본을 다시 읽어, 경보가 모두 루프백인 Falco 단독 사건과
  탐지 행에 `false_positive`를 적는다. 지우지 않는다(되돌리려면 그 칸을 NULL로).
"""

import ipaddress
import json
import logging

import httpx

from app.config import Settings
from app.incidents.store import IncidentStore
from app.incidents.tetragon import parse_time_ns

log = logging.getLogger(__name__)

NS = 1_000_000_000
MS = 1_000_000
REASON = "loopback"  # 저장되는 이유
BACKFILL_KEY = "falco_loopback_fp_v1"
WINDOW_NS = 2 * NS  # 사건·탐지 시각 앞뒤로 원본을 찾는 폭
PAGE = 1000


def loopback_host(host: str) -> bool:
    try:
        addr = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return False
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
        addr = addr.ipv4_mapped
    return addr.is_loopback or addr.is_unspecified


def is_loopback_alert(of: dict) -> bool:
    """연결 경보(fd.name = "a:p->b:p")인데 출발지·상대가 루프백(미지정 포함)이거나 상대 포트가 0이면 True.
    연결이 아닌 경보(셸 실행 등)는 False."""
    name = str((of or {}).get("fd.name") or "")
    if "->" not in name:
        return False
    left, right = name.split("->", 1)
    rhost, _, rport = right.rpartition(":")
    return loopback_host(left.rpartition(":")[0]) or loopback_host(rhost) or rport == "0"


def _alerts(lines: list[tuple[int, str]]) -> list[tuple[int, str, str | None, str | None, bool]]:
    """(시각 ns, 룰, namespace, pod, 루프백 여부)."""
    out = []
    for loki_ns, line in lines:
        try:
            d = json.loads(line)
        except ValueError:
            continue
        if not isinstance(d, dict) or not d.get("rule"):
            continue
        of = d.get("output_fields") or {}
        t = parse_time_ns(d.get("time") or "") or loki_ns
        out.append((t, d["rule"], of.get("k8s.ns.name"), of.get("k8s.pod.name"), is_loopback_alert(of)))
    return out


async def _read(loki, selector: str, start_ns: int, end_ns: int) -> list[tuple[int, str]]:
    lines, cur = [], start_ns
    while cur < end_ns:
        page = await loki.query_range(selector, cur, end_ns, limit=PAGE)
        lines += page
        if len(page) < PAGE:
            break
        cur = page[-1][0] + 1
    return lines


def _all_loopback(alerts, lo_ns: int, hi_ns: int, rules: set[str], ns: str | None, pod: str | None) -> bool:
    hit = [a for a in alerts if lo_ns <= a[0] <= hi_ns and a[1] in rules
           and (ns is None or a[2] == ns) and (pod is None or a[3] == pod)]
    return bool(hit) and all(a[4] for a in hit)


async def backfill_false_positives(store: IncidentStore, loki, settings: Settings, lock) -> tuple[int, int]:
    """지난 Falco 단독 사건·탐지 행 중 루프백 경보뿐인 것에 오탐 표시. (사건 수, 탐지 행 수)."""
    from app.core.params import CommonFilters

    if not settings.falco_ignore_loopback or await store.get_state(BACKFILL_KEY):
        return 0, 0
    incs = [i for i in await store.query(CommonFilters(0, 2**62, None, None, None)) if i.detected_by == "falco"]
    dets = await store.falco_detections()
    times = [i.start_ms * MS for i in incs] + [d["first_ns"] for d in dets]
    ends = [i.last_ms * MS for i in incs] + [d["last_ns"] for d in dets]
    n_inc = n_det = 0
    if times:
        selector = settings.loki_falco_selector + ' |= `"rule"` |= `->`'  # 연결 경보만 (fd.name에 "->")
        try:
            # 사건·탐지가 몰린 구간만 하루 단위로 나눠 읽는다
            alerts = []
            for day in sorted({t // (86400 * NS) for t in times}):
                lo, hi = day * 86400 * NS, (day + 1) * 86400 * NS
                if any(lo - WINDOW_NS <= t and s <= hi + WINDOW_NS for t, s in zip(ends, times)):
                    alerts += _alerts(await _read(loki, selector, lo - WINDOW_NS, hi + WINDOW_NS))
        except (httpx.HTTPError, KeyError, ValueError) as e:
            log.warning("오탐 표시: Loki 조회 실패 (%s), 다음 기동 때 다시 한다", type(e).__name__)
            return 0, 0
        async with lock:
            for inc in incs:
                fresh = await store.get(inc.trace_id)
                if fresh is None or fresh.false_positive or fresh.detected_by != "falco":
                    continue
                if _all_loopback(alerts, inc.start_ms * MS - WINDOW_NS, inc.last_ms * MS + WINDOW_NS,
                                 set(fresh.falco_rules), fresh.namespace, fresh.pod):
                    fresh.false_positive = REASON
                    await store.save(fresh)
                    n_inc += 1
            for d in dets:
                if _all_loopback(alerts, d["first_ns"] - WINDOW_NS, d["last_ns"] + WINDOW_NS,
                                 {d["name"]}, d["namespace"], None):
                    await store.mark_detection_fp(d["rowid"], REASON)
                    n_det += 1
    async with lock:
        await store.set_state(BACKFILL_KEY, f"{n_inc},{n_det}")
        await store.commit()
    log.info("오탐 표시: Falco 루프백 사건 %d건, 탐지 %d건", n_inc, n_det)
    return n_inc, n_det
