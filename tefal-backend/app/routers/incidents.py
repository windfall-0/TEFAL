"""사건 API (5.1): ① 운영 현황, ② 사건 상세."""

import logging
import re
import time
from typing import Annotated

import httpx
from fastapi import APIRouter, Depends, Query, Request

from app.core.demo import demo_ip
from app.core.errors import ApiError
from app.core.params import ALLOWED_LEVELS, CommonFilters, common_filters
from app.core.timefmt import fmt_hm, fmt_hms, fmt_md
from app.core.validators import is_valid_k8s_name, validate_trace_id
from app.incidents.store import Incident, IncidentStore

log = logging.getLogger(__name__)
router = APIRouter(tags=["incidents"])

STATUS_LABEL = {"blocked": "차단됨", "unblocked": "미차단", "pending": "판정 중"}
WINDOW_MS = 5 * 60 * 1000
_INTERVAL_RE = re.compile(r"^(\d+)([smhd])$")
_UNIT_MS = {"s": 1000, "m": 60_000, "h": 3_600_000, "d": 86_400_000}
MAX_BUCKETS = 2000

Filters = Annotated[CommonFilters, Depends(common_filters)]


def _store(request: Request) -> IncidentStore:
    return request.app.state.incidents


def _is_unblocked(status: str) -> bool:
    # 판정 중은 미차단 쪽에 넣어 센다 (4.4)
    return status != "blocked"


def src_ip_text(inc: Incident, shown: str | None) -> str:
    """출발지 IP 표시. 없으면 이유: Falco 경보만으로 만든 사건이거나, 연결된 HTTP 요청(Beyla)이 없다."""
    if shown:
        return f"{shown} · 시연용" if shown != inc.src_ip else shown
    if inc.detected_by == "falco":
        return "확인 불가 (Falco 단독 경보)"
    if not inc.beyla_trace_id:
        return "확인 불가 (HTTP 요청 연결 없음)"
    return "확인 불가"


def to_model(inc: Incident, tz: str, demo_pool: list[str] | None = None) -> dict:
    ms = inc.anchor_ms
    src_ip = demo_ip(inc.src_ip, demo_pool or [], inc.trace_id)
    frac = f"{inc.start_ms % 1000:03d}"
    return {
        "trace_id": inc.trace_id,
        "start_ms": inc.start_ms,
        "anchor_ms": inc.anchor_ms,
        "time": fmt_hms(inc.start_ms, tz),
        "status": inc.status,
        "status_label": STATUS_LABEL[inc.status],
        "level": inc.level,
        "level_source": inc.level_source,
        "action": inc.action,
        "detected_by": inc.detected_by,
        "namespace": inc.namespace,
        "pod": inc.pod,
        "workload": f"{inc.namespace} / {inc.pod}",
        "node": inc.node,
        "runtime": inc.runtime,
        "runtime_detail": inc.runtime_detail or inc.runtime,
        "summary": inc.summary,
        "mitre": inc.mitre,
        "src_ip": src_ip,
        "src_ip_original": inc.src_ip,
        "src_ip_demo": src_ip != inc.src_ip,
        # 화면 표시용: 시연 IP는 실제 출발지가 아니라는 표시를, 없으면 이유를 붙인다
        "src_ip_text": src_ip_text(inc, src_ip),
        "exec_id": inc.exec_id,
        "parent_exec_id": inc.parent_exec_id,
        "policy": inc.policy,
        "member_count": inc.member_count,
        "falco_rules": inc.falco_rules,
        "beyla_trace_id": inc.beyla_trace_id,
        "beyla_link_confidence": inc.beyla_link_confidence,
        "status_text": f"{STATUS_LABEL[inc.status]} · {inc.action}",
        "time_text": f"{fmt_hms(inc.start_ms, tz)}.{frac}",
        "mitre_text": " · ".join(inc.mitre) if inc.mitre else "-",
        "window_from_ms": inc.start_ms - WINDOW_MS,
        "window_to_ms": max(ms, inc.last_ms) + WINDOW_MS,
    }


@router.get("/incidents")
async def list_incidents(
    request: Request, f: Filters, limit: Annotated[int, Query(ge=1, le=1000)] = 100
) -> list[dict]:
    s = request.app.state.settings
    return [to_model(i, s.display_tz, s.demo_src_ip_list) for i in await _store(request).query(f, limit)]


async def _running_pods(request: Request, namespace: str | None) -> int | None:
    """Running pod 수 (kube-state-metrics). namespace 필터가 전체면 감시 대상 namespace 기준."""
    s = request.app.state.settings
    namespaces = [namespace] if namespace else s.watch_namespace_list
    if not namespaces:
        return None
    key = ",".join(sorted(namespaces))
    cache: dict = request.app.state.pod_count_cache
    hit = cache.get(key)
    if hit and time.monotonic() - hit[0] < 30:
        return hit[1]
    # namespace는 k8s 이름([a-z0-9-])만 통과시킨다. re.escape는 '-'를 '\-'로 바꿔 PromQL 문자열 오류가 난다
    namespaces = [n for n in namespaces if is_valid_k8s_name(n)]
    if not namespaces:
        return None
    sel = "|".join(namespaces)
    expr = f'count(kube_pod_status_phase{{phase="Running", namespace=~"{sel}"}} == 1) or vector(0)'
    try:
        r = await request.app.state.http.get(f"{s.prometheus_url.rstrip('/')}/api/v1/query", params={"query": expr})
        r.raise_for_status()
        result = r.json()["data"]["result"]
        value = int(float(result[0]["value"][1])) if result else 0
    except (httpx.HTTPError, KeyError, ValueError, IndexError) as e:
        log.warning("Prometheus 조회 실패: %s", type(e).__name__)
        return hit[1] if hit else None
    cache[key] = (time.monotonic(), value)
    return value


@router.get("/incidents/summary")
async def summary(request: Request, f: Filters) -> dict:
    tz = request.app.state.settings.display_tz
    items = await _store(request).query(f)
    unblocked = [i for i in items if _is_unblocked(i.status)]
    out = {
        "unblocked_count": len(unblocked),
        "unblocked_last_time": fmt_hm(max(i.start_ms for i in unblocked), tz) if unblocked else None,
        "blocked_count": len(items) - len(unblocked),
        "attacked_workloads": len({(i.namespace, i.pod) for i in items}),
        "total_workloads": await _running_pods(request, f.namespace),
    }
    for lv in ALLOWED_LEVELS:
        out[f"level_{lv}_count"] = sum(1 for i in items if i.level == lv)
    return out


@router.get("/incidents/by-workload")
async def by_workload(request: Request, f: Filters) -> list[dict]:
    groups: dict[str, dict] = {}
    for i in await _store(request).query(f):
        g = groups.setdefault(i.pod, {"pod": i.pod, "blocked": 0, "unblocked": 0, "total": 0})
        g["unblocked" if _is_unblocked(i.status) else "blocked"] += 1
        g["total"] += 1
    rows = sorted(groups.values(), key=lambda g: (-g["unblocked"], -g["total"], g["pod"]))
    for g in rows:
        g["label"] = f"{g['total']}건" + (f" · 미차단 {g['unblocked']}" if g["unblocked"] else "")
    return rows


def _interval_ms(value: str) -> int:
    m = _INTERVAL_RE.fullmatch(value.strip())
    if not m or int(m.group(1)) == 0:
        raise ApiError(400, "invalid_interval", "interval은 30s, 5m, 1h 같은 형식이어야 합니다")
    return int(m.group(1)) * _UNIT_MS[m.group(2)]


@router.get("/incidents/timeseries")
async def timeseries(request: Request, f: Filters, interval: str = "5m") -> list[dict]:
    step = _interval_ms(interval)
    first = f.from_ms - f.from_ms % step
    n = (f.to_ms - first) // step + 1
    if n > MAX_BUCKETS:
        step = -(-(f.to_ms - first) // (MAX_BUCKETS - 1))  # 구간이 너무 많으면 간격을 늘린다
        first = f.from_ms - f.from_ms % step
        n = (f.to_ms - first) // step + 1
    buckets = [{"time_ms": first + k * step, "blocked": 0, "unblocked": 0} for k in range(n)]
    for i in await _store(request).query(f):
        k = (i.start_ms - first) // step
        if 0 <= k < n:
            buckets[k]["unblocked" if _is_unblocked(i.status) else "blocked"] += 1
    return buckets


@router.get("/incidents/recent")
async def recent(request: Request, limit: Annotated[int, Query(ge=1, le=200)] = 50) -> list[dict]:
    """② 사건 선택 목록: 시간 범위와 상관없이 최신순. 맨 위가 가장 최근 사건(기본 선택).

    `option_text`는 드롭다운 표시용("10:55:28 · php2shell · 행위 요약"), `trace_id`는 값.
    """
    s = request.app.state.settings
    now = int(time.time() * 1000)
    incs = await _store(request).query(CommonFilters(0, now, None, None, None))
    incs = sorted(incs, key=lambda i: i.start_ms, reverse=True)[:limit]
    out = []
    for i in incs:
        m = to_model(i, s.display_tz, s.demo_src_ip_list)
        day = fmt_md(i.start_ms, s.display_tz)
        workload = re.sub(r"(-[a-z0-9]{8,10})?-[a-z0-9]{5}$", "", i.pod)
        out.append({"trace_id": i.trace_id, "start_ms": i.start_ms,
                    "option_text": f"{day} {fmt_hms(i.start_ms, s.display_tz)} · {workload} · {i.summary[:40]}",
                    "window_from_ms": m["window_from_ms"], "window_to_ms": m["window_to_ms"]})
    return out


@router.get("/incidents/{trace_id}")
async def get_incident(request: Request, trace_id: str) -> dict:
    tid = validate_trace_id(trace_id)
    inc = await _store(request).get(tid)
    if inc is None:
        raise ApiError(404, "not_found", "사건이 없습니다")
    s = request.app.state.settings
    return to_model(inc, s.display_tz, s.demo_src_ip_list)
