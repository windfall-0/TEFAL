"""정책 API (5.2): ① 정책 상태 · 방어가 제대로 도는가."""

import asyncio
import logging
from typing import Annotated

import httpx
from fastapi import APIRouter, Depends, Request

from app import policies
from app.core.errors import ApiError
from app.core.params import ALLOWED_LEVELS, CommonFilters, common_filters
from app.routers.infra import _cached, _falco_rules, _k8s, _tracing_policies

log = logging.getLogger(__name__)
router = APIRouter(tags=["policies"])

CACHE_SEC = 30
_EVENT_TYPES = ("process_kprobe", "process_uprobe", "process_lsm", "process_tracepoint")


def _range(f: CommonFilters) -> tuple[str, float]:
    sec = max(1, (f.to_ms - f.from_ms) // 1000)
    return f"[{sec}s]", f.to_ms / 1000


def tetragon_query(selector: str, namespace: str | None, rng: str) -> str:
    # 이벤트 종류마다 JSON 경로가 달라서 모두 꺼낸 뒤 이어 붙인다(한 줄에는 한 종류만 있다)
    fields = ", ".join(
        f'p{i}="{t}.policy_name", n{i}="{t}.process.pod.namespace"' for i, t in enumerate(_EVENT_TYPES))
    p = "".join(f"{{{{.p{i}}}}}" for i in range(len(_EVENT_TYPES)))
    n = "".join(f"{{{{.n{i}}}}}" for i in range(len(_EVENT_TYPES)))
    ns = f' | n="{namespace}"' if namespace else ""
    return (f'sum by (p) (count_over_time({selector} |= "policy_name" | json {fields} '
            f'| label_format p="{p}", n="{n}" | p!=""{ns} {rng}))')


def falco_query(selector: str, namespace: str | None, rng: str) -> str:
    ns = f' | ns="{namespace}"' if namespace else ""
    return (f'sum by (rule, priority) (count_over_time({selector} |= "\\"rule\\"" '
            f'| json rule="rule", priority="priority", ns="output_fields[\\"k8s.ns.name\\"]"{ns} {rng}))')


async def _loki(request: Request, expr: str, at: float) -> list[dict]:
    s = request.app.state.settings
    try:
        r = await request.app.state.http.get(f"{s.loki_url.rstrip('/')}/loki/api/v1/query",
                                             params={"query": expr, "time": at}, timeout=30.0)
        r.raise_for_status()
        return r.json()["data"]["result"]
    except (httpx.HTTPError, KeyError, ValueError) as e:
        log.warning("정책 히트 Loki 조회 실패: %s", type(e).__name__)
        raise ApiError(502, "loki_error", "정책 히트 수를 Loki에서 읽지 못했습니다") from None


async def _hits(request: Request, f: CommonFilters) -> dict:
    """시간 범위 안 정책·룰별 로그 수. /policies/stats와 /policies/levels가 같이 쓴다 (30초 캐시)."""
    k8s = request.app.state.k8s
    s = request.app.state.settings
    rng, at = _range(f)

    async def build():
        async def rules():  # K8s 없이도 로그 수는 센다 (Falco 룰 priority만 빠짐)
            return await _falco_rules(request, k8s) if k8s is not None else ("", 0)

        (rules_text, _), tet, fal = await asyncio.gather(
            rules(),
            _loki(request, tetragon_query(s.loki_tetragon_selector, f.namespace, rng), at),
            _loki(request, falco_query(s.loki_falco_selector, f.namespace, rng), at),
        )
        tet_hits = {x["metric"].get("p", ""): int(float(x["value"][1])) for x in tet}
        fal_hits: dict[str, int] = {}
        fal_prio = policies.falco_rule_priorities(rules_text)  # 정의 우선, 없으면 경보의 priority
        for x in fal:
            rule = x["metric"].get("rule", "")
            fal_hits[rule] = fal_hits.get(rule, 0) + int(float(x["value"][1]))
            fal_prio.setdefault(rule, x["metric"].get("priority", ""))  # 기본 룰
        return {"rules_text": rules_text, "tetragon": tet_hits, "falco": fal_hits, "falco_priority": fal_prio}

    # Grafana는 새로고침마다 from/to가 조금씩 바뀌므로 30초 단위로 묶어서 캐시한다
    key = f"hits:{f.namespace}:{f.from_ms // 30000}:{f.to_ms // 30000}"
    return await _cached(request, key, CACHE_SEC, build)


async def _current_policies(request: Request, f: CommonFilters) -> list[dict]:
    """지금 클러스터에 있는 TracingPolicy. namespace를 주면 다른 namespace의 TracingPolicyNamespaced는 뺀다."""
    tps = await _tracing_policies(_k8s(request))
    if f.namespace:
        tps = [tp for tp in tps if tp.get("kind") != "TracingPolicyNamespaced"
               or (tp.get("metadata") or {}).get("namespace") == f.namespace]
    return tps


@router.get("/policies/stats")
async def stats(request: Request, f: Annotated[CommonFilters, Depends(common_filters)]) -> list[dict]:
    levels = request.app.state.sigma_levels
    tps, h = await asyncio.gather(_current_policies(request, f), _hits(request, f))
    prio = h["falco_priority"]
    rows = policies.tetragon_rows(tps, h["tetragon"], levels.tetragon) + policies.falco_rows(
        policies.falco_rule_names(h["rules_text"]), h["falco"], lambda r: levels.falco(r, prio.get(r, "")))
    return sorted(rows, key=lambda r: (-r["hits"], r["policy"]))


@router.get("/policies/levels")
async def level_counts(request: Request, f: Annotated[CommonFilters, Depends(common_filters)]) -> dict:
    """① 경고 단계별 탐지 · 로그 기준. 사건 수가 아니라 Tetragon·Falco 로그 한 줄을 1로 센다.

    Tetragon은 지금 클러스터에 있는 TracingPolicy의 로그만 센다(옛 테스트 정책 로그는 Loki에 남아 있어도 뺀다).
    Falco는 모든 룰을 세되 자체 상태 경보는 뺀다.
    """
    levels = request.app.state.sigma_levels
    tps, h = await asyncio.gather(_current_policies(request, f), _hits(request, f))
    current = {tp["metadata"]["name"] for tp in tps}
    counts = dict.fromkeys(ALLOWED_LEVELS, 0)
    def add(level: str, n: int) -> None:
        counts[level if level in counts else "informational"] += n

    for policy, n in h["tetragon"].items():
        if policy in current:
            add(levels.tetragon(policy), n)
    for rule, n in h["falco"].items():
        if not rule.startswith(policies.FALCO_INTERNAL):
            add(levels.falco(rule, h["falco_priority"].get(rule, "")), n)
    return {"total": sum(counts.values()), **{f"level_{k}_count": v for k, v in counts.items()}}
