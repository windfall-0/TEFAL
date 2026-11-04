"""정책 API (5.2): ① 정책 상태 · 방어가 제대로 도는가."""

import asyncio
import logging
from typing import Annotated

import httpx
from fastapi import APIRouter, Depends, Request

from app import policies
from app.core.errors import ApiError
from app.core.params import CommonFilters, common_filters
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


@router.get("/policies/stats")
async def stats(request: Request, f: Annotated[CommonFilters, Depends(common_filters)]) -> list[dict]:
    k8s = _k8s(request)
    s = request.app.state.settings
    levels = request.app.state.sigma_levels
    rng, at = _range(f)

    async def build():
        tps, (rules_text, _), tet, fal = await asyncio.gather(
            _tracing_policies(k8s),
            _falco_rules(request, k8s),
            _loki(request, tetragon_query(s.loki_tetragon_selector, f.namespace, rng), at),
            _loki(request, falco_query(s.loki_falco_selector, f.namespace, rng), at),
        )
        if f.namespace:
            tps = [tp for tp in tps if tp.get("kind") != "TracingPolicyNamespaced"
                   or (tp.get("metadata") or {}).get("namespace") == f.namespace]
        tet_hits = {x["metric"].get("p", ""): int(float(x["value"][1])) for x in tet}
        fal_hits: dict[str, int] = {}
        fal_prio = policies.falco_rule_priorities(rules_text)  # 정의 우선, 없으면 경보의 priority
        for x in fal:
            rule = x["metric"].get("rule", "")
            fal_hits[rule] = fal_hits.get(rule, 0) + int(float(x["value"][1]))
            fal_prio.setdefault(rule, x["metric"].get("priority", ""))  # 기본 룰
        rows = policies.tetragon_rows(tps, tet_hits, levels.tetragon) + policies.falco_rows(
            policies.falco_rule_names(rules_text), fal_hits, lambda r: levels.falco(r, fal_prio.get(r, "")))
        return sorted(rows, key=lambda r: (-r["hits"], r["policy"]))

    # Grafana는 새로고침마다 from/to가 조금씩 바뀌므로 30초 단위로 묶어서 캐시한다
    key = f"policies:{f.namespace}:{f.from_ms // 30000}:{f.to_ms // 30000}"
    return await _cached(request, key, CACHE_SEC, build)
