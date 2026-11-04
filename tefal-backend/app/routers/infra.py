"""인프라 API (5.5): ④ 인프라 대시보드."""

import asyncio
import logging
import time
from typing import Annotated

import httpx
from fastapi import APIRouter, Query, Request

from app import infra
from app.core.errors import ApiError
from app.core.validators import is_valid_k8s_name
from app.k8s import K8sClient, K8sError

log = logging.getLogger(__name__)
router = APIRouter(tags=["infra"])

CACHE_SEC = 30
BPF_LSM_CACHE_SEC = 300


def _k8s(request: Request) -> K8sClient:
    k8s = request.app.state.k8s
    if k8s is None:
        raise ApiError(503, "k8s_unavailable", "K8s API를 쓸 수 없습니다 (ServiceAccount 토큰 없음)")
    return k8s


async def _cached(request: Request, key: str, ttl: float, fn):
    cache: dict = request.app.state.infra_cache
    hit = cache.get(key)
    if hit and time.monotonic() - hit[0] < ttl:
        return hit[1]
    try:
        value = await fn()
    except K8sError as e:
        log.warning("K8s API 실패: %s", e)
        if hit:
            return hit[1]  # 직전 값으로 응답 (3.4 stale)
        raise ApiError(502, "k8s_error", str(e)) from None
    cache[key] = (time.monotonic(), value)
    return value


async def _tracing_policies(k8s: K8sClient) -> list[dict]:
    cluster, namespaced = await asyncio.gather(
        k8s.items("/apis/cilium.io/v1alpha1/tracingpolicies"),
        k8s.items("/apis/cilium.io/v1alpha1/tracingpoliciesnamespaced"),
    )
    for tp in cluster:
        tp.setdefault("kind", "TracingPolicy")
    for tp in namespaced:
        tp.setdefault("kind", "TracingPolicyNamespaced")
    return cluster + namespaced


async def _network_policies(k8s: K8sClient) -> list[dict]:
    cnp, ccnp = await asyncio.gather(
        k8s.items("/apis/cilium.io/v2/ciliumnetworkpolicies"),
        k8s.items("/apis/cilium.io/v2/ciliumclusterwidenetworkpolicies"),
    )
    for c in cnp:
        c.setdefault("kind", "CiliumNetworkPolicy")
    for c in ccnp:
        c.setdefault("kind", "CiliumClusterwideNetworkPolicy")
    return cnp + ccnp


async def _falco_rules(request: Request, k8s: K8sClient) -> tuple[str, int]:
    ns, _, name = request.app.state.settings.falco_rules_configmap.partition("/")
    try:
        cm = await k8s.get(f"/api/v1/namespaces/{ns}/configmaps/{name}")
    except K8sError as e:
        log.warning("Falco 커스텀 룰 ConfigMap을 읽지 못함: %s", e)
        return "", 0
    text = "\n".join((cm.get("data") or {}).values())
    return text, text.count("- rule:")


@router.get("/infra/policies")
async def policies(request: Request) -> dict:
    k8s = _k8s(request)

    async def build():
        tps, cnps, (_, falco_n) = await asyncio.gather(
            _tracing_policies(k8s), _network_policies(k8s), _falco_rules(request, k8s)
        )
        isolate = [c for c in cnps if ((c.get("metadata") or {}).get("labels") or {}).get("tefal.io/isolate") == "true"]
        isolated = 0
        if isolate:
            pods = await k8s.items("/api/v1/pods")
            for p in pods:
                labels = (p.get("metadata") or {}).get("labels") or {}
                ns = (p.get("metadata") or {}).get("namespace")
                if any((c.get("kind") == "CiliumClusterwideNetworkPolicy" or c["metadata"].get("namespace") == ns)
                       and infra.selector_matches((c.get("spec") or {}).get("endpointSelector"), labels) for c in isolate):
                    isolated += 1
        return {
            "total": len(tps) + falco_n,
            "tracing_policies": len(tps),
            "tracing_block_policies": sum(1 for tp in tps if infra.is_block_policy(tp)),
            "falco_custom_rules": falco_n,
            "isolated_workloads": isolated,
        }

    return await _cached(request, "policies", CACHE_SEC, build)


async def _bpf_lsm_nodes(request: Request) -> set[str]:
    """최근 7일 process_lsm 이벤트가 나온 노드 = BPF LSM이 동작하는 노드."""
    cache: dict = request.app.state.infra_cache
    hit = cache.get("bpf_lsm")
    if hit and time.monotonic() - hit[0] < BPF_LSM_CACHE_SEC:
        return hit[1]
    s = request.app.state.settings
    expr = (f'sum by (node_name) (count_over_time({s.loki_tetragon_selector} |= "\\"process_lsm\\"" '
            f'| json node_name="node_name" [7d]))')
    try:
        r = await request.app.state.http.get(f"{s.loki_url.rstrip('/')}/loki/api/v1/query",
                                             params={"query": expr}, timeout=20.0)
        r.raise_for_status()
        nodes = {x["metric"].get("node_name") for x in r.json()["data"]["result"]}
    except (httpx.HTTPError, KeyError, ValueError) as e:
        log.warning("BPF LSM 판단용 Loki 조회 실패: %s", type(e).__name__)
        return hit[1] if hit else set()
    cache["bpf_lsm"] = (time.monotonic(), nodes)
    return nodes


@router.get("/infra/nodes")
async def nodes(request: Request) -> list[dict]:
    k8s = _k8s(request)

    async def build():
        node_list, pods, lsm_nodes = await asyncio.gather(
            k8s.items("/api/v1/nodes"),
            k8s.items("/api/v1/pods", fieldSelector="status.phase!=Succeeded,status.phase!=Failed"),
            _bpf_lsm_nodes(request),
        )
        per_node: dict[str, int] = {}
        for p in pods:
            n = (p.get("spec") or {}).get("nodeName")
            if n:
                per_node[n] = per_node.get(n, 0) + 1
        rows = []
        for n in node_list:
            name = n["metadata"]["name"]
            label = ((n["metadata"].get("labels") or {}).get("tefal.io/bpf-lsm") or "").lower()
            # 노드 라벨이 있으면 라벨, 없으면 LSM 이벤트 관측 여부. 관측이 없으면 판단하지 않는다
            bpf = label if label in ("true", "false") else ("true" if name in lsm_nodes else "unknown")
            rows.append(infra.node_row(n, per_node.get(name, 0), bpf))
        return sorted(rows, key=lambda r: r["node"])

    return await _cached(request, "nodes", CACHE_SEC, build)


@router.get("/infra/workloads")
async def workloads(request: Request, namespace: str | None = None) -> list[dict]:
    k8s = _k8s(request)
    ns = (namespace or "").strip() or (request.app.state.settings.watch_namespace_list or ["default"])[0]
    if not is_valid_k8s_name(ns):
        raise ApiError(400, "invalid_namespace", "namespace 형식이 올바르지 않습니다")

    async def build():
        pods, tps, cnps, (rules_text, rule_n), known = await asyncio.gather(
            k8s.items(f"/api/v1/namespaces/{ns}/pods"),
            _tracing_policies(k8s),
            _network_policies(k8s),
            _falco_rules(request, k8s),
            request.app.state.incidents.runtimes_by_pod(),
        )
        falco = infra.falco_text_for(ns, rules_text, rule_n)
        rows = [infra.workload_row(p, tps, cnps, falco, known) for p in pods]
        return sorted(rows, key=lambda r: r["pod"] or "")

    return await _cached(request, f"workloads:{ns}", CACHE_SEC, build)


@router.get("/infra/components")
async def components(request: Request) -> list[dict]:
    k8s = _k8s(request)

    async def one(name, kind, ns, obj_name):
        try:
            obj = await k8s.get(f"/apis/apps/v1/namespaces/{ns}/{infra.KIND_PATH[kind]}/{obj_name}")
        except K8sError:
            obj = None  # 설치 안 됨 또는 권한 없음 → "없음"
        return infra.component_row(name, kind, obj)

    async def build():
        return list(await asyncio.gather(*(one(*c) for c in infra.DEFAULT_COMPONENTS)))

    return await _cached(request, "components", CACHE_SEC, build)


@router.get("/network/drops")
async def network_drops(
    request: Request, limit: Annotated[int, Query(ge=1, le=200)] = 20
) -> list[dict]:
    # Hubble Relay(gRPC) 연결은 다음 단계. 지금은 빈 목록으로 답해 패널이 "막힌 흐름 없음"이 아닌
    # 안내 문구를 보이게 한다(대시보드 noValue).
    return []
