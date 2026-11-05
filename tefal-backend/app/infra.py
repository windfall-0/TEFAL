"""④ 인프라 표 만들기 (5.5). K8s 객체(dict) → 응답 행. 호출 없는 순수 함수만 둔다."""

import json
import re

# 보안·관측 컴포넌트 (이름, 종류, namespace, 객체 이름)
DEFAULT_COMPONENTS = [
    ("Cilium", "DS", "kube-system", "cilium"),
    ("Hubble Relay", "Deploy", "kube-system", "hubble-relay"),
    ("Tetragon", "DS", "kube-system", "tetragon"),
    ("Falco", "DS", "falco", "falco"),
    ("Falcosidekick", "Deploy", "falco", "falco-falcosidekick"),
    ("Alloy", "DS", "monitoring", "alloy"),
    ("Loki", "STS", "monitoring", "loki"),
    ("Tempo", "STS", "monitoring", "tempo"),
    ("Prometheus", "STS", "monitoring", "prometheus-kube-prometheus-stack-prometheus"),
    ("Grafana", "Deploy", "monitoring", "grafana"),
    ("tefal-backend", "Deploy", "monitoring", "tefal-backend"),
]
KIND_PATH = {"DS": "daemonsets", "Deploy": "deployments", "STS": "statefulsets"}
_DATA_IMAGES = ("mariadb", "mysql", "postgres", "redis", "mongo", "memcached")
_RUNTIME_KEYS = (("Java", ("java", "jdk", "jre", "spring", "log4")), ("PHP", ("php", "dvwa")),
                 ("Node", ("node", "react", "next")))
ROLE_SUFFIX = {"compare": "비교용", "traffic": "정상 트래픽", "traffic-gen": "정상 트래픽"}
_BLOCK_ACTION_RE = re.compile(r'"action":\s*"(Override|Sigkill)"', re.IGNORECASE)


# ---- 라벨 셀렉터 ----

def selector_matches(selector: dict | None, labels: dict) -> bool:
    """K8s LabelSelector(matchLabels, matchExpressions). 빈 셀렉터({})는 모두 맞는다."""
    selector = selector or {}
    for k, v in (selector.get("matchLabels") or {}).items():
        # Cilium endpointSelector는 "k8s:" 접두사를 쓸 수 있다
        if labels.get(k.removeprefix("k8s:")) != v:
            return False
    for e in selector.get("matchExpressions") or []:
        key, op, vals = e.get("key", "").removeprefix("k8s:"), e.get("operator"), e.get("values") or []
        has = key in labels
        if (op == "In" and labels.get(key) not in vals) or (op == "NotIn" and labels.get(key) in vals) \
                or (op == "Exists" and not has) or (op == "DoesNotExist" and has):
            return False
    return True


def is_block_policy(tp: dict) -> bool:
    return bool(_BLOCK_ACTION_RE.search(json.dumps(tp.get("spec") or {})))


def policy_applies(tp: dict, pod: dict) -> bool:
    """TracingPolicy가 pod에 걸리는지.

    - TracingPolicyNamespaced는 같은 namespace만.
    - podSelector가 없으면 Tetragon은 모든 pod에 건다. 실제로는 uprobe 대상 바이너리로 좁혀지므로
      표에서는 정책 이름 앞부분(예: php2shell-...)이 pod의 app 라벨과 같을 때만 그 pod의 정책으로 본다.
    """
    meta, spec = tp.get("metadata") or {}, tp.get("spec") or {}
    pmeta = pod.get("metadata") or {}
    labels = pmeta.get("labels") or {}
    if tp.get("kind") == "TracingPolicyNamespaced" and meta.get("namespace") != pmeta.get("namespace"):
        return False
    sel = spec.get("podSelector")
    if sel is None:
        app = labels.get("app") or labels.get("app.kubernetes.io/name")
        return bool(app) and meta.get("name", "").split("-")[0] == app
    return selector_matches(sel, labels)


# ---- 행 만들기 ----

def pod_status(pod: dict) -> str:
    for cs in (pod.get("status") or {}).get("containerStatuses") or []:
        waiting = (cs.get("state") or {}).get("waiting")
        if waiting and waiting.get("reason"):
            return waiting["reason"]  # CrashLoopBackOff 등
    return (pod.get("status") or {}).get("phase") or "Unknown"


def runtime_of(pod: dict, known: dict[str, str]) -> str | None:
    """사건에서 확인된 런타임 우선, 없으면 이미지·라벨 이름으로 추정."""
    name = (pod.get("metadata") or {}).get("name", "")
    if name in known:
        return known[name]
    images = " ".join(c.get("image", "") for c in (pod.get("spec") or {}).get("containers") or []).lower()
    # DB·캐시 이미지는 앱 런타임이 아니다 (php2shell-db처럼 라벨에 앱 이름이 들어가도)
    if any(k in images for k in _DATA_IMAGES):
        return None
    labels = " ".join(((pod.get("metadata") or {}).get("labels") or {}).values()).lower()
    for text in (images, labels):  # 이미지 우선, 없으면 라벨
        for rt, keys in _RUNTIME_KEYS:
            if any(k in text for k in keys):
                return rt
    return None


def workload_row(pod: dict, tps: list[dict], cnps: list[dict], falco_text: str, known_runtime: dict[str, str]) -> dict:
    meta, spec, status = pod.get("metadata") or {}, pod.get("spec") or {}, pod.get("status") or {}
    labels = meta.get("labels") or {}
    rt = runtime_of(pod, known_runtime)
    suffix = ROLE_SUFFIX.get(labels.get("tefal.io/role", ""), rt)
    applied = [tp for tp in tps if policy_applies(tp, pod)]
    blocks = sum(1 for tp in applied if is_block_policy(tp))
    observes = len(applied) - blocks
    parts = ([f"차단 {blocks}"] if blocks else []) + ([f"관찰 {observes}"] if observes else [])
    nets = sorted(c["metadata"]["name"] for c in cnps
                  if (c.get("kind") == "CiliumClusterwideNetworkPolicy" or c["metadata"].get("namespace") == meta.get("namespace"))
                  and selector_matches((c.get("spec") or {}).get("endpointSelector"), labels))
    return {
        "pod": meta.get("name"),
        "pod_label": f"{meta.get('name')} ({suffix})" if suffix else meta.get("name"),
        "runtime": rt,
        "status": pod_status(pod),
        "restarts": sum(cs.get("restartCount", 0) for cs in status.get("containerStatuses") or []),
        "node": spec.get("nodeName"),
        "tetragon_policy": " · ".join(parts),
        "tetragon_policies": sorted(tp["metadata"]["name"] for tp in applied),
        "falco": falco_text,
        "network": ", ".join(nets),
    }


def falco_text_for(namespace: str, rules_text: str, rule_count: int) -> str:
    """Falco 기본 룰은 모든 컨테이너에 걸린다. 커스텀 룰이 이 namespace를 다루면 함께 표시한다."""
    if rule_count and namespace in rules_text:
        return f"기본 + 커스텀 {rule_count}"
    return "기본"


def node_row(node: dict, pods_on_node: int, bpf_lsm: str) -> dict:
    meta, status = node.get("metadata") or {}, node.get("status") or {}
    labels = meta.get("labels") or {}
    ready = next((c.get("status") == "True" for c in status.get("conditions") or [] if c.get("type") == "Ready"), False)
    cp = "node-role.kubernetes.io/control-plane" in labels or "node-role.kubernetes.io/master" in labels
    no_schedule = any(t.get("effect") == "NoSchedule" for t in (node.get("spec") or {}).get("taints") or [])
    role = ("control-plane" if no_schedule else "control-plane + worker") if cp else "worker"
    return {
        "node": meta.get("name"),
        "ready": "true" if ready else "false",
        "role": role,
        "kernel": (status.get("nodeInfo") or {}).get("kernelVersion"),
        "bpf_lsm": bpf_lsm,
        "pods": pods_on_node,
    }


def component_row(name: str, kind: str, obj: dict | None) -> dict:
    st = (obj or {}).get("status") or {}
    if obj is None:
        ready, desired = 0, 0
    elif kind == "DS":
        ready, desired = st.get("numberReady", 0), st.get("desiredNumberScheduled", 0)
    else:
        ready, desired = st.get("readyReplicas", 0) or 0, (obj.get("spec") or {}).get("replicas", 0)
    return {"name": name, "kind": kind, "ready": ready, "desired": desired,
            "ready_text": f"{ready}/{desired}" if obj is not None else "없음"}
