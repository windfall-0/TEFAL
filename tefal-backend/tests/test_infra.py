"""④ 인프라 API. 객체 모양은 실제 클러스터(2026-11-04) 값을 줄여서 썼다."""

import httpx
import respx

from app import infra
from app.k8s import K8sError


def pod(name, app, node="k8s-worker1", image="x", phase="Running", restarts=0, waiting=None, ns="vuln-lab", role=None):
    labels = {"app": app, "lab": "vuln"}
    if role:
        labels["tefal.io/role"] = role
    cs = {"restartCount": restarts, "state": {"waiting": {"reason": waiting}} if waiting else {"running": {}}}
    return {"metadata": {"name": name, "namespace": ns, "labels": labels},
            "spec": {"nodeName": node, "containers": [{"image": image}]},
            "status": {"phase": phase, "containerStatuses": [cs]}}


def tp(name, sel, ns=None, block=False):
    action = "Override" if block else "Post"
    spec = {"lsmhooks" if block else "kprobes": [{"selectors": [{"matchActions": [{"action": action}]}]}]}
    if sel is not None:
        spec["podSelector"] = {"matchLabels": sel}
    meta = {"name": name}
    if ns:
        meta["namespace"] = ns
    return {"kind": "TracingPolicyNamespaced" if ns else "TracingPolicy", "metadata": meta, "spec": spec}


TPS = [
    tp("php2shell-uprobe-popen-observe", None),  # podSelector 없음 → 이름 앞부분으로 매칭
    tp("log4shell-uprobe-forkandexec-observe", {"app": "log4shell"}),
    tp("php2shell-lsm-bprmcheck-block", {"app": "php2shell"}, ns="vuln-lab", block=True),
    tp("php2shell-kprobe-execve-observe", {"app": "php2shell"}, ns="vuln-lab"),
    tp("php2shell-other-ns", {"app": "php2shell"}, ns="other", block=True),
]
CNPS = [{"kind": "CiliumNetworkPolicy", "metadata": {"name": "log4shell-egress-block", "namespace": "vuln-lab"},
         "spec": {"endpointSelector": {"matchLabels": {"k8s:app": "log4shell"}}}}]


def test_selector_matches():
    assert infra.selector_matches({"matchLabels": {"app": "a"}}, {"app": "a", "x": "y"})
    assert not infra.selector_matches({"matchLabels": {"app": "a"}}, {"app": "b"})
    assert infra.selector_matches({}, {"app": "b"}) and infra.selector_matches(None, {})
    assert infra.selector_matches({"matchExpressions": [{"key": "app", "operator": "In", "values": ["a", "b"]}]},
                                  {"app": "b"})
    assert not infra.selector_matches({"matchExpressions": [{"key": "x", "operator": "Exists"}]}, {"app": "b"})


def test_workload_row_policies_network_runtime():
    p = pod("php2shell-b994795c-kj4rm", "php2shell", node="k8s-worker2", image="docker.io/library/dvwa:php8.5.11",
            restarts=1)
    row = infra.workload_row(p, TPS, CNPS, "기본 + 커스텀 3", {})
    assert row["tetragon_policy"] == "차단 1 · 관찰 2"
    assert row["tetragon_policies"] == [
        "php2shell-kprobe-execve-observe", "php2shell-lsm-bprmcheck-block", "php2shell-uprobe-popen-observe"]
    assert row["pod_label"] == "php2shell-b994795c-kj4rm (PHP)" and row["restarts"] == 1 and row["network"] == ""

    j = infra.workload_row(pod("log4shell-5dd4", "log4shell", image="ghcr.io/x/log4shell-vulnerable-app"),
                           TPS, CNPS, "기본", {})
    assert j["runtime"] == "Java" and j["tetragon_policy"] == "관찰 1" and j["network"] == "log4shell-egress-block"

    db = infra.workload_row(pod("php2shell-db-7d97", "php2shell-db", image="mariadb:11", waiting="CrashLoopBackOff"),
                            TPS, CNPS, "기본", {})
    assert db["status"] == "CrashLoopBackOff" and db["tetragon_policy"] == "" and db["pod_label"] == "php2shell-db-7d97"

    known = infra.workload_row(pod("react2shell-dfcb", "react2shell", image="react2shell:latest", role="compare"),
                               TPS, CNPS, "기본", {"react2shell-dfcb": "Node"})
    assert known["runtime"] == "Node" and known["pod_label"] == "react2shell-dfcb (비교용)"


def test_node_and_component_rows():
    master = {"metadata": {"name": "k8s-master", "labels": {"node-role.kubernetes.io/control-plane": ""}},
              "spec": {"taints": [{"key": "node-role.kubernetes.io/control-plane", "effect": "NoSchedule"}]},
              "status": {"conditions": [{"type": "Ready", "status": "True"}],
                         "nodeInfo": {"kernelVersion": "7.0.0-42-generic"}}}
    assert infra.node_row(master, 12, "unknown") == {
        "node": "k8s-master", "ready": "true", "role": "control-plane",
        "kernel": "7.0.0-42-generic", "bpf_lsm": "unknown", "pods": 12}
    ds = {"status": {"numberReady": 3, "desiredNumberScheduled": 3}}
    assert infra.component_row("Cilium", "DS", ds)["ready_text"] == "3/3"
    assert infra.component_row("Grafana", "Deploy", {"spec": {"replicas": 1}, "status": {}})["ready_text"] == "0/1"
    assert infra.component_row("X", "DS", None)["ready_text"] == "없음"


def test_falco_text():
    assert infra.falco_text_for("vuln-lab", "k8s.ns.name=vuln-lab", 3) == "기본 + 커스텀 3"
    assert infra.falco_text_for("web", "k8s.ns.name=vuln-lab", 3) == "기본"


# ---- API ----

class FakeK8s:
    def __init__(self, objs: dict) -> None:
        self.objs = objs

    async def get(self, path, **params):
        if path not in self.objs:
            raise K8sError(f"{path}: HTTP 404")
        return self.objs[path]

    async def items(self, path, **params):
        return (await self.get(path)).get("items", [])

    async def close(self):
        pass


def _fake(app):
    nodes = [{"metadata": {"name": n, "labels": {}}, "spec": {},
              "status": {"conditions": [{"type": "Ready", "status": "True"}], "nodeInfo": {"kernelVersion": "7.0"}}}
             for n in ("k8s-worker1", "k8s-worker2")]
    pods = [pod("php2shell-a", "php2shell", node="k8s-worker2", image="dvwa:php"), pod("log4shell-b", "log4shell")]
    rules = "- rule: A\n- rule: B\n  condition: k8s.ns.name=vuln-lab\n- rule: C"
    app.state.k8s = FakeK8s({
        "/apis/cilium.io/v1alpha1/tracingpolicies": {"items": [t for t in TPS if "namespace" not in t["metadata"]]},
        "/apis/cilium.io/v1alpha1/tracingpoliciesnamespaced": {"items": [t for t in TPS if "namespace" in t["metadata"]]},
        "/apis/cilium.io/v2/ciliumnetworkpolicies": {"items": CNPS},
        "/apis/cilium.io/v2/ciliumclusterwidenetworkpolicies": {"items": []},
        "/api/v1/namespaces/falco/configmaps/falco-rules": {"data": {"r.yaml": rules}},
        "/api/v1/nodes": {"items": nodes},
        "/api/v1/pods": {"items": pods},
        "/api/v1/namespaces/vuln-lab/pods": {"items": pods},
        "/apis/apps/v1/namespaces/kube-system/daemonsets/cilium": {"status": {"numberReady": 3,
                                                                             "desiredNumberScheduled": 3}},
    })


@respx.mock(assert_all_called=False)
def test_infra_api(client, app, auth, respx_mock):
    respx_mock.route(host="testserver").pass_through()
    respx_mock.get("http://loki.test:3100/loki/api/v1/query").mock(return_value=httpx.Response(
        200, json={"data": {"result": [{"metric": {"node_name": "k8s-worker2"}, "value": [0, "12"]}]}}))
    _fake(app)
    pol = client.get("/infra/policies", headers=auth).json()
    assert pol == {"total": 8, "tracing_policies": 5, "tracing_block_policies": 2,
                   "falco_custom_rules": 3, "isolated_workloads": 0}

    nodes = client.get("/infra/nodes", headers=auth).json()
    assert [(n["node"], n["bpf_lsm"], n["pods"]) for n in nodes] == [
        ("k8s-worker1", "unknown", 1), ("k8s-worker2", "true", 1)]

    wl = client.get("/infra/workloads", params={"namespace": "vuln-lab"}, headers=auth).json()
    assert [(w["pod"], w["tetragon_policy"], w["falco"]) for w in wl] == [
        ("log4shell-b", "관찰 1", "기본 + 커스텀 3"), ("php2shell-a", "차단 1 · 관찰 2", "기본 + 커스텀 3")]
    assert client.get("/infra/workloads", params={"namespace": "Bad_NS"}, headers=auth).status_code == 400

    comp = {c["name"]: c["ready_text"] for c in client.get("/infra/components", headers=auth).json()}
    assert comp["Cilium"] == "3/3" and comp["Tempo"] == "없음" and len(comp) == len(infra.DEFAULT_COMPONENTS)

    assert client.get("/infra/nodes").status_code == 401


def test_infra_without_k8s(client, auth):
    r = client.get("/infra/policies", headers=auth)
    assert r.status_code == 503 and r.json()["error"] == "k8s_unavailable"


def test_isolated_workloads_counted(client, app, auth):
    _fake(app)
    iso = {"kind": "CiliumNetworkPolicy",
           "metadata": {"name": "iso", "namespace": "vuln-lab", "labels": {"tefal.io/isolate": "true"}},
           "spec": {"endpointSelector": {"matchLabels": {"app": "php2shell"}}}}
    app.state.k8s.objs["/apis/cilium.io/v2/ciliumnetworkpolicies"] = {"items": [*CNPS, iso]}
    assert client.get("/infra/policies", headers=auth).json()["isolated_workloads"] == 1
