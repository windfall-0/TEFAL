"""① 정책 상태(/policies/stats)와 ④ Hubble 차단 흐름(/network/drops)."""

from urllib.parse import parse_qs, urlparse

import httpx
import respx

from app import policies
from app.hubble.client import HubbleError, drop_rows
from app.hubble.pb.flow import flow_pb2
from tests.test_infra import TPS, _fake


def flow(src_pod, dst_ip, port, t_ms, ns="vuln-lab", policy=None, names=()):
    f = flow_pb2.Flow(verdict=flow_pb2.DROPPED, drop_reason_desc=flow_pb2.POLICY_DENIED,
                      traffic_direction=flow_pb2.EGRESS, destination_names=list(names))
    f.time.FromMilliseconds(t_ms)
    f.source.namespace, f.source.pod_name = ns, src_pod
    f.destination.labels.append("reserved:world")
    f.IP.source, f.IP.destination = "10.233.65.10", dst_ip
    f.l4.TCP.destination_port = port
    if policy:
        f.egress_denied_by.add(name=policy, namespace=ns)
    return f


def test_drop_rows_merge_and_order():
    flows = [flow("log4shell-a", "203.0.113.9", 4444, 1000, policy="log4shell-egress-block"),
             flow("log4shell-a", "203.0.113.9", 4444, 3000),
             flow("php2shell-b", "198.51.100.7", 80, 2000, names=["evil.example"])]
    rows = drop_rows(flows, 20)
    assert rows[0] == {"src_pod": "vuln-lab/log4shell-a", "dst": "203.0.113.9 (world) · TCP 4444",
                       "verdict": "DROPPED", "reason": "POLICY_DENIED", "direction": "EGRESS",
                       "policy": "log4shell-egress-block", "count": 2, "time_ms": 3000}
    assert rows[1]["dst"] == "evil.example · TCP 80" and rows[1]["count"] == 1
    assert len(drop_rows(flows, 1)) == 1


def test_layer_action_rules():
    block = next(t for t in TPS if t["metadata"]["name"] == "php2shell-lsm-bprmcheck-block")
    assert policies.layer_of(block) == "커널 (LSM)" and policies.action_of(block) == "차단 (Override)"
    observe = TPS[0]
    assert policies.layer_of(observe) == "커널 (kprobe)" and policies.action_of(observe) == "기록"
    text = "- rule: A\n  x: 1\n  priority: CRITICAL\n- rule: 'B c'\n- macro: m\n"
    assert policies.falco_rule_names(text) == ["A", "B c"]
    assert policies.falco_rule_priorities(text) == {"A": "CRITICAL"}
    rows = policies.falco_rows(["A"], {"A": 0, "Run shell": 2, "Falco internal: drop": 9}, lambda r: "low")
    assert [(r["policy"], r["layer"], r["hits"]) for r in rows] == [("A", "Falco (커스텀)", 0), ("Run shell", "Falco", 2)]


def _loki(request):
    q = parse_qs(urlparse(str(request.url)).query)["query"][0]
    if "process_kprobe.policy_name" in q:
        assert '| n="vuln-lab"' in q and "[3600s]" in q
        return httpx.Response(200, json={"data": {"result": [
            {"metric": {"p": "php2shell-lsm-bprmcheck-block"}, "value": [0, "59"]},
            {"metric": {"p": "old-policy"}, "value": [0, "3"]}]}})
    assert 'ns="vuln-lab"' in q
    return httpx.Response(200, json={"data": {"result": [
        {"metric": {"rule": "B", "priority": "Warning"}, "value": [0, "4"]},
        {"metric": {"rule": "Run shell untrusted", "priority": "Notice"}, "value": [0, "1"]}]}})


@respx.mock(assert_all_called=False)
def test_policies_stats_api(client, app, auth, respx_mock):
    respx_mock.route(host="testserver").pass_through()
    respx_mock.get("http://loki.test:3100/loki/api/v1/query").mock(side_effect=_loki)
    _fake(app)
    rows = client.get("/policies/stats", params={"from": 0, "to": 3_600_000, "namespace": "vuln-lab"},
                      headers=auth).json()
    names = [r["policy"] for r in rows]
    assert names[0] == "php2shell-lsm-bprmcheck-block" and rows[0]["hits"] == 59
    assert "php2shell-other-ns" not in names and "old-policy" not in names  # 다른 namespace 정책, 지금 없는 정책
    assert {r["policy"]: r["layer"] for r in rows if r["layer"].startswith("Falco")} == {
        "B": "Falco (커스텀)", "A": "Falco (커스텀)", "C": "Falco (커스텀)", "Run shell untrusted": "Falco"}
    assert all(r["fp_note"] is None for r in rows)


@respx.mock(assert_all_called=False)
def test_policies_levels_api(client, app, auth, respx_mock, settings):
    respx_mock.route(host="testserver").pass_through()
    respx_mock.get("http://loki.test:3100/loki/api/v1/query").mock(side_effect=_loki)
    with open(settings.sigma_levels_file, "w", encoding="utf-8") as fh:
        fh.write("tetragon:\n  php2shell-lsm-bprmcheck-block: critical\nfalco: {}\n")
    _fake(app)
    r = client.get("/policies/levels", params={"from": 0, "to": 3_600_000, "namespace": "vuln-lab"},
                   headers=auth).json()
    # Tetragon: 지금 있는 정책 59 → critical, 클러스터에 없는 옛 정책 3건은 세지 않는다
    # Falco: 룰 B(priority Warning → medium) 4, 기본 룰 Notice 1 → low
    assert r["level_critical_count"] == 59 and r["level_informational_count"] == 0
    assert r["level_medium_count"] == 4 and r["level_low_count"] == 1 and r["total"] == 59 + 4 + 1


def test_policies_stats_loki_error(client, app, auth):
    _fake(app)
    with respx.mock(assert_all_called=False) as m:
        m.route(host="testserver").pass_through()
        m.get("http://loki.test:3100/loki/api/v1/query").mock(return_value=httpx.Response(500))
        r = client.get("/policies/stats", headers=auth)
    assert r.status_code == 502 and r.json()["error"] == "loki_error"


class FakeHubble:
    def __init__(self, flows=None, error=False):
        self.flows, self.error, self.calls = flows or [], error, []

    async def dropped_flows(self, ns, from_ms, to_ms):
        self.calls.append((ns, from_ms, to_ms))
        if self.error:
            raise HubbleError("GetFlows: UNAVAILABLE")
        return self.flows

    async def close(self):
        pass


def test_network_drops_api(client, app, auth):
    assert client.get("/network/drops", headers=auth).status_code == 503  # Hubble 꺼짐
    app.state.hubble = FakeHubble([flow("log4shell-a", "203.0.113.9", 4444, 1000)])
    rows = client.get("/network/drops", params={"from": 0, "to": 5000, "limit": 5}, headers=auth).json()
    assert rows[0]["count"] == 1 and app.state.hubble.calls == [("vuln-lab", 0, 5000)]
    assert client.get("/network/drops", params={"namespace": "Bad_NS"}, headers=auth).status_code == 400

    app.state.hubble = FakeHubble(error=True)
    r = client.get("/network/drops", params={"from": 999_000_000, "to": 999_100_000}, headers=auth)
    assert r.status_code == 502 and r.json()["error"] == "hubble_error"
