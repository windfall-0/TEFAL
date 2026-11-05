"""① 정책 상태(/policies/stats)와 ④ Hubble 차단 흐름(/network/drops)."""

import json

from app import policies
from app.hubble.client import HubbleError, drop_rows
from app.hubble.pb.flow import flow_pb2
from tests.test_incidents import NS, T0, FakeLoki, _iso, line
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


LSM = {"policy": "php2shell-lsm-bprmcheck-block", "action": "KPROBE_ACTION_OVERRIDE", "file_arg": "/usr/bin/dash"}


def _tetragon_lines():
    return [
        # 막힌 실행을 1ms 안에 3번 다시 시도 → 1건, 5초 뒤 다시 → 1건
        line("process_lsm", "child", 0, **LSM), line("process_lsm", "child", 0.0004, **LSM),
        line("process_lsm", "child", 0.0009, **LSM), line("process_lsm", "child", 5.0, **LSM),
        line("process_kprobe", "child", 0.1, policy="old-policy"),  # 지금 클러스터에 없는 정책
        line("process_lsm", "child", 0, ns="other", **LSM),  # 다른 namespace
    ]


def _falco_line(dt, rule, priority, ns="vuln-lab", cmd="id -u"):
    return json.dumps({"time": _iso(T0 + int(dt * NS)), "rule": rule, "priority": priority,
                       "output_fields": {"k8s.ns.name": ns, "k8s.pod.name": "php2shell-a", "proc.cmdline": cmd}})


def _falco_lines():
    return [_falco_line(0, "B", "Warning"), _falco_line(0.2, "B", "Warning"),  # 1초 안 반복 → 1건
            _falco_line(0.3, "B", "Warning", cmd="whoami"),  # 명령이 다르면 다른 행위
            _falco_line(1, "Run shell untrusted", "Notice"), _falco_line(2, "B", "Warning", ns="other")]


def _seed_detections(client, settings, lines, now_ns=None):
    from app.incidents.detections import CURSOR_KEY, DetectionCollector

    async def seed():
        store = client.app.state.incidents
        det = DetectionCollector(settings, store, FakeLoki(lines))
        await store.set_state(CURSOR_KEY, str(T0 - 120 * NS))
        while await det.step(now_ns=now_ns or T0 + 60 * NS):
            pass

    client.portal.call(seed)


Q = {"from": T0 // 1_000_000 - 600_000, "to": T0 // 1_000_000 + 600_000, "namespace": "vuln-lab"}


def test_policies_stats_api(client, app, auth, settings):
    _fake(app)
    _seed_detections(client, settings, _tetragon_lines() + _falco_lines())
    rows = client.get("/policies/stats", params=Q, headers=auth).json()
    hits = {r["policy"]: r["hits"] for r in rows}
    assert hits["php2shell-lsm-bprmcheck-block"] == 2  # 1ms 안 3번 → 1건, 5초 뒤 1건
    assert [r["hits"] for r in rows] == sorted((r["hits"] for r in rows), reverse=True)
    assert "php2shell-other-ns" not in hits and "old-policy" not in hits  # 다른 namespace 정책, 지금 없는 정책
    assert hits["B"] == 2 and hits["Run shell untrusted"] == 1
    assert {r["policy"]: r["layer"] for r in rows if r["layer"].startswith("Falco")} == {
        "B": "Falco (커스텀)", "A": "Falco (커스텀)", "C": "Falco (커스텀)", "Run shell untrusted": "Falco"}
    assert all(r["fp_note"] is None for r in rows)


def test_policies_levels_api(client, app, auth, settings):
    with open(settings.sigma_levels_file, "w", encoding="utf-8") as fh:
        fh.write("tetragon:\n  php2shell-lsm-bprmcheck-block: critical\nfalco: {}\n")
    _fake(app)
    _seed_detections(client, settings, _tetragon_lines() + _falco_lines())
    r = client.get("/policies/levels", params=Q, headers=auth).json()
    # Tetragon: 지금 있는 정책 2건(반복 접음) → critical, 옛 정책은 세지 않는다
    # Falco: 룰 B(priority Warning → medium) 2건, 기본 룰 Notice 1건 → low
    assert r["level_critical_count"] == 2 and r["level_informational_count"] == 0
    assert r["level_medium_count"] == 2 and r["level_low_count"] == 1 and r["total"] == 5
    # 다른 namespace의 탐지는 namespace=All 일 때만 보인다
    r_all = client.get("/policies/levels", params={**Q, "namespace": "All"}, headers=auth).json()
    assert r_all["level_critical_count"] == 3


def test_detections_continue_across_chunks(client, settings):
    # 수집 구간 경계(커서) 양쪽에 걸친 반복도 1건으로 이어 붙인다
    lines = [line("process_lsm", "child", 0, **LSM), line("process_lsm", "child", 0.5, **LSM)]

    async def run():
        from app.incidents.detections import CURSOR_KEY, DetectionCollector
        store = client.app.state.incidents
        det = DetectionCollector(settings, store, FakeLoki(lines))
        # FakeLoki 타임스탬프 = 이벤트 + 1초. 첫 구간은 첫 줄만, 다음 구간에 둘째 줄
        await store.set_state(CURSOR_KEY, str(T0))
        det.s = settings.model_copy(update={"collect_chunk_sec": 1})
        while await det.step(now_ns=T0 + 60 * NS):
            pass
        return await store.detection_counts(0, 2**62, None)

    assert client.portal.call(run)["tetragon"] == {"php2shell-lsm-bprmcheck-block": 1}


def test_dedup_collapse_gap():
    from app.incidents.dedup import collapse

    runs = collapse([("a", 0), ("a", 900), ("a", 1800), ("b", 100), ("a", 5000)], lambda x: x[0], lambda x: x[1], 1000)
    # 마지막 줄 기준으로 이어진다: 0 → 900 → 1800은 한 묶음
    assert [(r.first[0], r.count, r.first_ns, r.last_ns) for r in runs] == [
        ("a", 3, 0, 1800), ("b", 1, 100, 100), ("a", 1, 5000, 5000)]


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


def test_trace_spans_fold_repeats():
    from app.incidents.correlate import redact
    from app.incidents.tempo import tetragon_spans
    from app.incidents.tetragon import parse_event

    evs = [parse_event(x) for x in (
        line("process_lsm", "child", 0, **LSM), line("process_lsm", "child", 0.0004, **LSM),
        line("process_lsm", "child", 0.0009, **LSM), line("process_lsm", "child", 5.0, **LSM))]
    spans = [s for s in tetragon_spans("a" * 32, "b" * 16, evs, redact) if "bprm_check_security" in s["name"]]
    attrs = [{a["key"]: a["value"] for a in s["attributes"]} for s in spans]
    assert [s["name"].split(" ", 1)[1] for s in spans] == ["bprm_check_security ×3", "bprm_check_security"]
    assert [a["tefal.repeat_count"] for a in attrs] == [{"intValue": "3"}, {"intValue": "1"}]
    assert int(spans[0]["endTimeUnixNano"]) - int(spans[0]["startTimeUnixNano"]) == 900_000
