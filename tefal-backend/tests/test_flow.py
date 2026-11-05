"""① 계층별 방어 흐름: 사건별 계층(layers) 계산, /flow/summary 집계와 정합성, 지난 사건 채우기."""

import pytest
from fastapi.testclient import TestClient

from app import flow
from app.incidents.events import BACKFILL_KEY, backfill_layers
from app.incidents.falco import ingest_falco
from app.incidents.levels import SigmaLevels
from tests.test_incidents import NS, T0, FakeLoki, _all, _run, attack_lines, falco_body


@pytest.fixture
async def store(tmp_path):
    from app.incidents.store import IncidentStore
    s = await IncidentStore.open(str(tmp_path / "flow.db"))
    yield s
    await s.close()


async def test_layers_tetragon_only(settings, store):
    await _run(settings, store, attack_lines(), now_ns=T0 + 60 * NS)
    inc = (await store.query(_all()))[0]
    # uprobe zif_system(앱) → kprobe execve(프로세스) → LSM 차단(커널)
    assert inc.layers == ["app", "proc", "lsm"]
    assert inc.layer_policies["lsm"] == "php2shell-lsm-bprm-block"
    assert flow.short_policy(inc.layer_policies["app"]) == "zifsystem"


async def test_layers_falco_only_and_merged(settings, store):
    lv = SigmaLevels(settings.sigma_levels_file)
    await ingest_falco(store, lv, settings, falco_body(0, uuid="solo", pid=9999, ppid=9998))
    solo = (await store.query(_all()))[0]
    assert solo.layers == ["falco"] and solo.layer_policies["falco"] == "Shell Spawned in Vuln Lab"
    # 같은 계보의 Falco 선행 경보 + Tetragon 차단 → 한 사건에 두 출처의 계층이 모두
    await ingest_falco(store, lv, settings, falco_body(-0.5, uuid="pre"))
    await _run(settings, store, attack_lines(), now_ns=T0 + 60 * NS)
    merged = next(i for i in await store.query(_all()) if i.detected_by == "tetragon+falco")
    assert merged.layers == ["app", "proc", "lsm", "falco"]


def test_flow_summary_matches_incident_summary(app, settings, auth):
    with TestClient(app) as c:
        async def seed():
            s, lv = app.state.incidents, app.state.sigma_levels
            await _run(settings, s, attack_lines(), now_ns=T0 + 60 * NS)
            await ingest_falco(s, lv, settings, falco_body(100, uuid="u-2", pid=1, ppid=2))

        c.portal.call(seed)
        q = {"from": T0 // 1_000_000 - 3_600_000, "to": T0 // 1_000_000 + 3_600_000}
        d = c.get("/flow/summary", params=q, headers=auth).json()
        rows = {r["runtime"]: r for r in d["rows"]}
        php = rows["PHP"]
        assert (php["incidents"], php["app"], php["proc"], php["lsm"], php["blocked"]) == (1, 1, 1, 1, 1)
        assert php["policy"]["lsm"] == "bprm" and rows["Falco 탐지"]["incidents"] == 1
        assert rows["Java"]["incidents"] == 0 and "기타" not in rows
        # 정합성: 상단 카드와 같은 숫자
        s = c.get("/incidents/summary", params=q, headers=auth).json()
        assert sum(r["blocked"] for r in d["rows"]) == s["blocked_count"]
        assert sum(r["unblocked"] for r in d["rows"]) == s["unblocked_count"]
        html = d["html"]
        assert 'class="tf-box tet"' in html and "Falco 탐지" in html and "차단 1" in html
        assert "<script" not in html and "tf-item" in html and "tf-item new" not in html  # 오래된 사건은 새 줄 표시 없음
        fl = d["flat"]
        assert fl["php_lsm"] == 1 and fl["php_lsm_text"] == "1" and fl["falco_unblocked"] == 1
        assert fl["last_block_text"].startswith("마지막 차단") or fl["last_block_text"] == "최근 7일 차단 없음"


def test_flow_rows_null_when_layer_policy_missing():
    from app.incidents.store import Incident

    inc = Incident("a" * 32, 0, 0, 0, "blocked", "critical", None, "Override", "tetragon", "vuln-lab", "p", "n",
                   "Node", None, "", layers=["app", "lsm"], layer_policies={"app": "react2shell-uprobe-uvspawn-observe"})
    from app.routers.flow import build_rows
    rows = {r["runtime"]: r for r in build_rows([inc], 0, {"Node": {"app", "lsm"}}, {})}
    node = rows["Node"]
    assert node["app"] == 1 and node["proc"] is None and node["egress"] is None and node["policy"]["app"] == "uvspawn"


async def test_backfill_fills_old_incidents_once(settings, store):
    import asyncio
    await _run(settings, store, attack_lines(), now_ns=T0 + 60 * NS)
    inc = (await store.query(_all()))[0]
    inc.layers, inc.layer_policies = [], {}  # 계층 기록 전 버전에서 만든 사건
    await store.save(inc)
    await store.commit()
    lock = asyncio.Lock()
    assert await backfill_layers(store, FakeLoki(attack_lines()), settings, lock) == 1
    assert (await store.get(inc.trace_id)).layers == ["app", "proc", "lsm"]
    assert await store.get_state(BACKFILL_KEY) == "1"
    assert await backfill_layers(store, FakeLoki(attack_lines()), settings, lock) == 0  # 한 번만


def test_flow_view_range_and_escape():
    from app import flow_view
    now = 1_800_000_000_000
    assert flow_view.range_text(now - 86400000, now, now, "Asia/Seoul") == "최근 1일"
    assert flow_view.range_text(now - 6 * 3600000, now, now, "Asia/Seoul") == "최근 6시간"
    assert flow_view.range_text(now - 15 * 60000, now, now, "Asia/Seoul") == "최근 15분"
    assert " ~ " in flow_view.range_text(now - 7200000, now - 3600000, now, "Asia/Seoul")
    row = {"runtime": "PHP", "incidents": 1, "app": 1, "proc": None, "lsm": 0, "blocked": 1, "unblocked": 0,
           "policy": {"app": "<img src=x onerror=1>"}, "recent": {"app": 1}}
    html = flow_view.render([row], [], "x", "최근 1일", {"from": 0, "to": 1}, "Asia/Seoul", False)
    assert "<img" not in html and "&lt;img" in html and "tf-cell lv1 recent" in html
    assert "해당 없음" in html and "tf-cell zero" in html and "tf-live" not in html


def test_flow_link_range_relative_when_live():
    from app import flow_view
    now = 1_800_000_000_000
    assert flow_view.link_range(now - 86_400_000, now, now) == {"from": "now-1d", "to": "now"}
    assert flow_view.link_range(now - 5_000 - 21_600_000, now - 5_000, now) == {"from": "now-6h", "to": "now"}
    assert flow_view.link_range(now - 86_395_000, now, now) == {"from": "now-86395s", "to": "now"}
    assert flow_view.link_range(1, 2, now) == {"from": 1, "to": 2}
