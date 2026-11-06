"""Falco 루프백 오탐: 새 경보 무시, 지난 사건·탐지 표시(삭제 없음), 화면·집계 제외."""

import asyncio
import json

import pytest

from app.incidents.falco import ingest_falco
from app.incidents.falsepos import (
    BACKFILL_KEY,
    backfill_false_positives,
    is_loopback_alert,
)
from app.incidents.levels import SigmaLevels
from tests.test_incidents import NS, POD, T0, FakeLoki, _all, falco_body

RULE = "Outbound Connection from Vuln Lab"
LOOPBACKS = ["::1:51661->::1:80", "::ffff:127.0.0.1:57650->::a070:d993:7770:0:0", ":::0->::1:0", "::1:48110->:::0"]
REAL = "10.233.65.121:41000->8.8.8.8:443"


def outbound(dt: float, fd_name: str, uuid: str, pid: int) -> dict:
    b = falco_body(dt, uuid=uuid, pid=pid, ppid=pid - 1, priority="Warning")
    b["rule"] = RULE
    b["output_fields"] = {**b["output_fields"], "fd.name": fd_name, "proc.cmdline": "apache2 -DFOREGROUND"}
    b["output_fields"].pop("fd.rip", None)
    return b


def raw(b: dict) -> str:  # Loki에 들어간 Falco 원본 줄
    return json.dumps({"time": b["time"], "rule": b["rule"], "priority": b["priority"],
                       "output_fields": b["output_fields"]})


@pytest.fixture
async def store(tmp_path):
    from app.incidents.store import IncidentStore
    s = await IncidentStore.open(str(tmp_path / "fp.db"))
    yield s
    await s.close()


def test_is_loopback_alert():
    for name in LOOPBACKS:
        assert is_loopback_alert({"fd.name": name}), name
    assert not is_loopback_alert({"fd.name": REAL})
    assert not is_loopback_alert({"proc.cmdline": "sh -c id"})  # 연결이 아닌 경보


async def test_webhook_ignores_loopback(settings, store):
    lv = SigmaLevels(settings.sigma_levels_file)
    r = await ingest_falco(store, lv, settings, outbound(0, LOOPBACKS[0], "lb", 7001))
    assert r == {"ignored": True, "reason": "loopback"}
    r = await ingest_falco(store, lv, settings, outbound(1, REAL, "real", 7101))
    assert r["status"] == "pending"
    assert [i.falco_rules for i in await store.query(_all())] == [[RULE]]


async def test_backfill_marks_old_loopback_only(settings, store):
    old = settings.model_copy(update={"falco_ignore_loopback": False})  # 판정 전 버전에서 쌓인 데이터
    lv = SigmaLevels(settings.sigma_levels_file)
    bodies = [outbound(i * 0.1, n, f"lb{i}", 8001 + i * 10) for i, n in enumerate(LOOPBACKS)]
    real = outbound(100, REAL, "real", 9001)
    for b in [*bodies, real]:
        await ingest_falco(store, lv, old, b)
    for b in [bodies[0], real]:
        t = int((T0 // NS + (0 if b is bodies[0] else 100)) * NS)
        await store.add_detection("falco", RULE, "vuln-lab", "Warning", t, t, 1)
    await store.commit()
    assert len(await store.query(_all())) == 5

    loki = FakeLoki([raw(b) for b in [*bodies, real]])
    n = await backfill_false_positives(store, loki, settings, asyncio.Lock())
    assert n == (4, 1)
    left = await store.query(_all())
    assert len(left) == 1 and left[0].pod == POD  # 진짜 외부 연결만 남는다
    every = await store.query(_all(), include_fp=True)
    assert sum(1 for i in every if i.false_positive == "loopback") == 4  # 지우지 않고 표시만
    hidden = next(i for i in every if i.false_positive)
    assert (await store.get(hidden.trace_id)).false_positive == "loopback"  # trace_id로는 열린다
    c = await store.detection_counts(0, 2**62, None)
    assert c["falco"][RULE] == 1
    assert await store.get_state(BACKFILL_KEY) == "4,1"
    assert await backfill_false_positives(store, loki, settings, asyncio.Lock()) == (0, 0)  # 한 번만


def test_hidden_from_api(app, settings, auth):
    from fastapi.testclient import TestClient

    with TestClient(app) as c:
        async def seed():
            s = app.state.incidents
            old = settings.model_copy(update={"falco_ignore_loopback": False})
            await ingest_falco(s, app.state.sigma_levels, old, outbound(0, LOOPBACKS[0], "lb", 7001))
            inc = (await s.query(_all()))[0]
            inc.false_positive = "loopback"
            await s.save(inc)
            await s.commit()
            return inc.trace_id

        tid = c.portal.call(seed)
        q = {"from": T0 // 1_000_000 - 600_000, "to": T0 // 1_000_000 + 600_000}
        assert c.get("/incidents", params=q, headers=auth).json() == []
        assert c.get("/incidents/summary", params=q, headers=auth).json()["unblocked_count"] == 0
        assert c.get(f"/incidents/{tid}", headers=auth).json()["false_positive"] == "loopback"

