"""사건 큐 MITRE: 정책·규칙 → 기법 매핑(sigma_levels.yaml), Falco tags, 지난 사건 채우기."""

import asyncio
import pathlib

import pytest

from app.incidents.events import MITRE_BACKFILL_KEY, backfill_mitre
from app.incidents.falco import ingest_falco
from app.incidents.levels import SigmaLevels, merge_mitre, mitre_from_tags
from tests.test_incidents import NS, T0, _all, _run, attack_lines, falco_body

REAL_TABLE = pathlib.Path(__file__).parents[1] / "config" / "sigma_levels.yaml"


@pytest.fixture
def mset(settings):
    return settings.model_copy(update={"sigma_levels_file": str(REAL_TABLE)})


@pytest.fixture
async def store(tmp_path):
    from app.incidents.store import IncidentStore
    s = await IncidentStore.open(str(tmp_path / "mitre.db"))
    yield s
    await s.close()


def test_table_and_helpers():
    lv = SigmaLevels(str(REAL_TABLE))
    assert lv.mitre_tetragon("php2shell-uprobe-zifsystem-observe") == ["T1190", "T1505.003", "T1059.004"]
    assert lv.mitre_tetragon("없는-정책") == []
    assert lv.mitre_falco("Recon Tool in Vuln Lab") == ["T1082"]
    assert lv.falco("Recon Tool in Vuln Lab", "Warning") == "medium"  # 기법만 적은 Falco 항목은 단계를 바꾸지 않는다
    assert lv.mitre_name("T1059.004") == "Unix Shell"
    assert mitre_from_tags(["mitre_execution", "T1059", "t1059.004", "container", 3]) == ["T1059", "T1059.004"]
    assert merge_mitre(["T1190"], ["T1059", "T1190"], None) == ["T1190", "T1059"]


async def test_tetragon_incident_gets_mitre(mset, store):
    await _run(mset, store, attack_lines(), now_ns=T0 + 60 * NS)
    inc = (await store.query(_all()))[0]
    assert inc.mitre[:3] == ["T1190", "T1505.003", "T1059.004"]


async def test_falco_tags_first_then_table(mset, store):
    lv = SigmaLevels(mset.sigma_levels_file)
    body = {**falco_body(0, uuid="tag", pid=9001, ppid=9000), "tags": ["mitre_execution", "T1059", "container"]}
    await ingest_falco(store, lv, mset, body)
    await ingest_falco(store, lv, mset, falco_body(500, uuid="notag", pid=9101, ppid=9100))
    got = {i.falco_rules[0] + str(i.start_ms): i.mitre for i in await store.query(_all())}
    assert sorted(got.values()) == [["T1059"], ["T1059.004"]]  # 태그 우선, 없으면 표의 falco 절


async def test_backfill_mitre_once(mset, store):
    await _run(mset, store, attack_lines(), now_ns=T0 + 60 * NS)
    inc = (await store.query(_all()))[0]
    inc.mitre = []  # MITRE 기록 전 버전에서 만든 사건
    await store.save(inc)
    await store.commit()
    lv, lock = SigmaLevels(mset.sigma_levels_file), asyncio.Lock()
    assert await backfill_mitre(store, lv, lock) == 1
    assert (await store.get(inc.trace_id)).mitre[:3] == ["T1190", "T1505.003", "T1059.004"]
    assert await store.get_state(MITRE_BACKFILL_KEY) == "1"
    assert await backfill_mitre(store, lv, lock) == 0  # 한 번만
