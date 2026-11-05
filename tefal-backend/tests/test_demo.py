"""시연 모드: 내부 출발지 IP → 공인 IP (core/demo.py)."""

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.config import Settings
from app.core.demo import demo_ip, parse_pool
from app.incidents.falco import ingest_falco
from app.main import create_app
from tests.conftest import TOKEN
from tests.test_incidents import falco_body

POOL = ["162.142.125.10", "167.94.138.35", "71.6.199.23"]


def test_parse_pool_trims_and_dedups():
    assert parse_pool(" 162.142.125.10, ,167.94.138.35,162.142.125.10 ") == POOL[:2]
    assert parse_pool("") == []


@pytest.mark.parametrize("bad", ["10.0.0.1", "192.168.0.200", "198.51.100.7", "not-an-ip"])
def test_parse_pool_rejects_non_public(bad):
    with pytest.raises(ValueError):
        parse_pool(f"162.142.125.10,{bad}")


def test_demo_ip_maps_private_deterministically():
    a = demo_ip("10.233.66.37", POOL)
    assert a in POOL and demo_ip("10.233.66.37", POOL) == a
    # 내부 IP가 여러 개면 풀 안에서 고루 나뉜다
    assert len({demo_ip(f"10.233.66.{i}", POOL) for i in range(50)}) == len(POOL)


@pytest.mark.parametrize("ip", [None, "", "8.8.8.8", "garbage"])
def test_demo_ip_leaves_public_and_invalid(ip):
    assert demo_ip(ip, POOL) == ip


def test_demo_ip_off_without_pool():
    assert demo_ip("10.233.66.37", []) == "10.233.66.37"


def test_settings_rejects_private_pool(tmp_path):
    with pytest.raises(ValidationError):
        Settings(tefal_api_token=TOKEN, demo_src_ip_pool="10.0.0.1", cache_db=f"sqlite:///{tmp_path / 'x.db'}",
                 _env_file=None)


def _client(settings: Settings, pool: str):
    s = settings.model_copy(update={"demo_src_ip_pool": pool})
    s.__dict__.pop("demo_src_ip_list", None)  # cached_property 다시 계산
    app = create_app(s)
    c = TestClient(app)
    c.__enter__()
    c.portal.call(lambda: ingest_falco(app.state.incidents, app.state.sigma_levels, s, falco_body(0)))
    return c


def _q():
    return {"from": 0, "to": 2**41}


@pytest.mark.parametrize("pool", [",".join(POOL), ""])
def test_api_masks_only_in_response(settings, auth, pool):
    c = _client(settings, pool)
    try:
        rows = c.get("/incidents", params=_q(), headers=auth).json()
        assert len(rows) == 1
        r = rows[0]
        assert r["src_ip_original"] == "198.51.100.7"
        if pool:
            assert r["src_ip"] in POOL and r["src_ip_demo"] is True
        else:
            assert r["src_ip"] == "198.51.100.7" and r["src_ip_demo"] is False
        one = c.get(f"/incidents/{r['trace_id']}", headers=auth).json()
        assert one["src_ip"] == r["src_ip"]
        # DB에는 원래 값이 그대로 있다
        inc = c.portal.call(c.app.state.incidents.get, r["trace_id"])
        assert inc.src_ip == "198.51.100.7"
    finally:
        c.__exit__(None, None, None)


def test_demo_ip_per_incident_key():
    # 내부 IP가 하나여도 사건(trace_id)마다 풀 안에서 고루 나뉘고, 같은 사건은 항상 같은 IP
    picks = {demo_ip("10.233.66.37", POOL, f"{i:032x}") for i in range(60)}
    assert picks == set(POOL)
    assert demo_ip("10.233.66.37", POOL, "a" * 32) == demo_ip("10.233.66.37", POOL, "a" * 32)
    assert demo_ip("8.8.8.8", POOL, "a" * 32) == "8.8.8.8"


def test_src_ip_text_reasons():
    from app.incidents.store import Incident
    from app.routers.incidents import src_ip_text

    def inc(**kw):
        base = {"trace_id": "a" * 32, "start_ms": 0, "anchor_ms": 0, "last_ms": 0, "status": "blocked", "level": "critical",
                    "level_source": None, "action": "Override", "detected_by": "tetragon", "namespace": "vuln-lab", "pod": "p",
                    "node": "n", "runtime": None, "runtime_detail": None, "summary": ""}
        return Incident(**{**base, **kw})

    assert src_ip_text(inc(detected_by="falco"), None) == "확인 불가 (Falco 단독 경보)"
    assert src_ip_text(inc(), None) == "확인 불가 (HTTP 요청 연결 없음)"
    assert src_ip_text(inc(beyla_trace_id="b" * 32), None) == "확인 불가"
    assert src_ip_text(inc(src_ip="10.233.66.37"), "162.142.125.10") == "162.142.125.10 · 시연용"
    assert src_ip_text(inc(src_ip="8.8.8.8"), "8.8.8.8") == "8.8.8.8"
