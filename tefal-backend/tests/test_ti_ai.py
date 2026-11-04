"""5단계: 위협 인텔리전스(/ti)와 AI 해석(/ai). 외부 API는 respx로 흉내 낸다."""

import httpx
import pytest
import respx
from pydantic import SecretStr

from app.ai.analysis import AiService, event_lines, finalize
from app.core.cache import SqliteCache
from app.incidents.tetragon import parse_event
from app.ti.geo import Geo
from app.ti.service import ABUSE_URL, TiService
from tests.test_incidents import BLOCK, NS, T0, FakeLoki, _run, attack_lines, line

PUB = "8.8.8.8"


class FakeGeo:
    available = True

    def lookup(self, ip):
        return Geo(country="US", city="Mountain View", lat=37.4, lon=-122.1, asn="AS15169", isp="GOOGLE")

    def close(self):
        pass


def _keys(settings):
    return settings.model_copy(update={
        "abuseipdb_api_key": SecretStr("a" * 80), "virustotal_api_key": SecretStr("v" * 64),
        "virustotal_per_min": 4})


def _mock_ti(m, score=87):
    abuse = m.get(ABUSE_URL).mock(return_value=httpx.Response(200, json={"data": {
        "abuseConfidenceScore": score, "totalReports": 214, "lastReportedAt": "2026-11-04T01:00:00+00:00",
        "usageType": "Data Center/Web Hosting/Transit", "isTor": False, "isp": "Google LLC", "countryCode": "US",
        "reports": [{"categories": [21, 15]}, {"categories": [21]}]}}))
    vt = m.get(f"https://www.virustotal.com/api/v3/ip_addresses/{PUB}").mock(return_value=httpx.Response(
        200, json={"data": {"attributes": {"last_analysis_stats": {
            "malicious": 6, "suspicious": 2, "harmless": 71, "undetected": 15, "timeout": 0}}}}))
    return abuse, vt


@pytest.fixture
async def ti(settings, tmp_path):
    cache = await SqliteCache.open(str(tmp_path / "c.db"))
    async with httpx.AsyncClient() as http:
        yield TiService(_keys(settings), cache, http, FakeGeo())
    await cache.close()


async def test_ti_lookup_merges_and_caches(ti):
    with respx.mock(assert_all_called=False) as m:
        abuse, vt = _mock_ti(m)
        a = await ti.lookup(PUB)
        b = await ti.lookup(PUB)  # 24시간 캐시
    assert abuse.call_count == 1 and vt.call_count == 1
    assert a["abuse_score"] == 87 and a["risk_level"] == "high" and a["vt_text"] == "6 / 94"
    assert a["abuse_categories"] == ["Web App Attack", "Hacking"] and a["asn_isp"] == "AS15169 · GOOGLE"
    assert a["cached"] is False and b["cached"] is True
    u = await ti.usage()
    assert u["abuseipdb_used"] == 1 and u["virustotal_used"] == 1 and u["cache_hit"] == 2


async def test_ti_never_sends_private_ip(ti):
    with respx.mock(assert_all_called=False) as m:
        abuse, _ = _mock_ti(m)
        for ip in ("10.233.66.37", "192.168.0.157", "127.0.0.1", "100.64.1.1"):
            with pytest.raises(ValueError):
                await ti.lookup(ip)
    assert abuse.call_count == 0


async def test_ti_quota_and_vt_rate_limit(ti):
    from app.ti.service import _today
    await ti.cache.incr("abuseipdb", _today(), 900)  # 1000의 90%
    ti._vt_calls.extend([__import__("time").monotonic()] * 4)  # 이번 분 VT 4회 사용
    with respx.mock(assert_all_called=False) as m:
        abuse, vt = _mock_ti(m)
        r = await ti.lookup(PUB)
    assert abuse.call_count == 0 and vt.call_count == 0
    assert r["abuse_score"] is None and r["vt_total"] is None


async def test_ti_api_targets_src_and_outbound(app, settings, auth):
    from fastapi.testclient import TestClient

    with TestClient(app) as c:
        async def seed():
            app.state.ti = TiService(_keys(settings), app.state.cache, app.state.http, FakeGeo())
            s = app.state.incidents
            await _run(settings, s, attack_lines(), now_ns=T0 + 60 * NS)
            inc = (await s.query(__import__("tests.test_incidents", fromlist=["_all"])._all()))[0]
            # 출발지는 사설 IP라 대상이 아니고, 같은 pod가 사건 직후 밖으로 연결한 공인 IP가 대상이 된다
            inc.src_ip = "10.233.66.37"
            await s.save(inc)
            await s.add_remote_ip(PUB, "vuln-lab", inc.pod, "tetragon", 1389, T0 + 5 * NS)
            await s.add_remote_ip("192.168.0.157", "vuln-lab", inc.pod, "tetragon", 1389, T0 + 5 * NS)
            await s.commit()

        c.portal.call(seed)
        q = {"from": T0 // 1_000_000 - 600_000, "to": T0 // 1_000_000 + 600_000}
        with respx.mock(assert_all_called=False) as m:
            m.route(host="testserver").pass_through()
            _mock_ti(m)
            rows = c.get("/ti/ips", params=q, headers=auth).json()
            assert [(r["ip"], r["role"], r["related_incidents"]) for r in rows] == [(PUB, "외부 연결", 1)]
            assert c.get("/ti/ips", params={**q, "min_abuse": 90}, headers=auth).json() == []
            s = c.get("/ti/summary", params=q, headers=auth).json()
            assert s["public_ip_count"] == 1 and s["high_risk_count"] == 1 and s["abuseipdb_used"] == 1
            d = c.get(f"/ti/ip/{PUB}", headers=auth).json()
            assert d["vt_text"] == "6 / 94 악성" and d["country_asn"] == "US · AS15169"
            r = c.get("/ti/ip/10.233.66.37", headers=auth)
            assert r.status_code == 400 and r.json()["error"] == "private_ip"
            assert c.get("/ti/files", headers=auth).json() == []


def test_remote_ip_extraction():
    from app.incidents.detections import _falco_remote, _public
    assert _public("::ffff:8.8.8.8") == "8.8.8.8" and _public("::ffff:192.168.0.157") is None
    assert _falco_remote({"fd.name": "10.233.64.21:46092->8.8.8.8:443"}) == ("8.8.8.8", 443)
    assert _falco_remote({"fd.rip": "1.1.1.1", "fd.rport": 53}) == ("1.1.1.1", 53)


# ---- AI ----

class FakeGemini:
    model = "gemini-flash-latest"

    def __init__(self, out=None, fail=0):
        self.out = out or {
            "summary": "apache2가 dash 실행을 시도했고 LSM이 막았다.", "verdict": "공격", "risk": "높음",
            "mitre": [{"id": "T1059.004", "name": "Unix Shell"}, {"id": "BAD", "name": "x"}],
            "evidence": [{"line": "E1", "why": "웹 서버가 셸 실행"}, {"line": "E99", "why": "지어낸 줄"}],
            "guide": ["업로드 경로 실행 권한 제거"]}
        self.fail, self.calls, self.prompts = fail, 0, []

    async def generate_json(self, system, prompt, schema):
        from app.ai.gemini import GeminiError
        self.calls += 1
        self.prompts.append(prompt)
        if self.calls <= self.fail:
            raise GeminiError("HTTP 500")
        return self.out


def test_event_lines_fold_and_finalize():
    evs = [parse_event(x) for x in (line("process_lsm", "child", 0, **BLOCK), line("process_lsm", "child", 0.0005, **BLOCK))]
    lines = event_lines(evs, "Asia/Seoul", NS)
    assert len(lines) == 1 and lines[0].endswith("×2") and "action=OVERRIDE" in lines[0]
    d = finalize(FakeGemini().out, lines)
    assert [e["line"] for e in d["evidence"]] == lines  # E99는 입력에 없어서 버림
    assert d["mitre"] == [{"id": "T1059.004", "name": "Unix Shell"}]
    assert finalize({"verdict": "확실한 공격", "risk": "매우 높음"}, [])["verdict"] == "판단 불가"


def test_ai_api(app, settings, auth, monkeypatch):
    from fastapi.testclient import TestClient

    monkeypatch.setattr("app.ai.analysis.RETRY_WAIT_SEC", 0)

    with TestClient(app) as c:
        holder = {}

        async def seed():
            s = app.state.incidents
            await _run(settings, s, attack_lines(), now_ns=T0 + 60 * NS)
            g = FakeGemini(fail=1)  # 첫 호출 실패 → 1회 재시도
            app.state.ai = AiService(settings, app.state.cache, s, FakeLoki(attack_lines()), g, None)
            holder["g"] = g
            holder["tid"] = (await s.query(__import__("tests.test_incidents", fromlist=["_all"])._all()))[0].trace_id

        c.portal.call(seed)
        tid, g = holder["tid"], holder["g"]
        r = c.get(f"/ai/analysis/{tid}", headers=auth).json()
        assert r["verdict"] == "공격" and r["model"] == "gemini-flash-latest" and g.calls == 2
        assert len(r["evidence"]) == 1 and "**판정: 공격 · 위험도 높음**" in r["markdown"]
        assert "E1: " in g.prompts[0] and "php2shell-lsm-bprm-block" in g.prompts[0]
        c.get(f"/ai/analysis/{tid}", headers=auth)  # 캐시
        assert g.calls == 2
        c.get(f"/ai/analysis/{tid}", params={"refresh": "true"}, headers=auth)
        assert g.calls == 3
        assert c.get(f"/ai/analysis/{'0' * 32}", headers=auth).status_code == 404

        app.state.ai.gemini = None
        app.state.ai.cache = app.state.cache

        async def drop():
            await app.state.cache.delete("ai", tid)
        c.portal.call(drop)
        r = c.get(f"/ai/analysis/{tid}", headers=auth)
        assert r.status_code == 503 and r.json()["error"] == "ai_unavailable"


def test_ti_demo_ips_are_labeled(settings, auth):
    from fastapi.testclient import TestClient

    from app.main import create_app
    s = _keys(settings).model_copy(update={"demo_src_ip_pool": PUB})
    app = create_app(s)
    with TestClient(app) as c:
        async def seed():
            app.state.ti = TiService(s, app.state.cache, app.state.http, FakeGeo())
            st = app.state.incidents
            await _run(s, st, attack_lines(), now_ns=T0 + 60 * NS)
            inc = (await st.query(__import__("tests.test_incidents", fromlist=["_all"])._all()))[0]
            inc.src_ip = "10.233.66.37"
            await st.save(inc)
            await st.commit()
            return inc.trace_id

        tid = c.portal.call(seed)
        q = {"from": T0 // 1_000_000 - 600_000, "to": T0 // 1_000_000 + 600_000}
        with respx.mock(assert_all_called=False) as m:
            m.route(host="testserver").pass_through()
            _mock_ti(m)
            assert c.get(f"/incidents/{tid}", headers=auth).json()["src_ip_text"] == f"{PUB} · 시연용"
            rows = c.get("/ti/ips", params=q, headers=auth).json()
            assert [(r["ip"], r["role"], r["demo"]) for r in rows] == [(PUB, "출발지 (시연용)", True)]
            d = c.get(f"/ti/ip/{PUB}", headers=auth).json()
            assert d["demo"] is True and "실제 공격 출발지가 아닙니다" in d["notice"]
            sm = c.get("/ti/summary", params=q, headers=auth).json()
            assert sm["demo_mode"] is True and sm["demo_lookups"] >= 2


async def test_cache_concurrent_access(tmp_path):
    # 동시 요청에서 commit과 SELECT가 겹쳐도 실패하지 않는다
    import asyncio
    cache = await SqliteCache.open(str(tmp_path / "c.db"))
    await asyncio.gather(*(cache.incr("x", "d") for _ in range(50)),
                         *(cache.get("ns", f"k{i}") for i in range(50)),
                         *(cache.set("ns", f"k{i}", {"v": i}, 60) for i in range(50)))
    assert await cache.get_counter("x", "d") == 50
    await cache.close()
