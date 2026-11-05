"""위협 인텔리전스 조회 (5.4): GeoIP + AbuseIPDB + VirusTotal.

- 공인 IP만 외부로 보낸다. 사설·예약 IP는 이 모듈에 들어오기 전에 걸러지고, 여기서도 한 번 더 막는다.
- 같은 IP는 TI_CACHE_TTL_HOURS 동안 다시 조회하지 않는다(SQLite kv). 만료된 값도 남겨 두고
  한도 초과·외부 오류 때 그 값을 준다.
- 일일 사용량을 UTC 날짜별로 센다. 한도의 90%를 넘으면 새 조회를 멈춘다.
- VirusTotal 공개 API는 분당 4회라, 이번 분 몫을 다 쓰면 그 IP의 VT 조회는 다음 요청으로 미룬다.
"""

import asyncio
import datetime
import ipaddress
import logging
import time
from collections import deque

import httpx

from app.config import Settings
from app.core.cache import SqliteCache
from app.core.validators import is_public_ip
from app.ti.geo import GeoIP

log = logging.getLogger(__name__)

ABUSE_URL = "https://api.abuseipdb.com/api/v2/check"
VT_URL = "https://www.virustotal.com/api/v3/ip_addresses/{ip}"
QUOTA_STOP = 0.9  # 한도의 90%에서 멈춘다

# AbuseIPDB 신고 분류 (https://www.abuseipdb.com/categories)
ABUSE_CATEGORIES = {
    1: "DNS Compromise", 2: "DNS Poisoning", 3: "Fraud Orders", 4: "DDoS Attack", 5: "FTP Brute-Force",
    6: "Ping of Death", 7: "Phishing", 8: "Fraud VoIP", 9: "Open Proxy", 10: "Web Spam", 11: "Email Spam",
    12: "Blog Spam", 13: "VPN IP", 14: "Port Scan", 15: "Hacking", 16: "SQL Injection", 17: "Spoofing",
    18: "Brute-Force", 19: "Bad Web Bot", 20: "Exploited Host", 21: "Web App Attack", 22: "SSH",
    23: "IoT Targeted",
}


def risk_level(score: int | None) -> str:
    if score is None:
        return "low"
    return "high" if score >= 75 else "mid" if score >= 25 else "low"


def _today() -> str:
    return datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%d")


def _ago(iso: str | None) -> str | None:
    if not iso:
        return None
    try:
        t = datetime.datetime.fromisoformat(iso)
    except ValueError:
        return None
    sec = int((datetime.datetime.now(datetime.UTC) - t).total_seconds())
    if sec < 3600:
        return f"{max(sec // 60, 1)}분 전"
    if sec < 86400:
        return f"{sec // 3600}시간 전"
    return f"{sec // 86400}일 전"


class TiService:
    def __init__(self, settings: Settings, cache: SqliteCache, http: httpx.AsyncClient, geo: GeoIP) -> None:
        self.s = settings
        self.cache = cache
        self.http = http
        self.geo = geo
        self.ttl = settings.ti_cache_ttl_hours * 3600
        self._locks: dict[str, asyncio.Lock] = {}
        self._vt_calls: deque[float] = deque()

    # ---- 사용량 ----
    async def usage(self) -> dict:
        day = _today()
        return {
            "abuseipdb_used": await self.cache.get_counter("abuseipdb", day),
            "abuseipdb_limit": self.s.abuseipdb_daily_limit,
            "virustotal_used": await self.cache.get_counter("virustotal", day),
            "virustotal_limit": self.s.virustotal_daily_limit,
            "cache_hit": await self.cache.get_counter("ti_cache_hit", day),
            "cache_miss": await self.cache.get_counter("ti_cache_miss", day),
            "demo_lookups": await self.cache.get_counter("ti_demo_lookup", day),
        }

    async def _quota_ok(self, name: str, limit: int) -> bool:
        return await self.cache.get_counter(name, _today()) < int(limit * QUOTA_STOP)

    def _vt_slot(self) -> bool:
        now = time.monotonic()
        while self._vt_calls and now - self._vt_calls[0] > 60:
            self._vt_calls.popleft()
        if len(self._vt_calls) >= self.s.virustotal_per_min:
            return False
        self._vt_calls.append(now)
        return True

    # ---- 외부 조회 ----
    async def _abuse(self, ip: str) -> dict | None:
        key = self.s.abuseipdb_api_key
        if key is None or not await self._quota_ok("abuseipdb", self.s.abuseipdb_daily_limit):
            return None
        await self.cache.incr("abuseipdb", _today())
        r = await self.http.get(ABUSE_URL, params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": ""},
                                headers={"Key": key.get_secret_value(), "Accept": "application/json"}, timeout=10.0)
        r.raise_for_status()
        d = r.json()["data"]
        cats: dict[int, int] = {}
        for rep in d.get("reports") or []:
            for c in rep.get("categories") or []:
                cats[c] = cats.get(c, 0) + 1
        return {
            "abuse_score": d.get("abuseConfidenceScore"),
            "abuse_reports": d.get("totalReports"),
            "last_reported_at": d.get("lastReportedAt"),
            "usage_type": d.get("usageType"),
            "is_tor": bool(d.get("isTor")),
            "abuse_isp": d.get("isp"),
            "abuse_country": d.get("countryCode"),
            "abuse_categories": [ABUSE_CATEGORIES.get(c, str(c)) for c, _ in sorted(cats.items(), key=lambda x: -x[1])][:6],
        }

    async def _vt(self, ip: str) -> dict | None:
        key = self.s.virustotal_api_key
        if key is None or not await self._quota_ok("virustotal", self.s.virustotal_daily_limit) or not self._vt_slot():
            return None
        await self.cache.incr("virustotal", _today())
        r = await self.http.get(VT_URL.format(ip=ip), headers={"x-apikey": key.get_secret_value()}, timeout=10.0)
        if r.status_code == 404:
            return {"vt_malicious": 0, "vt_suspicious": 0, "vt_harmless": 0, "vt_undetected": 0, "vt_total": 0}
        r.raise_for_status()
        st = (r.json().get("data") or {}).get("attributes", {}).get("last_analysis_stats") or {}
        out = {f"vt_{k}": int(st.get(k, 0)) for k in ("malicious", "suspicious", "harmless", "undetected")}
        out["vt_total"] = sum(int(v) for v in st.values() if isinstance(v, int))
        return out

    async def _cached(self, ns: str, ip: str, fetch, allow_fetch: bool) -> tuple[dict | None, bool, float | None]:
        """(값, 캐시에서 왔는지, 저장 시각). 만료됐고 새로 못 가져오면 만료된 값을 준다."""
        hit = await self.cache.get(ns, ip)
        if hit is not None and not hit.expired:
            await self.cache.incr("ti_cache_hit", _today())
            return hit.value, True, hit.stored_at
        if not allow_fetch:
            return (hit.value if hit else None), True, (hit.stored_at if hit else None)
        await self.cache.incr("ti_cache_miss", _today())
        try:
            value = await fetch(ip)
        except (httpx.HTTPError, KeyError, ValueError) as e:
            log.warning("%s 조회 실패: %s", ns, type(e).__name__)
            value = None
        if value is None:
            return (hit.value if hit else None), hit is not None, (hit.stored_at if hit else None)
        await self.cache.set(ns, ip, value, self.ttl)
        return value, False, time.time()

    async def lookup(self, ip: str, allow_fetch: bool = True) -> dict:
        addr = ipaddress.ip_address(ip)
        if not is_public_ip(addr):
            raise ValueError("private_ip")  # 호출하는 쪽에서 걸러야 한다. 여기까지 오면 버그
        if ip in self.s.demo_src_ip_list:
            await self.cache.incr("ti_demo_lookup", _today())  # 시연 IP 조회는 따로 센다
        lock = self._locks.setdefault(ip, asyncio.Lock())
        async with lock:  # 같은 IP 동시 요청은 한 번만 외부로 나간다
            abuse, a_cached, a_at = await self._cached("ti_abuse", ip, self._abuse, allow_fetch)
            vt, v_cached, v_at = await self._cached("ti_vt", ip, self._vt, allow_fetch)
        geo = self.geo.lookup(ip)
        abuse, vt = abuse or {}, vt or {}
        score = abuse.get("abuse_score")
        checked = max((t for t in (a_at, v_at) if t), default=None)
        country = geo.country or abuse.get("abuse_country")
        isp = geo.isp or abuse.get("abuse_isp")
        vt_total = vt.get("vt_total")
        return {
            "ip": ip,
            "country": country,
            "city": geo.city,
            "asn": geo.asn,
            "isp": isp,
            "lat": geo.lat,
            "lon": geo.lon,
            "abuse_score": score,
            "abuse_reports": abuse.get("abuse_reports"),
            "risk_level": risk_level(score),
            "last_reported": _ago(abuse.get("last_reported_at")) or ("신고 없음" if abuse else None),
            "usage_type": abuse.get("usage_type"),
            "is_tor": abuse.get("is_tor") if abuse else None,
            "abuse_categories": abuse.get("abuse_categories") or [],
            "vt_malicious": vt.get("vt_malicious"),
            "vt_suspicious": vt.get("vt_suspicious"),
            "vt_harmless": vt.get("vt_harmless"),
            "vt_undetected": vt.get("vt_undetected"),
            "vt_total": vt_total,
            "cached": a_cached and v_cached,
            "checked_at": checked,
            # 표시용
            "asn_isp": " · ".join(x for x in (geo.asn, isp) if x) or None,
            "country_asn": " · ".join(x for x in (country, geo.asn) if x) or None,
            "vt_text": f"{vt.get('vt_malicious', 0)} / {vt_total}" if vt_total is not None else None,
            "abuse_categories_text": ", ".join(abuse.get("abuse_categories") or []) or None,
        }
