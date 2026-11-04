import ipaddress
import logging
import time

import pytest

from app.core.cache import SqliteCache
from app.core.errors import ApiError
from app.core.logging import RedactFilter
from app.core.params import common_filters
from app.core.timefmt import fmt_hms, fmt_relative_ko
from app.core.validators import is_public_ip, parse_ip, validate_trace_id

# ---- validators ----


def test_trace_id_valid():
    tid = "4F9A2E" + "0" * 26
    assert validate_trace_id(tid) == tid.lower()


@pytest.mark.parametrize("bad", ["", "abc", "g" * 32, "0" * 31, "0" * 33, "0" * 31 + " x"])
def test_trace_id_invalid(bad):
    with pytest.raises(ApiError) as e:
        validate_trace_id(bad)
    assert e.value.status_code == 400


@pytest.mark.parametrize(
    "ip",
    ["10.1.2.3", "172.16.0.1", "172.31.255.255", "192.168.1.1", "127.0.0.1",
     "169.254.1.1", "100.64.0.1", "100.127.255.255", "fc00::1", "fd12::1",
     "fe80::1", "::1", "::ffff:10.0.0.1", "0.0.0.0", "224.0.0.1"],
)
def test_non_public_ip(ip):
    assert not is_public_ip(ipaddress.ip_address(ip))


@pytest.mark.parametrize("ip", ["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111", "::ffff:8.8.8.8"])
def test_public_ip(ip):
    assert is_public_ip(ipaddress.ip_address(ip))


def test_parse_ip_invalid():
    with pytest.raises(ApiError):
        parse_ip("999.1.1.1")


def test_parse_ip_unwraps_mapped():
    assert str(parse_ip("::ffff:8.8.8.8")) == "8.8.8.8"


# ---- params ----


def test_filters_all():
    f = common_filters(from_=1000, to=2000, namespace="All", runtime="$__all", status="All")
    assert (f.from_ms, f.to_ms, f.namespace, f.runtimes, f.status) == (1000, 2000, None, None, None)


def test_filters_values():
    f = common_filters(from_=1, to=2, namespace="web", runtime="{Java,php}", status="Blocked")
    assert f.namespace == "web"
    assert f.runtimes == frozenset({"java", "php"})
    assert f.status == "blocked"


def test_filters_default_range():
    f = common_filters()
    assert f.to_ms - f.from_ms == 3_600_000


@pytest.mark.parametrize(
    "kwargs",
    [
        {"from_": 5, "to": 1},
        {"namespace": "Web Ns"},
        {"runtime": "ruby"},
        {"status": "maybe"},
    ],
)
def test_filters_invalid(kwargs):
    with pytest.raises(ApiError):
        common_filters(**kwargs)


# ---- timefmt ----


def test_fmt_hms_kst():
    # 2025-11-03T05:12:30Z = 14:12:30 KST
    assert fmt_hms(1762146750412, "Asia/Seoul") == "14:12:30"


def test_relative():
    now = 10_000_000_000
    assert fmt_relative_ko(now - 30_000, now) == "방금 전"
    assert fmt_relative_ko(now - 5 * 60_000, now) == "5분 전"
    assert fmt_relative_ko(now - 3 * 3_600_000, now) == "3시간 전"
    assert fmt_relative_ko(now - 2 * 86_400_000, now) == "2일 전"


# ---- cache ----


async def test_cache_roundtrip_and_stale(tmp_path):
    cache = await SqliteCache.open(str(tmp_path / "c.db"))
    try:
        await cache.set("ti", "8.8.8.8", {"score": 1, "isp": "구글"}, ttl_seconds=60)
        e = await cache.get("ti", "8.8.8.8")
        assert e.value == {"score": 1, "isp": "구글"} and not e.expired

        await cache.set("ti", "old", [1], ttl_seconds=-1)
        old = await cache.get("ti", "old")
        assert old is not None and old.expired  # 만료돼도 stale 용으로 남는다

        assert await cache.get("ti", "missing") is None
        await cache.delete("ti", "8.8.8.8")
        assert await cache.get("ti", "8.8.8.8") is None
    finally:
        await cache.close()


async def test_cache_counters(tmp_path):
    cache = await SqliteCache.open(str(tmp_path / "c.db"))
    try:
        day = time.strftime("%Y-%m-%d", time.gmtime())
        assert await cache.get_counter("abuseipdb", day) == 0
        assert await cache.incr("abuseipdb", day) == 1
        assert await cache.incr("abuseipdb", day, 2) == 3
        assert await cache.get_counter("abuseipdb", day) == 3
    finally:
        await cache.close()


# ---- logging ----


def test_redact_filter():
    flt = RedactFilter(["supersecretkey"])
    rec = logging.LogRecord("x", logging.INFO, "", 0, "key=%s auth=Bearer abc.def", ("supersecretkey",), None)
    flt.filter(rec)
    msg = rec.getMessage()
    assert "supersecretkey" not in msg and "abc.def" not in msg
