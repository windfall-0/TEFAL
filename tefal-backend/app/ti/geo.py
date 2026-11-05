"""GeoIP (MaxMind GeoLite2 City·ASN mmdb). 로컬 파일만 읽고 외부로 호출하지 않는다 (5.4)."""

import logging
import os
from dataclasses import dataclass

import maxminddb

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class Geo:
    country: str | None = None
    city: str | None = None
    lat: float | None = None
    lon: float | None = None
    asn: str | None = None  # "AS15169"
    isp: str | None = None  # ASN 조직 이름


class GeoIP:
    def __init__(self, city_path: str, asn_path: str) -> None:
        self._city = self._open(city_path)
        self._asn = self._open(asn_path)

    @staticmethod
    def _open(path: str):
        if not os.path.exists(path):
            log.warning("GeoIP DB가 없습니다: %s", path)
            return None
        return maxminddb.open_database(path)

    def close(self) -> None:
        for db in (self._city, self._asn):
            if db is not None:
                db.close()

    @property
    def available(self) -> bool:
        return self._city is not None or self._asn is not None

    def lookup(self, ip: str) -> Geo:
        city = (self._city.get(ip) if self._city else None) or {}
        asn = (self._asn.get(ip) if self._asn else None) or {}
        loc = city.get("location") or {}
        num = asn.get("autonomous_system_number")
        return Geo(
            country=(city.get("country") or city.get("registered_country") or {}).get("iso_code"),
            city=((city.get("city") or {}).get("names") or {}).get("en"),
            lat=loc.get("latitude"),
            lon=loc.get("longitude"),
            asn=f"AS{num}" if num else None,
            isp=asn.get("autonomous_system_organization"),
        )
