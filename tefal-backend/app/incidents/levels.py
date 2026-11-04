"""경고 단계 (Sigma level, 4.8).

매칭 표 `sigma_levels.yaml`은 파일이 바뀌면 다시 읽는다. 파일이 없으면 기본값만 쓴다.
"""

import logging
import os

import yaml

log = logging.getLogger(__name__)

LEVELS = ("critical", "high", "medium", "low", "informational")  # 높은 순
_RANK = {lv: i for i, lv in enumerate(LEVELS)}

# Falco priority → level 기본값 (표에 없는 룰)
_FALCO_PRIORITY_LEVEL = {
    "emergency": "critical",
    "alert": "critical",
    "critical": "critical",
    "error": "high",
    "warning": "medium",
    "notice": "low",
}
FALCO_PRIORITY_ORDER = ["debug", "informational", "notice", "warning", "error", "critical", "alert", "emergency"]


def falco_priority_rank(priority: str) -> int:
    p = (priority or "").strip().lower()
    p = "informational" if p == "info" else p
    return FALCO_PRIORITY_ORDER.index(p) if p in FALCO_PRIORITY_ORDER else 0


def highest(candidates: list[tuple[str, str]]) -> tuple[str, str | None]:
    """[(level, source)] 중 가장 높은 단계. 비어 있으면 informational."""
    if not candidates:
        return "informational", None
    return min(candidates, key=lambda c: _RANK.get(c[0], len(LEVELS)))


class SigmaLevels:
    def __init__(self, path: str) -> None:
        self._path = path
        self._mtime: float | None = None
        self._tetragon: dict[str, str] = {}
        self._falco: dict[str, str] = {}

    @staticmethod
    def _read(section) -> dict[str, str]:
        out = {}
        for key, val in (section or {}).items():
            lv = (val.get("level") if isinstance(val, dict) else val) or ""
            lv = str(lv).lower()
            if lv in _RANK:
                out[str(key)] = lv
            else:
                log.warning("sigma_levels: %s의 level이 올바르지 않음: %r", key, lv)
        return out

    def _reload(self) -> None:
        try:
            mtime = os.stat(self._path).st_mtime
        except OSError:
            if self._mtime is not None:
                log.warning("sigma_levels: 파일이 사라짐 (%s), 기본값 사용", self._path)
            self._mtime, self._tetragon, self._falco = None, {}, {}
            return
        if mtime == self._mtime:
            return
        try:
            with open(self._path, encoding="utf-8") as f:
                doc = yaml.safe_load(f) or {}
            self._tetragon = self._read(doc.get("tetragon"))
            self._falco = self._read(doc.get("falco"))
            log.info("sigma_levels: tetragon %d, falco %d건 읽음", len(self._tetragon), len(self._falco))
        except (OSError, yaml.YAMLError, AttributeError) as e:
            log.error("sigma_levels: 읽기 실패, 이전 표 유지: %s", e)
        self._mtime = mtime

    def tetragon(self, policy: str) -> str:
        self._reload()
        return self._tetragon.get(policy, "informational")

    def falco(self, rule: str, priority: str) -> str:
        self._reload()
        if rule in self._falco:
            return self._falco[rule]
        return _FALCO_PRIORITY_LEVEL.get((priority or "").strip().lower(), "informational")
