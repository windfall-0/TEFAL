"""경고 단계 (Sigma level, 4.8).

매칭 표 `sigma_levels.yaml`은 파일이 바뀌면 다시 읽는다. 파일이 없으면 기본값만 쓴다.
"""

import logging
import os
import re

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


MITRE_ID = re.compile(r"^T\d{4}(\.\d{3})?$")


def mitre_from_tags(tags) -> list[str]:
    """Falco 경보 tags 중 ATT&CK 기법 ID(T1059, T1059.004)만."""
    return [t.upper() for t in (tags or []) if isinstance(t, str) and MITRE_ID.match(t.upper())]


def merge_mitre(*lists) -> list[str]:
    """순서를 지키며 합친다(중복 제거)."""
    out: list[str] = []
    for ids in lists:
        for i in ids or []:
            if i not in out:
                out.append(i)
    return out


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
        self._mitre_t: dict[str, list[str]] = {}
        self._mitre_f: dict[str, list[str]] = {}
        self._mitre_names: dict[str, str] = {}

    @staticmethod
    def _read_mitre(section) -> dict[str, list[str]]:
        out = {}
        for key, val in (section or {}).items():
            ids = val.get("mitre") if isinstance(val, dict) else None
            ids = [str(i).upper() for i in (ids or []) if MITRE_ID.match(str(i).upper())]
            if ids:
                out[str(key)] = ids
        return out

    @staticmethod
    def _read(section) -> dict[str, str]:
        out = {}
        for key, val in (section or {}).items():
            lv = (val.get("level") if isinstance(val, dict) else val) or ""
            lv = str(lv).lower()
            if not lv and isinstance(val, dict) and "mitre" in val:
                continue  # 단계 없이 기법만 적은 항목 (Falco 규칙은 priority 기본값을 쓴다)
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
            self._mitre_t, self._mitre_f, self._mitre_names = {}, {}, {}
            return
        if mtime == self._mtime:
            return
        try:
            with open(self._path, encoding="utf-8") as f:
                doc = yaml.safe_load(f) or {}
            self._tetragon = self._read(doc.get("tetragon"))
            self._falco = self._read(doc.get("falco"))
            self._mitre_t = self._read_mitre(doc.get("tetragon"))
            self._mitre_f = self._read_mitre(doc.get("falco"))
            self._mitre_names = {str(k).upper(): str(v) for k, v in (doc.get("mitre_names") or {}).items()}
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

    # ---- MITRE ATT&CK (같은 표의 mitre 필드) ----
    def mitre_tetragon(self, policy: str | None) -> list[str]:
        self._reload()
        return list(self._mitre_t.get(policy or "", []))

    def mitre_falco(self, rule: str | None) -> list[str]:
        self._reload()
        return list(self._mitre_f.get(rule or "", []))

    def mitre_name(self, tid: str) -> str | None:
        self._reload()
        return self._mitre_names.get(tid) or self._mitre_names.get(tid.split(".")[0])

    def mitre_of(self, policies, falco_rules) -> list[str]:
        """사건에 걸린 정책·규칙 이름으로 기법 목록 (지난 사건 채우기용)."""
        return merge_mitre(*(self.mitre_tetragon(p) for p in policies), *(self.mitre_falco(r) for r in falco_rules))
