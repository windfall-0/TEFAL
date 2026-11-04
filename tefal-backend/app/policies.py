"""① 정책 상태 표 (5.2). 정책 객체·히트 수 → 응답 행. 호출 없는 순수 함수만 둔다."""

import json
import re

from app.infra import is_block_policy

_LAYERS = (("lsmhooks", "커널 (LSM)"), ("kprobes", "커널 (kprobe)"), ("tracepoints", "커널 (tracepoint)"),
           ("uprobes", "앱 (uprobe)"))
_ACTION_RE = re.compile(r'"action":\s*"(Override|Sigkill)"', re.IGNORECASE)
_RULE_RE = re.compile(r"^\s*-\s*rule:\s*(.+?)\s*$", re.MULTILINE)
_PRIORITY_RE = re.compile(r"^\s*priority:\s*(\w+)", re.MULTILINE)
FALCO_INTERNAL = "Falco internal"  # 'Falco internal: syscall event drop' 같은 자체 상태 경보


def layer_of(tp: dict) -> str:
    spec = tp.get("spec") or {}
    parts = [name for key, name in _LAYERS if spec.get(key)]
    return " + ".join(parts) or "—"


def action_of(tp: dict) -> str:
    if not is_block_policy(tp):
        return "기록"
    m = _ACTION_RE.search(json.dumps(tp.get("spec") or {}))
    return f"차단 ({m.group(1).capitalize()})" if m else "차단"


def falco_rule_names(rules_text: str) -> list[str]:
    return [m.strip("'\"") for m in _RULE_RE.findall(rules_text)]


def falco_rule_priorities(rules_text: str) -> dict[str, str]:
    """룰 정의의 priority. 히트가 없는 룰도 경고 단계를 정할 수 있게 한다."""
    out = {}
    matches = list(_RULE_RE.finditer(rules_text))
    for i, m in enumerate(matches):
        block = rules_text[m.end(): matches[i + 1].start() if i + 1 < len(matches) else len(rules_text)]
        p = _PRIORITY_RE.search(block)
        if p:
            out[m.group(1).strip("'\"")] = p.group(1)
    return out


def tetragon_rows(tps: list[dict], hits: dict[str, int], level_of) -> list[dict]:
    return [{
        "policy": tp["metadata"]["name"],
        "tag": level_of(tp["metadata"]["name"]),
        "layer": layer_of(tp),
        "action": action_of(tp),
        "hits": hits.get(tp["metadata"]["name"], 0),
        "false_positive_suspect": None,  # 오탐 판정은 아직 하지 않는다
        "fp_note": None,
    } for tp in tps]


def falco_rows(custom: list[str], hits: dict[str, int], level_of) -> list[dict]:
    """커스텀 룰은 히트가 없어도 보이고, 기본 룰은 이 namespace에서 맞은 것만 보인다."""
    names = list(dict.fromkeys(custom)) + sorted(
        r for r, n in hits.items() if n and r not in custom and not r.startswith(FALCO_INTERNAL))
    return [{
        "policy": r,
        "tag": level_of(r),
        "layer": "Falco (커스텀)" if r in custom else "Falco",
        "action": "탐지",
        "hits": hits.get(r, 0),
        "false_positive_suspect": None,
        "fp_note": None,
    } for r in names]
