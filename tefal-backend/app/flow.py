"""① 계층별 방어 흐름: 사건이 어느 계층에 걸렸는지 (`incidents.layers`) 와 `/flow/summary` 집계.

계층
- app: 앱 uprobe (예: PHP zif_system, Node uv_spawn, Java forkAndExec)
- proc: 커널 kprobe·tracepoint (예: execve)
- lsm: 커널 LSM 훅에서 **차단**(Override·Sigkill)
- egress: 이름에 egress가 들어간 정책 (지금은 Tetragon 이벤트로 오지 않는다. Hubble 연결은 다음 단계)
- falco: Falco 경보

정책 이름을 알아야 계층을 알 수 있는데 members 표에는 정책이 없어서, 사건을 만들거나 합칠 때
구성 이벤트에서 계산해 합집합으로 저장한다. 지난 사건은 기동 시 한 번 Loki에서 다시 읽어 채운다.
"""

import re

from app.incidents.store import Incident
from app.incidents.tetragon import TetragonEvent

LAYERS = ("app", "proc", "lsm", "egress", "falco")
RUNTIMES = ("PHP", "Java", "Node")
FALCO_ONLY = "Falco만"
_PREFIX_RE = re.compile(r"^(php2shell|log4shell|react2shell|r2s)-", re.IGNORECASE)
_TYPE_RE = re.compile(r"^(uprobe|kprobe|lsm|tracepoint)-", re.IGNORECASE)
_SUFFIX_RE = re.compile(r"-(observe|block|lab)$", re.IGNORECASE)


def event_layer(e: TetragonEvent) -> str | None:
    if not e.policy:
        return None
    if "egress" in e.policy.lower():
        return "egress"
    if e.event_type == "process_uprobe":
        return "app"
    if e.event_type in ("process_kprobe", "process_tracepoint"):
        return "proc"
    if e.event_type == "process_lsm" and e.is_anchor:
        return "lsm"
    return None


def add_layers(inc: Incident, events: list[TetragonEvent]) -> None:
    """이벤트의 계층을 사건에 더한다(합집합). 계층별 정책은 처음 걸린 것을 남긴다."""
    layers = set(inc.layers)
    for e in sorted(events, key=lambda e: e.time_ns):
        layer = event_layer(e)
        if layer:
            layers.add(layer)
            inc.layer_policies.setdefault(layer, e.policy)
    inc.layers = [x for x in LAYERS if x in layers]


def add_falco(inc: Incident, rule: str) -> None:
    if "falco" not in inc.layers:
        inc.layers = [x for x in LAYERS if x in {*inc.layers, "falco"}]
    inc.layer_policies.setdefault("falco", rule)


def short_policy(name: str | None) -> str | None:
    """php2shell-uprobe-zifsystem-observe → zifsystem"""
    if not name:
        return None
    return _SUFFIX_RE.sub("", _TYPE_RE.sub("", _PREFIX_RE.sub("", name))) or name


def merge_into(dst: Incident, src: Incident) -> None:
    """사건을 합칠 때 계층도 합친다."""
    dst.layers = [x for x in LAYERS if x in {*dst.layers, *src.layers}]
    for k, v in src.layer_policies.items():
        dst.layer_policies.setdefault(k, v)
