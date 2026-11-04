"""기준점 묶기와 관련 이벤트 수집 (4.3 ~ 4.5). Loki·DB 접근 없는 순수 함수만 둔다."""

import hashlib
import os
import re
from dataclasses import dataclass, field

from app.incidents.tetragon import ANCHOR_ACTIONS, TetragonEvent

NS = 1_000_000_000


# trace_id 규칙 버전. Tempo에 잘못 기록된 trace는 지울 수 없어서, 다시 만들 때 버전을 올려 새 ID를 쓴다.
#   1: 최초, 2: 중복 span 기록 수정, 3: Beyla 조회 범위 수정, 4: Sigma 매칭 표 적용 후 재생성 (2026-11-04)
TRACE_ID_VERSION = "4"


def make_trace_id(node: str, anchor_id: str, anchor_time_ns: int) -> str:
    key = f"v{TRACE_ID_VERSION}|{node}|{anchor_id}|{anchor_time_ns}"
    h = hashlib.sha256(key.encode()).hexdigest()[:32]
    return h[:31] + "1" if h == "0" * 32 else h


@dataclass
class AnchorCluster:
    """같은 부모 아래에서 merge_sec 간격 안에 이어진 기준점들 (4.4 연속 차단 병합)."""

    node: str
    parent_exec_id: str
    anchors: list[TetragonEvent] = field(default_factory=list)

    @property
    def first(self) -> TetragonEvent:
        return self.anchors[0]

    @property
    def last(self) -> TetragonEvent:
        return self.anchors[-1]


def merge_key(ev: TetragonEvent) -> tuple[str, str]:
    return ev.node, (ev.process.parent_exec_id or ev.process.exec_id)


def cluster_anchors(anchors: list[TetragonEvent], merge_sec: int) -> list[AnchorCluster]:
    open_by_key: dict[tuple[str, str], AnchorCluster] = {}
    out: list[AnchorCluster] = []
    for ev in sorted(anchors, key=lambda e: e.time_ns):
        key = merge_key(ev)
        c = open_by_key.get(key)
        if c is None or ev.time_ns - c.last.time_ns > merge_sec * NS:
            c = AnchorCluster(node=key[0], parent_exec_id=key[1])
            open_by_key[key] = c
            out.append(c)
        c.anchors.append(ev)
    return out


def lineage(cluster: AnchorCluster, window: list[TetragonEvent], max_depth: int) -> set[str]:
    """기준점 프로세스와 그 조상(컨테이너 init 직전까지)의 exec_id."""
    known: dict[str, tuple[int | None, str | None]] = {}  # exec_id → (container_pid, parent_exec_id)
    for ev in [*window, *cluster.anchors]:
        for p in (ev.process, ev.parent):
            if p is not None:
                known.setdefault(p.exec_id, (p.container_pid, p.parent_exec_id))
    ids: set[str] = set()
    for a in cluster.anchors:
        ids.add(a.process.exec_id)
        cur = a.process.parent_exec_id
        for _ in range(max_depth):
            if not cur or cur in ids or cur not in known:
                break
            cpid, parent = known[cur]
            if cpid == 1:  # 컨테이너 init: 모든 사건에 공통이라 묶지 않는다
                break
            ids.add(cur)
            cur = parent
    return ids


def members(
    cluster: AnchorCluster,
    window: list[TetragonEvent],
    ids: set[str],
    lookback_sec: int,
    not_before_ns: int | None = None,
) -> list[TetragonEvent]:
    lo = cluster.first.time_ns - lookback_sec * NS
    if not_before_ns is not None:
        # 연결된 HTTP 요청이 시작되기 전 이벤트는 앞선 다른 요청의 것이다 (1초 여유)
        lo = max(lo, not_before_ns - NS)
    hi = cluster.last.time_ns + 2 * NS
    seen, out = set(), []
    for ev in [*window, *cluster.anchors]:
        if not (lo <= ev.time_ns <= hi) or ev.pod != cluster.first.pod:
            continue
        if ev.process.exec_id in ids or (ev.parent and ev.parent.exec_id in ids):
            k = (ev.process.exec_id, ev.time_ns, ev.event_type)
            if k not in seen:
                seen.add(k)
                out.append(ev)
    return sorted(out, key=lambda e: e.time_ns)


# ---- 표시용 값 ----

_SECRET_PATTERNS = [
    (re.compile(r"(-u\s+)[^\s:]+:\S+"), r"\1<가림>"),
    (re.compile(r"(?i)(--?password[=\s])\S+"), r"\1<가림>"),
    (re.compile(r"(?i)(authorization:\s*)(\w+\s+)?\S+"), r"\1<가림>"),
    (re.compile(r"(?i)((?:token|passwd|pwd|secret|api[_-]?key)=)[^\s&]+"), r"\1<가림>"),
]


_WS_RE = re.compile(r"\s+")


def redact(text: str) -> str:
    """비밀값을 가리고 줄바꿈·연속 공백을 한 칸으로 줄인다 (표 한 줄 표시용)."""
    text = _WS_RE.sub(" ", text).strip()
    for pat, rep in _SECRET_PATTERNS:
        text = pat.sub(rep, text)
    return text


def detect_runtime(binaries: list[str]) -> str | None:
    names = " ".join(os.path.basename(b).lower() for b in binaries if b)
    if "java" in names:
        return "Java"
    if "node" in names:
        return "Node"
    if any(k in names for k in ("apache2", "httpd", "php")):
        return "PHP"
    return None


def summarize(anchor: TetragonEvent) -> str:
    """summary_rules.yaml이 없을 때의 기본 문구: 기준점의 실행 파일 + 인자."""
    proc = os.path.basename(anchor.process.binary) or anchor.process.binary
    if anchor.function == "bprm_check_security" and anchor.file_arg:
        return redact(f"{proc} → {anchor.file_arg} 실행 차단")
    text = redact(f"{anchor.process.binary} {anchor.process.arguments}")
    verb = "강제 종료" if anchor.action == "KPROBE_ACTION_SIGKILL" else "차단"
    return f"{text[:200]} ({verb})"


def action_label(anchors: list[TetragonEvent]) -> str:
    acts = {a.action for a in anchors}
    return ANCHOR_ACTIONS["KPROBE_ACTION_SIGKILL"] if "KPROBE_ACTION_SIGKILL" in acts else ANCHOR_ACTIONS["KPROBE_ACTION_OVERRIDE"]
