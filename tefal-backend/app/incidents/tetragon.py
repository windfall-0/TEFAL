"""Tetragon export JSON 한 줄 → TetragonEvent."""

import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime

ANCHOR_ACTIONS = {"KPROBE_ACTION_SIGKILL": "Sigkill", "KPROBE_ACTION_OVERRIDE": "Override"}
_TIME_RE = re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{1,9}))?Z$")


def parse_time_ns(value: str) -> int | None:
    """RFC3339(나노초, UTC 'Z') → epoch ns. datetime은 마이크로초까지라 직접 자른다."""
    m = _TIME_RE.match(value or "")
    if not m:
        return None
    sec = int(datetime.strptime(m.group(1), "%Y-%m-%dT%H:%M:%S").replace(tzinfo=UTC).timestamp())
    frac = (m.group(2) or "").ljust(9, "0")
    return sec * 1_000_000_000 + int(frac)


@dataclass(frozen=True)
class Proc:
    exec_id: str
    parent_exec_id: str | None
    pid: int | None
    container_pid: int | None  # 컨테이너 안의 pid. 1이면 컨테이너 init
    binary: str
    arguments: str


def _proc(d: dict | None) -> Proc | None:
    if not d or not d.get("exec_id"):
        return None
    container = (d.get("pod") or {}).get("container") or {}
    return Proc(
        exec_id=d["exec_id"],
        parent_exec_id=d.get("parent_exec_id"),
        pid=d.get("pid"),
        container_pid=container.get("pid"),
        binary=d.get("binary", ""),
        arguments=d.get("arguments", ""),
    )


@dataclass(frozen=True)
class TetragonEvent:
    time_ns: int
    event_type: str  # process_exec | process_exit | process_kprobe | process_lsm | process_uprobe ...
    node: str
    namespace: str
    pod: str
    workload: str | None
    container_id: str  # containerd ID (접두사 없이)
    image: str
    process: Proc
    parent: Proc | None
    policy: str | None
    function: str | None
    action: str | None
    file_arg: str | None  # 첫 file_arg 경로 (LSM bprm_check_security면 실행하려던 파일)

    @property
    def is_anchor(self) -> bool:
        return self.action in ANCHOR_ACTIONS


def parse_event(line: str) -> TetragonEvent | None:
    try:
        raw = json.loads(line)
    except ValueError:
        return None
    if not isinstance(raw, dict):
        return None
    etype = next((k for k in raw if k.startswith("process_")), None)
    if etype is None:
        return None
    body = raw[etype] or {}
    proc_d = body.get("process") or {}
    pod = proc_d.get("pod") or {}
    proc = _proc(proc_d)
    t = parse_time_ns(raw.get("time", ""))
    if proc is None or t is None or not pod.get("name"):
        return None  # 호스트 프로세스 등 pod 정보가 없는 이벤트는 대상이 아니다
    container = pod.get("container") or {}
    # 실행하려던 파일: 정책에 따라 file_arg(path) 또는 string_arg로 온다
    file_arg = None
    for a in body.get("args") or []:
        if isinstance(a, dict) and isinstance(a.get("file_arg"), dict):
            file_arg = a["file_arg"].get("path")
            break
    if file_arg is None:
        file_arg = next(
            (a["string_arg"] for a in body.get("args") or [] if isinstance(a, dict) and isinstance(a.get("string_arg"), str)),
            None,
        )
    return TetragonEvent(
        time_ns=t,
        event_type=etype,
        node=raw.get("node_name", ""),
        namespace=pod.get("namespace", ""),
        pod=pod["name"],
        workload=pod.get("workload"),
        container_id=(container.get("id") or "").split("://")[-1],
        image=((container.get("image") or {}).get("name") or ""),
        process=proc,
        parent=_proc(body.get("parent")),
        policy=body.get("policy_name"),
        function=body.get("function_name") or body.get("symbol"),  # uprobe는 symbol(예: uv_spawn)
        action=body.get("action"),
        file_arg=file_arg,
    )
