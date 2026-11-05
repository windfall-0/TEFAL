"""AI 입력에서 실습 환경 이름을 가리고, 정책 이름 대신 훅 설명을 쓴다.

`php2shell`, `react2shell`, `log4shell`, `vuln-lab`, `dvwa` 같은 이름은 모델에게 정답을 알려 준다.
모델이 이름이 아니라 실제로 실행된 훅과 행위로 판단하도록, 보낼 때만 이렇게 바꾼다.
- namespace·pod·워크로드·정책 이름·이미지 이름 → 가림
- 정책 이름 → "훅 종류 + 함수 + 조치"와 그 훅이 무엇을 보는지(HOOKS)
- 화면에 보이는 근거 줄은 원래 줄이다(같은 E 번호). 모델 출력에 이름이 섞이지 않게 입력만 바꾼다.
"""

import re

from app.incidents.store import Incident
from app.incidents.tetragon import TetragonEvent

MASK = "[가림]"

# 실습 환경을 드러내는 낱말 (대소문자 무시). namespace·pod·정책 이름은 사건마다 따로 더한다
LAB_WORDS = ("php2shell", "react2shell", "log4shell", "r2s", "vuln-lab", "vuln lab", "vulnlab", "dvwa", "vulnerable")

# 훅 함수별 설명: 무엇이 일어났을 때 걸리는지
HOOKS = {
    "bprm_check_security": "프로그램 실행 직전 커널 LSM 검사. 차단이면 실행 자체가 거부된다",
    "__x64_sys_execve": "프로세스가 새 프로그램을 실행(execve 시스템 콜)",
    "__x64_sys_execveat": "프로세스가 새 프로그램을 실행(execveat 시스템 콜, 파일 디스크립터 기준)",
    "__x64_sys_clone": "프로세스가 자식 프로세스를 만듦(clone)",
    "__x64_sys_memfd_create": "메모리에만 있는 파일을 만듦. 디스크 없이 실행하는 기법에 쓰인다",
    "tcp_connect": "프로세스가 밖으로 TCP 연결을 시작",
    "security_file_permission": "파일 읽기·쓰기 권한 검사",
    "security_file_open": "파일 열기",
    "zif_system": "PHP system() 함수 호출(셸 명령 실행)",
    "zif_shell_exec": "PHP shell_exec() 함수 호출",
    "zif_exec": "PHP exec() 함수 호출",
    "zif_passthru": "PHP passthru() 함수 호출",
    "zif_proc_open": "PHP proc_open() 함수 호출",
    "popen": "popen()으로 셸 명령 실행(PHP popen/backtick 등이 이 경로를 쓴다)",
    "system": "C 라이브러리 system()으로 셸 명령 실행(PHP system()·exec() 등이 이 경로를 쓴다)",
    "execve": "C 라이브러리 execve()로 새 프로그램 실행",
    "uv_spawn": "Node.js 자식 프로세스 생성(child_process가 쓰는 libuv 함수)",
    "forkAndExec": "Java 자식 프로세스 생성(Runtime.exec / ProcessBuilder가 쓰는 JDK 내부 함수)",
}
KIND = {"process_lsm": "LSM 훅", "process_kprobe": "커널 kprobe", "process_uprobe": "앱 uprobe",
        "process_tracepoint": "커널 tracepoint"}
RUNTIME_TEXT = {"PHP": "PHP 웹 애플리케이션", "Node": "Node.js 애플리케이션", "Java": "Java 애플리케이션"}


def hook_name(e: TetragonEvent) -> str:
    action = (e.action or "").removeprefix("KPROBE_ACTION_")
    verb = "차단" if action in ("OVERRIDE", "SIGKILL") else "관찰"
    return f"{KIND.get(e.event_type, e.event_type)} {e.function or '?'} · {verb}"


def hook_help(e: TetragonEvent) -> str | None:
    return HOOKS.get(e.function or "")


class Masker:
    """사건 하나의 가릴 이름 목록. 긴 이름부터 바꾼다(pod 이름 안의 워크로드 이름보다 pod 이름이 먼저)."""

    def __init__(self, inc: Incident, policies: list[str] = ()) -> None:
        words = {inc.namespace, inc.pod, *policies, *LAB_WORDS}
        if inc.pod:
            words.add(re.sub(r"(-[a-z0-9]{8,10})?-[a-z0-9]{5}$", "", inc.pod))  # 워크로드 이름(해시 앞)
        if inc.runtime_detail:
            words.add(inc.runtime_detail.split(":")[0].rsplit("/", 1)[-1])  # 이미지 이름(태그 앞)
        words = sorted((w for w in words if w and len(w) >= 3), key=len, reverse=True)
        self._re = re.compile("|".join(re.escape(w) for w in words), re.IGNORECASE) if words else None

    def __call__(self, text: str | None) -> str:
        if not text or self._re is None:
            return text or ""
        return self._re.sub(MASK, text)

    def leaks(self, text: str) -> list[str]:
        return sorted({m.group(0).lower() for m in self._re.finditer(text)}) if self._re else []


def runtime_text(inc: Incident) -> str:
    base = RUNTIME_TEXT.get(inc.runtime or "", "애플리케이션")
    m = re.search(r"(\d+\.\d+(?:\.\d+)?)", inc.runtime_detail or "")
    return f"{base} ({inc.runtime} {m.group(1)})" if m and inc.runtime else base
