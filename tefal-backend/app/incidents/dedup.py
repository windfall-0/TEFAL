"""짧은 시간 안에 반복된 같은 행위를 1건으로 접는다.

2026-11-04 vuln-lab 로그 분석: Tetragon 698줄 중 85%가 같은 프로세스가 막힌 실행을 1ms 안에 수십~수백 번
다시 시도한 묶음이었다. 같은 행위로 접는 간격을 1초 → 10초로 늘려도 거의 줄지 않았고(128 → 118),
30초부터는 따로 실행한 공격 시도가 합쳐졌다. 그래서 기준을 좁게 잡는다.

- 같은 행위: Tetragon은 같은 pod의 같은 프로세스(exec_id) + 정책 + 함수 + 이벤트 종류 + 대상 파일 + 인자.
  Falco는 pod + 룰 + 명령줄 + 연결 대상(fd.name).
- 간격이 `gap_ns` 이하로 이어지는 동안을 한 묶음으로 본다(마지막 줄 기준이라 계속 반복되면 묶음이 이어진다).
- 원본 로그는 지우지 않는다. 세거나 보여 줄 때만 접는다.
"""

from collections.abc import Callable, Hashable, Iterable
from dataclasses import dataclass

from app.incidents.tetragon import TetragonEvent


@dataclass
class Run[T]:
    first: T
    count: int
    first_ns: int
    last_ns: int


def tetragon_key(e: TetragonEvent) -> tuple:
    return (e.namespace, e.pod, e.process.exec_id, e.policy or "", e.function or "", e.event_type,
            e.file_arg or "", e.process.arguments)


def falco_key(pod: str, rule: str, cmdline: str, fd_name: str) -> tuple:
    return (pod, rule, cmdline, fd_name)


def collapse[T](items: Iterable[T], key: Callable[[T], Hashable], time_ns: Callable[[T], int], gap_ns: int) -> list[Run[T]]:
    """시간 순으로 훑으며 같은 key가 gap_ns 안에 다시 나오면 직전 묶음에 더한다. 결과는 첫 줄 시각 순."""
    runs: list[Run[T]] = []
    open_runs: dict[Hashable, Run[T]] = {}
    for it in sorted(items, key=time_ns):
        k, t = key(it), time_ns(it)
        run = open_runs.get(k)
        if run is not None and t - run.last_ns <= gap_ns:
            run.count += 1
            run.last_ns = t
        else:
            run = Run(it, 1, t, t)
            open_runs[k] = run
            runs.append(run)
    return runs
