"""시각 표시 규약 (3.1): epoch ms 정수 + 표시용 문자열."""

import time
from datetime import datetime
from functools import lru_cache
from zoneinfo import ZoneInfo


@lru_cache
def _tz(name: str) -> ZoneInfo:
    return ZoneInfo(name)


def now_ms() -> int:
    return int(time.time() * 1000)


def fmt_hms(epoch_ms: int, tz: str) -> str:
    return datetime.fromtimestamp(epoch_ms / 1000, _tz(tz)).strftime("%H:%M:%S")


def fmt_hm(epoch_ms: int, tz: str) -> str:
    return datetime.fromtimestamp(epoch_ms / 1000, _tz(tz)).strftime("%H:%M")


def fmt_relative_ko(epoch_ms: int, now: int | None = None) -> str:
    """'방금 전', 'N분 전', 'N시간 전', 'N일 전'."""
    diff = max(0, ((now if now is not None else now_ms()) - epoch_ms) // 1000)
    if diff < 60:
        return "방금 전"
    if diff < 3600:
        return f"{diff // 60}분 전"
    if diff < 86400:
        return f"{diff // 3600}시간 전"
    return f"{diff // 86400}일 전"
