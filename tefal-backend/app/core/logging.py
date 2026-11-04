"""로그 마스킹 (8장): API 키와 Authorization 헤더 값을 로그에 남기지 않는다."""

import logging
import re

_BEARER_RE = re.compile(r"(?i)(bearer\s+)[^\s\"',]+")
_MASK = "***"


class RedactFilter(logging.Filter):
    def __init__(self, secrets: list[str]) -> None:
        super().__init__()
        self._secrets = [s for s in secrets if len(s) >= 4]

    def filter(self, record: logging.LogRecord) -> bool:
        msg = record.getMessage()
        redacted = _BEARER_RE.sub(rf"\1{_MASK}", msg)
        for s in self._secrets:
            redacted = redacted.replace(s, _MASK)
        if redacted != msg:
            record.msg, record.args = redacted, None
        return True


def setup_logging(secrets: list[str]) -> None:
    flt = RedactFilter(secrets)
    root = logging.getLogger()
    if not root.handlers:
        logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    for name in ("", "uvicorn", "uvicorn.error", "uvicorn.access", "httpx"):
        logger = logging.getLogger(name)
        if not any(isinstance(f, RedactFilter) for f in logger.filters):
            logger.addFilter(flt)
    # httpx는 요청 URL을 INFO로 남긴다 (VT 등 키가 쿼리에 들어갈 수 있음)
    logging.getLogger("httpx").setLevel(logging.WARNING)
