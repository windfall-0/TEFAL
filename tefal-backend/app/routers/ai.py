"""AI 해석 API (5.3): ② AI 해석 · 대응 가이드.

사람이 요청할 때만 Gemini를 부른다. 패널은 평소에 저장된 결과만 읽고(`req` 없음),
[AI 분석 요청]·[다시 분석] 버튼이 `req`를 붙여 다시 불러온다.

- `req=run:<trace_id>`: 저장된 분석이 없을 때만 만든다.
- `req=refresh:<trace_id>:<created_ms>`: 저장된 분석이 그 시각 것(=버튼을 누를 때 보던 것)이면 다시 만든다.
  새로 만든 뒤에는 created_ms가 바뀌므로, 주소에 남은 같은 요청으로 새로고침해도 다시 만들지 않는다.
- `req`의 trace_id가 지금 사건과 다르면 무시한다(사건을 바꿨는데 주소에 남은 요청이 실행되지 않게).
"""

from fastapi import APIRouter, Request

from app.ai.analysis import AiService, AiUnavailable
from app.ai.gemini import GeminiError
from app.core.errors import ApiError
from app.core.validators import validate_trace_id
from app.routers.incidents import WINDOW_MS

router = APIRouter(tags=["ai"])


def parse_req(req: str, tid: str) -> tuple[str, int] | None:
    parts = (req or "").strip().split(":")
    if len(parts) < 2 or parts[1].lower() != tid:
        return None
    if parts[0] == "run":
        return "run", 0
    if parts[0] == "refresh" and len(parts) == 3 and parts[2].isdigit():
        return "refresh", int(parts[2])
    return None


def _view(inc, d: dict | None, message: str | None = None) -> dict:
    # 버튼 링크가 사건 화면의 시간 범위를 유지하도록 사건 구간을 함께 준다
    # (텍스트 패널은 ${__from} 같은 Grafana 내장 변수를 바꿔 주지 않는다)
    win = {"window_from_ms": inc.start_ms - WINDOW_MS, "window_to_ms": max(inc.anchor_ms, inc.last_ms) + WINDOW_MS}
    if d is None:
        return {"trace_id": inc.trace_id, "analyzed": False, "created_ms": 0, "markdown": "", "message": message, **win}
    return {**d, "analyzed": True, "created_ms": d.get("created_ms", 0), "message": message, **win}


@router.get("/ai/analysis/{trace_id}")
async def analysis(request: Request, trace_id: str, req: str = "") -> dict:
    tid = validate_trace_id(trace_id)
    inc = await request.app.state.incidents.get(tid)
    if inc is None:
        raise ApiError(404, "not_found", "사건이 없습니다")
    ai: AiService = request.app.state.ai
    saved = await ai.cached(tid)
    action = parse_req(req, tid)
    if action is None:
        return _view(inc, saved)
    kind, after = action
    if kind == "run" and saved is not None:
        return _view(inc, saved)
    if kind == "refresh":
        if saved is not None and saved.get("created_ms", 0) > after:
            return _view(inc, saved)  # 이미 다시 만든 결과
        if not await ai.refresh_allowed():
            return _view(inc, saved, "다시 분석은 분당 횟수 제한에 걸렸습니다. 잠시 뒤 다시 눌러 주세요.")
    try:
        return _view(inc, await ai.analyze(inc, refresh=kind == "refresh"))
    except AiUnavailable as e:
        return _view(inc, saved, f"AI 분석을 쓸 수 없습니다: {e}")
    except GeminiError as e:
        return _view(inc, saved, f"Gemini 호출 실패: {e}")
