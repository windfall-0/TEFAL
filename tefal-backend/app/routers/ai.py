"""AI 해석 API (5.3): ② AI 해석 · 대응 가이드."""

from fastapi import APIRouter, Request

from app.ai.analysis import AiService, AiUnavailable
from app.ai.gemini import GeminiError
from app.core.errors import ApiError
from app.core.validators import validate_trace_id

router = APIRouter(tags=["ai"])


@router.get("/ai/analysis/{trace_id}")
async def analysis(request: Request, trace_id: str, refresh: bool = False) -> dict:
    tid = validate_trace_id(trace_id)
    inc = await request.app.state.incidents.get(tid)
    if inc is None:
        raise ApiError(404, "not_found", "사건이 없습니다")
    ai: AiService = request.app.state.ai
    if refresh and not await ai.refresh_allowed():
        refresh = False  # 분당 한도를 넘으면 캐시를 준다 (AI_REFRESH_PER_MIN)
    try:
        return await ai.analyze(inc, refresh=refresh)
    except AiUnavailable as e:
        raise ApiError(503, "ai_unavailable", str(e)) from None
    except GeminiError as e:
        raise ApiError(502, "ai_error", f"Gemini 호출 실패: {e}") from None
