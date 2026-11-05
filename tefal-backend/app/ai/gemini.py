"""Gemini REST 클라이언트 (generateContent, 구조화 출력)."""

import json
import logging

import httpx

log = logging.getLogger(__name__)

URL = "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"


class GeminiError(Exception):
    pass


class GeminiClient:
    def __init__(self, http: httpx.AsyncClient, api_key: str, model: str, timeout: float = 30.0) -> None:
        self._http = http
        self._key = api_key
        self.model = model
        self._timeout = timeout

    async def generate_json(self, system: str, prompt: str, schema: dict) -> dict:
        """JSON schema를 강제해서 받는다. 응답을 JSON으로 읽지 못하면 GeminiError."""
        body = {
            "systemInstruction": {"parts": [{"text": system}]},
            "contents": [{"role": "user", "parts": [{"text": prompt}]}],
            "generationConfig": {"responseMimeType": "application/json", "responseSchema": schema,
                                 "temperature": 0.2},
        }
        try:
            r = await self._http.post(URL.format(model=self.model), json=body,
                                      headers={"x-goog-api-key": self._key}, timeout=self._timeout)
        except httpx.HTTPError as e:
            raise GeminiError(type(e).__name__) from e
        if r.status_code >= 400:
            # 오류 본문에는 키가 들어 있지 않다. 상태와 메시지 앞부분만 남긴다
            msg = ""
            try:
                msg = (r.json().get("error") or {}).get("message", "")[:200]
            except ValueError:
                pass
            raise GeminiError(f"HTTP {r.status_code} {msg}")
        try:
            parts = r.json()["candidates"][0]["content"]["parts"]
            return json.loads("".join(p.get("text", "") for p in parts))
        except (KeyError, IndexError, ValueError, TypeError) as e:
            raise GeminiError(f"응답 해석 실패: {type(e).__name__}") from e
