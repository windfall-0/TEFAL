"""K8s API 읽기 전용 클라이언트 (④ 인프라, 5.5).

새 의존성 없이 httpx로 호출한다. pod의 ServiceAccount 토큰과 CA를 쓴다.
토큰은 kubelet이 주기적으로 바꾸므로 60초마다 파일에서 다시 읽는다.
"""

import logging
import os
import time

import httpx

log = logging.getLogger(__name__)

SA_DIR = "/var/run/secrets/kubernetes.io/serviceaccount"


class K8sError(Exception):
    pass


class K8sClient:
    def __init__(self, base_url: str, token_path: str, ca_path: str, timeout: float = 10.0) -> None:
        self._base = base_url.rstrip("/")
        self._token_path = token_path
        self._token: tuple[float, str] | None = None
        self._http = httpx.AsyncClient(verify=ca_path if os.path.exists(ca_path) else True, timeout=timeout)

    @classmethod
    def in_cluster(cls, base_url: str, sa_dir: str = SA_DIR) -> "K8sClient | None":
        token, ca = os.path.join(sa_dir, "token"), os.path.join(sa_dir, "ca.crt")
        if not os.path.exists(token):
            log.warning("ServiceAccount 토큰이 없어 K8s API를 쓰지 않습니다 (%s)", token)
            return None
        return cls(base_url, token, ca)

    async def close(self) -> None:
        await self._http.aclose()

    def _read_token(self) -> str:
        # 작은 파일이라 동기로 읽되 60초마다만 다시 읽는다(kubelet이 토큰을 갱신한다)
        if self._token is None or time.monotonic() - self._token[0] > 60:
            with open(self._token_path, encoding="utf-8") as f:
                self._token = (time.monotonic(), f.read().strip())
        return self._token[1]

    async def get(self, path: str, **params) -> dict:
        try:
            token = self._read_token()
            r = await self._http.get(f"{self._base}{path}", params=params or None,
                                     headers={"Authorization": f"Bearer {token}"})
        except (OSError, httpx.HTTPError) as e:
            raise K8sError(f"{path}: {type(e).__name__}") from e
        if r.status_code >= 400:
            raise K8sError(f"{path}: HTTP {r.status_code}")
        return r.json()

    async def items(self, path: str, **params) -> list[dict]:
        return (await self.get(path, **params)).get("items") or []
