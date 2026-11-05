"""캐시 / 카운터 저장소 (SQLite, 단일 Pod).

- kv: 만료된 값도 지우지 않고 남겨 둔다 → 외부 API 실패 시 stale 응답에 쓴다 (3.4).
- counters: 일일 한도(UTC 날짜 버킷), 캐시 적중/미스 집계에 쓴다.
"""

import asyncio
import functools
import json
import os
import time
from dataclasses import dataclass
from typing import Any

import aiosqlite

_SCHEMA = """
CREATE TABLE IF NOT EXISTS kv (
    namespace  TEXT NOT NULL,
    key        TEXT NOT NULL,
    value      TEXT NOT NULL,
    stored_at  REAL NOT NULL,
    expires_at REAL NOT NULL,
    PRIMARY KEY (namespace, key)
);
CREATE TABLE IF NOT EXISTS counters (
    name   TEXT NOT NULL,
    bucket TEXT NOT NULL,
    count  INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (name, bucket)
);
"""


def _serialized(fn):
    """한 연결을 여러 요청이 같이 쓰므로 조회·커밋을 한 번에 하나씩 한다.

    Grafana가 패널 여러 개를 동시에 부르면, 한 요청의 commit이 다른 요청의 열린 SELECT와 겹쳐
    'cannot commit transaction - SQL statements in progress'로 실패했다.
    """
    @functools.wraps(fn)
    async def wrapper(self, *args, **kwargs):
        async with self._lock:
            return await fn(self, *args, **kwargs)
    return wrapper


@dataclass(frozen=True)
class CacheEntry:
    value: Any
    stored_at: float
    expires_at: float

    @property
    def expired(self) -> bool:
        return time.time() >= self.expires_at


class SqliteCache:
    def __init__(self, conn: aiosqlite.Connection) -> None:
        self._conn = conn
        self._lock = asyncio.Lock()

    @classmethod
    async def open(cls, path: str) -> "SqliteCache":
        if path != ":memory:":
            parent = os.path.dirname(os.path.abspath(path))
            os.makedirs(parent, exist_ok=True)
        conn = await aiosqlite.connect(path)
        await conn.execute("PRAGMA journal_mode=WAL")
        await conn.executescript(_SCHEMA)
        await conn.commit()
        return cls(conn)

    async def close(self) -> None:
        await self._conn.close()

    @_serialized
    async def ping(self) -> None:
        async with self._conn.execute("SELECT 1") as cur:
            await cur.fetchone()

    # ---- kv ----
    @_serialized
    async def get(self, namespace: str, key: str) -> CacheEntry | None:
        async with self._conn.execute(
            "SELECT value, stored_at, expires_at FROM kv WHERE namespace=? AND key=?",
            (namespace, key),
        ) as cur:
            row = await cur.fetchone()
        if row is None:
            return None
        return CacheEntry(json.loads(row[0]), row[1], row[2])

    @_serialized
    async def set(self, namespace: str, key: str, value: Any, ttl_seconds: float) -> None:
        now = time.time()
        await self._conn.execute(
            "INSERT INTO kv(namespace, key, value, stored_at, expires_at) VALUES (?,?,?,?,?) "
            "ON CONFLICT(namespace, key) DO UPDATE SET "
            "value=excluded.value, stored_at=excluded.stored_at, expires_at=excluded.expires_at",
            (namespace, key, json.dumps(value, ensure_ascii=False), now, now + ttl_seconds),
        )
        await self._conn.commit()

    @_serialized
    async def delete(self, namespace: str, key: str) -> None:
        await self._conn.execute("DELETE FROM kv WHERE namespace=? AND key=?", (namespace, key))
        await self._conn.commit()

    # ---- counters ----
    @_serialized
    async def incr(self, name: str, bucket: str, amount: int = 1) -> int:
        async with self._conn.execute(
            "INSERT INTO counters(name, bucket, count) VALUES (?,?,?) "
            "ON CONFLICT(name, bucket) DO UPDATE SET count = count + excluded.count "
            "RETURNING count",
            (name, bucket, amount),
        ) as cur:
            row = await cur.fetchone()
        await self._conn.commit()
        return int(row[0])

    @_serialized
    async def get_counter(self, name: str, bucket: str) -> int:
        async with self._conn.execute(
            "SELECT count FROM counters WHERE name=? AND bucket=?", (name, bucket)
        ) as cur:
            row = await cur.fetchone()
        return int(row[0]) if row else 0
