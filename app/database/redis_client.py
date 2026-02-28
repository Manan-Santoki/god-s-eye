"""
Async Redis client for job queuing, pub/sub, and caching.

Used for:
- Module job queuing (for distributed/worker mode)
- Real-time progress pub/sub
- Short-lived session state
- Distributed rate limiting (when running multiple workers)

Usage:
    redis = RedisClient()
    await redis.connect()
    await redis.publish_progress("req_123", {"phase": 1, "module": "hibp", "done": True})
    await redis.enqueue_job("module_jobs", {"module": "shodan", "target": "1.2.3.4"})
"""

import json
from typing import Any

import redis.asyncio as aioredis
from redis.asyncio import Redis

from app.core.config import settings
from app.core.exceptions import DatabaseError
from app.core.logging import get_logger

logger = get_logger(__name__)


class RedisClient:
    """
    Async Redis wrapper for GOD_EYE operations.

    Provides: key-value storage, job queues (LPUSH/BRPOP), pub/sub.
    """

    def __init__(self) -> None:
        self._redis: Redis | None = None

    async def connect(self) -> None:
        """Establish Redis connection."""
        try:
            self._redis = aioredis.from_url(
                settings.redis_url,
                encoding="utf-8",
                decode_responses=True,
                max_connections=20,
                socket_timeout=5.0,
                socket_connect_timeout=5.0,
            )
            # Test connection
            await self._redis.ping()
            logger.info("redis_connected", url=settings.redis_url)
        except Exception as e:
            raise DatabaseError("redis", "connect", str(e)) from e

    async def disconnect(self) -> None:
        """Close Redis connection."""
        if self._redis:
            await self._redis.close()
            self._redis = None

    def _r(self) -> Redis:
        assert self._redis is not None, "Call connect() first"
        return self._redis

    # ── Key-Value Store ──────────────────────────────────────────

    async def set(self, key: str, value: Any, ttl_seconds: int | None = None) -> None:
        """Store a JSON-serializable value."""
        serialized = json.dumps(value)
        if ttl_seconds:
            await self._r().setex(key, ttl_seconds, serialized)
        else:
            await self._r().set(key, serialized)

    async def get(self, key: str) -> Any | None:
        """Retrieve a value by key."""
        raw = await self._r().get(key)
        return json.loads(raw) if raw else None

    async def delete(self, *keys: str) -> int:
        """Delete one or more keys. Returns count deleted."""
        return await self._r().delete(*keys)

    async def exists(self, key: str) -> bool:
        """Check if a key exists."""
        return bool(await self._r().exists(key))

    async def expire(self, key: str, seconds: int) -> None:
        """Set expiry on a key."""
        await self._r().expire(key, seconds)

    # ── Scan Progress ────────────────────────────────────────────

    async def set_scan_progress(
        self, request_id: str, data: dict[str, Any]
    ) -> None:
        """Store real-time scan progress (expires after 24h)."""
        key = f"progress:{request_id}"
        await self.set(key, data, ttl_seconds=86400)

    async def get_scan_progress(self, request_id: str) -> dict[str, Any] | None:
        """Get current scan progress."""
        return await self.get(f"progress:{request_id}")

    async def publish_progress(self, request_id: str, data: dict[str, Any]) -> None:
        """Publish progress update to pub/sub channel (for real-time dashboard)."""
        channel = f"god_eye:progress:{request_id}"
        await self._r().publish(channel, json.dumps(data))
        # Also store latest state
        await self.set_scan_progress(request_id, data)

    # ── Job Queue ────────────────────────────────────────────────

    async def enqueue_job(self, queue_name: str, job: dict[str, Any]) -> None:
        """Push a job to the queue (for distributed worker mode)."""
        await self._r().lpush(queue_name, json.dumps(job))

    async def dequeue_job(
        self, queue_name: str, timeout: int = 5
    ) -> dict[str, Any] | None:
        """
        Pop a job from the queue (blocking with timeout).

        Returns None if queue is empty after timeout.
        """
        result = await self._r().brpop(queue_name, timeout=timeout)
        if result:
            _, job_json = result
            return json.loads(job_json)
        return None

    async def queue_length(self, queue_name: str) -> int:
        """Get the current length of a queue."""
        return await self._r().llen(queue_name)

    # ── Rate Limiting (distributed) ──────────────────────────────

    async def increment_counter(
        self, key: str, ttl_seconds: int = 60
    ) -> int:
        """
        Atomic increment with TTL — for distributed rate limiting.

        Returns the count after increment.
        """
        pipe = self._r().pipeline()
        pipe.incr(key)
        pipe.expire(key, ttl_seconds)
        results = await pipe.execute()
        return results[0]

    # ── Session Store ────────────────────────────────────────────

    async def store_session(
        self, session_id: str, data: dict[str, Any], ttl_hours: int = 24
    ) -> None:
        """Store a browser session state."""
        await self.set(f"session:{session_id}", data, ttl_seconds=ttl_hours * 3600)

    async def get_session(self, session_id: str) -> dict[str, Any] | None:
        """Retrieve stored session state."""
        return await self.get(f"session:{session_id}")

    # ── Misc ─────────────────────────────────────────────────────

    async def health_check(self) -> bool:
        """Check Redis connectivity."""
        try:
            await self._r().ping()
            return True
        except Exception:
            return False

    async def flush_scan_data(self, request_id: str) -> None:
        """Clean up all Redis keys for a scan."""
        keys = await self._r().keys(f"*:{request_id}*")
        if keys:
            await self._r().delete(*keys)


# ── Singleton ─────────────────────────────────────────────────────
_redis: RedisClient | None = None


async def get_redis() -> RedisClient:
    """Get or create the global Redis client instance."""
    global _redis
    if _redis is None:
        _redis = RedisClient()
        await _redis.connect()
    return _redis
