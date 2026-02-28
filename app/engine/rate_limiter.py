"""
Async token bucket rate limiter.

Each external API gets its own rate limiter instance, configured with
requests-per-minute (RPM) from module metadata.

Usage:
    limiter = get_limiter("haveibeenpwned.com", rate_rpm=40)
    await limiter.acquire()  # Blocks until a token is available
    # Make your API call
"""

import asyncio
import time
from collections import defaultdict
from typing import Optional

from app.core.logging import get_logger

logger = get_logger(__name__)


class TokenBucketLimiter:
    """
    Async token bucket rate limiter.

    Tokens refill at `rate_rpm / 60` tokens per second.
    Each `acquire()` call consumes one token.
    If no tokens are available, the call blocks until a token refills.

    Thread-safe for asyncio (single event loop).
    """

    def __init__(
        self,
        name: str = "default",
        rate_rpm: int = 60,
        burst_size: int | None = None,
        rate: int | None = None,
        capacity: int | None = None,
    ) -> None:
        """
        Initialize a rate limiter.

        Args:
            name: Human-readable name for logging (e.g., "hibp", "shodan").
            rate_rpm: Maximum requests per minute.
            burst_size: Maximum burst capacity (defaults to rate_rpm).
        """
        if rate is not None:
            rate_rpm = rate
        if capacity is not None:
            burst_size = capacity

        self.name = name
        self.rate_rpm = rate_rpm
        self.rate_per_second = rate_rpm / 60.0
        self.burst_size = burst_size or max(rate_rpm, 1)
        self._tokens = float(self.burst_size)
        self._last_refill = time.monotonic()
        self._lock = asyncio.Lock()
        self._total_waits = 0
        self._total_requests = 0

    async def acquire(self, tokens: int = 1) -> float:
        """
        Acquire tokens from the bucket.

        Blocks until the requested tokens are available.

        Args:
            tokens: Number of tokens to acquire (default: 1).

        Returns:
            Wait time in seconds (0.0 if no wait needed).
        """
        async with self._lock:
            self._refill()
            wait_time = 0.0

            if self._tokens < tokens:
                # Calculate how long to wait
                shortage = tokens - self._tokens
                wait_time = shortage / self.rate_per_second
                self._total_waits += 1

                if wait_time > 0.1:
                    logger.debug(
                        "rate_limit_wait",
                        limiter=self.name,
                        wait_seconds=round(wait_time, 2),
                        tokens_available=round(self._tokens, 2),
                    )

            # Wait outside the lock to allow other coroutines to run
            if wait_time > 0:
                await asyncio.sleep(wait_time)
                self._refill()

            self._tokens = max(0, self._tokens - tokens)
            self._total_requests += 1
            return wait_time

    def _refill(self) -> None:
        """Refill tokens based on elapsed time since last refill."""
        now = time.monotonic()
        elapsed = now - self._last_refill
        new_tokens = elapsed * self.rate_per_second
        self._tokens = min(self.burst_size, self._tokens + new_tokens)
        self._last_refill = now

    @property
    def available_tokens(self) -> float:
        """Current number of available tokens."""
        self._refill()
        return self._tokens

    def get_stats(self) -> dict:
        """Return rate limiter statistics."""
        return {
            "name": self.name,
            "rate_rpm": self.rate_rpm,
            "tokens_available": round(self.available_tokens, 2),
            "total_requests": self._total_requests,
            "total_waits": self._total_waits,
        }

    def reset(self) -> None:
        """Reset the bucket to full."""
        self._tokens = float(self.burst_size)
        self._last_refill = time.monotonic()


class GlobalRateLimiter:
    """
    Registry of per-domain rate limiters with a global cap.

    Maintains one TokenBucketLimiter per domain/API name.
    Also enforces a global maximum across all modules.
    """

    def __init__(self, global_max_rps: int = 50) -> None:
        self._limiters: dict[str, TokenBucketLimiter] = {}
        self._global_limiter = TokenBucketLimiter("global", rate_rpm=global_max_rps * 60, burst_size=global_max_rps * 2)

    def get_limiter(self, name: str, rate_rpm: int = 60) -> TokenBucketLimiter:
        """
        Get or create a rate limiter for the given API name.

        Args:
            name: API name / domain (e.g., "hibp", "shodan").
            rate_rpm: Requests per minute limit.
        """
        if name not in self._limiters:
            self._limiters[name] = TokenBucketLimiter(name, rate_rpm=rate_rpm)
        return self._limiters[name]

    @classmethod
    def get(cls, name: str, rate_rpm: int = 60) -> TokenBucketLimiter:
        """Backward-compatible singleton accessor used by older tests/code."""
        return get_global_limiter().get_limiter(name, rate_rpm)

    async def acquire(self, name: str, rate_rpm: int = 60) -> None:
        """
        Acquire from both the per-API limiter and the global limiter.

        This ensures we respect both per-API rate limits and the
        overall system throughput limit.
        """
        limiter = self.get_limiter(name, rate_rpm)
        await asyncio.gather(
            limiter.acquire(),
            self._global_limiter.acquire(),
        )

    def get_all_stats(self) -> list[dict]:
        """Return stats for all registered limiters."""
        return [l.get_stats() for l in self._limiters.values()]


# ── Singleton ─────────────────────────────────────────────────────
_global_limiter: GlobalRateLimiter | None = None


def get_global_limiter() -> GlobalRateLimiter:
    """Get the global rate limiter singleton."""
    global _global_limiter
    if _global_limiter is None:
        _global_limiter = GlobalRateLimiter(global_max_rps=50)
    return _global_limiter


def get_limiter(name: str, rate_rpm: int = 60) -> TokenBucketLimiter:
    """Convenience function to get a per-API limiter from the global registry."""
    return get_global_limiter().get_limiter(name, rate_rpm)
