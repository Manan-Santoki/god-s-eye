"""
SQLite cache using aiosqlite for async I/O.

Provides:
- API response caching (deduplication + TTL)
- Rate limit tracking per domain
- Scan history persistence
- Immutable audit log

Database file: data/cache/osint_cache.db
"""

import json
import os
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import aiosqlite

from app.core.exceptions import CacheError
from app.core.logging import get_logger

logger = get_logger(__name__)


class SQLiteCache:
    """
    Async SQLite cache manager.

    Usage:
        cache = SQLiteCache()
        await cache.connect()

        # Cache an API response
        await cache.set("hibp:user@example.com", response_data, ttl_seconds=3600)

        # Check cache
        data = await cache.get("hibp:user@example.com")
        if data:
            return data  # Cache hit

        # Track rate limits
        count = await cache.increment_rate_counter("haveibeenpwned.com")
    """

    def __init__(self, db_path: Path | None = None) -> None:
        self.db_path = db_path or Path("data/cache/osint_cache.db")
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._db: aiosqlite.Connection | None = None

    async def connect(self) -> None:
        """Open database connection and create schema if needed."""
        try:
            self._db = await aiosqlite.connect(str(self.db_path))
            self._db.row_factory = aiosqlite.Row
            await self._create_schema()
            logger.info("sqlite_connected", path=str(self.db_path))
        except Exception as e:
            raise CacheError(f"Failed to connect to SQLite: {e}") from e

    async def disconnect(self) -> None:
        """Close database connection."""
        if self._db:
            await self._db.close()
            self._db = None

    async def initialize(self) -> None:
        """Backward-compatible alias for connect()."""
        await self.connect()

    async def close(self) -> None:
        """Backward-compatible alias for disconnect()."""
        await self.disconnect()

    async def _create_schema(self) -> None:
        """Create all tables and indexes if they don't exist."""
        assert self._db is not None
        await self._db.executescript("""
            CREATE TABLE IF NOT EXISTS api_cache (
                cache_key TEXT PRIMARY KEY,
                response_json TEXT NOT NULL,
                status_code INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP NOT NULL,
                hit_count INTEGER DEFAULT 0
            );

            CREATE INDEX IF NOT EXISTS idx_cache_expires
                ON api_cache(expires_at);

            CREATE TABLE IF NOT EXISTS rate_limits (
                domain TEXT PRIMARY KEY,
                request_count INTEGER DEFAULT 0,
                window_start TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                window_size_seconds INTEGER DEFAULT 60,
                max_requests INTEGER DEFAULT 60
            );

            CREATE TABLE IF NOT EXISTS scans (
                request_id TEXT PRIMARY KEY,
                target TEXT NOT NULL,
                target_type TEXT NOT NULL,
                status TEXT DEFAULT 'pending',
                started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                completed_at TIMESTAMP,
                modules_executed TEXT,
                modules_failed TEXT,
                modules_skipped TEXT,
                total_findings INTEGER DEFAULT 0,
                risk_score REAL,
                risk_level TEXT,
                metadata_json TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_scans_status
                ON scans(status);

            CREATE INDEX IF NOT EXISTS idx_scans_target
                ON scans(target);

            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                action TEXT NOT NULL,
                request_id TEXT,
                target TEXT,
                module_name TEXT,
                details TEXT,
                system_user TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_audit_timestamp
                ON audit_log(timestamp);

            CREATE INDEX IF NOT EXISTS idx_audit_request
                ON audit_log(request_id);
        """)
        await self._db.commit()

    # ── Cache Operations ─────────────────────────────────────────

    async def get(self, key: str) -> Any | None:
        """
        Retrieve cached value by key.

        Returns None if key doesn't exist or is expired.
        """
        assert self._db is not None
        try:
            now = datetime.utcnow().isoformat()
            async with self._db.execute(
                "SELECT response_json FROM api_cache WHERE cache_key = ? AND expires_at > ?",
                (key, now),
            ) as cursor:
                row = await cursor.fetchone()
                if row:
                    # Increment hit counter
                    await self._db.execute(
                        "UPDATE api_cache SET hit_count = hit_count + 1 WHERE cache_key = ?",
                        (key,),
                    )
                    await self._db.commit()
                    return json.loads(row["response_json"])
            return None
        except Exception as e:
            logger.warning("cache_get_failed", key=key, error=str(e))
            return None

    async def set(
        self,
        key: str,
        value: Any,
        ttl_seconds: int = 3600,
        status_code: int | None = None,
    ) -> bool:
        """
        Store a value in the cache with TTL.

        Args:
            key: Cache key (format: "{module}:{target}" or "{module}:{target}:{params_hash}")
            value: JSON-serializable value to cache
            ttl_seconds: Time-to-live in seconds (default: 1 hour)
            status_code: Optional HTTP status code to record
        """
        assert self._db is not None
        try:
            expires_at = (datetime.utcnow() + timedelta(seconds=ttl_seconds)).isoformat()
            await self._db.execute(
                """INSERT OR REPLACE INTO api_cache
                   (cache_key, response_json, status_code, expires_at)
                   VALUES (?, ?, ?, ?)""",
                (key, json.dumps(value), status_code, expires_at),
            )
            await self._db.commit()
            return True
        except Exception as e:
            logger.warning("cache_set_failed", key=key, error=str(e))
            return False

    async def has_fresh_result(self, key: str, max_age_seconds: int) -> bool:
        """Check if a fresh (non-expired) result exists for key."""
        assert self._db is not None
        min_time = (datetime.utcnow() - timedelta(seconds=max_age_seconds)).isoformat()
        async with self._db.execute(
            "SELECT 1 FROM api_cache WHERE cache_key = ? AND created_at > ?",
            (key, min_time),
        ) as cursor:
            return await cursor.fetchone() is not None

    async def delete(self, key: str) -> None:
        """Remove a cache entry."""
        assert self._db is not None
        await self._db.execute("DELETE FROM api_cache WHERE cache_key = ?", (key,))
        await self._db.commit()

    async def clear_expired(self) -> int:
        """Remove all expired cache entries. Returns count deleted."""
        assert self._db is not None
        now = datetime.utcnow().isoformat()
        async with self._db.execute(
            "DELETE FROM api_cache WHERE expires_at <= ?", (now,)
        ) as cursor:
            count = cursor.rowcount
        await self._db.commit()
        logger.info("cache_cleared_expired", count=count)
        return count

    async def get_stats(self) -> dict[str, Any]:
        """Return cache statistics."""
        assert self._db is not None
        async with self._db.execute(
            "SELECT COUNT(*), SUM(hit_count) FROM api_cache WHERE expires_at > ?",
            (datetime.utcnow().isoformat(),),
        ) as cursor:
            row = await cursor.fetchone()
        return {
            "active_entries": row[0] or 0,
            "total_hits": row[1] or 0,
        }

    # ── Rate Limit Tracking ──────────────────────────────────────

    async def increment_rate_counter(self, domain: str, window_seconds: int = 60) -> int:
        """
        Increment request counter for a domain.

        Automatically resets the counter when the time window expires.
        Returns the current request count in the window.
        """
        assert self._db is not None
        try:
            now = datetime.utcnow()
            async with self._db.execute(
                "SELECT request_count, window_start FROM rate_limits WHERE domain = ?",
                (domain,),
            ) as cursor:
                row = await cursor.fetchone()

            if row:
                window_start = datetime.fromisoformat(row["window_start"])
                if (now - window_start).total_seconds() > window_seconds:
                    # Window expired — reset counter
                    await self._db.execute(
                        "UPDATE rate_limits SET request_count = 1, window_start = ? WHERE domain = ?",
                        (now.isoformat(), domain),
                    )
                    await self._db.commit()
                    return 1
                else:
                    new_count = row["request_count"] + 1
                    await self._db.execute(
                        "UPDATE rate_limits SET request_count = ? WHERE domain = ?",
                        (new_count, domain),
                    )
                    await self._db.commit()
                    return new_count
            else:
                await self._db.execute(
                    "INSERT INTO rate_limits (domain, request_count, window_start) VALUES (?, 1, ?)",
                    (domain, now.isoformat()),
                )
                await self._db.commit()
                return 1
        except Exception as e:
            logger.warning("rate_limit_error", domain=domain, error=str(e))
            return 0

    async def get_rate_count(self, domain: str, window_seconds: int = 60) -> int:
        """Get current request count for a domain within the time window."""
        assert self._db is not None
        min_time = (datetime.utcnow() - timedelta(seconds=window_seconds)).isoformat()
        async with self._db.execute(
            "SELECT request_count FROM rate_limits WHERE domain = ? AND window_start > ?",
            (domain, min_time),
        ) as cursor:
            row = await cursor.fetchone()
        return row["request_count"] if row else 0

    # ── Scan History ─────────────────────────────────────────────

    async def save_scan(self, request_id: str, metadata: dict[str, Any]) -> None:
        """Save or update scan metadata."""
        assert self._db is not None
        await self._db.execute(
            """INSERT OR REPLACE INTO scans
               (request_id, target, target_type, status, started_at,
                completed_at, modules_executed, modules_failed, modules_skipped,
                total_findings, risk_score, risk_level, metadata_json)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                request_id,
                metadata.get("target", ""),
                metadata.get("target_type", ""),
                metadata.get("status", "pending"),
                metadata.get("started_at", datetime.utcnow().isoformat()),
                metadata.get("completed_at"),
                json.dumps(metadata.get("modules_executed", [])),
                json.dumps(metadata.get("modules_failed", [])),
                json.dumps(metadata.get("modules_skipped", [])),
                metadata.get("total_findings", 0),
                metadata.get("risk_score"),
                metadata.get("risk_level"),
                json.dumps(metadata),
            ),
        )
        await self._db.commit()

    async def get_scan(self, request_id: str) -> dict[str, Any] | None:
        """Retrieve scan metadata by request ID."""
        assert self._db is not None
        async with self._db.execute(
            "SELECT metadata_json FROM scans WHERE request_id = ?",
            (request_id,),
        ) as cursor:
            row = await cursor.fetchone()
        if row and row["metadata_json"]:
            return json.loads(row["metadata_json"])
        return None

    async def list_scans(self, limit: int = 20, status: str | None = None) -> list[dict[str, Any]]:
        """List recent scans, optionally filtered by status."""
        assert self._db is not None
        if status:
            query = (
                "SELECT metadata_json FROM scans WHERE status = ? ORDER BY started_at DESC LIMIT ?"
            )
            params = (status, limit)
        else:
            query = "SELECT metadata_json FROM scans ORDER BY started_at DESC LIMIT ?"
            params = (limit,)

        async with self._db.execute(query, params) as cursor:
            rows = await cursor.fetchall()
        return [json.loads(r["metadata_json"]) for r in rows if r["metadata_json"]]

    async def update_scan_status(self, request_id: str, status: str, **kwargs: Any) -> None:
        """Update scan status and optional fields."""
        assert self._db is not None
        updates = ["status = ?"]
        values: list[Any] = [status]

        for key, value in kwargs.items():
            if key in ("completed_at", "total_findings", "risk_score", "risk_level"):
                updates.append(f"{key} = ?")
                values.append(value)

        values.append(request_id)
        await self._db.execute(
            f"UPDATE scans SET {', '.join(updates)} WHERE request_id = ?",
            values,
        )
        await self._db.commit()

    # ── Audit Log ────────────────────────────────────────────────

    async def audit(
        self,
        action: str,
        request_id: str | None = None,
        target: str | None = None,
        module_name: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        """
        Append an entry to the immutable audit log.

        The audit log records all searches for compliance and ethics.
        It must never be deleted or modified.
        """
        assert self._db is not None
        try:
            system_user = os.environ.get("USER") or os.environ.get("USERNAME") or "unknown"
            await self._db.execute(
                """INSERT INTO audit_log
                   (action, request_id, target, module_name, details, system_user)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (
                    action,
                    request_id,
                    target,
                    module_name,
                    json.dumps(details) if details else None,
                    system_user,
                ),
            )
            await self._db.commit()
        except Exception as e:
            logger.error("audit_log_failed", action=action, error=str(e))


# ── Singleton ─────────────────────────────────────────────────────
_cache: SQLiteCache | None = None


async def get_cache() -> SQLiteCache:
    """Get or create the global cache instance."""
    global _cache
    if _cache is None:
        _cache = SQLiteCache()
        await _cache.connect()
    return _cache
