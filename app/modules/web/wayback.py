"""
Wayback Machine archive lookup module.

Checks Internet Archive availability and retrieves snapshot history for
a given URL or domain using both the availability API and the CDX API.

No API key required.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

import aiohttp
from tenacity import retry, stop_after_attempt, wait_exponential

from app.core.config import settings
from app.core.constants import ModulePhase, TargetType
from app.core.exceptions import APIError, RateLimitError
from app.core.logging import get_logger
from app.modules.base import BaseModule, ModuleMetadata, ModuleResult

logger = get_logger(__name__)

_AVAILABILITY_URL = "https://archive.org/wayback/available"
_CDX_URL = "https://web.archive.org/cdx/search/cdx"
_WAYBACK_BASE = "https://web.archive.org/web"


class WaybackModule(BaseModule):
    """Wayback Machine snapshot history module."""

    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            name="wayback",
            display_name="Wayback Machine",
            description=(
                "Checks Internet Archive for archived snapshots of a URL/domain. "
                "Returns snapshot history, earliest/latest captures, and availability."
            ),
            phase=ModulePhase.SEARCH_ENGINE,
            supported_targets=[
                TargetType.DOMAIN,
                TargetType.EMAIL,
                TargetType.COMPANY,
            ],
            requires_auth=False,
            enabled_by_default=True,
            tags=["web", "archive", "history", "wayback", "no-key"],
        )

    async def run(
        self,
        target: str,
        target_type: TargetType,
        context: dict[str, Any],
    ) -> ModuleResult:
        # Normalise the target to a clean domain/URL
        domain = self._extract_domain(target)

        errors: list[str] = []
        warnings: list[str] = []

        import asyncio

        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=settings.request_timeout_seconds),
            headers={"User-Agent": "GOD_EYE/1.0 (+https://github.com/god-eye)"},
        ) as session:
            availability_task = self._check_availability(session, domain, errors)
            cdx_task = self._fetch_cdx_snapshots(session, domain, errors, warnings)

            availability, snapshots = await asyncio.gather(
                availability_task, cdx_task, return_exceptions=True
            )

        if isinstance(availability, Exception):
            errors.append(f"Availability check failed: {availability}")
            availability = {}

        if isinstance(snapshots, Exception):
            errors.append(f"CDX fetch failed: {snapshots}")
            snapshots = []

        # Derive summary fields
        has_archives = bool(snapshots) or bool(
            availability.get("available")  # type: ignore[union-attr]
        )
        earliest = snapshots[0]["timestamp"] if snapshots else None  # type: ignore[index]
        latest = snapshots[-1]["timestamp"] if snapshots else None  # type: ignore[index]

        availability_url: str = availability.get("url", "")  # type: ignore[union-attr]

        logger.info(
            "wayback_complete",
            domain=domain,
            has_archives=has_archives,
            total_snapshots=len(snapshots),  # type: ignore[arg-type]
            earliest=earliest,
            latest=latest,
        )

        return ModuleResult(
            success=True,
            data={
                "has_archives": has_archives,
                "earliest_snapshot": earliest,
                "latest_snapshot": latest,
                "total_snapshots": len(snapshots),  # type: ignore[arg-type]
                "snapshots": snapshots,
                "availability_url": availability_url,
            },
            errors=errors,
            warnings=warnings,
        )

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10),
        reraise=True,
    )
    async def _check_availability(
        self,
        session: aiohttp.ClientSession,
        target: str,
        errors: list[str],
    ) -> dict[str, Any]:
        """
        Call the Wayback availability API.

        Returns a dict with 'available' (bool) and 'url' (closest snapshot URL).
        """
        params = {"url": target}
        logger.debug("wayback_availability_check", target=target)

        async with session.get(_AVAILABILITY_URL, params=params) as resp:
            if resp.status == 429:
                raise RateLimitError("WaybackAvailability")
            if resp.status == 404:
                return {"available": False, "url": ""}
            if resp.status != 200:
                raise APIError("WaybackAvailability", resp.status, await resp.text())

            payload = await resp.json(content_type=None)

        archived = payload.get("archived_snapshots", {})
        closest = archived.get("closest", {})
        available = closest.get("available", False)
        snap_url = closest.get("url", "")

        return {"available": available, "url": snap_url}

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=3, max=15),
        reraise=True,
    )
    async def _fetch_cdx_snapshots(
        self,
        session: aiohttp.ClientSession,
        domain: str,
        errors: list[str],
        warnings: list[str],
    ) -> list[dict[str, str]]:
        """
        Fetch snapshot history from the CDX API (limited to 50 entries).

        Returns a list of dicts with timestamp, url, status, and wayback_url.
        The list is sorted oldest-first.
        """
        params: dict[str, Any] = {
            "url": domain,
            "output": "json",
            "limit": 50,
            "fl": "timestamp,original,statuscode",
            "collapse": "digest",  # Remove near-duplicate snapshots
            "from": "",
        }

        logger.debug("wayback_cdx_fetch", domain=domain)

        async with session.get(_CDX_URL, params=params) as resp:
            if resp.status == 429:
                raise RateLimitError("WaybackCDX")
            if resp.status == 404:
                return []
            if resp.status != 200:
                raise APIError("WaybackCDX", resp.status, await resp.text())

            # CDX returns JSON array-of-arrays; first row is header
            raw = await resp.json(content_type=None)

        if not raw or len(raw) < 2:
            return []

        header = raw[0]  # ["timestamp", "original", "statuscode"]
        rows = raw[1:]

        # Build index mapping column name -> position
        try:
            ts_idx = header.index("timestamp")
            url_idx = header.index("original")
            code_idx = header.index("statuscode")
        except ValueError:
            warnings.append("CDX API returned unexpected column headers")
            return []

        snapshots: list[dict[str, str]] = []
        for row in rows:
            if len(row) < max(ts_idx, url_idx, code_idx) + 1:
                continue
            ts = row[ts_idx]
            orig_url = row[url_idx]
            status = row[code_idx]

            # Build the Wayback Machine replay URL
            wayback_url = f"{_WAYBACK_BASE}/{ts}/{orig_url}"

            snapshots.append(
                {
                    "timestamp": ts,
                    "url": orig_url,
                    "status": status,
                    "wayback_url": wayback_url,
                }
            )

        # Sort oldest-first
        snapshots.sort(key=lambda x: x["timestamp"])
        return snapshots

    @staticmethod
    def _extract_domain(target: str) -> str:
        """
        Normalise target to a bare domain or URL suitable for Wayback lookups.

        - If it looks like a URL, strip the scheme.
        - If it's an email, extract the domain part.
        - Otherwise return as-is.
        """
        target = target.strip()

        # Email address — extract domain
        if "@" in target and not target.startswith("http"):
            return target.split("@", 1)[1]

        # If it has a scheme, parse it
        if "://" in target:
            parsed = urlparse(target)
            return parsed.netloc or target

        return target
