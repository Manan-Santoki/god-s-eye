"""
Bing Web Search module.

Uses the Microsoft Bing Web Search API v7 to retrieve up to 20 web results
for the given target query.
"""

from __future__ import annotations

from typing import Any

import aiohttp
from tenacity import retry, stop_after_attempt, wait_exponential

from app.core.config import settings
from app.core.constants import ModulePhase, TargetType
from app.core.exceptions import APIError, RateLimitError
from app.core.logging import get_logger
from app.modules.base import BaseModule, ModuleMetadata, ModuleResult

logger = get_logger(__name__)

_BING_SEARCH_URL = "https://api.bing.microsoft.com/v7.0/search"


class BingSearchModule(BaseModule):
    """Bing Web Search API v7 module."""

    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            name="bing_search",
            display_name="Bing Web Search",
            description="Searches Bing for target mentions, returning up to 20 web results.",
            phase=ModulePhase.SEARCH_ENGINE,
            supported_targets=[
                TargetType.PERSON,
                TargetType.EMAIL,
                TargetType.USERNAME,
                TargetType.DOMAIN,
                TargetType.COMPANY,
                TargetType.PHONE,
                TargetType.IP,
            ],
            requires_auth=True,
            enabled_by_default=True,
            tags=["search", "bing", "microsoft", "web"],
        )

    async def run(
        self,
        target: str,
        target_type: TargetType,
        context: dict[str, Any],
    ) -> ModuleResult:
        api_key = self._get_secret(settings.bing_api_key)

        if not api_key:
            logger.warning(
                "bing_search_skipped",
                reason="BING_API_KEY not configured",
            )
            return ModuleResult.fail(
                "Bing Search not configured: set BING_API_KEY in .env"
            )

        errors: list[str] = []
        warnings: list[str] = []

        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=settings.request_timeout_seconds),
            headers={
                "Ocp-Apim-Subscription-Key": api_key,
                "User-Agent": "GOD_EYE/1.0",
            },
        ) as session:
            try:
                results = await self._fetch_results(
                    session=session,
                    query=target,
                )
            except RateLimitError:
                return ModuleResult.fail("Bing API rate limit exceeded (HTTP 429)")
            except APIError as exc:
                return ModuleResult.fail(str(exc))

        total_results = len(results)
        logger.info(
            "bing_search_complete",
            target=target,
            total_results=total_results,
        )

        return ModuleResult(
            success=True,
            data={
                "results": results,
                "total_results": total_results,
            },
            errors=errors,
            warnings=warnings,
        )

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10),
        reraise=True,
    )
    async def _fetch_results(
        self,
        session: aiohttp.ClientSession,
        query: str,
    ) -> list[dict[str, str]]:
        """
        Call the Bing Web Search API and return a list of result dicts.

        Each result has: name, url, snippet.

        Raises:
            RateLimitError: On HTTP 429.
            APIError: On 401, 403, or other non-200 codes.
        """
        params: dict[str, Any] = {
            "q": query,
            "count": 20,
            "offset": 0,
            "mkt": "en-US",
            "safeSearch": "Off",
        }

        logger.debug("bing_search_fetch", query=query)

        async with session.get(_BING_SEARCH_URL, params=params) as resp:
            if resp.status == 429:
                raise RateLimitError("BingSearch")
            if resp.status == 401:
                raise APIError("BingSearch", 401, "Invalid or missing Ocp-Apim-Subscription-Key")
            if resp.status == 403:
                raise APIError("BingSearch", 403, "Access forbidden — check subscription tier")
            if resp.status == 404:
                return []
            if resp.status != 200:
                body = await resp.text()
                raise APIError("BingSearch", resp.status, body[:200])

            payload = await resp.json()

        results: list[dict[str, str]] = []
        web_pages = payload.get("webPages", {})
        for item in web_pages.get("value", []):
            results.append(
                {
                    "name": item.get("name", ""),
                    "url": item.get("url", ""),
                    "snippet": item.get("snippet", ""),
                }
            )

        return results
