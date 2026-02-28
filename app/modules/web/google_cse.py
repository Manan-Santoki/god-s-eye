"""
Google Custom Search Engine (CSE) module.

Performs standard search queries and OSINT dork queries against Google's
Custom Search JSON API, paginating up to 2 pages (20 results) per query.
"""

from __future__ import annotations

import asyncio
from typing import Any

import aiohttp
from tenacity import retry, stop_after_attempt, wait_exponential

from app.core.config import settings
from app.core.constants import ModulePhase, TargetType
from app.core.exceptions import APIError, RateLimitError
from app.core.logging import get_logger
from app.modules.base import BaseModule, ModuleMetadata, ModuleResult

logger = get_logger(__name__)

_GOOGLE_CSE_URL = "https://www.googleapis.com/customsearch/v1"

# Dork templates: {target} is replaced at runtime.
_DORK_TEMPLATES: list[str] = [
    '"{target}" site:linkedin.com',
    '"{target}" site:github.com',
    '"{target}" filetype:pdf',
    '"{target}" inurl:resume OR inurl:cv',
    '"{target}" site:pastebin.com',
]


class GoogleCSEModule(BaseModule):
    """Google Custom Search Engine OSINT module."""

    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            name="google_cse",
            display_name="Google Custom Search",
            description=(
                "Queries Google CSE for target mentions including dork queries "
                "(LinkedIn, GitHub, Pastebin, PDF, CV/resume)."
            ),
            phase=ModulePhase.SEARCH_ENGINE,
            supported_targets=[
                TargetType.PERSON,
                TargetType.EMAIL,
                TargetType.USERNAME,
                TargetType.DOMAIN,
                TargetType.COMPANY,
                TargetType.PHONE,
            ],
            requires_auth=True,
            enabled_by_default=True,
            tags=["search", "google", "dorks", "web"],
        )

    async def run(
        self,
        target: str,
        target_type: TargetType,
        context: dict[str, Any],
    ) -> ModuleResult:
        api_key = self._get_secret(settings.google_cse_api_key)
        engine_id = settings.google_cse_engine_id

        if not api_key or not engine_id:
            logger.warning(
                "google_cse_skipped",
                reason="GOOGLE_CSE_API_KEY or GOOGLE_CSE_ENGINE_ID not configured",
            )
            return ModuleResult.fail(
                "Google CSE not configured: set GOOGLE_CSE_API_KEY and GOOGLE_CSE_ENGINE_ID"
            )

        results: list[dict[str, Any]] = []
        dork_results: dict[str, list[dict[str, Any]]] = {}
        errors: list[str] = []
        warnings: list[str] = []

        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=settings.request_timeout_seconds),
            headers={"User-Agent": "GOD_EYE/1.0"},
        ) as session:
            # ── Standard paginated search (2 pages, 10 results each) ──────────
            main_results = await self._search_paginated(
                session=session,
                api_key=api_key,
                engine_id=engine_id,
                query=target,
                pages=2,
                errors=errors,
                warnings=warnings,
            )
            results.extend(main_results)

            # ── Dork queries (run in parallel) ───────────────────────────────
            dork_queries = {
                template: template.replace("{target}", target)
                for template in _DORK_TEMPLATES
            }

            dork_tasks = {
                template: self._search_paginated(
                    session=session,
                    api_key=api_key,
                    engine_id=engine_id,
                    query=query,
                    pages=1,
                    errors=errors,
                    warnings=warnings,
                )
                for template, query in dork_queries.items()
            }

            dork_responses = await asyncio.gather(
                *dork_tasks.values(), return_exceptions=True
            )

            for template, response in zip(dork_tasks.keys(), dork_responses):
                if isinstance(response, Exception):
                    errors.append(f"Dork '{template}' failed: {response}")
                    dork_results[template] = []
                else:
                    dork_results[template] = response  # type: ignore[assignment]

        total_results = len(results) + sum(len(v) for v in dork_results.values())
        logger.info(
            "google_cse_complete",
            target=target,
            main_results=len(results),
            dork_queries=len(dork_results),
            total=total_results,
        )

        return ModuleResult(
            success=True,
            data={
                "results": results,
                "dork_results": dork_results,
                "total_results": total_results,
            },
            errors=errors,
            warnings=warnings,
        )

    async def _search_paginated(
        self,
        session: aiohttp.ClientSession,
        api_key: str,
        engine_id: str,
        query: str,
        pages: int,
        errors: list[str],
        warnings: list[str],
    ) -> list[dict[str, Any]]:
        """
        Fetch up to `pages` pages (10 results each) from the Google CSE API.

        Returns a flat list of result dicts with title/url/snippet/source.
        """
        all_items: list[dict[str, Any]] = []

        for page in range(pages):
            start_index = page * 10 + 1  # Google CSE start is 1-based
            try:
                items = await self._fetch_page(
                    session=session,
                    api_key=api_key,
                    engine_id=engine_id,
                    query=query,
                    start=start_index,
                )
                if not items:
                    break  # No more results
                all_items.extend(items)
                if len(items) < 10:
                    break  # Last page was partial — no need to fetch next
            except RateLimitError:
                warnings.append(f"Google CSE rate-limited on page {page + 1} for query: {query}")
                break
            except APIError as exc:
                errors.append(str(exc))
                break

        return all_items

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10),
        reraise=True,
    )
    async def _fetch_page(
        self,
        session: aiohttp.ClientSession,
        api_key: str,
        engine_id: str,
        query: str,
        start: int,
    ) -> list[dict[str, Any]]:
        """
        Fetch a single page of Google CSE results.

        Raises:
            RateLimitError: On HTTP 429.
            APIError: On non-200, non-404 status codes.
        """
        params: dict[str, str | int] = {
            "key": api_key,
            "cx": engine_id,
            "q": query,
            "start": start,
            "num": 10,
        }

        logger.debug("google_cse_fetch", query=query, start=start)

        async with session.get(_GOOGLE_CSE_URL, params=params) as resp:
            if resp.status == 429:
                raise RateLimitError("GoogleCSE")
            if resp.status == 401:
                raise APIError("GoogleCSE", 401, "Invalid API key or engine ID")
            if resp.status == 400:
                # Often means no more results are available
                return []
            if resp.status == 404:
                return []
            if resp.status != 200:
                body = await resp.text()
                raise APIError("GoogleCSE", resp.status, body[:200])

            payload = await resp.json()

        items: list[dict[str, Any]] = []
        for item in payload.get("items", []):
            items.append(
                {
                    "title": item.get("title", ""),
                    "url": item.get("link", ""),
                    "snippet": item.get("snippet", ""),
                    "source": item.get("displayLink", ""),
                }
            )

        return items
