"""
DuckDuckGo search module.

Uses two DuckDuckGo endpoints:
  1. Instant Answer JSON API  — for abstract, answer, and related topics.
  2. HTML search endpoint     — scraped with BeautifulSoup for organic results.

No API key required.
"""

from __future__ import annotations

import re
from typing import Any

import aiohttp
from bs4 import BeautifulSoup
from tenacity import retry, stop_after_attempt, wait_exponential

from app.core.config import settings
from app.core.constants import ModulePhase, TargetType
from app.core.exceptions import APIError, RateLimitError
from app.core.logging import get_logger
from app.modules.base import BaseModule, ModuleMetadata, ModuleResult
from app.utils.request_log import append_request_log

logger = get_logger(__name__)

_DDG_API_URL = "https://api.duckduckgo.com/"
_DDG_HTML_URL = "https://html.duckduckgo.com/html/"

_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36"
    ),
    "Accept-Language": "en-US,en;q=0.9",
}


class DuckDuckGoModule(BaseModule):
    """DuckDuckGo Instant Answer + HTML search scraper."""

    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            name="duckduckgo",
            display_name="DuckDuckGo Search",
            description=(
                "Searches DuckDuckGo for target mentions via the Instant Answer API "
                "and HTML scraping. No API key required."
            ),
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
            requires_auth=False,
            enabled_by_default=True,
            tags=["search", "duckduckgo", "web", "no-key"],
        )

    async def run(
        self,
        target: str,
        target_type: TargetType,
        context: dict[str, Any],
    ) -> ModuleResult:
        errors: list[str] = []
        warnings: list[str] = []

        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=settings.request_timeout_seconds),
            headers=_HEADERS,
        ) as session:
            # Run both endpoints concurrently
            import asyncio

            api_task = self._fetch_instant_answer(session, target, context, errors)
            html_task = self._fetch_html_results(session, target, context, errors, warnings)

            api_data, web_results = await asyncio.gather(
                api_task, html_task, return_exceptions=True
            )

        # Handle gather exceptions
        if isinstance(api_data, Exception):
            errors.append(f"Instant Answer API error: {api_data}")
            api_data = {}

        if isinstance(web_results, Exception):
            errors.append(f"HTML scrape error: {web_results}")
            web_results = []

        abstract: str = api_data.get("abstract", "")  # type: ignore[union-attr]
        abstract_url: str = api_data.get("abstract_url", "")  # type: ignore[union-attr]
        answer: str = api_data.get("answer", "")  # type: ignore[union-attr]
        related_topics: list[dict[str, str]] = api_data.get("related_topics", [])  # type: ignore[union-attr]

        total = len(web_results) + len(related_topics)  # type: ignore[arg-type]

        logger.info(
            "duckduckgo_complete",
            target=target,
            web_results=len(web_results),  # type: ignore[arg-type]
            related_topics=len(related_topics),
            has_abstract=bool(abstract),
        )

        return ModuleResult(
            success=True,
            data={
                "abstract": abstract,
                "abstract_url": abstract_url,
                "answer": answer,
                "related_topics": related_topics,
                "web_results": web_results,
                "total": total,
            },
            errors=errors,
            warnings=warnings,
        )

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10),
        reraise=True,
    )
    async def _fetch_instant_answer(
        self,
        session: aiohttp.ClientSession,
        query: str,
        context: dict[str, Any],
        errors: list[str],
    ) -> dict[str, Any]:
        """
        Call the DuckDuckGo Instant Answer JSON API.

        Returns a dict with abstract, abstract_url, answer, and related_topics.
        """
        params = {
            "q": query,
            "format": "json",
            "no_html": "1",
            "skip_disambig": "1",
        }

        logger.debug("ddg_instant_answer_fetch", query=query)
        append_request_log(
            context,
            module="duckduckgo",
            event="request",
            endpoint=_DDG_API_URL,
            query=query,
            mode="instant_answer",
        )

        async with session.get(_DDG_API_URL, params=params) as resp:
            append_request_log(
                context,
                module="duckduckgo",
                event="response",
                query=query,
                mode="instant_answer",
                status=resp.status,
            )
            if resp.status == 429:
                raise RateLimitError("DuckDuckGo")
            if resp.status != 200:
                raise APIError("DuckDuckGo", resp.status, await resp.text())

            payload = await resp.json(content_type=None)

        related_topics: list[dict[str, str]] = []
        for topic in payload.get("RelatedTopics", []):
            if isinstance(topic, dict):
                # Flatten nested topic groups
                if "Topics" in topic:
                    for sub in topic["Topics"]:
                        if isinstance(sub, dict):
                            related_topics.append(
                                {
                                    "text": sub.get("Text", ""),
                                    "url": sub.get("FirstURL", ""),
                                }
                            )
                else:
                    related_topics.append(
                        {
                            "text": topic.get("Text", ""),
                            "url": topic.get("FirstURL", ""),
                        }
                    )

        return {
            "abstract": payload.get("AbstractText", ""),
            "abstract_url": payload.get("AbstractURL", ""),
            "answer": payload.get("Answer", ""),
            "related_topics": related_topics,
        }

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=3, max=15),
        reraise=True,
    )
    async def _fetch_html_results(
        self,
        session: aiohttp.ClientSession,
        query: str,
        context: dict[str, Any],
        errors: list[str],
        warnings: list[str],
    ) -> list[dict[str, str]]:
        """
        Scrape DuckDuckGo HTML search for organic web results.

        Returns a list of dicts with title, url, and snippet.
        """
        params = {"q": query, "b": ""}

        logger.debug("ddg_html_fetch", query=query)
        append_request_log(
            context,
            module="duckduckgo",
            event="request",
            endpoint=_DDG_HTML_URL,
            query=query,
            mode="html",
        )

        async with session.post(_DDG_HTML_URL, data=params) as resp:
            append_request_log(
                context,
                module="duckduckgo",
                event="response",
                query=query,
                mode="html",
                status=resp.status,
            )
            if resp.status == 429:
                warnings.append("DuckDuckGo HTML search rate-limited")
                return []
            if resp.status == 403:
                warnings.append("DuckDuckGo HTML search blocked (403)")
                return []
            if resp.status != 200:
                raise APIError("DuckDuckGoHTML", resp.status, await resp.text())

            html = await resp.text()

        soup = BeautifulSoup(html, "html.parser")
        results: list[dict[str, str]] = []

        # DuckDuckGo HTML results are in <div class="result"> elements
        for result_div in soup.select("div.result"):
            title_tag = result_div.select_one("a.result__a")
            snippet_tag = result_div.select_one("a.result__snippet")

            if not title_tag:
                continue

            title = title_tag.get_text(strip=True)
            raw_href = title_tag.get("href", "")

            # DDG encodes URLs in a redirect: extract the actual URL
            url = self._extract_url(str(raw_href))
            snippet = snippet_tag.get_text(strip=True) if snippet_tag else ""

            if title and url:
                results.append({"title": title, "url": url, "snippet": snippet})

        return results

    @staticmethod
    def _extract_url(href: str) -> str:
        """
        Extract the destination URL from a DuckDuckGo redirect link.

        DuckDuckGo wraps outbound URLs in: //duckduckgo.com/l/?uddg=<encoded_url>&...
        """
        if not href:
            return ""

        # Already a direct URL
        if href.startswith(("http://", "https://")):
            return href

        # Extract uddg parameter from redirect
        match = re.search(r"[?&]uddg=([^&]+)", href)
        if match:
            from urllib.parse import unquote

            return unquote(match.group(1))

        # Relative path with /l/ redirect
        if "/l/?" in href:
            match = re.search(r"[?&]uddg=([^&]+)", href)
            if match:
                from urllib.parse import unquote

                return unquote(match.group(1))

        return href
