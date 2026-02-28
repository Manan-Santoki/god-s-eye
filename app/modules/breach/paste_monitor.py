"""
Paste site monitoring module.

Searches multiple paste sites for mentions of the target without requiring
any API key. Uses DuckDuckGo HTML search for site-scoped queries and also
scrapes Pastebin's own search endpoint.

Sites monitored:
  - pastebin.com  (DuckDuckGo site: query + direct Pastebin search)
  - paste.ee      (DuckDuckGo site: query)

Parsing is done with BeautifulSoup. All network calls are async via aiohttp.

Phase: BREACH_DB (no API key required).
"""

from __future__ import annotations

import asyncio
import time
from typing import Any

import aiohttp
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

try:
    from bs4 import BeautifulSoup

    _BS4_AVAILABLE = True
except ImportError:
    _BS4_AVAILABLE = False

from app.core.config import settings
from app.core.constants import ModulePhase, TargetType
from app.core.exceptions import RateLimitError
from app.core.logging import get_logger
from app.modules.base import BaseModule, ModuleMetadata, ModuleResult

logger = get_logger(__name__)

# DuckDuckGo HTML endpoint (no JS required, rate-limit friendly)
_DDG_URL = "https://html.duckduckgo.com/html/"

# Pastebin direct search endpoint
_PASTEBIN_SEARCH_URL = "https://pastebin.com/search"

# Sites to query via DuckDuckGo
_PASTE_SITES = [
    "pastebin.com",
    "paste.ee",
]

_USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)


class PasteMonitorModule(BaseModule):
    """
    Paste site monitor — searches pastebin.com and paste.ee for target mentions.

    Uses DuckDuckGo's HTML search interface for site-scoped queries and also
    checks Pastebin's own search page. No API key is required. All HTTP calls
    are async with tenacity retry logic.
    """

    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            name="paste_monitor",
            display_name="Paste Site Monitor",
            description=(
                "Searches pastebin.com and paste.ee for pastes mentioning the target. "
                "Uses DuckDuckGo site: queries and Pastebin direct search. "
                "No API key required."
            ),
            phase=ModulePhase.BREACH_DB,
            supported_targets=[
                TargetType.EMAIL,
                TargetType.USERNAME,
                TargetType.PERSON,
                TargetType.DOMAIN,
                TargetType.PHONE,
            ],
            requires_auth=False,
            rate_limit_rpm=10,
            timeout_seconds=30,
            enabled_by_default=True,
            tags=["paste", "pastebin", "leak", "no-key", "breach", "monitoring"],
        )

    async def run(
        self,
        target: str,
        target_type: TargetType,
        context: dict[str, Any],
    ) -> ModuleResult:
        if not _BS4_AVAILABLE:
            return ModuleResult.fail(
                "BeautifulSoup4 is not installed. Run: pip install beautifulsoup4"
            )

        term = target.strip()
        start = time.monotonic()
        warnings: list[str] = []
        errors: list[str] = []

        logger.info("paste_monitor_start", target=term)

        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=settings.request_timeout_seconds),
            headers={
                "User-Agent": _USER_AGENT,
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.5",
            },
        ) as session:
            # Run DuckDuckGo site: queries in parallel for each paste site
            ddg_tasks = [
                self._search_ddg(session, term, site, warnings, errors) for site in _PASTE_SITES
            ]
            # Also run Pastebin direct search concurrently
            pastebin_task = self._search_pastebin_direct(session, term, warnings, errors)

            results = await asyncio.gather(
                *ddg_tasks,
                pastebin_task,
                return_exceptions=True,
            )

        # Flatten and deduplicate all found pastes
        all_pastes: list[dict[str, Any]] = []
        seen_urls: set[str] = set()

        for result in results:
            if isinstance(result, Exception):
                errors.append(f"Search task failed: {result}")
                continue
            if isinstance(result, list):
                for paste in result:
                    url = paste.get("url", "")
                    if url and url not in seen_urls:
                        seen_urls.add(url)
                        all_pastes.append(paste)

        # Sort by date descending (most recent first), unknown dates last
        all_pastes.sort(key=lambda p: p.get("date") or "", reverse=True)

        sites_checked = _PASTE_SITES + ["pastebin.com (direct)"]
        total_found = len(all_pastes)

        elapsed_ms = int((time.monotonic() - start) * 1000)
        logger.info(
            "paste_monitor_complete",
            target=term,
            total_found=total_found,
            elapsed_ms=elapsed_ms,
        )

        return ModuleResult(
            success=True,
            data={
                "found_pastes": all_pastes,
                "total_found": total_found,
                "sites_checked": sites_checked,
            },
            errors=errors,
            warnings=warnings,
        )

    # ── DuckDuckGo site: search ───────────────────────────────────────────────

    @retry(
        retry=retry_if_exception_type(RateLimitError),
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=2, min=5, max=30),
        reraise=False,  # Return [] on final failure rather than propagating
    )
    async def _search_ddg(
        self,
        session: aiohttp.ClientSession,
        term: str,
        site: str,
        warnings: list[str],
        errors: list[str],
    ) -> list[dict[str, Any]]:
        """
        Search DuckDuckGo HTML for: site:{site} "{term}".

        Parses DuckDuckGo's HTML result page for result URLs, titles, and
        snippet text. Returns list of paste records.
        """
        query = f'site:{site} "{term}"'
        params = {"q": query, "b": ""}

        logger.debug("ddg_search", query=query, site=site)

        try:
            async with session.post(_DDG_URL, data=params) as resp:
                if resp.status == 429:
                    raise RateLimitError("DuckDuckGo")
                if resp.status != 200:
                    warnings.append(f"DuckDuckGo returned HTTP {resp.status} for {site} search")
                    return []
                html = await resp.text()
        except RateLimitError:
            raise
        except TimeoutError:
            warnings.append(f"DuckDuckGo search timed out for site:{site}")
            return []
        except Exception as exc:
            warnings.append(f"DuckDuckGo search error for site:{site}: {exc}")
            return []

        return self._parse_ddg_results(html, site)

    def _parse_ddg_results(self, html: str, site: str) -> list[dict[str, Any]]:
        """
        Parse DuckDuckGo HTML search results page.

        Extracts result links, titles, and snippet text from the standard
        DuckDuckGo HTML layout.
        """
        pastes: list[dict[str, Any]] = []
        try:
            soup = BeautifulSoup(html, "html.parser")

            # DuckDuckGo HTML results are in divs with class "result"
            results = soup.find_all("div", class_="result")
            if not results:
                # Fallback: look for any anchor tags pointing to the site
                results = soup.find_all("a", href=lambda h: h and site in h)

            for result in results:
                # Extract URL
                url = ""
                if hasattr(result, "find"):
                    link = result.find("a", class_="result__a")
                    if not link:
                        link = result.find("a", href=lambda h: h and site in (h or ""))
                    if link and link.get("href"):
                        url = str(link["href"])
                        # DuckDuckGo sometimes wraps URLs in redirects
                        if "duckduckgo.com" in url and "uddg=" in url:
                            from urllib.parse import parse_qs, urlparse

                            parsed = urlparse(url)
                            qs = parse_qs(parsed.query)
                            url = qs.get("uddg", [url])[0]
                elif isinstance(result, str):
                    continue

                if not url or site not in url:
                    continue

                # Extract title
                title = ""
                if hasattr(result, "find"):
                    title_tag = result.find("a", class_="result__a")
                    if title_tag:
                        title = title_tag.get_text(strip=True)

                # Extract snippet/preview
                preview = ""
                if hasattr(result, "find"):
                    snippet_tag = result.find(class_="result__snippet")
                    if snippet_tag:
                        preview = snippet_tag.get_text(strip=True)[:300]

                pastes.append(
                    {
                        "url": url,
                        "title": title or url,
                        "date": "",  # DuckDuckGo results rarely include dates
                        "preview": preview,
                        "source": site,
                        "method": "duckduckgo",
                    }
                )
        except Exception as exc:
            logger.warning("ddg_parse_error", site=site, error=str(exc))

        return pastes

    # ── Pastebin direct search ────────────────────────────────────────────────

    async def _search_pastebin_direct(
        self,
        session: aiohttp.ClientSession,
        term: str,
        warnings: list[str],
        errors: list[str],
    ) -> list[dict[str, Any]]:
        """
        Search Pastebin's own search page: https://pastebin.com/search?q={term}.

        Pastebin's search returns HTML results with paste titles, URLs, and
        dates. This is scraped with BeautifulSoup.
        """
        params = {"q": term}
        logger.debug("pastebin_direct_search", term=term)

        try:
            async with session.get(_PASTEBIN_SEARCH_URL, params=params) as resp:
                if resp.status == 429:
                    warnings.append("Pastebin direct search rate limited")
                    return []
                if resp.status != 200:
                    warnings.append(f"Pastebin direct search returned HTTP {resp.status}")
                    return []
                html = await resp.text()
        except TimeoutError:
            warnings.append("Pastebin direct search timed out")
            return []
        except Exception as exc:
            warnings.append(f"Pastebin direct search error: {exc}")
            return []

        return self._parse_pastebin_results(html)

    def _parse_pastebin_results(self, html: str) -> list[dict[str, Any]]:
        """
        Parse Pastebin search results page HTML.

        Pastebin's search results use a standard layout with .gsc-result or
        similar container divs and anchor tags for each paste entry.
        """
        pastes: list[dict[str, Any]] = []
        try:
            soup = BeautifulSoup(html, "html.parser")

            # Pastebin search results page layout — look for paste links
            # The results are typically in a <ul class="search-results"> or similar
            result_containers = (
                soup.find_all("div", class_="visit-paste-first-line")
                or soup.find_all("li", class_="item")
                or soup.find_all("div", class_="search-result")
            )

            for container in result_containers:
                link = container.find("a")
                if not link or not link.get("href"):
                    continue

                href = str(link["href"])
                if not href.startswith("http"):
                    href = f"https://pastebin.com{href}"

                title = link.get_text(strip=True)

                # Attempt to extract date
                date = ""
                date_tag = container.find("span", class_="date") or container.find("date")
                if date_tag:
                    date = date_tag.get_text(strip=True)

                # Attempt to extract preview
                preview = ""
                preview_tag = container.find("p") or container.find("div", class_="paste-content")
                if preview_tag:
                    preview = preview_tag.get_text(strip=True)[:300]

                pastes.append(
                    {
                        "url": href,
                        "title": title or href,
                        "date": date,
                        "preview": preview,
                        "source": "pastebin.com",
                        "method": "pastebin_direct",
                    }
                )

        except Exception as exc:
            logger.warning("pastebin_parse_error", error=str(exc))

        return pastes
