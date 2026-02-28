"""
SerpApi-backed Google search module.

Runs exact-match and OSINT dork queries through SerpApi's Google engine,
capturing both primary results and platform-specific dork hits.
"""

from __future__ import annotations

import asyncio
from typing import Any

import aiohttp
from tenacity import retry, stop_after_attempt, wait_exponential

from app.core.config import get_module_setting, settings
from app.core.constants import ModulePhase, TargetType
from app.core.exceptions import APIError, RateLimitError
from app.core.logging import get_logger
from app.modules.base import BaseModule, ModuleMetadata, ModuleResult
from app.utils.request_log import append_request_log

logger = get_logger(__name__)

_SERPAPI_URL = "https://serpapi.com/search.json"

_DORK_SUFFIXES: list[str] = [
    # Professional networks
    "site:linkedin.com/in",
    "site:github.com",
    "site:stackoverflow.com",
    "site:upwork.com",
    "site:freelancer.com",
    # Social media
    "site:instagram.com",
    "site:facebook.com",
    "(site:x.com OR site:twitter.com)",
    "site:tiktok.com",
    "site:youtube.com",
    "site:reddit.com",
    "site:pinterest.com",
    "site:flickr.com",
    # Q&A and content
    "site:quora.com",
    "site:medium.com",
    "site:dev.to",
    "site:substack.com",
    "site:huggingface.co",
    # Messaging / directories
    "site:t.me",
    "site:keybase.io",
    # Leaks / paste
    "site:pastebin.com",
    "site:raidforums.com OR site:breached.to",
    # Academic / portfolio
    "filetype:pdf",
    "(inurl:resume OR inurl:cv OR inurl:portfolio)",
    "site:academia.edu",
    "site:researchgate.net",
    "(site:news.ycombinator.com OR site:lobste.rs)",
]


class SerpAPISearchModule(BaseModule):
    """Google search and dorking through SerpApi."""

    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            name="serpapi_search",
            display_name="SerpApi Google Search",
            description=(
                "Queries Google search through SerpApi, including dork queries "
                "for LinkedIn, GitHub, Pastebin, PDF, and CV/resume pages."
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
            tags=["search", "serpapi", "google", "dorks", "web"],
        )

    async def run(
        self,
        target: str,
        target_type: TargetType,
        context: dict[str, Any],
    ) -> ModuleResult:
        api_key = self._get_secret(settings.serpapi_api_key)
        if not api_key:
            logger.warning(
                "serpapi_search_skipped",
                reason="SERPAPI_API_KEY not configured",
            )
            return ModuleResult.fail("SerpApi not configured: set SERPAPI_API_KEY")

        results: list[dict[str, Any]] = []
        query_reports: list[dict[str, Any]] = []
        dork_results: dict[str, list[dict[str, Any]]] = {}
        inline_images: list[dict[str, Any]] = []
        dork_inline_images: dict[str, list[dict[str, Any]]] = {}
        image_search_results: list[dict[str, Any]] = []
        knowledge_graph_hits: list[dict[str, Any]] = []
        errors: list[str] = []
        warnings: list[str] = []
        seen_urls: set[str] = set()
        seen_image_urls: set[str] = set()
        fatal_error = False
        pages = max(1, int(get_module_setting("web", "serpapi_search", "pages", 2) or 2))
        max_results = max(
            10,
            int(
                get_module_setting("web", "serpapi_search", "max_results", pages * 10)
                or (pages * 10)
            ),
        )

        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=settings.request_timeout_seconds),
            headers={"User-Agent": "GOD_EYE/1.0"},
        ) as session:
            search_queries = self._build_primary_queries(target, target_type, context)
            append_request_log(
                context,
                module="serpapi_search",
                event="query_plan",
                primary_queries=search_queries,
            )

            for query in search_queries:
                (
                    main_results,
                    image_results,
                    knowledge_items,
                    query_report,
                ) = await self._search_paginated(
                    session=session,
                    api_key=api_key,
                    query=query,
                    pages=pages,
                    limit=max_results,
                    context=context,
                    errors=errors,
                    warnings=warnings,
                )
                query_report["query_type"] = "primary"
                query_reports.append(query_report)
                self._extend_unique(results, main_results, seen_urls, limit=max_results)
                self._extend_unique_images(inline_images, image_results, seen_image_urls)
                self._extend_unique_artifacts(knowledge_graph_hits, knowledge_items)
                if query_report.get("error_status") in {401, 403}:
                    fatal_error = True
                    break

            if not fatal_error:
                dork_queries = self._build_dork_queries(search_queries, context)
                append_request_log(
                    context,
                    module="serpapi_search",
                    event="dork_plan",
                    dork_queries=list(dork_queries.values()),
                )

                dork_tasks = {
                    template: self._search_paginated(
                        session=session,
                        api_key=api_key,
                        query=query,
                        pages=1,
                        limit=max_results,
                        context=context,
                        errors=errors,
                        warnings=warnings,
                    )
                    for template, query in dork_queries.items()
                }

                dork_responses = await asyncio.gather(*dork_tasks.values(), return_exceptions=True)

                for template, response in zip(dork_tasks.keys(), dork_responses, strict=False):
                    if isinstance(response, Exception):
                        errors.append(f"Dork '{template}' failed: {response}")
                        dork_results[template] = []
                    else:
                        items, image_results, knowledge_items, query_report = response  # type: ignore[misc]
                        query_report["query_type"] = "dork"
                        dork_results[template] = items
                        dork_inline_images[template] = image_results
                        query_reports.append(query_report)
                        self._extend_unique_artifacts(knowledge_graph_hits, knowledge_items)
                        if query_report.get("error_status") in {401, 403}:
                            fatal_error = True
                            break

            if not fatal_error:
                image_queries = self._build_image_queries(search_queries, context)
                image_query_limit = max(
                    1,
                    int(get_module_setting("web", "serpapi_search", "image_query_limit", 2) or 2),
                )
                image_result_limit = max(
                    1,
                    int(
                        get_module_setting("web", "serpapi_search", "image_results_per_query", 10)
                        or 10
                    ),
                )
                for query in image_queries[:image_query_limit]:
                    images, image_report = await self._search_images(
                        session=session,
                        api_key=api_key,
                        query=query,
                        limit=image_result_limit,
                        context=context,
                        errors=errors,
                    )
                    image_report["query_type"] = "image"
                    query_reports.append(image_report)
                    self._extend_unique_images(image_search_results, images, seen_image_urls)

        total_results = len(results) + sum(len(v) for v in dork_results.values())
        discovered_image_urls = self._build_discovered_image_urls(
            inline_images,
            dork_inline_images,
            image_search_results,
        )
        discovered_urls = self._build_discovered_urls(
            results,
            dork_results,
            knowledge_graph_hits,
            image_search_results,
        )
        if fatal_error and errors:
            return ModuleResult(
                success=False,
                data={
                    "provider": "serpapi",
                    "search_engine": "google",
                    "results": results,
                    "dork_results": dork_results,
                    "inline_images": inline_images,
                    "dork_inline_images": dork_inline_images,
                    "image_search_results": image_search_results,
                    "knowledge_graph_hits": knowledge_graph_hits,
                    "discovered_image_urls": discovered_image_urls,
                    "discovered_urls": discovered_urls,
                    "total_results": total_results,
                    "total_inline_images": len(discovered_image_urls),
                    "query_reports": query_reports,
                },
                errors=errors,
                warnings=warnings,
            )
        if total_results == 0 and not errors:
            warnings.append(
                "SerpApi returned zero results for these Google queries. Check the exact query "
                "set in request_log.log or broaden the search inputs."
            )
        logger.info(
            "serpapi_search_complete",
            target=target,
            main_results=len(results),
            dork_queries=len(dork_results),
            total=total_results,
        )

        return ModuleResult(
            success=True,
            data={
                "provider": "serpapi",
                "search_engine": "google",
                "results": results,
                "dork_results": dork_results,
                "inline_images": inline_images,
                "dork_inline_images": dork_inline_images,
                "image_search_results": image_search_results,
                "knowledge_graph_hits": knowledge_graph_hits,
                "discovered_image_urls": discovered_image_urls,
                "discovered_urls": discovered_urls,
                "total_results": total_results,
                "total_inline_images": len(discovered_image_urls),
                "query_reports": query_reports,
            },
            errors=errors,
            warnings=warnings,
        )

    async def _search_paginated(
        self,
        session: aiohttp.ClientSession,
        api_key: str,
        query: str,
        pages: int,
        limit: int,
        context: dict[str, Any],
        errors: list[str],
        warnings: list[str],
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
        """Fetch up to `pages` pages of SerpApi Google results."""
        all_items: list[dict[str, Any]] = []
        inline_images: list[dict[str, Any]] = []
        knowledge_graph_hits: list[dict[str, Any]] = []
        reported_total_results = 0
        search_time = 0.0
        error_status: int | None = None
        error_message: str | None = None
        metadata: dict[str, Any] = {}

        for page in range(pages):
            start_index = page * 10
            page_size = min(10, max(1, limit - len(all_items)))
            if page_size <= 0:
                break
            try:
                page_payload = await self._fetch_page(
                    session=session,
                    api_key=api_key,
                    query=query,
                    start=start_index,
                    num=page_size,
                    context=context,
                )
                items = page_payload["items"]
                reported_total_results = max(
                    reported_total_results,
                    int(page_payload.get("reported_total_results", 0) or 0),
                )
                search_time = max(search_time, float(page_payload.get("search_time", 0.0) or 0.0))
                self._extend_unique_images(
                    inline_images, page_payload.get("inline_images", []), set()
                )
                self._extend_unique_artifacts(
                    knowledge_graph_hits, page_payload.get("knowledge_graph_hits", [])
                )
                metadata = page_payload.get("metadata", metadata)
                if not items:
                    break
                all_items.extend(items)
                if len(items) < page_size or len(all_items) >= limit:
                    break
            except RateLimitError:
                warnings.append(f"SerpApi rate-limited on page {page + 1} for query: {query}")
                break
            except APIError as exc:
                errors.append(str(exc))
                error_status = exc.status_code
                error_message = str(exc)
                break

        return (
            all_items[:limit],
            inline_images,
            knowledge_graph_hits,
            {
                "query": query,
                "pages_requested": pages,
                "results_returned": len(all_items[:limit]),
                "reported_total_results": reported_total_results,
                "search_time": search_time,
                "location_used": metadata.get("location_used"),
                "location_requested": metadata.get("location_requested"),
                "organic_results_state": metadata.get("organic_results_state"),
                "json_endpoint": metadata.get("json_endpoint"),
                "raw_html_file": metadata.get("raw_html_file"),
                "error_status": error_status,
                "error": error_message,
            },
        )

    async def _search_images(
        self,
        session: aiohttp.ClientSession,
        api_key: str,
        query: str,
        limit: int,
        context: dict[str, Any],
        errors: list[str],
    ) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        """Fetch Google Images results via SerpApi."""
        try:
            page_payload = await self._fetch_image_page(
                session=session,
                api_key=api_key,
                query=query,
                limit=limit,
                context=context,
            )
            return (
                page_payload["items"],
                {
                    "query": query,
                    "pages_requested": 1,
                    "results_returned": len(page_payload["items"]),
                    "reported_total_results": len(page_payload["items"]),
                    "search_time": float(page_payload.get("search_time", 0.0) or 0.0),
                    "location_used": page_payload.get("metadata", {}).get("location_used"),
                    "location_requested": page_payload.get("metadata", {}).get(
                        "location_requested"
                    ),
                    "organic_results_state": "image_results",
                    "json_endpoint": page_payload.get("metadata", {}).get("json_endpoint"),
                    "raw_html_file": page_payload.get("metadata", {}).get("raw_html_file"),
                    "error_status": None,
                    "error": None,
                },
            )
        except APIError as exc:
            errors.append(str(exc))
            return (
                [],
                {
                    "query": query,
                    "pages_requested": 1,
                    "results_returned": 0,
                    "reported_total_results": 0,
                    "search_time": 0.0,
                    "location_used": None,
                    "location_requested": None,
                    "organic_results_state": "image_results",
                    "json_endpoint": None,
                    "raw_html_file": None,
                    "error_status": exc.status_code,
                    "error": str(exc),
                },
            )

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10),
        reraise=True,
    )
    async def _fetch_page(
        self,
        session: aiohttp.ClientSession,
        api_key: str,
        query: str,
        start: int,
        num: int,
        context: dict[str, Any],
    ) -> dict[str, Any]:
        """Fetch a single page of SerpApi Google results."""
        params: dict[str, str | int] = {
            "engine": "google",
            "api_key": api_key,
            "q": query,
            "start": start,
            "num": num,
        }

        google_domain = get_module_setting("web", "serpapi_search", "google_domain", None)
        location = settings.serpapi_location or get_module_setting(
            "web", "serpapi_search", "location", None
        )
        gl = get_module_setting("web", "serpapi_search", "gl", None)
        hl = get_module_setting("web", "serpapi_search", "hl", None)
        safe = get_module_setting("web", "serpapi_search", "safe", None)
        if google_domain:
            params["google_domain"] = str(google_domain)
        if location:
            params["location"] = str(location)
        if gl:
            params["gl"] = str(gl)
        if hl:
            params["hl"] = str(hl)
        if safe:
            params["safe"] = str(safe)

        endpoint = settings.serpapi_base_url or _SERPAPI_URL
        logger.debug("serpapi_fetch", query=query, start=start, num=num)
        append_request_log(
            context,
            module="serpapi_search",
            event="request",
            endpoint=endpoint,
            query=query,
            start=start,
            num=num,
            engine="google",
            location=params.get("location"),
        )

        async with session.get(endpoint, params=params) as resp:
            payload: Any
            try:
                payload = await resp.json(content_type=None)
            except Exception:
                payload = await resp.text()

            append_request_log(
                context,
                module="serpapi_search",
                event="response",
                query=query,
                start=start,
                status=resp.status,
            )

            if resp.status == 429:
                raise RateLimitError("SerpApi")
            if resp.status in {401, 403}:
                message = self._extract_error_message(payload) or "SerpApi authentication failed"
                raise APIError("SerpApi", resp.status, message)
            if resp.status == 400 and start > 0:
                return {"items": [], "reported_total_results": 0, "search_time": 0.0}
            if resp.status != 200:
                raise APIError("SerpApi", resp.status, self._extract_error_message(payload))
            if isinstance(payload, dict) and payload.get("error"):
                message = self._extract_error_message(payload)
                if self._is_empty_result_message(message):
                    return {
                        "items": [],
                        "inline_images": [],
                        "knowledge_graph_hits": [],
                        "reported_total_results": 0,
                        "search_time": 0.0,
                        "metadata": {},
                    }
                raise APIError("SerpApi", 502, message)

        organic_results = payload.get("organic_results", []) if isinstance(payload, dict) else []
        items: list[dict[str, Any]] = []
        for item in organic_results:
            if not isinstance(item, dict):
                continue
            items.append(
                {
                    "title": item.get("title", ""),
                    "url": item.get("link", ""),
                    "snippet": item.get("snippet", ""),
                    "source": item.get("displayed_link", "") or item.get("source", ""),
                    "position": item.get("position"),
                }
            )

        inline_images = self._parse_inline_images(payload)
        knowledge_graph_hits = self._parse_knowledge_graph(payload)
        search_information = (
            payload.get("search_information", {}) if isinstance(payload, dict) else {}
        )
        search_metadata = payload.get("search_metadata", {}) if isinstance(payload, dict) else {}
        search_parameters = (
            payload.get("search_parameters", {}) if isinstance(payload, dict) else {}
        )

        return {
            "items": items,
            "inline_images": inline_images,
            "knowledge_graph_hits": knowledge_graph_hits,
            "reported_total_results": int(search_information.get("total_results", 0) or 0),
            "search_time": float(search_metadata.get("total_time_taken", 0.0) or 0.0),
            "metadata": {
                "location_requested": search_parameters.get("location_requested"),
                "location_used": search_parameters.get("location_used"),
                "organic_results_state": search_information.get("organic_results_state"),
                "json_endpoint": search_metadata.get("json_endpoint"),
                "raw_html_file": search_metadata.get("raw_html_file"),
            },
        }

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10),
        reraise=True,
    )
    async def _fetch_image_page(
        self,
        session: aiohttp.ClientSession,
        api_key: str,
        query: str,
        limit: int,
        context: dict[str, Any],
    ) -> dict[str, Any]:
        """Fetch Google Images results from SerpApi."""
        params: dict[str, str | int] = {
            "engine": "google_images",
            "api_key": api_key,
            "q": query,
            "ijn": 0,
        }
        google_domain = get_module_setting("web", "serpapi_search", "google_domain", None)
        location = settings.serpapi_location or get_module_setting(
            "web", "serpapi_search", "location", None
        )
        gl = get_module_setting("web", "serpapi_search", "gl", None)
        hl = get_module_setting("web", "serpapi_search", "hl", None)
        if google_domain:
            params["google_domain"] = str(google_domain)
        if location:
            params["location"] = str(location)
        if gl:
            params["gl"] = str(gl)
        if hl:
            params["hl"] = str(hl)

        endpoint = settings.serpapi_base_url or _SERPAPI_URL
        append_request_log(
            context,
            module="serpapi_search",
            event="image_request",
            endpoint=endpoint,
            query=query,
            engine="google_images",
            location=params.get("location"),
        )
        async with session.get(endpoint, params=params) as resp:
            payload: Any
            try:
                payload = await resp.json(content_type=None)
            except Exception:
                payload = await resp.text()
            append_request_log(
                context,
                module="serpapi_search",
                event="image_response",
                query=query,
                status=resp.status,
            )
            if resp.status == 429:
                raise RateLimitError("SerpApi")
            if resp.status in {401, 403}:
                raise APIError("SerpApi", resp.status, self._extract_error_message(payload))
            if resp.status != 200:
                raise APIError("SerpApi", resp.status, self._extract_error_message(payload))
            if isinstance(payload, dict) and payload.get("error"):
                message = self._extract_error_message(payload)
                if self._is_empty_result_message(message):
                    return {"items": [], "search_time": 0.0, "metadata": {}}
                raise APIError("SerpApi", 502, message)

        results = payload.get("images_results", []) if isinstance(payload, dict) else []
        items: list[dict[str, Any]] = []
        for item in results[:limit]:
            if not isinstance(item, dict):
                continue
            items.append(
                {
                    "title": item.get("title", ""),
                    "source_page": item.get("link", ""),
                    "thumbnail": item.get("thumbnail", ""),
                    "original": item.get("original", ""),
                    "source_name": item.get("source", ""),
                    "position": item.get("position"),
                }
            )

        search_metadata = payload.get("search_metadata", {}) if isinstance(payload, dict) else {}
        search_parameters = (
            payload.get("search_parameters", {}) if isinstance(payload, dict) else {}
        )
        return {
            "items": items,
            "search_time": float(search_metadata.get("total_time_taken", 0.0) or 0.0),
            "metadata": {
                "location_requested": search_parameters.get("location_requested"),
                "location_used": search_parameters.get("location_used"),
                "json_endpoint": search_metadata.get("json_endpoint"),
                "raw_html_file": search_metadata.get("raw_html_file"),
            },
        }

    @staticmethod
    def _extract_error_message(payload: Any) -> str:
        if isinstance(payload, dict):
            message = payload.get("error") or payload.get("message")
            if message:
                return str(message)
        return str(payload)[:200]

    @staticmethod
    def _is_empty_result_message(message: str) -> bool:
        normalized = message.lower()
        return "hasn't returned any results" in normalized or "returned any results" in normalized

    @staticmethod
    def _parse_inline_images(payload: Any) -> list[dict[str, Any]]:
        images = payload.get("inline_images", []) if isinstance(payload, dict) else []
        parsed: list[dict[str, Any]] = []
        for item in images:
            if not isinstance(item, dict):
                continue
            parsed.append(
                {
                    "title": item.get("title", ""),
                    "source_page": item.get("source", ""),
                    "thumbnail": item.get("thumbnail", ""),
                    "original": item.get("original", ""),
                    "source_name": item.get("source_name", ""),
                }
            )
        return parsed

    @staticmethod
    def _parse_knowledge_graph(payload: Any) -> list[dict[str, Any]]:
        knowledge_graph = payload.get("knowledge_graph", {}) if isinstance(payload, dict) else {}
        results: list[dict[str, Any]] = []
        if not isinstance(knowledge_graph, dict):
            return results

        for item in knowledge_graph.get("see_results_about", []) or []:
            if not isinstance(item, dict):
                continue
            results.append(
                {
                    "name": item.get("name", ""),
                    "link": item.get("link", ""),
                }
            )
        return results

    @staticmethod
    def _build_image_queries(
        search_queries: list[str],
        context: dict[str, Any],
    ) -> list[str]:
        inputs = context.get("target_inputs", {}) if isinstance(context, dict) else {}
        if not isinstance(inputs, dict):
            inputs = {}

        work = str(inputs.get("work", "") or "").strip()
        location_filter = str(inputs.get("location", "") or "").strip()
        preferred: list[str] = []

        # Build narrowed image queries when work/location available
        name = str(inputs.get("name", "") or "").strip()
        if name and work:
            preferred.append(f"{name} {work}")
        if name and location_filter:
            preferred.append(f"{name} {location_filter}")

        for value in (
            inputs.get("name"),
            inputs.get("username"),
            inputs.get("company"),
        ):
            normalized = str(value or "").strip()
            if normalized:
                preferred.append(normalized)

        for query in search_queries:
            normalized = str(query).strip()
            if not normalized:
                continue
            if any(token in normalized for token in ("@", "site:", "filetype:", "inurl:")):
                continue
            preferred.append(normalized)

        return list(dict.fromkeys(preferred))

    @staticmethod
    def _build_primary_queries(
        target: str,
        target_type: TargetType,
        context: dict[str, Any],
    ) -> list[str]:
        inputs = context.get("target_inputs", {}) if isinstance(context, dict) else {}
        if not isinstance(inputs, dict):
            inputs = {}

        name = str(inputs.get("name", "")).strip()
        email = str(inputs.get("email", "")).strip()
        username = str(inputs.get("username", "")).strip()
        phone = str(inputs.get("phone", "")).strip()
        company = str(inputs.get("company", "")).strip()
        domain = str(inputs.get("domain", "")).strip()
        # Narrowing filters — improve precision for common names
        work = str(inputs.get("work", "")).strip()
        location_filter = str(inputs.get("location", "")).strip()
        normalized = target.strip()

        q = SerpAPISearchModule._quote
        exact_queries: list[str] = []
        relaxed_queries: list[str] = []

        # High-precision narrowed queries when work/location provided (most important — goes first)
        if name and work and location_filter:
            exact_queries.append(f"{q(name)} {q(work)} {q(location_filter)}")
            relaxed_queries.append(f"{name} {work} {location_filter}")
        if name and work:
            exact_queries.append(f"{q(name)} {q(work)}")
            relaxed_queries.append(f"{name} {work}")
        if name and location_filter:
            exact_queries.append(f"{q(name)} {q(location_filter)}")
            relaxed_queries.append(f"{name} {location_filter}")

        if name and email:
            exact_queries.append(f"{q(name)} {q(email)}")
            relaxed_queries.append(f"{name} {email}")
        if name and username:
            exact_queries.append(f"{q(name)} {q(username)}")
            relaxed_queries.append(f"{name} {username}")
        if company and domain:
            exact_queries.append(f"{q(company)} {q(domain)}")
            relaxed_queries.append(f"{company} {domain}")

        for value in [name, email, username, company, phone, normalized]:
            if value:
                exact_queries.append(q(value))
                relaxed_queries.append(value)

        if email and "@" in email:
            local_part, email_domain = email.split("@", 1)
            exact_queries.append(f"{q(local_part)} {q(email_domain)}")
            relaxed_queries.append(f"{local_part} {email_domain}")

        if target_type == TargetType.DOMAIN and normalized:
            exact_queries.append(f"site:{normalized}")
        elif domain:
            exact_queries.append(f"site:{domain}")

        queries = exact_queries + relaxed_queries
        return [
            query for query in dict.fromkeys(query.strip() for query in queries if query.strip())
        ]

    @staticmethod
    def _build_dork_queries(
        search_queries: list[str],
        context: dict[str, Any] | None = None,
    ) -> dict[str, str]:
        max_queries = max(
            1, int(get_module_setting("web", "google_dorker", "max_queries", 30) or 30)
        )
        queries: dict[str, str] = {}

        inputs: dict[str, Any] = {}
        if context and isinstance(context, dict):
            inputs = context.get("target_inputs", {}) or {}

        work = str(inputs.get("work", "") or "").strip()
        location_filter = str(inputs.get("location", "") or "").strip()
        q = SerpAPISearchModule._quote

        # Context-aware LinkedIn dorks (highest value — go first)
        for expression in search_queries:
            if expression.startswith("site:") or not expression:
                continue
            if work and location_filter:
                key = f"linkedin_work_loc :: {expression}"
                queries[key] = f"{expression} site:linkedin.com/in {q(work)} {q(location_filter)}"
            if work:
                key = f"linkedin_work :: {expression}"
                queries[key] = f"{expression} site:linkedin.com/in {q(work)}"
            if location_filter:
                key = f"linkedin_loc :: {expression}"
                queries[key] = f"{expression} site:linkedin.com/in {q(location_filter)}"
            if len(queries) >= max_queries:
                return queries
            break  # Only do context-aware for the first (most specific) primary query

        for suffix in _DORK_SUFFIXES:
            for expression in search_queries:
                if expression.startswith("site:"):
                    continue
                query = f"{expression} {suffix}".strip()
                key = f"{suffix} :: {expression}"
                if key not in queries:
                    queries[key] = query
                if len(queries) >= max_queries:
                    return queries

        return queries

    @staticmethod
    def _quote(value: str) -> str:
        escaped = value.strip().replace('"', '\\"')
        return f'"{escaped}"'

    @staticmethod
    def _extend_unique(
        destination: list[dict[str, Any]],
        incoming: list[dict[str, Any]],
        seen_urls: set[str],
        limit: int,
    ) -> None:
        for item in incoming:
            url = str(item.get("url", "")).strip()
            if not url or url in seen_urls:
                continue
            seen_urls.add(url)
            destination.append(item)
            if len(destination) >= limit:
                break

    @staticmethod
    def _extend_unique_images(
        destination: list[dict[str, Any]],
        incoming: list[dict[str, Any]],
        seen_image_urls: set[str],
    ) -> None:
        local_seen = seen_image_urls
        if not local_seen:
            local_seen = {
                str(item.get("original") or item.get("thumbnail") or "").strip()
                for item in destination
                if isinstance(item, dict)
            }
        for item in incoming:
            if not isinstance(item, dict):
                continue
            image_url = str(item.get("original") or item.get("thumbnail") or "").strip()
            if not image_url or image_url in local_seen:
                continue
            local_seen.add(image_url)
            destination.append(item)

    @staticmethod
    def _extend_unique_artifacts(
        destination: list[dict[str, Any]],
        incoming: list[dict[str, Any]],
    ) -> None:
        for item in incoming:
            if item and item not in destination:
                destination.append(item)

    @staticmethod
    def _build_discovered_image_urls(
        inline_images: list[dict[str, Any]],
        dork_inline_images: dict[str, list[dict[str, Any]]],
        image_search_results: list[dict[str, Any]],
    ) -> list[dict[str, str]]:
        discovered: list[dict[str, str]] = []
        seen: set[str] = set()
        for item in inline_images:
            SerpAPISearchModule._append_discovered_image(discovered, seen, item)
        for items in dork_inline_images.values():
            for item in items:
                SerpAPISearchModule._append_discovered_image(discovered, seen, item)
        for item in image_search_results:
            SerpAPISearchModule._append_discovered_image(discovered, seen, item)
        return discovered

    @staticmethod
    def _append_discovered_image(
        destination: list[dict[str, str]],
        seen: set[str],
        item: dict[str, Any],
    ) -> None:
        image_url = str(item.get("original") or item.get("thumbnail") or "").strip()
        if not image_url or image_url in seen:
            return
        seen.add(image_url)
        destination.append(
            {
                "url": image_url,
                "platform": str(item.get("source_name") or "serpapi").strip().lower() or "serpapi",
                "description": str(item.get("title") or item.get("source_page") or "").strip(),
            }
        )

    @staticmethod
    def _build_discovered_urls(
        results: list[dict[str, Any]],
        dork_results: dict[str, list[dict[str, Any]]],
        knowledge_graph_hits: list[dict[str, Any]],
        image_search_results: list[dict[str, Any]],
    ) -> list[dict[str, str]]:
        discovered: list[dict[str, str]] = []
        seen: set[str] = set()

        def add(
            url: str, title: str = "", snippet: str = "", source_module: str = "serpapi_search"
        ) -> None:
            normalized = str(url).strip()
            if not normalized or normalized in seen:
                return
            seen.add(normalized)
            discovered.append(
                {
                    "url": normalized,
                    "title": str(title).strip(),
                    "snippet": str(snippet).strip(),
                    "source_module": source_module,
                }
            )

        for item in results:
            if isinstance(item, dict):
                add(item.get("url", ""), item.get("title", ""), item.get("snippet", ""))

        for items in dork_results.values():
            for item in items:
                if isinstance(item, dict):
                    add(item.get("url", ""), item.get("title", ""), item.get("snippet", ""))

        for item in knowledge_graph_hits:
            if isinstance(item, dict):
                add(item.get("link", ""), item.get("name", ""), "", "serpapi_knowledge_graph")

        for item in image_search_results:
            if isinstance(item, dict):
                add(
                    item.get("source_page", ""),
                    item.get("title", ""),
                    "",
                    "serpapi_image_search",
                )

        return discovered
