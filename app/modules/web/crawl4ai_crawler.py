"""
Crawl4AI-backed crawler that enriches search engine results with page content.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import aiohttp
from tenacity import retry, stop_after_attempt, wait_exponential

from app.core.config import get_module_setting, settings
from app.core.constants import ModulePhase, TargetType
from app.core.exceptions import APIError, RateLimitError
from app.core.logging import get_logger
from app.modules.base import BaseModule, ModuleMetadata, ModuleResult
from app.utils.request_log import append_request_log

logger = get_logger(__name__)

DEFAULT_SOURCES = ("serpapi_search", "duckduckgo", "bing_search", "google_cse")


class Crawl4AICrawlerModule(BaseModule):
    """Send discovered search-result URLs to a Crawl4AI service."""

    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            name="crawl4ai",
            display_name="Crawl4AI Enrichment",
            description=(
                "Crawls URLs discovered by search modules using a Crawl4AI server "
                "and stores extracted page content."
            ),
            phase=ModulePhase.DEEP_ANALYSIS,
            supported_targets=[
                TargetType.PERSON,
                TargetType.EMAIL,
                TargetType.USERNAME,
                TargetType.DOMAIN,
                TargetType.COMPANY,
                TargetType.PHONE,
            ],
            requires_auth=False,
            enabled_by_default=True,
            tags=["web", "crawl", "crawl4ai", "content"],
        )

    async def run(
        self,
        target: str,
        target_type: TargetType,
        context: dict[str, Any],
    ) -> ModuleResult:
        base_url = self._get_base_url()
        if not base_url:
            return ModuleResult(
                success=True,
                data={
                    "crawled_pages": [],
                    "total_urls_considered": 0,
                    "total_urls_queued": 0,
                    "total_crawled": 0,
                    "source_breakdown": {},
                },
                warnings=[
                    "Crawl4AI not configured: set CRAWL4AI_BASE_URL or modules.web.crawl4ai.base_url"
                ],
            )

        source_names = self._get_source_names()
        module_results = context.get("module_results", {})
        available_sources = (
            sorted(module_results.keys()) if isinstance(module_results, dict) else []
        )
        effective_sources = self._resolve_effective_sources(module_results, source_names)
        candidates = self._collect_search_urls(module_results, effective_sources)
        candidates = self._merge_url_candidates(
            candidates,
            self._extract_context_urls(context),
        )

        raw_data_fallback_used = False
        if not candidates:
            raw_module_results = self._load_raw_module_results(context, effective_sources)
            if raw_module_results:
                raw_data_fallback_used = True
                effective_sources = self._resolve_effective_sources(
                    raw_module_results, effective_sources
                )
                candidates = self._collect_search_urls(raw_module_results, effective_sources)
                candidates = self._merge_url_candidates(
                    candidates,
                    self._extract_raw_discovered_urls(raw_module_results),
                )
        max_urls = max(1, int(get_module_setting("web", "crawl4ai", "max_urls", 5) or 5))
        selected = candidates[:max_urls]

        if not selected:
            return ModuleResult(
                success=True,
                data={
                    "service_url": base_url,
                    "search_sources": source_names,
                    "effective_sources": effective_sources,
                    "available_sources": available_sources,
                    "raw_data_fallback_used": raw_data_fallback_used,
                    "crawled_pages": [],
                    "total_urls_considered": 0,
                    "total_urls_queued": 0,
                    "total_crawled": 0,
                    "source_breakdown": {},
                },
                warnings=[
                    "No search result URLs were available for Crawl4AI enrichment",
                    f"configured_sources={source_names}",
                    f"available_sources={available_sources}",
                ],
            )

        errors: list[str] = []
        warnings: list[str] = []

        try:
            crawled_pages = await self._crawl_urls(
                base_url=base_url, urls=selected, context=context
            )
        except RateLimitError:
            errors.append("Crawl4AI rate limit exceeded")
            crawled_pages = []
        except APIError as exc:
            errors.append(str(exc))
            crawled_pages = []
        except Exception as exc:
            errors.append(f"Crawl4AI request failed: {exc}")
            crawled_pages = []

        normalized_pages = self._normalize_pages(crawled_pages, selected)

        if not normalized_pages:
            warnings.append("Crawl4AI returned no page content for the selected URLs")

        logger.info(
            "crawl4ai_complete",
            target=target,
            total_urls_considered=len(candidates),
            total_urls_queued=len(selected),
            total_crawled=len(normalized_pages),
        )

        return ModuleResult(
            success=not errors,
            data={
                "service_url": base_url,
                "search_sources": source_names,
                "effective_sources": effective_sources,
                "available_sources": available_sources,
                "raw_data_fallback_used": raw_data_fallback_used,
                "crawled_pages": normalized_pages,
                "total_urls_considered": len(candidates),
                "total_urls_queued": len(selected),
                "total_crawled": len(normalized_pages),
                "source_breakdown": self._source_breakdown(selected),
            },
            errors=errors,
            warnings=warnings,
        )

    def _get_base_url(self) -> str | None:
        configured = settings.crawl4ai_base_url or get_module_setting(
            "web", "crawl4ai", "base_url", None
        )
        if not configured:
            return None
        return str(configured).rstrip("/")

    def _get_source_names(self) -> list[str]:
        raw = get_module_setting("web", "crawl4ai", "search_sources", list(DEFAULT_SOURCES))
        if isinstance(raw, list):
            names = [str(item).strip() for item in raw if str(item).strip()]
            return names or list(DEFAULT_SOURCES)
        return list(DEFAULT_SOURCES)

    def _resolve_effective_sources(
        self,
        module_results: dict[str, Any] | Any,
        source_names: list[str],
    ) -> list[str]:
        if not isinstance(module_results, dict):
            return list(source_names)

        effective = [name for name in source_names if name in module_results]
        if effective:
            return effective

        detected = [
            name
            for name, data in module_results.items()
            if isinstance(data, dict) and self._has_extractable_urls(name, data)
        ]
        return detected or list(source_names)

    def _collect_search_urls(
        self,
        module_results: dict[str, Any],
        source_names: list[str],
    ) -> list[dict[str, Any]]:
        seen: set[str] = set()
        collected: list[dict[str, Any]] = []

        for source_name in source_names:
            data = module_results.get(source_name)
            if not isinstance(data, dict):
                continue

            for page in self._extract_urls_for_source(source_name, data):
                url = page.get("url", "")
                normalized_url = url.strip()
                if not normalized_url or normalized_url in seen:
                    continue
                parsed = urlparse(normalized_url)
                if parsed.scheme not in {"http", "https"}:
                    continue
                seen.add(normalized_url)
                page["url"] = normalized_url
                collected.append(page)

        return collected

    def _load_raw_module_results(
        self,
        context: dict[str, Any],
        source_names: list[str],
    ) -> dict[str, Any]:
        request_id = str(context.get("request_id", "")).strip()
        if not request_id:
            return {}

        raw_dir = Path(settings.data_dir) / "requests" / request_id / "raw_data"
        if not raw_dir.exists():
            return {}

        loaded: dict[str, Any] = {}
        for source_name in source_names:
            json_path = raw_dir / f"{source_name}.json"
            if not json_path.exists():
                continue
            try:
                loaded[source_name] = json.loads(json_path.read_text(encoding="utf-8"))
            except Exception:
                continue

        if loaded:
            return loaded

        for json_path in sorted(raw_dir.glob("*.json")):
            source_name = json_path.stem
            if source_name in loaded:
                continue
            try:
                data = json.loads(json_path.read_text(encoding="utf-8"))
            except Exception:
                continue
            if isinstance(data, dict) and self._has_extractable_urls(source_name, data):
                loaded[source_name] = data
        return loaded

    def _has_extractable_urls(self, source_name: str, data: dict[str, Any]) -> bool:
        return bool(self._extract_urls_for_source(source_name, data))

    def _extract_urls_for_source(
        self,
        source_name: str,
        data: dict[str, Any],
    ) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []

        if source_name in {"serpapi_search", "google_cse"}:
            for item in data.get("results", []):
                if isinstance(item, dict):
                    results.append(
                        {
                            "url": item.get("url", ""),
                            "title": item.get("title", ""),
                            "snippet": item.get("snippet", ""),
                            "source_module": source_name,
                        }
                    )
            for items in data.get("dork_results", {}).values():
                if not isinstance(items, list):
                    continue
                for item in items:
                    if isinstance(item, dict):
                        results.append(
                            {
                                "url": item.get("url", ""),
                                "title": item.get("title", ""),
                                "snippet": item.get("snippet", ""),
                                "source_module": source_name,
                            }
                        )
            return results

        if source_name == "duckduckgo":
            for item in data.get("web_results", []):
                if isinstance(item, dict):
                    results.append(
                        {
                            "url": item.get("url", ""),
                            "title": item.get("title", ""),
                            "snippet": item.get("snippet", ""),
                            "source_module": source_name,
                        }
                    )
            return results

        if source_name == "bing_search":
            for item in data.get("results", []):
                if isinstance(item, dict):
                    results.append(
                        {
                            "url": item.get("url", ""),
                            "title": item.get("name", ""),
                            "snippet": item.get("snippet", ""),
                            "source_module": source_name,
                        }
                    )
            return results

        for item in data.get("discovered_urls", []):
            if isinstance(item, dict):
                results.append(
                    {
                        "url": item.get("url", ""),
                        "title": item.get("title", ""),
                        "snippet": item.get("snippet", ""),
                        "source_module": item.get("source_module", source_name),
                    }
                )
            elif isinstance(item, str):
                results.append(
                    {
                        "url": item,
                        "title": "",
                        "snippet": "",
                        "source_module": source_name,
                    }
                )

        return results

    def _extract_context_urls(self, context: dict[str, Any]) -> list[dict[str, Any]]:
        """Collect crawlable URLs already promoted into the scan context."""
        candidates: list[dict[str, Any]] = []
        for item in context.get("discovered_urls", []) or []:
            if isinstance(item, dict):
                candidates.append(
                    {
                        "url": item.get("url", ""),
                        "title": item.get("title", ""),
                        "snippet": item.get("snippet", ""),
                        "source_module": item.get("source_module", "context"),
                    }
                )
            elif isinstance(item, str):
                candidates.append(
                    {
                        "url": item,
                        "title": "",
                        "snippet": "",
                        "source_module": "context",
                    }
                )

        for key, source_module in (
            ("discovered_linkedin_profiles", "linkedin_profile"),
            ("discovered_instagram_profiles", "instagram_profile"),
        ):
            for item in context.get(key, []) or []:
                if isinstance(item, dict):
                    candidates.append(
                        {
                            "url": item.get("url", ""),
                            "title": item.get("slug") or item.get("username") or "",
                            "snippet": "",
                            "source_module": source_module,
                        }
                    )
                elif isinstance(item, str):
                    candidates.append(
                        {
                            "url": item,
                            "title": "",
                            "snippet": "",
                            "source_module": source_module,
                        }
                    )

        return candidates

    def _extract_raw_discovered_urls(
        self, raw_module_results: dict[str, Any]
    ) -> list[dict[str, Any]]:
        candidates: list[dict[str, Any]] = []
        for source_name, data in raw_module_results.items():
            if not isinstance(data, dict):
                continue
            for item in data.get("discovered_urls", []) or []:
                if isinstance(item, dict):
                    candidates.append(
                        {
                            "url": item.get("url", ""),
                            "title": item.get("title", ""),
                            "snippet": item.get("snippet", ""),
                            "source_module": item.get("source_module", source_name),
                        }
                    )
                elif isinstance(item, str):
                    candidates.append(
                        {
                            "url": item,
                            "title": "",
                            "snippet": "",
                            "source_module": source_name,
                        }
                    )
        return candidates

    @staticmethod
    def _merge_url_candidates(
        existing: list[dict[str, Any]],
        extra: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        merged = list(existing)
        seen = {str(item.get("url", "")).strip() for item in merged if isinstance(item, dict)}
        for item in extra:
            if not isinstance(item, dict):
                continue
            normalized = str(item.get("url", "")).strip()
            if not normalized or normalized in seen:
                continue
            seen.add(normalized)
            merged.append(item)
        return merged

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10),
        reraise=True,
    )
    async def _crawl_urls(
        self,
        base_url: str,
        urls: list[dict[str, Any]],
        context: dict[str, Any],
    ) -> Any:
        endpoint = f"{base_url}/crawl"
        payload = {
            "urls": [item["url"] for item in urls],
            "browser_config": {
                "type": "BrowserConfig",
                "params": {
                    "headless": True,
                    "verbose": False,
                },
            },
            "crawler_config": {
                "type": "CrawlerRunConfig",
                "params": {
                    "cache_mode": "bypass",
                    "stream": False,
                },
            },
        }
        headers = {"User-Agent": "GOD_EYE/1.0"}
        token = self._get_secret(settings.crawl4ai_bearer_token)
        if token:
            headers["Authorization"] = f"Bearer {token}"

        logger.debug("crawl4ai_request", endpoint=endpoint, urls=len(urls))
        append_request_log(
            context,
            module="crawl4ai",
            event="request",
            endpoint=endpoint,
            url_count=len(urls),
            urls=[item["url"] for item in urls],
        )

        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=settings.crawl4ai_timeout_seconds),
            headers=headers,
        ) as session:
            async with session.post(endpoint, json=payload) as resp:
                append_request_log(
                    context,
                    module="crawl4ai",
                    event="response",
                    endpoint=endpoint,
                    url_count=len(urls),
                    status=resp.status,
                )
                if resp.status == 429:
                    raise RateLimitError("Crawl4AI")
                if resp.status in {401, 403}:
                    raise APIError("Crawl4AI", resp.status, "Authentication failed")
                if resp.status >= 400:
                    raise APIError("Crawl4AI", resp.status, (await resp.text())[:300])
                return await resp.json(content_type=None)

    def _normalize_pages(
        self,
        response_payload: Any,
        selected_urls: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        if isinstance(response_payload, list):
            raw_pages = response_payload
        elif isinstance(response_payload, dict):
            raw_pages = (
                response_payload.get("results")
                or response_payload.get("result")
                or response_payload.get("data")
                or []
            )
            if isinstance(raw_pages, dict):
                raw_pages = [raw_pages]
        else:
            raw_pages = []

        selected_by_url = {item["url"]: item for item in selected_urls}
        normalized: list[dict[str, Any]] = []

        for item in raw_pages:
            if not isinstance(item, dict):
                continue
            url = str(item.get("url") or item.get("source_url") or "").strip()
            if not url:
                continue
            source = selected_by_url.get(url, {})
            markdown = self._extract_text(item, "markdown")
            cleaned_html = self._extract_text(item, "cleaned_html")
            normalized.append(
                {
                    "url": url,
                    "title": item.get("title") or source.get("title", ""),
                    "source_module": source.get("source_module", ""),
                    "snippet": source.get("snippet", ""),
                    "success": bool(item.get("success", True)),
                    "markdown": markdown,
                    "cleaned_html": cleaned_html,
                    "links": self._extract_links(item),
                    "metadata": item.get("metadata", {})
                    if isinstance(item.get("metadata"), dict)
                    else {},
                }
            )

        return normalized

    @staticmethod
    def _extract_text(item: dict[str, Any], field: str) -> str:
        value = item.get(field, "")
        if isinstance(value, str):
            return value
        if isinstance(value, dict):
            return str(
                value.get("raw_markdown") or value.get("fit_markdown") or value.get("content") or ""
            )
        return ""

    @staticmethod
    def _extract_links(item: dict[str, Any]) -> list[str]:
        links = item.get("links", {})
        if isinstance(links, list):
            return [str(link) for link in links if link]
        if isinstance(links, dict):
            flattened: list[str] = []
            for values in links.values():
                if isinstance(values, list):
                    flattened.extend(str(link) for link in values if link)
            return flattened
        return []

    @staticmethod
    def _source_breakdown(urls: list[dict[str, Any]]) -> dict[str, int]:
        counts: dict[str, int] = {}
        for item in urls:
            source = str(item.get("source_module", "unknown"))
            counts[source] = counts.get(source, 0) + 1
        return counts
