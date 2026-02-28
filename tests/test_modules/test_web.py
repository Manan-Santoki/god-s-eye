"""
Tests for web search and crawling modules.
"""

from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from app.core.constants import TargetType


class TestBaseModuleValidateCompatibility:
    @pytest.mark.asyncio
    async def test_validate_wrapper_accepts_context_for_legacy_signature(self):
        from app.modules.social.youtube_api import YouTubeAPI

        module = YouTubeAPI()
        assert await module.validate(
            "john.doe@example.com",
            TargetType.EMAIL,
            context={"module_results": {}},
            target_inputs={"email": "john.doe@example.com"},
        ) is True


class TestSerpAPISearchModule:
    @pytest.mark.asyncio
    async def test_build_primary_queries_for_name_and_email(self):
        from app.modules.web.serpapi_search import SerpAPISearchModule

        queries = SerpAPISearchModule._build_primary_queries(
            "john.doe@example.com",
            TargetType.EMAIL,
            {
                "target_inputs": {
                    "name": "John Doe",
                    "email": "john.doe@example.com",
                }
            },
        )

        assert '"John Doe" "john.doe@example.com"' in queries
        assert '"John Doe"' in queries
        assert '"john.doe@example.com"' in queries
        assert '"john.doe" "example.com"' in queries

    def test_build_primary_queries_includes_work_and_location(self):
        from app.modules.web.serpapi_search import SerpAPISearchModule

        queries = SerpAPISearchModule._build_primary_queries(
            "Roshni Joshi",
            TargetType.PERSON,
            {
                "target_inputs": {
                    "name": "Roshni Joshi",
                    "work": "BlackRock",
                    "location": "Mumbai",
                }
            },
        )

        # All three combinations must appear (most specific first)
        assert '"Roshni Joshi" "BlackRock" "Mumbai"' in queries
        assert '"Roshni Joshi" "BlackRock"' in queries
        assert '"Roshni Joshi" "Mumbai"' in queries
        # Narrowed triple-match query must come before plain name query
        triple_idx = queries.index('"Roshni Joshi" "BlackRock" "Mumbai"')
        plain_idx = queries.index('"Roshni Joshi"')
        assert triple_idx < plain_idx

    def test_build_primary_queries_work_only_no_location(self):
        from app.modules.web.serpapi_search import SerpAPISearchModule

        queries = SerpAPISearchModule._build_primary_queries(
            "Roshni Joshi",
            TargetType.PERSON,
            {
                "target_inputs": {
                    "name": "Roshni Joshi",
                    "work": "McKinsey",
                }
            },
        )

        assert '"Roshni Joshi" "McKinsey"' in queries
        assert '"Roshni Joshi"' in queries
        # Location-only query must NOT appear when location not provided
        assert not any("Mumbai" in q for q in queries)

    @pytest.mark.asyncio
    async def test_serpapi_returns_failure_on_auth_denied(self, monkeypatch, mock_aiohttp_response):
        monkeypatch.setenv("SERPAPI_API_KEY", "test-key")

        from app.modules.web.serpapi_search import SerpAPISearchModule

        module = SerpAPISearchModule()
        mock_resp = mock_aiohttp_response(
            {
                "error": "Invalid API key",
            },
            status=403,
        )

        with patch("aiohttp.ClientSession.get", return_value=mock_resp):
            result = await module.run(
                "John Doe",
                TargetType.PERSON,
                {"target_inputs": {"name": "John Doe"}},
            )

        assert result.success is False
        assert result.errors
        assert "Invalid API key" in result.errors[0]
        assert result.data["query_reports"][0]["error_status"] == 403

    @pytest.mark.asyncio
    async def test_serpapi_parses_inline_images_and_metadata(self, monkeypatch, mock_aiohttp_response):
        monkeypatch.setenv("SERPAPI_API_KEY", "test-key")
        monkeypatch.setenv("SERPAPI_LOCATION", "Austin, Texas, United States")

        from app.modules.web.serpapi_search import SerpAPISearchModule

        module = SerpAPISearchModule()
        mock_resp = mock_aiohttp_response(
            {
                "search_metadata": {
                    "status": "Success",
                    "json_endpoint": "https://serpapi.com/searches/example.json",
                    "raw_html_file": "https://serpapi.com/searches/example.html",
                    "total_time_taken": 0.85,
                },
                "search_parameters": {
                    "location_requested": "Austin, Texas, United States",
                    "location_used": "Austin,Texas,United States",
                },
                "search_information": {
                    "total_results": 2400,
                    "organic_results_state": "Results for exact spelling",
                },
                "organic_results": [
                    {
                        "title": "Manan Santoki - LinkedIn",
                        "link": "https://in.linkedin.com/in/manan-santoki",
                        "snippet": "Profile",
                        "displayed_link": "in.linkedin.com",
                        "position": 1,
                    }
                ],
                "knowledge_graph": {
                    "see_results_about": [
                        {
                            "name": "Manan Santoki",
                            "link": "https://www.google.com/search?q=Manan+Santoki",
                        }
                    ]
                },
                "inline_images": [
                    {
                        "source": "https://in.linkedin.com/in/manan-santoki",
                        "thumbnail": "https://serpapi.com/thumbnail.jpeg",
                        "original": "https://media.licdn.com/profile.jpeg",
                        "title": "Manan Santoki - Graduate Student at Arizona State University ...",
                        "source_name": "LinkedIn",
                    }
                ],
            },
            status=200,
        )

        with patch("aiohttp.ClientSession.get", return_value=mock_resp):
            result = await module.run(
                "manan santoki",
                TargetType.PERSON,
                {"target_inputs": {"name": "manan santoki"}},
            )

        assert result.success is True
        assert result.data["results"][0]["url"] == "https://in.linkedin.com/in/manan-santoki"
        assert result.data["inline_images"][0]["original"] == "https://media.licdn.com/profile.jpeg"
        assert result.data["discovered_image_urls"][0]["platform"] == "linkedin"
        assert result.data["knowledge_graph_hits"][0]["name"] == "Manan Santoki"
        assert result.data["query_reports"][0]["location_used"] == "Austin,Texas,United States"
        assert result.data["query_reports"][0]["reported_total_results"] == 2400

    def test_request_log_appends_structured_line(self, tmp_path: Path):
        from app.utils.request_log import append_request_log

        log_path = tmp_path / "request_log.log"
        append_request_log(
            {"request_log_path": str(log_path)},
            module="serpapi_search",
            event="request",
            query='"John Doe"',
            status=200,
        )

        content = log_path.read_text(encoding="utf-8")
        assert 'module="serpapi_search"' in content
        assert 'event="request"' in content
        assert 'query="\\"John Doe\\""' in content
        assert "status=200" in content


class TestCrawl4AIModule:
    @pytest.mark.asyncio
    async def test_collects_search_urls_and_normalizes_response(self, monkeypatch, mock_aiohttp_response, tmp_path: Path):
        monkeypatch.setenv("CRAWL4AI_BASE_URL", "https://crawl4ai.example.com")

        from app.modules.web.crawl4ai_crawler import Crawl4AICrawlerModule

        module = Crawl4AICrawlerModule()
        payload = {
            "results": [
                {
                    "url": "https://example.com/profile",
                    "title": "Example Profile",
                    "success": True,
                    "markdown": "Profile content",
                    "links": {"internal": ["https://example.com/about"]},
                    "metadata": {"language": "en"},
                }
            ]
        }
        mock_resp = mock_aiohttp_response(payload, status=200)
        request_log = tmp_path / "request_log.log"
        context = {
            "request_log_path": str(request_log),
            "module_results": {
                "serpapi_search": {
                    "results": [
                        {
                            "title": "Example Profile",
                            "url": "https://example.com/profile",
                            "snippet": "Snippet",
                        }
                    ],
                    "dork_results": {},
                }
            }
        }

        with patch("aiohttp.ClientSession.post", return_value=mock_resp):
            result = await module.run("john doe", TargetType.PERSON, context)

        assert result.success is True
        assert result.data["total_urls_queued"] == 1
        assert result.data["total_crawled"] == 1
        assert result.data["crawled_pages"][0]["url"] == "https://example.com/profile"

    @pytest.mark.asyncio
    async def test_uses_discovered_urls_from_context(self, monkeypatch, mock_aiohttp_response):
        monkeypatch.setenv("CRAWL4AI_BASE_URL", "https://crawl4ai.example.com")

        from app.modules.web.crawl4ai_crawler import Crawl4AICrawlerModule

        module = Crawl4AICrawlerModule()
        mock_resp = mock_aiohttp_response(
            {
                "results": [
                    {
                        "url": "https://example.com/profile",
                        "title": "Example Profile",
                        "success": True,
                        "markdown": "Profile content",
                    }
                ]
            },
            status=200,
        )

        with patch("aiohttp.ClientSession.post", return_value=mock_resp):
            result = await module.run(
                "john doe",
                TargetType.PERSON,
                {
                    "discovered_urls": [
                        {
                            "url": "https://example.com/profile",
                            "title": "Example Profile",
                            "source_module": "serpapi_search",
                        }
                    ]
                },
            )

        assert result.success is True
        assert result.data["total_urls_considered"] == 1
        assert result.data["total_urls_queued"] == 1
        assert result.data["crawled_pages"][0]["url"] == "https://example.com/profile"


class TestWebSnapshotModule:
    @pytest.mark.asyncio
    async def test_collects_context_urls_and_saves_screenshot(self, monkeypatch, tmp_path: Path):
        monkeypatch.setenv("DATA_DIR", str(tmp_path))

        from app.modules.web.web_snapshot import WebSnapshotModule

        module = WebSnapshotModule()
        page = AsyncMock()
        page.title = AsyncMock(return_value="Example Profile")
        factory = AsyncMock()
        factory.new_page = AsyncMock(return_value=page)
        factory.human_goto = AsyncMock()

        async def fake_screenshot(_page, path: str) -> None:
            Path(path).parent.mkdir(parents=True, exist_ok=True)
            Path(path).write_bytes(b"png")

        factory.take_screenshot = AsyncMock(side_effect=fake_screenshot)
        factory.close_page = AsyncMock()

        with patch("app.engine.browser.BrowserFactory.create", AsyncMock(return_value=factory)):
            result = await module.run(
                "john doe",
                TargetType.PERSON,
                {
                    "request_id": "req_test",
                    "discovered_urls": [
                        {
                            "url": "https://example.com/profile",
                            "title": "Example Profile",
                            "source_module": "serpapi_search",
                        }
                    ],
                },
            )

        assert result.success is True
        assert result.data["total_snapshots"] == 1
        assert Path(result.data["screenshots"][0]["screenshot_path"]).exists()
        factory.close_page.assert_awaited_once_with(page, save_session=False)

    @pytest.mark.asyncio
    async def test_returns_warning_when_no_search_urls_exist(self, monkeypatch):
        monkeypatch.setenv("CRAWL4AI_BASE_URL", "https://crawl4ai.example.com")

        from app.modules.web.crawl4ai_crawler import Crawl4AICrawlerModule

        module = Crawl4AICrawlerModule()
        result = await module.run("john doe", TargetType.PERSON, {"module_results": {}})

        assert result.success is True
        assert result.data["total_urls_queued"] == 0
        assert result.warnings

    @pytest.mark.asyncio
    async def test_falls_back_to_raw_search_results_when_context_is_empty(
        self,
        monkeypatch,
        mock_aiohttp_response,
        tmp_path: Path,
    ):
        monkeypatch.setenv("CRAWL4AI_BASE_URL", "https://crawl4ai.example.com")
        monkeypatch.setenv("DATA_DIR", str(tmp_path))

        from app.modules.web.crawl4ai_crawler import Crawl4AICrawlerModule

        request_id = "req_test_123"
        raw_dir = tmp_path / "requests" / request_id / "raw_data"
        raw_dir.mkdir(parents=True, exist_ok=True)
        (raw_dir / "serpapi_search.json").write_text(
            """
            {
              "results": [
                {
                  "title": "Example Profile",
                  "url": "https://example.com/profile",
                  "snippet": "Snippet"
                }
              ],
              "dork_results": {}
            }
            """,
            encoding="utf-8",
        )

        module = Crawl4AICrawlerModule()
        mock_resp = mock_aiohttp_response(
            {
                "results": [
                    {
                        "url": "https://example.com/profile",
                        "title": "Example Profile",
                        "success": True,
                        "markdown": "Profile content"
                    }
                ]
            },
            status=200,
        )

        with patch.object(module, "_get_source_names", return_value=["google_cse"]), patch(
            "aiohttp.ClientSession.post",
            return_value=mock_resp,
        ):
            result = await module.run(
                "john doe",
                TargetType.PERSON,
                {"request_id": request_id, "module_results": {}},
            )

        assert result.success is True
        assert result.data["raw_data_fallback_used"] is True
        assert result.data["effective_sources"] == ["serpapi_search"]
        assert result.data["total_urls_queued"] == 1
        assert result.data["crawled_pages"][0]["url"] == "https://example.com/profile"
