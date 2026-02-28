"""
Tests for social browser modules.
"""

from unittest.mock import AsyncMock, patch

import pytest

from app.core.constants import TargetType


class TestLinkedInScraper:
    def test_select_search_term_with_work_and_location(self):
        from app.modules.social.linkedin_scraper import LinkedInScraper

        value = LinkedInScraper._select_search_term(
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

        # Base search term is just the name — work/location narrowing happens in _search_profiles
        assert "Roshni Joshi" in value

    def test_select_search_term_prefers_name_for_email_target(self):
        from app.modules.social.linkedin_scraper import LinkedInScraper

        value = LinkedInScraper._select_search_term(
            "john.doe@example.com",
            TargetType.EMAIL,
            {
                "target_inputs": {
                    "name": "John Doe",
                    "email": "john.doe@example.com",
                }
            },
        )

        assert value == "John Doe"

    def test_select_search_term_falls_back_to_email_local_part(self):
        from app.modules.social.linkedin_scraper import LinkedInScraper

        value = LinkedInScraper._select_search_term(
            "john.doe@example.com",
            TargetType.EMAIL,
            {"target_inputs": {"email": "john.doe@example.com"}},
        )

        assert value == "john doe"

    @pytest.mark.asyncio
    async def test_run_uses_selected_search_term(self, monkeypatch):
        monkeypatch.setenv("LINKEDIN_EMAIL", "research@example.com")
        monkeypatch.setenv("LINKEDIN_PASSWORD", "secret")

        from app.modules.social.linkedin_scraper import LinkedInScraper

        module = LinkedInScraper()
        page = AsyncMock()
        factory = AsyncMock()
        factory.new_page = AsyncMock(return_value=page)
        factory.close_page = AsyncMock()

        with patch("app.engine.browser.BrowserFactory.create", AsyncMock(return_value=factory)):
            with patch.object(module, "_ensure_logged_in", AsyncMock(return_value=True)):
                with patch.object(
                    module,
                    "_search_and_extract",
                    AsyncMock(return_value=[{"name": "John Doe", "profile_url": "https://www.linkedin.com/in/john-doe"}]),
                ) as search_extract:
                    result = await module.run(
                        "john.doe@example.com",
                        TargetType.EMAIL,
                        {"target_inputs": {"name": "John Doe", "email": "john.doe@example.com"}},
                    )

        assert result.success is True
        assert result.data["searched_query"] == "John Doe"
        search_extract.assert_awaited_once()
        factory.close_page.assert_awaited_once_with(page, save_session=True)


class TestInstagramScraper:
    def test_select_candidate_usernames_includes_work_variants(self):
        from app.modules.social.instagram_scraper import InstagramScraper

        candidates = InstagramScraper._select_candidate_usernames(
            "Roshni Joshi",
            TargetType.PERSON,
            {
                "target_inputs": {
                    "name": "Roshni Joshi",
                    "work": "BlackRock",
                }
            },
        )

        # Standard name variants
        assert "roshnijoshi" in candidates
        # At least one work-based variant present (e.g. roshnijoshi.blackrock)
        assert any("blackrock" in c for c in candidates)

    def test_select_candidate_usernames_prefers_search_discovery(self):
        from app.modules.social.instagram_scraper import InstagramScraper

        candidates = InstagramScraper._select_candidate_usernames(
            "john.doe@example.com",
            TargetType.EMAIL,
            {
                "target_inputs": {
                    "name": "John Doe",
                    "email": "john.doe@example.com",
                },
                "module_results": {
                    "serpapi_search": {
                        "results": [
                            {"url": "https://www.instagram.com/john.doe/"},
                        ],
                    }
                },
            },
        )

        assert candidates[0] == "john.doe"
        assert "john_doe" in candidates

    @pytest.mark.asyncio
    async def test_run_uses_search_resolved_candidate(self, monkeypatch):
        monkeypatch.setenv("INSTAGRAM_USERNAME", "researcher")
        monkeypatch.setenv("INSTAGRAM_PASSWORD", "secret")

        from app.modules.social.instagram_scraper import InstagramScraper

        module = InstagramScraper()
        page = AsyncMock()
        factory = AsyncMock()
        factory.new_page = AsyncMock(return_value=page)
        factory.close_page = AsyncMock()

        with patch("app.engine.browser.BrowserFactory.create", AsyncMock(return_value=factory)):
            with patch.object(module, "_is_logged_in", AsyncMock(return_value=True)):
                with patch.object(
                    module,
                    "_scrape_profile",
                    AsyncMock(return_value={"username": "john.doe", "profile_url": "https://www.instagram.com/john.doe/"}),
                ) as scrape_profile:
                    result = await module.run(
                        "john.doe@example.com",
                        TargetType.EMAIL,
                        {
                            "target_inputs": {
                                "name": "John Doe",
                                "email": "john.doe@example.com",
                            },
                            "module_results": {
                                "serpapi_search": {
                                    "results": [
                                        {"url": "https://www.instagram.com/john.doe/"},
                                    ],
                                }
                            },
                        },
                    )

        assert result.success is True
        assert result.data["matched_username"] == "john.doe"
        scrape_profile.assert_awaited_once()
        assert scrape_profile.await_args.args[2] == "john.doe"
        factory.close_page.assert_awaited_once_with(page, save_session=True)


class TestGitHubAPIModule:
    def test_build_search_queries_uses_name_and_email_variants(self):
        from app.modules.social.github_api import GitHubAPIModule

        queries = GitHubAPIModule._build_search_queries(
            "john.doe@example.com",
            TargetType.EMAIL,
            {
                "target_inputs": {
                    "name": "John Doe",
                    "email": "john.doe@example.com",
                }
            },
        )

        assert queries[:4] == ["John Doe", "john.doe", "john-doe", "john doe"]

    @pytest.mark.asyncio
    async def test_run_falls_back_to_user_search_on_404(self):
        from app.core.exceptions import APIError
        from app.modules.social.github_api import GitHubAPIModule

        module = GitHubAPIModule()

        with patch.object(
            module,
            "_fetch_profile",
            AsyncMock(
                side_effect=[
                    APIError("GitHub", 404, "not found"),
                    {
                        "name": "John Doe",
                        "bio": "",
                        "company": "",
                        "location": "",
                        "email": "",
                        "blog": "",
                        "twitter_username": "",
                        "public_repos": 0,
                        "public_gists": 0,
                        "followers": 0,
                        "following": 0,
                        "created_at": "",
                        "updated_at": "",
                        "avatar_url": "",
                        "html_url": "https://github.com/john-doe",
                        "type": "User",
                        "site_admin": False,
                    },
                ]
            ),
        ):
            with patch.object(
                module,
                "_search_users",
                AsyncMock(return_value=[{"login": "john-doe", "html_url": "https://github.com/john-doe", "score": 1.0}]),
            ) as search_users:
                with patch.object(module, "_fetch_repos", AsyncMock(return_value=[])):
                    with patch.object(module, "_fetch_events", AsyncMock(return_value=[])):
                        with patch.object(module, "_fetch_gists", AsyncMock(return_value=[])):
                            result = await module.run(
                                "john.doe",
                                TargetType.USERNAME,
                                {
                                    "request_id": "req_test",
                                    "request_log_path": "data/requests/req_test/request_log.log",
                                    "target_inputs": {
                                        "name": "John Doe",
                                        "email": "john.doe@example.com",
                                    },
                                },
                            )

        assert result.success is True
        assert result.data["username"] == "john-doe"
        assert result.data["resolved_via_search"] is True
        assert result.data["resolution_query"] == "John Doe"
        search_users.assert_awaited()
