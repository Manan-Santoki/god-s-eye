"""
Direct API username verification module.

Checks username existence and profile information across GitHub, Reddit, and
Twitter/X simultaneously using their respective public APIs. All three
checks run in parallel via asyncio.gather — failure of one check does not
affect the others.

Phase: FAST_API.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any

import aiohttp

from app.core.config import settings
from app.core.constants import ModulePhase, TargetType
from app.core.exceptions import APIError, AuthenticationError, RateLimitError
from app.core.logging import get_logger
from app.modules.base import BaseModule, ModuleMetadata, ModuleResult

logger = get_logger(__name__)

_GITHUB_API = "https://api.github.com"
_REDDIT_API = "https://www.reddit.com"
_TWITTER_API = "https://api.twitter.com/2"


class SocialCheckerModule(BaseModule):
    """
    Multi-platform username checker using official APIs.

    Checks GitHub, Reddit, and Twitter/X in parallel and consolidates the
    results into a single structured output.
    """

    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            name="social_checker",
            display_name="Social Platform Checker",
            description=(
                "Verifies username presence and extracts profile data from "
                "GitHub, Reddit, and Twitter/X APIs in parallel."
            ),
            phase=ModulePhase.FAST_API,
            supported_targets=[TargetType.USERNAME],
            requires_auth=False,  # GitHub/Reddit work without auth; Twitter needs bearer token
            enabled_by_default=True,
            tags=["username", "github", "reddit", "twitter", "social", "api"],
        )

    async def run(
        self,
        target: str,
        target_type: TargetType,
        context: dict[str, Any],
    ) -> ModuleResult:
        username = target.strip()
        start = time.monotonic()
        warnings: list[str] = []

        logger.info("social_checker_start", username=username)

        # ── Build auth headers per service ───────────────────────────────────
        github_headers = {"Accept": "application/vnd.github+json", "User-Agent": "god_eye/1.0"}
        github_token = self._get_secret(settings.github_token)
        if github_token:
            github_headers["Authorization"] = f"token {github_token}"

        reddit_headers = {"User-Agent": settings.reddit_user_agent}

        twitter_headers = {"User-Agent": "god_eye/1.0"}
        twitter_bearer = self._get_secret(settings.twitter_bearer_token)
        if twitter_bearer:
            twitter_headers["Authorization"] = f"Bearer {twitter_bearer}"

        # ── Run all three checks concurrently ────────────────────────────────
        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=settings.request_timeout_seconds)
        ) as session:
            github_task = asyncio.create_task(
                self._check_github(session, username, github_headers, warnings)
            )
            reddit_task = asyncio.create_task(
                self._check_reddit(session, username, reddit_headers, warnings)
            )
            twitter_task = asyncio.create_task(
                self._check_twitter(session, username, twitter_headers, warnings)
            )

            github_result, reddit_result, twitter_result = await asyncio.gather(
                github_task, reddit_task, twitter_task, return_exceptions=False
            )

        # ── Build found_platforms list ───────────────────────────────────────
        found_platforms: list[str] = []
        if github_result:
            found_platforms.append("github")
        if reddit_result:
            found_platforms.append("reddit")
        if twitter_result:
            found_platforms.append("twitter")

        elapsed = int((time.monotonic() - start) * 1000)
        logger.info(
            "social_checker_complete",
            username=username,
            found_platforms=found_platforms,
            elapsed_ms=elapsed,
        )

        return ModuleResult(
            success=True,
            data={
                "username": username,
                "found_platforms": found_platforms,
                "github": github_result,
                "reddit": reddit_result,
                "twitter": twitter_result,
            },
            warnings=warnings,
        )

    # ── GitHub ───────────────────────────────────────────────────────────────

    async def _check_github(
        self,
        session: aiohttp.ClientSession,
        username: str,
        headers: dict[str, str],
        warnings: list[str],
    ) -> dict[str, Any] | None:
        """
        GET /users/{username} from the GitHub API.

        Returns a normalised profile dict or None if not found.
        """
        url = f"{_GITHUB_API}/users/{username}"
        try:
            async with session.get(url, headers=headers) as resp:
                if resp.status == 404:
                    logger.debug("github_user_not_found", username=username)
                    return None
                if resp.status == 429:
                    retry_after = int(resp.headers.get("Retry-After", "60"))
                    warnings.append(f"GitHub rate limited (retry after {retry_after}s)")
                    return None
                if resp.status == 401:
                    warnings.append("GitHub: invalid or expired API token")
                    return None
                if resp.status != 200:
                    body = await resp.text()
                    warnings.append(f"GitHub returned HTTP {resp.status}: {body[:200]}")
                    return None
                data = await resp.json()
                return self._parse_github_profile(data)
        except asyncio.TimeoutError:
            warnings.append("GitHub check timed out")
            return None
        except Exception as exc:
            warnings.append(f"GitHub check failed: {exc}")
            logger.exception("github_check_error", username=username, error=str(exc))
            return None

    @staticmethod
    def _parse_github_profile(raw: dict[str, Any]) -> dict[str, Any]:
        return {
            "login": raw.get("login"),
            "name": raw.get("name"),
            "bio": raw.get("bio"),
            "company": raw.get("company"),
            "location": raw.get("location"),
            "email": raw.get("email"),
            "blog": raw.get("blog"),
            "twitter_username": raw.get("twitter_username"),
            "public_repos": raw.get("public_repos", 0),
            "public_gists": raw.get("public_gists", 0),
            "followers": raw.get("followers", 0),
            "following": raw.get("following", 0),
            "created_at": raw.get("created_at"),
            "updated_at": raw.get("updated_at"),
            "avatar_url": raw.get("avatar_url"),
            "html_url": raw.get("html_url"),
            "site_admin": raw.get("site_admin", False),
            "type": raw.get("type", "User"),
            "hireable": raw.get("hireable"),
        }

    # ── Reddit ───────────────────────────────────────────────────────────────

    async def _check_reddit(
        self,
        session: aiohttp.ClientSession,
        username: str,
        headers: dict[str, str],
        warnings: list[str],
    ) -> dict[str, Any] | None:
        """
        GET /user/{username}/about.json from Reddit (no auth required).

        Returns a normalised profile dict or None if not found.
        """
        url = f"{_REDDIT_API}/user/{username}/about.json"
        try:
            async with session.get(url, headers=headers) as resp:
                if resp.status == 404:
                    logger.debug("reddit_user_not_found", username=username)
                    return None
                if resp.status == 429:
                    warnings.append("Reddit rate limited")
                    return None
                if resp.status == 403:
                    # Subreddit/account banned or private
                    warnings.append(f"Reddit: access forbidden for user '{username}' (may be banned/suspended)")
                    return None
                if resp.status != 200:
                    body = await resp.text()
                    warnings.append(f"Reddit returned HTTP {resp.status}: {body[:200]}")
                    return None
                payload = await resp.json()
                data = payload.get("data", {})
                return self._parse_reddit_profile(data)
        except asyncio.TimeoutError:
            warnings.append("Reddit check timed out")
            return None
        except Exception as exc:
            warnings.append(f"Reddit check failed: {exc}")
            logger.exception("reddit_check_error", username=username, error=str(exc))
            return None

    @staticmethod
    def _parse_reddit_profile(raw: dict[str, Any]) -> dict[str, Any]:
        return {
            "name": raw.get("name"),
            "id": raw.get("id"),
            "icon_img": raw.get("icon_img"),
            "is_employee": raw.get("is_employee", False),
            "is_mod": raw.get("is_mod", False),
            "is_gold": raw.get("is_gold", False),
            "verified": raw.get("verified", False),
            "has_verified_email": raw.get("has_verified_email", False),
            "comment_karma": raw.get("comment_karma", 0),
            "link_karma": raw.get("link_karma", 0),
            "total_karma": raw.get("total_karma", 0),
            "awardee_karma": raw.get("awardee_karma", 0),
            "awarder_karma": raw.get("awarder_karma", 0),
            "created_utc": raw.get("created_utc"),
            "is_suspended": raw.get("is_suspended", False),
            "pref_show_snoovatar": raw.get("pref_show_snoovatar", False),
            "profile_url": f"https://www.reddit.com/user/{raw.get('name', '')}",
        }

    # ── Twitter/X ─────────────────────────────────────────────────────────

    async def _check_twitter(
        self,
        session: aiohttp.ClientSession,
        username: str,
        headers: dict[str, str],
        warnings: list[str],
    ) -> dict[str, Any] | None:
        """
        GET /users/by/username/{username} from the Twitter v2 API.

        Requires a Bearer token. Returns a normalised profile dict or None.
        """
        twitter_bearer = self._get_secret(settings.twitter_bearer_token)
        if not twitter_bearer:
            warnings.append("Twitter check skipped: TWITTER_BEARER_TOKEN not configured")
            return None

        url = f"{_TWITTER_API}/users/by/username/{username}"
        params = {
            "user.fields": "description,public_metrics,created_at,profile_image_url,verified,location,url,entities,pinned_tweet_id"
        }
        try:
            async with session.get(url, params=params, headers=headers) as resp:
                if resp.status == 404:
                    logger.debug("twitter_user_not_found", username=username)
                    return None
                if resp.status == 429:
                    retry_after = int(resp.headers.get("x-rate-limit-reset", "60"))
                    warnings.append(f"Twitter rate limited (reset at {retry_after})")
                    return None
                if resp.status == 401:
                    warnings.append("Twitter: invalid or expired Bearer token")
                    return None
                if resp.status == 403:
                    warnings.append("Twitter: access forbidden — check token permissions")
                    return None
                if resp.status != 200:
                    body = await resp.text()
                    warnings.append(f"Twitter returned HTTP {resp.status}: {body[:200]}")
                    return None
                payload = await resp.json()
                # Check for Twitter API-level errors
                if "errors" in payload and "data" not in payload:
                    errors = payload["errors"]
                    if any(e.get("title") == "Not Found Error" for e in errors):
                        return None
                    warnings.append(f"Twitter API errors: {errors}")
                    return None
                data = payload.get("data", {})
                return self._parse_twitter_profile(data)
        except asyncio.TimeoutError:
            warnings.append("Twitter check timed out")
            return None
        except Exception as exc:
            warnings.append(f"Twitter check failed: {exc}")
            logger.exception("twitter_check_error", username=username, error=str(exc))
            return None

    @staticmethod
    def _parse_twitter_profile(raw: dict[str, Any]) -> dict[str, Any]:
        metrics = raw.get("public_metrics", {})
        return {
            "id": raw.get("id"),
            "name": raw.get("name"),
            "username": raw.get("username"),
            "description": raw.get("description"),
            "location": raw.get("location"),
            "url": raw.get("url"),
            "created_at": raw.get("created_at"),
            "profile_image_url": raw.get("profile_image_url"),
            "verified": raw.get("verified", False),
            "pinned_tweet_id": raw.get("pinned_tweet_id"),
            "followers_count": metrics.get("followers_count", 0),
            "following_count": metrics.get("following_count", 0),
            "tweet_count": metrics.get("tweet_count", 0),
            "listed_count": metrics.get("listed_count", 0),
            "profile_url": f"https://twitter.com/{raw.get('username', '')}",
        }
