"""
Reddit OAuth2 OSINT module.

Authenticates via client_credentials and queries:
  - User profile (karma, account age, verified status)
  - Recent submissions (posts)
  - Recent comments

Extracts behavioral signals: posting patterns, top subreddits, mentioned locations.
"""

from __future__ import annotations

import asyncio
import base64
import re
from collections import Counter
from datetime import datetime, timezone
from typing import Any

import aiohttp
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential

from app.core.config import settings
from app.core.constants import ModulePhase, TargetType
from app.core.exceptions import APIError, RateLimitError
from app.core.logging import get_logger
from app.modules.base import BaseModule, ModuleMetadata, ModuleResult

logger = get_logger(__name__)

_REDDIT_TOKEN_URL = "https://www.reddit.com/api/v1/access_token"
_REDDIT_OAUTH_BASE = "https://oauth.reddit.com"

# Common location keywords for naive extraction
_LOCATION_PATTERNS = re.compile(
    r"\b(New York|Los Angeles|Chicago|Houston|London|Paris|Berlin|Tokyo|"
    r"Sydney|Toronto|Vancouver|Seattle|San Francisco|Boston|Austin|Denver|"
    r"Atlanta|Miami|Dallas|Phoenix|Portland|Amsterdam|Dubai|Singapore|"
    r"[\w ]{3,30},\s*[A-Z]{2})\b"  # e.g., "Austin, TX"
)


class RedditAPIModule(BaseModule):
    """Reddit OAuth2 OSINT — profile, posts, comments, patterns."""

    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            name="reddit_api",
            display_name="Reddit OSINT",
            description=(
                "Authenticates to Reddit OAuth2 and collects user profile, "
                "recent posts, comments, subreddit activity, and behavioral patterns."
            ),
            phase=ModulePhase.FAST_API,
            supported_targets=[
                TargetType.USERNAME,
                TargetType.PERSON,
            ],
            requires_auth=True,
            enabled_by_default=True,
            tags=["social", "reddit", "posts", "comments"],
        )

    async def run(
        self,
        target: str,
        target_type: TargetType,
        context: dict[str, Any],
    ) -> ModuleResult:
        username = target.lstrip("u/").lstrip("@")

        client_id = settings.reddit_client_id
        client_secret = self._get_secret(settings.reddit_client_secret)

        if not client_id or not client_secret:
            logger.warning(
                "reddit_api_skipped",
                reason="REDDIT_CLIENT_ID or REDDIT_CLIENT_SECRET not configured",
            )
            return ModuleResult.fail(
                "Reddit API not configured: set REDDIT_CLIENT_ID and REDDIT_CLIENT_SECRET in .env"
            )

        errors: list[str] = []
        warnings: list[str] = []

        # Obtain OAuth2 token
        try:
            access_token = await self._get_access_token(
                client_id=client_id,
                client_secret=client_secret,
            )
        except APIError as exc:
            return ModuleResult.fail(f"Reddit OAuth failed: {exc}")

        headers = {
            "Authorization": f"Bearer {access_token}",
            "User-Agent": settings.reddit_user_agent,
        }

        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=settings.request_timeout_seconds),
            headers=headers,
        ) as session:
            # Fetch profile first — abort if user not found
            try:
                profile = await self._fetch_profile(session, username)
            except APIError as exc:
                if exc.status_code == 404:
                    return ModuleResult.fail(f"Reddit user '{username}' not found")
                return ModuleResult.fail(str(exc))

            # Fetch posts and comments concurrently
            posts_task = self._fetch_submitted(session, username, errors)
            comments_task = self._fetch_comments(session, username, errors)

            posts, comments = await asyncio.gather(
                posts_task, comments_task, return_exceptions=True
            )

            if isinstance(posts, Exception):
                errors.append(f"Posts fetch failed: {posts}")
                posts = []
            if isinstance(comments, Exception):
                errors.append(f"Comments fetch failed: {comments}")
                comments = []

        # Analyse activity
        activity_pattern = self._analyse_activity(
            posts=posts,  # type: ignore[arg-type]
            comments=comments,  # type: ignore[arg-type]
        )

        logger.info(
            "reddit_api_complete",
            username=username,
            posts=len(posts),  # type: ignore[arg-type]
            comments=len(comments),  # type: ignore[arg-type]
        )

        return ModuleResult(
            success=True,
            data={
                "username": username,
                "profile": profile,
                "posts": {
                    "count": len(posts),  # type: ignore[arg-type]
                    "top_subreddits": activity_pattern["top_subreddits"],
                },
                "activity_pattern": activity_pattern,
            },
            errors=errors,
            warnings=warnings,
        )

    # ── Auth ────────────────────────────────────────────────────────────────

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10),
        reraise=True,
    )
    async def _get_access_token(
        self,
        client_id: str,
        client_secret: str,
    ) -> str:
        """
        Obtain a Reddit client_credentials access token.

        Returns the raw access token string.
        """
        credentials = base64.b64encode(
            f"{client_id}:{client_secret}".encode()
        ).decode()

        headers = {
            "Authorization": f"Basic {credentials}",
            "User-Agent": settings.reddit_user_agent,
            "Content-Type": "application/x-www-form-urlencoded",
        }
        data = {"grant_type": "client_credentials"}

        logger.debug("reddit_oauth_token_request")

        async with aiohttp.ClientSession() as session:
            async with session.post(
                _REDDIT_TOKEN_URL,
                headers=headers,
                data=data,
                timeout=aiohttp.ClientTimeout(total=15),
            ) as resp:
                if resp.status == 429:
                    raise RateLimitError("Reddit")
                if resp.status == 401:
                    raise APIError("Reddit", 401, "Invalid client_id or client_secret")
                if resp.status != 200:
                    raise APIError("Reddit", resp.status, await resp.text())

                payload = await resp.json()

        token = payload.get("access_token")
        if not token:
            raise APIError("Reddit", 200, "No access_token in response")
        return token

    # ── Profile ─────────────────────────────────────────────────────────────

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10),
        retry=retry_if_exception_type(RateLimitError),
        reraise=True,
    )
    async def _fetch_profile(
        self,
        session: aiohttp.ClientSession,
        username: str,
    ) -> dict[str, Any]:
        """Fetch /user/{username}/about and return normalised profile dict."""
        url = f"{_REDDIT_OAUTH_BASE}/user/{username}/about"
        logger.debug("reddit_fetch_profile", username=username)

        async with session.get(url) as resp:
            if resp.status == 404:
                raise APIError("Reddit", 404, f"User '{username}' not found")
            if resp.status == 429:
                raise RateLimitError("Reddit")
            if resp.status == 403:
                raise APIError("Reddit", 403, f"User '{username}' profile is private or suspended")
            if resp.status != 200:
                raise APIError("Reddit", resp.status, await resp.text())

            payload = await resp.json()

        data = payload.get("data", {})

        # Convert created_utc (Unix epoch) to ISO string
        created_utc = data.get("created_utc", 0)
        created_iso = (
            datetime.fromtimestamp(created_utc, tz=timezone.utc).isoformat()
            if created_utc
            else ""
        )

        return {
            "name": data.get("name", username),
            "link_karma": data.get("link_karma", 0),
            "comment_karma": data.get("comment_karma", 0),
            "total_karma": data.get("total_karma", 0),
            "created_utc": created_iso,
            "is_gold": data.get("is_gold", False),
            "is_mod": data.get("is_mod", False),
            "verified": data.get("verified", False),
            "has_verified_email": data.get("has_verified_email", False),
            "icon_img": data.get("icon_img") or "",
            "subreddit": (data.get("subreddit") or {}).get("display_name_prefixed") or "",
            "is_suspended": data.get("is_suspended", False),
        }

    # ── Submissions (posts) ──────────────────────────────────────────────────

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10),
        retry=retry_if_exception_type(RateLimitError),
        reraise=True,
    )
    async def _fetch_submitted(
        self,
        session: aiohttp.ClientSession,
        username: str,
        errors: list[str],
    ) -> list[dict[str, Any]]:
        """Fetch /user/{username}/submitted (up to 50 posts)."""
        url = f"{_REDDIT_OAUTH_BASE}/user/{username}/submitted"
        params = {"limit": 50, "sort": "new"}

        logger.debug("reddit_fetch_posts", username=username)

        async with session.get(url, params=params) as resp:
            if resp.status == 429:
                raise RateLimitError("Reddit")
            if resp.status in (404, 403):
                return []
            if resp.status != 200:
                errors.append(f"Posts fetch failed: HTTP {resp.status}")
                return []

            payload = await resp.json()

        posts: list[dict[str, Any]] = []
        for child in payload.get("data", {}).get("children", []):
            item = child.get("data", {})
            created_utc = item.get("created_utc", 0)
            posts.append(
                {
                    "title": item.get("title", ""),
                    "subreddit": item.get("subreddit", ""),
                    "score": item.get("score", 0),
                    "num_comments": item.get("num_comments", 0),
                    "url": item.get("url", ""),
                    "permalink": f"https://reddit.com{item.get('permalink', '')}",
                    "created_utc": (
                        datetime.fromtimestamp(created_utc, tz=timezone.utc).isoformat()
                        if created_utc
                        else ""
                    ),
                    "is_self": item.get("is_self", False),
                    "selftext": (item.get("selftext") or "")[:500],
                }
            )

        return posts

    # ── Comments ─────────────────────────────────────────────────────────────

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10),
        retry=retry_if_exception_type(RateLimitError),
        reraise=True,
    )
    async def _fetch_comments(
        self,
        session: aiohttp.ClientSession,
        username: str,
        errors: list[str],
    ) -> list[dict[str, Any]]:
        """Fetch /user/{username}/comments (up to 50 comments)."""
        url = f"{_REDDIT_OAUTH_BASE}/user/{username}/comments"
        params = {"limit": 50, "sort": "new"}

        logger.debug("reddit_fetch_comments", username=username)

        async with session.get(url, params=params) as resp:
            if resp.status == 429:
                raise RateLimitError("Reddit")
            if resp.status in (404, 403):
                return []
            if resp.status != 200:
                errors.append(f"Comments fetch failed: HTTP {resp.status}")
                return []

            payload = await resp.json()

        comments: list[dict[str, Any]] = []
        for child in payload.get("data", {}).get("children", []):
            item = child.get("data", {})
            created_utc = item.get("created_utc", 0)
            comments.append(
                {
                    "subreddit": item.get("subreddit", ""),
                    "body": (item.get("body") or "")[:500],
                    "score": item.get("score", 0),
                    "permalink": f"https://reddit.com{item.get('permalink', '')}",
                    "created_utc": (
                        datetime.fromtimestamp(created_utc, tz=timezone.utc).isoformat()
                        if created_utc
                        else ""
                    ),
                }
            )

        return comments

    # ── Analysis ─────────────────────────────────────────────────────────────

    def _analyse_activity(
        self,
        posts: list[dict[str, Any]],
        comments: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """
        Derive behavioral signals from posts and comments.

        Returns:
            Dict with top_subreddits, posting_pattern, mentioned_locations,
            total_posts, total_comments.
        """
        # Top subreddits by combined post + comment activity
        subreddit_counter: Counter[str] = Counter()
        for post in posts:
            if sr := post.get("subreddit"):
                subreddit_counter[sr] += 1
        for comment in comments:
            if sr := comment.get("subreddit"):
                subreddit_counter[sr] += 1

        top_subreddits = [
            {"subreddit": sr, "count": count}
            for sr, count in subreddit_counter.most_common(10)
        ]

        # Extract location mentions from all text
        all_text = " ".join(
            [p.get("selftext", "") or p.get("title", "") for p in posts]
            + [c.get("body", "") for c in comments]
        )
        mentioned_locations = list(
            dict.fromkeys(  # deduplicate, preserve order
                m.strip() for m in _LOCATION_PATTERNS.findall(all_text)
            )
        )

        # Posting pattern: rough hour-of-day distribution
        hour_counts: Counter[int] = Counter()
        for item in posts + comments:
            ts_str = item.get("created_utc", "")
            if ts_str:
                try:
                    dt = datetime.fromisoformat(ts_str)
                    hour_counts[dt.hour] += 1
                except ValueError:
                    pass

        most_active_hours = [
            {"hour": h, "count": c} for h, c in sorted(hour_counts.items())
        ]

        return {
            "total_posts": len(posts),
            "total_comments": len(comments),
            "top_subreddits": top_subreddits,
            "mentioned_locations": mentioned_locations[:20],
            "most_active_hours": most_active_hours,
        }
