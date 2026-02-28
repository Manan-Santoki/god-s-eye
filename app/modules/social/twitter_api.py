"""
Twitter/X API v2 module.

Looks up a Twitter username to retrieve profile information and recent tweets.
Uses Bearer Token authentication (OAuth 2.0 App-Only).

API reference: https://developer.twitter.com/en/docs/twitter-api
"""

from __future__ import annotations

from typing import Any

import aiohttp
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential

from app.core.config import settings
from app.core.constants import ModulePhase, TargetType
from app.core.exceptions import APIError, RateLimitError
from app.core.logging import get_logger
from app.modules.base import BaseModule, ModuleMetadata, ModuleResult

logger = get_logger(__name__)

_TWITTER_API_BASE = "https://api.twitter.com/2"


class TwitterAPIModule(BaseModule):
    """Twitter/X API v2 OSINT — profile lookup and recent tweets."""

    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            name="twitter_api",
            display_name="Twitter/X OSINT",
            description=(
                "Looks up a Twitter/X username via API v2, retrieving profile details "
                "and the 10 most recent tweets."
            ),
            phase=ModulePhase.FAST_API,
            supported_targets=[
                TargetType.USERNAME,
                TargetType.PERSON,
            ],
            requires_auth=True,
            enabled_by_default=True,
            tags=["social", "twitter", "x", "tweets"],
        )

    async def run(
        self,
        target: str,
        target_type: TargetType,
        context: dict[str, Any],
    ) -> ModuleResult:
        # Strip leading @ if present
        username = target.lstrip("@")

        bearer_token = self._get_secret(settings.twitter_bearer_token)

        if not bearer_token:
            logger.warning(
                "twitter_api_skipped",
                reason="TWITTER_BEARER_TOKEN not configured",
            )
            return ModuleResult.fail(
                "Twitter API not configured: set TWITTER_BEARER_TOKEN in .env"
            )

        headers = {
            "Authorization": f"Bearer {bearer_token}",
            "User-Agent": "GOD_EYE/1.0",
        }

        errors: list[str] = []
        warnings: list[str] = []

        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=settings.request_timeout_seconds),
            headers=headers,
        ) as session:
            # Step 1: Resolve username to user ID + profile fields
            try:
                user_data = await self._fetch_user_by_username(session, username)
            except APIError as exc:
                if exc.status_code == 404:
                    return ModuleResult(
                        success=True,
                        data={"found": False, "username": username, "profile": {}, "recent_tweets": []},
                    )
                if exc.status_code == 401:
                    return ModuleResult.fail(
                        "Twitter Bearer Token is invalid or expired"
                    )
                return ModuleResult.fail(str(exc))

            if user_data is None:
                # User not found (API returned empty data)
                return ModuleResult(
                    success=True,
                    data={"found": False, "username": username, "profile": {}, "recent_tweets": []},
                )

            user_id: str = user_data["id"]
            profile = self._normalise_profile(user_data)

            # Step 2: Fetch recent tweets
            try:
                recent_tweets = await self._fetch_recent_tweets(session, user_id)
            except (APIError, RateLimitError) as exc:
                warnings.append(f"Could not fetch recent tweets: {exc}")
                recent_tweets = []

        logger.info(
            "twitter_api_complete",
            username=username,
            user_id=user_id,
            followers=profile.get("followers", 0),
            tweets_fetched=len(recent_tweets),
        )

        return ModuleResult(
            success=True,
            data={
                "found": True,
                "username": username,
                "profile": profile,
                "recent_tweets": recent_tweets,
            },
            errors=errors,
            warnings=warnings,
        )

    # ── API call methods ────────────────────────────────────────────────────

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10),
        retry=retry_if_exception_type(RateLimitError),
        reraise=True,
    )
    async def _fetch_user_by_username(
        self,
        session: aiohttp.ClientSession,
        username: str,
    ) -> dict[str, Any] | None:
        """
        GET /2/users/by/username/{username}

        Returns the raw user object dict from the API, or None if not found.

        Raises:
            RateLimitError: On HTTP 429.
            APIError: On 401 or other non-200 codes.
        """
        url = f"{_TWITTER_API_BASE}/users/by/username/{username}"
        params = {
            "user.fields": (
                "description,public_metrics,created_at,profile_image_url,"
                "verified,location,entities,url,protected"
            ),
        }

        logger.debug("twitter_fetch_user", username=username)

        async with session.get(url, params=params) as resp:
            if resp.status == 429:
                raise RateLimitError("Twitter")
            if resp.status == 401:
                raise APIError("Twitter", 401, "Invalid or missing Bearer Token")
            if resp.status == 403:
                raise APIError("Twitter", 403, "Forbidden — check Twitter API access tier")
            if resp.status == 404:
                raise APIError("Twitter", 404, f"User '{username}' not found")
            if resp.status != 200:
                body = await resp.text()
                raise APIError("Twitter", resp.status, body[:200])

            payload = await resp.json()

        # API returns {"data": {...}} or {"errors": [...]}
        if "errors" in payload and "data" not in payload:
            # User not found or other API-level error
            first_error = payload["errors"][0] if payload["errors"] else {}
            if first_error.get("parameter") == "username":
                return None
            raise APIError("Twitter", 200, str(first_error.get("detail", "Unknown API error")))

        return payload.get("data")

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10),
        retry=retry_if_exception_type(RateLimitError),
        reraise=True,
    )
    async def _fetch_recent_tweets(
        self,
        session: aiohttp.ClientSession,
        user_id: str,
    ) -> list[dict[str, Any]]:
        """
        GET /2/users/{id}/tweets

        Returns the 10 most recent tweets for the given user ID.

        Raises:
            RateLimitError: On HTTP 429.
            APIError: On non-200 codes.
        """
        url = f"{_TWITTER_API_BASE}/users/{user_id}/tweets"
        params = {
            "max_results": 10,
            "tweet.fields": "created_at,public_metrics,geo,lang,possibly_sensitive",
            "expansions": "geo.place_id",
        }

        logger.debug("twitter_fetch_tweets", user_id=user_id)

        async with session.get(url, params=params) as resp:
            if resp.status == 429:
                raise RateLimitError("Twitter")
            if resp.status == 401:
                raise APIError("Twitter", 401, "Invalid or missing Bearer Token")
            if resp.status == 403:
                # Often means the account is protected or API access level is insufficient
                return []
            if resp.status == 404:
                return []
            if resp.status != 200:
                body = await resp.text()
                raise APIError("Twitter", resp.status, body[:200])

            payload = await resp.json()

        tweets: list[dict[str, Any]] = []
        for tweet in payload.get("data", []):
            metrics = tweet.get("public_metrics") or {}
            tweets.append(
                {
                    "id": tweet.get("id", ""),
                    "text": tweet.get("text", ""),
                    "created_at": tweet.get("created_at", ""),
                    "lang": tweet.get("lang", ""),
                    "likes": metrics.get("like_count", 0),
                    "retweets": metrics.get("retweet_count", 0),
                    "replies": metrics.get("reply_count", 0),
                    "quotes": metrics.get("quote_count", 0),
                    "possibly_sensitive": tweet.get("possibly_sensitive", False),
                    "geo": tweet.get("geo") or {},
                }
            )

        return tweets

    # ── Normalisation ────────────────────────────────────────────────────────

    @staticmethod
    def _normalise_profile(user: dict[str, Any]) -> dict[str, Any]:
        """
        Extract and flatten the fields we care about from the raw user object.

        Returns a clean profile dict suitable for the ModuleResult.
        """
        metrics = user.get("public_metrics") or {}

        return {
            "id": user.get("id", ""),
            "name": user.get("name", ""),
            "username": user.get("username", ""),
            "description": user.get("description") or "",
            "location": user.get("location") or "",
            "profile_image_url": user.get("profile_image_url") or "",
            "verified": user.get("verified", False),
            "protected": user.get("protected", False),
            "created_at": user.get("created_at") or "",
            "followers": metrics.get("followers_count", 0),
            "following": metrics.get("following_count", 0),
            "tweets_count": metrics.get("tweet_count", 0),
            "listed_count": metrics.get("listed_count", 0),
            "url": (user.get("entities", {}) or {})
                   .get("url", {})
                   .get("urls", [{}])[0]
                   .get("expanded_url", user.get("url") or ""),
        }
