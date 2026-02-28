"""
YouTube Data API v3 — channel and video discovery.
"""

import asyncio
import time

import aiohttp
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type

from app.core.config import settings
from app.core.constants import TargetType, ModulePhase
from app.core.exceptions import APIError, RateLimitError
from app.core.logging import get_logger
from app.modules.base import BaseModule, ModuleMetadata, ModuleResult

logger = get_logger(__name__)
BASE = "https://www.googleapis.com/youtube/v3"


class YouTubeAPI(BaseModule):

    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            name="youtube_api",
            display_name="YouTube Data API",
            description="Find YouTube channels and videos linked to a target",
            supported_targets=[TargetType.PERSON, TargetType.USERNAME, TargetType.EMAIL],
            phase=ModulePhase.FAST_API,
            requires_auth=False,
            rate_limit_rpm=60,
            timeout_seconds=30,
            enabled_by_default=True,
        )

    async def validate(self, target: str, target_type: TargetType) -> bool:
        return bool(target.strip())

    async def run(self, target: str, target_type: TargetType, context: dict) -> ModuleResult:
        start = time.monotonic()

        if not settings.has_api_key("youtube_api_key"):
            return ModuleResult(
                module_name=self.metadata().name,
                target=target,
                success=False,
                errors=["YouTube API key not configured (YOUTUBE_API_KEY)"],
            )

        key = settings.youtube_api_key.get_secret_value()

        try:
            # Search for channels
            channels = await self._search_channels(target, key)
            videos: list[dict] = []

            if channels:
                # Get top videos from first channel
                channel_id = channels[0].get("id")
                if channel_id:
                    videos = await self._get_channel_videos(channel_id, key)

            elapsed = int((time.monotonic() - start) * 1000)
            return ModuleResult(
                module_name=self.metadata().name,
                target=target,
                success=True,
                data={
                    "channels": channels,
                    "total_channels": len(channels),
                    "videos": videos[:20],
                    "total_videos": len(videos),
                },
                execution_time_ms=elapsed,
            )

        except Exception as e:
            logger.error("youtube_api_error", error=str(e))
            return ModuleResult(
                module_name=self.metadata().name,
                target=target,
                success=False,
                errors=[str(e)],
            )

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(min=2, max=30),
           retry=retry_if_exception_type(RateLimitError))
    async def _search_channels(self, query: str, key: str) -> list[dict]:
        url = f"{BASE}/search"
        params = {"part": "snippet", "q": query, "type": "channel", "maxResults": 5, "key": key}

        async with aiohttp.ClientSession() as session:
            async with session.get(url, params=params, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                if resp.status == 429:
                    raise RateLimitError("youtube")
                if resp.status != 200:
                    return []
                data = await resp.json()

        channels = []
        for item in data.get("items", []):
            snippet = item.get("snippet", {})
            channel_id = item.get("id", {}).get("channelId", "")
            channels.append({
                "id": channel_id,
                "title": snippet.get("title"),
                "description": snippet.get("description", "")[:300],
                "published_at": snippet.get("publishedAt"),
                "thumbnail": snippet.get("thumbnails", {}).get("default", {}).get("url"),
                "url": f"https://www.youtube.com/channel/{channel_id}",
            })
        return channels

    async def _get_channel_videos(self, channel_id: str, key: str) -> list[dict]:
        url = f"{BASE}/search"
        params = {
            "part": "snippet",
            "channelId": channel_id,
            "type": "video",
            "maxResults": 20,
            "order": "date",
            "key": key,
        }
        async with aiohttp.ClientSession() as session:
            async with session.get(url, params=params, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                if resp.status != 200:
                    return []
                data = await resp.json()

        videos = []
        for item in data.get("items", []):
            snippet = item.get("snippet", {})
            video_id = item.get("id", {}).get("videoId", "")
            videos.append({
                "id": video_id,
                "title": snippet.get("title"),
                "description": snippet.get("description", "")[:200],
                "published_at": snippet.get("publishedAt"),
                "url": f"https://www.youtube.com/watch?v={video_id}",
            })
        return videos
