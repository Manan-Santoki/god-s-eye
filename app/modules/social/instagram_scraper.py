"""
Instagram profile scraper using Playwright browser automation.

Extracts: profile info, posts, images, follower counts.
Requires Instagram credentials in .env.
"""

import asyncio
import time
from typing import Any

from app.core.config import settings
from app.core.constants import TargetType, ModulePhase
from app.core.exceptions import CaptchaError, LoginError
from app.core.logging import get_logger
from app.modules.base import BaseModule, ModuleMetadata, ModuleResult

logger = get_logger(__name__)


class InstagramScraper(BaseModule):
    """Playwright-based Instagram profile scraper."""

    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            name="instagram_scraper",
            display_name="Instagram Scraper",
            description="Extract Instagram profile, posts, and images",
            supported_targets=[TargetType.PERSON, TargetType.USERNAME],
            phase=ModulePhase.BROWSER_AUTH,
            requires_auth=True,
            requires_browser=True,
            requires_proxy=True,
            rate_limit_rpm=4,
            timeout_seconds=180,
            priority=3,
            enabled_by_default=True,
        )

    async def validate(self, target: str, target_type: TargetType) -> bool:
        return target_type in (TargetType.PERSON, TargetType.USERNAME)

    async def run(self, target: str, target_type: TargetType, context: dict) -> ModuleResult:
        start = time.monotonic()

        if not settings.instagram_username or not settings.instagram_password:
            return ModuleResult(
                module_name=self.metadata().name,
                target=target,
                success=False,
                errors=["Instagram credentials not configured (INSTAGRAM_USERNAME / INSTAGRAM_PASSWORD)"],
            )

        # Determine username to look up
        usernames = context.get("discovered_usernames", [])
        username = target if target_type == TargetType.USERNAME else (usernames[0] if usernames else target)

        try:
            from app.engine.browser import BrowserFactory
            factory = await BrowserFactory.create()
            page = await factory.new_page(persist_session="instagram")

            if not await self._is_logged_in(page):
                await self._login(page, factory)

            profile = await self._scrape_profile(page, factory, username)
            elapsed = int((time.monotonic() - start) * 1000)

            return ModuleResult(
                module_name=self.metadata().name,
                target=target,
                success=bool(profile),
                data=profile or {},
                errors=[] if profile else [f"Profile not found: {username}"],
                execution_time_ms=elapsed,
            )

        except (LoginError, CaptchaError) as e:
            return ModuleResult(
                module_name=self.metadata().name,
                target=target,
                success=False,
                errors=[str(e)],
            )
        except Exception as e:
            logger.error("instagram_scraper_error", error=str(e))
            return ModuleResult(
                module_name=self.metadata().name,
                target=target,
                success=False,
                errors=[str(e)],
            )

    async def _is_logged_in(self, page) -> bool:
        try:
            await page.goto("https://www.instagram.com/", timeout=15000, wait_until="domcontentloaded")
            await asyncio.sleep(2)
            return "accounts/login" not in page.url
        except Exception:
            return False

    async def _login(self, page, factory) -> None:
        logger.info("instagram_login_attempt")
        await factory.human_goto(page, "https://www.instagram.com/accounts/login/")
        await asyncio.sleep(3)

        # Accept cookies if present
        try:
            cookie_btn = page.locator("button:has-text('Accept')").first
            if await cookie_btn.count() > 0:
                await cookie_btn.click()
                await asyncio.sleep(1)
        except Exception:
            pass

        await factory.human_type(page, "input[name='username']", settings.instagram_username)
        await factory.human_type(page, "input[name='password']", settings.instagram_password.get_secret_value())
        await factory.human_click(page, "button[type='submit']")
        await asyncio.sleep(5)

        if "accounts/login" in page.url:
            raise LoginError("instagram_scraper", "instagram")

        # Handle "Save login info" dialog
        try:
            save_btn = page.locator("button:has-text('Not now')").first
            if await save_btn.count() > 0:
                await save_btn.click()
                await asyncio.sleep(1)
        except Exception:
            pass

        logger.info("instagram_login_success")

    async def _scrape_profile(self, page, factory, username: str) -> dict[str, Any] | None:
        profile_url = f"https://www.instagram.com/{username}/"
        await factory.human_goto(page, profile_url)
        await asyncio.sleep(3)

        if "Page Not Found" in await page.title():
            return None

        # Extract profile stats via meta tags and page content
        bio = ""
        followers = posts_count = following = 0

        try:
            # Bio
            bio_el = page.locator("header section div span").first
            if await bio_el.count():
                bio = await bio_el.inner_text()

            # Stats: followers, following, posts
            stats = await page.locator("header section ul li").all()
            for stat in stats:
                text = await stat.inner_text()
                if "posts" in text.lower():
                    posts_count = self._parse_count(text)
                elif "followers" in text.lower():
                    followers = self._parse_count(text)
                elif "following" in text.lower():
                    following = self._parse_count(text)
        except Exception as e:
            logger.debug("instagram_stats_parse_error", error=str(e))

        # Collect image URLs from posts
        image_urls: list[str] = []
        post_data: list[dict] = []
        try:
            await factory.human_scroll(page, distance=3000, steps=6)
            img_elements = await page.locator("article img").all()
            for img in img_elements[:50]:
                src = await img.get_attribute("src")
                alt = await img.get_attribute("alt") or ""
                if src:
                    image_urls.append(src)
                    post_data.append({"image_url": src, "caption": alt[:200]})
        except Exception as e:
            logger.debug("instagram_posts_error", error=str(e))

        return {
            "username": username,
            "profile_url": profile_url,
            "bio": bio.strip(),
            "followers": followers,
            "following": following,
            "posts_count": posts_count,
            "posts": post_data[:50],
            "discovered_image_urls": [{"url": u, "platform": "instagram"} for u in image_urls],
        }

    def _parse_count(self, text: str) -> int:
        """Parse follower/post counts like '1.2M', '500K', '1,234'."""
        import re
        num_str = re.search(r"[\d,.KkMm]+", text)
        if not num_str:
            return 0
        s = num_str.group().replace(",", "").upper()
        if "M" in s:
            return int(float(s.replace("M", "")) * 1_000_000)
        if "K" in s:
            return int(float(s.replace("K", "")) * 1_000)
        try:
            return int(s)
        except ValueError:
            return 0
