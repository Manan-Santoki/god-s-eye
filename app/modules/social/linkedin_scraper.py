"""
LinkedIn profile scraper using Playwright browser automation.

Uses stealth mode, session persistence, and human-like behavior.
Requires LinkedIn credentials in .env (LINKEDIN_EMAIL / LINKEDIN_PASSWORD).

WARNING: Use a dedicated research account. Your account may be restricted
         if LinkedIn detects automated access. This is for authorized OSINT.
"""

import asyncio
import time
from pathlib import Path
from typing import Any

from app.core.config import settings
from app.core.constants import TargetType, ModulePhase
from app.core.exceptions import BrowserError, LoginError, CaptchaError
from app.core.logging import get_logger
from app.modules.base import BaseModule, ModuleMetadata, ModuleResult

logger = get_logger(__name__)


class LinkedInScraper(BaseModule):
    """Playwright-based LinkedIn profile scraper with session persistence."""

    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            name="linkedin_scraper",
            display_name="LinkedIn Scraper",
            description="Extract LinkedIn profiles, experience, education, and skills",
            supported_targets=[TargetType.PERSON, TargetType.EMAIL],
            phase=ModulePhase.BROWSER_AUTH,
            requires_auth=True,
            requires_browser=True,
            requires_proxy=True,
            rate_limit_rpm=6,
            timeout_seconds=120,
            priority=2,
            enabled_by_default=True,
        )

    async def validate(self, target: str, target_type: TargetType) -> bool:
        return target_type in (TargetType.PERSON, TargetType.EMAIL)

    async def run(self, target: str, target_type: TargetType, context: dict) -> ModuleResult:
        start = time.monotonic()

        if not settings.linkedin_email or not settings.linkedin_password:
            return ModuleResult(
                module_name=self.metadata().name,
                target=target,
                success=False,
                errors=["LinkedIn credentials not configured (LINKEDIN_EMAIL / LINKEDIN_PASSWORD)"],
            )

        try:
            from app.engine.browser import BrowserFactory
            factory = await BrowserFactory.create()
            page = await factory.new_page(persist_session="linkedin")

            # Login or use saved session
            if not await self._is_logged_in(page):
                await self._login(page, factory)

            # Search for target
            profiles = await self._search_profiles(page, factory, target)

            elapsed = int((time.monotonic() - start) * 1000)
            return ModuleResult(
                module_name=self.metadata().name,
                target=target,
                success=True,
                data={
                    "profiles_found": len(profiles),
                    "profiles": profiles,
                    "primary_profile": profiles[0] if profiles else None,
                },
                execution_time_ms=elapsed,
            )

        except (LoginError, CaptchaError) as e:
            logger.warning("linkedin_auth_failed", error=str(e))
            return ModuleResult(
                module_name=self.metadata().name,
                target=target,
                success=False,
                errors=[str(e)],
            )
        except Exception as e:
            logger.error("linkedin_scraper_error", error=str(e))
            return ModuleResult(
                module_name=self.metadata().name,
                target=target,
                success=False,
                errors=[str(e)],
            )

    async def _is_logged_in(self, page) -> bool:
        """Check if we have an active LinkedIn session."""
        try:
            await page.goto("https://www.linkedin.com/feed/", timeout=15000, wait_until="domcontentloaded")
            return "feed" in page.url and "login" not in page.url
        except Exception:
            return False

    async def _login(self, page, factory) -> None:
        """Perform LinkedIn login with human-like behavior."""
        logger.info("linkedin_login_attempt")
        await factory.human_goto(page, "https://www.linkedin.com/login")

        # Check for CAPTCHA
        if await page.locator("iframe[title*='challenge']").count() > 0:
            raise CaptchaError("linkedin_scraper", page.url)

        # Type credentials with human delays
        await factory.human_type(page, "#username", settings.linkedin_email)
        await factory.human_type(
            page, "#password", settings.linkedin_password.get_secret_value()
        )
        await factory.human_click(page, "button[type='submit']")
        await asyncio.sleep(3)

        # Verify login
        if "feed" not in page.url and "checkpoint" not in page.url:
            raise LoginError("linkedin_scraper", "linkedin")

        if "checkpoint" in page.url:
            raise CaptchaError("linkedin_scraper", page.url)

        logger.info("linkedin_login_success")

    async def _search_profiles(self, page, factory, target: str) -> list[dict[str, Any]]:
        """Search LinkedIn for target and extract profiles."""
        search_url = f"https://www.linkedin.com/search/results/people/?keywords={target}"
        await factory.human_goto(page, search_url)
        await asyncio.sleep(2)

        profiles = []
        profile_links = await page.locator("a[href*='/in/']").all()
        unique_urls: set[str] = set()

        for link in profile_links[:3]:  # Max 3 profiles
            try:
                href = await link.get_attribute("href")
                if href and "/in/" in href:
                    # Normalize URL
                    clean = href.split("?")[0]
                    if clean not in unique_urls:
                        unique_urls.add(clean)
                        profile = await self._extract_profile(page, factory, clean)
                        if profile:
                            profiles.append(profile)
            except Exception as e:
                logger.debug("linkedin_link_error", error=str(e))

        return profiles

    async def _extract_profile(self, page, factory, profile_url: str) -> dict[str, Any] | None:
        """Navigate to a LinkedIn profile and extract all data."""
        try:
            await factory.human_goto(page, profile_url)
            await asyncio.sleep(2)

            # Take screenshot
            request_id = page.url.split("/")[-1]
            screenshots_dir = Path(settings.data_dir) / "requests"
            # Save screenshot if we can determine the path
            try:
                screenshot_path = f"screenshots/linkedin_{request_id}.png"
                await factory.take_screenshot(page, screenshot_path)
            except Exception:
                screenshot_path = None

            # Extract basic info
            name = await self._safe_text(page, "h1")
            headline = await self._safe_text(page, ".text-body-medium")
            location = await self._safe_text(page, ".text-body-small.inline")
            about = await self._safe_text(page, "#about ~ div .visually-hidden")

            # Scroll down to load more sections
            await factory.human_scroll(page, distance=2000, steps=4)
            await asyncio.sleep(1)

            # Extract experience
            experience = await self._extract_list_section(page, "#experience")

            # Extract education
            education = await self._extract_list_section(page, "#education")

            # Extract skills
            skills_elements = await page.locator(".pvs-list__item--line-separated span[aria-hidden='true']").all()
            skills = [await e.inner_text() for e in skills_elements[:20]]

            return {
                "name": name,
                "headline": headline,
                "location": location,
                "about": about[:500] if about else None,
                "profile_url": profile_url,
                "experience": experience[:5],
                "education": education[:5],
                "skills": [s for s in skills if s and len(s) > 1],
                "screenshot_path": screenshot_path,
            }

        except Exception as e:
            logger.warning("linkedin_profile_extract_failed", url=profile_url, error=str(e))
            return None

    async def _safe_text(self, page, selector: str) -> str | None:
        """Safely extract text from a selector."""
        try:
            el = page.locator(selector).first
            if await el.count() > 0:
                text = await el.inner_text()
                return text.strip() or None
        except Exception:
            pass
        return None

    async def _extract_list_section(self, page, section_id: str) -> list[dict]:
        """Extract experience or education section items."""
        items = []
        try:
            section = page.locator(f"{section_id} ~ div .pvs-list__item--line-separated")
            count = await section.count()
            for i in range(min(count, 5)):
                item = section.nth(i)
                title = await self._safe_element_text(item, "span[aria-hidden='true']")
                items.append({"text": title})
        except Exception:
            pass
        return items

    async def _safe_element_text(self, element, selector: str) -> str | None:
        """Safely get text from child element."""
        try:
            child = element.locator(selector).first
            if await child.count() > 0:
                return (await child.inner_text()).strip()
        except Exception:
            pass
        return None
