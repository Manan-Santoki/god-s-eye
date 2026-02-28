"""
LinkedIn profile scraper using Playwright browser automation.

Uses stealth mode, session persistence, and human-like behavior.
Requires LinkedIn credentials in .env (LINKEDIN_EMAIL / LINKEDIN_PASSWORD).

WARNING: Use a dedicated research account. Your account may be restricted
         if LinkedIn detects automated access. This is for authorized OSINT.

Login flow:
1. Load saved session state from disk (if present)
2. Navigate to /feed/ — if we see the primary nav, we're logged in
3. If not logged in: fill in credentials, submit, handle 2FA/checkpoint
4. Save session state after successful login so subsequent runs skip login
5. Search for target with keyword + optional work/location filters
6. Extract up to MAX_PROFILES profiles, taking screenshots ONLY of /in/ pages
"""

from __future__ import annotations

import asyncio
import re
import time
from pathlib import Path
from typing import Any
from urllib.parse import quote_plus

from app.core.config import settings
from app.core.constants import ModulePhase, TargetType
from app.core.exceptions import BrowserError, CaptchaError, LoginError
from app.core.logging import get_logger
from app.modules.base import BaseModule, ModuleMetadata, ModuleResult

logger = get_logger(__name__)

MAX_PROFILES = 5          # Max profiles to deep-scrape per search
SEARCH_TIMEOUT = 20_000   # ms to wait for search results page
PROFILE_TIMEOUT = 25_000  # ms to wait for a profile page to load
LOGIN_TIMEOUT  = 30_000   # ms to wait for login elements

# LinkedIn selectors (multiple fallbacks per field)
_SEL_USERNAME   = ["input#username", "input[name='session_key']", "input[autocomplete='username']"]
_SEL_PASSWORD   = ["input#password", "input[name='session_password']", "input[autocomplete='current-password']"]
_SEL_SUBMIT     = ["button[type='submit']", "button[data-litms-control-urn*='sign-in']", ".login__form button"]
_SEL_NAV        = ["nav[aria-label='Primary Navigation']", ".global-nav", "[data-test-global-nav]", ".authentication-outlet"]
_SEL_PROFILE_H1 = ["h1.text-heading-xlarge", "h1.inline.t-24", "h1"]
_SEL_HEADLINE   = [".text-body-medium.break-words", "div.text-body-medium", ".pv-text-details__left-panel h2"]
_SEL_LOCATION   = [".text-body-small.inline.t-black--light", ".pv-text-details__left-panel span:nth-child(2)"]
_SEL_ABOUT      = ["#about ~ .pvs-list__outer-container span[aria-hidden='true']",
                   "#about ~ div span.visually-hidden", "#about ~ div .inline-show-more-text"]
_SEL_CONNECT    = [".pv-top-card-profile-picture__image", "img.profile-photo-edit__preview", "img.pv-top-card-profile-picture__image"]

# Pages where we're definitely NOT logged in
_LOGIN_URL_TOKENS = ("accounts/login", "/login", "/checkpoint", "/challenge",
                     "uas/authenticate", "authwall")


class LinkedInScraper(BaseModule):
    """Playwright-based LinkedIn profile scraper with robust login + session persistence."""

    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            name="linkedin_scraper",
            display_name="LinkedIn Scraper",
            description="Extract LinkedIn profiles, experience, education, skills, and images",
            supported_targets=[TargetType.PERSON, TargetType.EMAIL],
            phase=ModulePhase.BROWSER_AUTH,
            requires_auth=True,
            requires_browser=True,
            requires_proxy=True,
            rate_limit_rpm=6,
            timeout_seconds=180,
            priority=2,
            enabled_by_default=True,
        )

    async def validate(self, target: str, target_type: TargetType) -> bool:
        return target_type in (TargetType.PERSON, TargetType.EMAIL)

    # ── Entry point ───────────────────────────────────────────────────────────

    async def run(self, target: str, target_type: TargetType, context: dict) -> ModuleResult:
        start = time.monotonic()

        if not settings.linkedin_email or not settings.linkedin_password:
            return ModuleResult(
                module_name=self.metadata().name,
                target=target,
                success=False,
                errors=["LinkedIn credentials not configured (LINKEDIN_EMAIL / LINKEDIN_PASSWORD)"],
            )

        search_term = self._select_search_term(target, target_type, context)
        if not search_term:
            return ModuleResult(
                module_name=self.metadata().name,
                target=target,
                success=False,
                errors=["Cannot determine a search term for LinkedIn — provide --name or email with name"],
            )

        page = None
        factory = None
        try:
            from app.engine.browser import BrowserFactory
            factory = await BrowserFactory.create()
            page = await factory.new_page(persist_session="linkedin")

            logged_in = await self._ensure_logged_in(page, factory)
            if not logged_in:
                return ModuleResult(
                    module_name=self.metadata().name,
                    target=target,
                    success=False,
                    errors=["LinkedIn login failed — check credentials or clear the session file"],
                )

            profiles = await self._search_and_extract(page, factory, search_term, context)

            elapsed = int((time.monotonic() - start) * 1000)
            return ModuleResult(
                module_name=self.metadata().name,
                target=target,
                success=True,
                data={
                    "searched_query": search_term,
                    "profiles_found": len(profiles),
                    "profiles": profiles,
                    "primary_profile": profiles[0] if profiles else None,
                },
                execution_time_ms=elapsed,
            )

        except (LoginError, CaptchaError) as exc:
            logger.warning("linkedin_auth_failed", error=str(exc))
            return ModuleResult(
                module_name=self.metadata().name,
                target=target,
                success=False,
                errors=[str(exc)],
            )
        except BrowserError as exc:
            logger.error("linkedin_browser_error", error=str(exc))
            return ModuleResult(
                module_name=self.metadata().name,
                target=target,
                success=False,
                errors=[str(exc)],
            )
        except Exception as exc:
            logger.error("linkedin_scraper_error", error=str(exc))
            return ModuleResult(
                module_name=self.metadata().name,
                target=target,
                success=False,
                errors=[str(exc)],
            )
        finally:
            if page is not None and factory is not None:
                try:
                    await factory.close_page(page, save_session=True)
                except Exception as close_exc:
                    logger.debug("linkedin_page_close_error", error=str(close_exc))

    # ── Login ─────────────────────────────────────────────────────────────────

    async def _ensure_logged_in(self, page, factory) -> bool:
        """Return True when we have a valid LinkedIn session. Attempt login if not."""
        if await self._is_logged_in(page, factory):
            logger.info("linkedin_session_active")
            return True

        logger.info("linkedin_session_expired_attempting_login")
        try:
            await self._do_login(page, factory)
        except (LoginError, CaptchaError):
            raise
        except Exception as exc:
            raise LoginError("linkedin_scraper", "linkedin") from exc

        return await self._is_logged_in(page, factory)

    async def _is_logged_in(self, page, factory) -> bool:
        """Check for the LinkedIn primary navigation — presence means we're logged in."""
        try:
            await factory.human_goto(page, "https://www.linkedin.com/feed/")
            await asyncio.sleep(2)

            current = page.url.lower()
            if self._is_auth_page(current):
                return False

            for sel in _SEL_NAV:
                try:
                    nav = page.locator(sel).first
                    if await nav.count() > 0:
                        return True
                except Exception:
                    continue
            return False
        except Exception:
            return False

    async def _do_login(self, page, factory) -> None:
        """Fill the LinkedIn login form, submit, and wait for the feed."""
        logger.info("linkedin_login_start")
        await factory.human_goto(page, "https://www.linkedin.com/login")
        await asyncio.sleep(2)

        await self._dismiss_cookies(page, factory)

        # Fill username
        username_el = await self._wait_for_any(page, _SEL_USERNAME, LOGIN_TIMEOUT)
        if username_el is None:
            raise LoginError("linkedin_scraper", "linkedin")
        await username_el.click()
        await username_el.fill("")
        await factory.human_type(page, _SEL_USERNAME[0], settings.linkedin_email)

        # Fill password
        password_el = await self._wait_for_any(page, _SEL_PASSWORD, 5000)
        if password_el is None:
            raise LoginError("linkedin_scraper", "linkedin")
        await password_el.click()
        await password_el.fill("")
        await factory.human_type(page, _SEL_PASSWORD[0], settings.linkedin_password.get_secret_value())

        # Submit
        submit_el = await self._wait_for_any(page, _SEL_SUBMIT, 5000)
        if submit_el is None:
            raise LoginError("linkedin_scraper", "linkedin")
        await submit_el.click()

        # Wait for redirect — may go to /feed/, /checkpoint/, /email-verification/, /2step/, etc.
        await asyncio.sleep(6)
        current = page.url.lower()
        logger.info("linkedin_post_login_url", url=current[:80])

        # Handle post-login verification screens — skip gracefully
        if "checkpoint" in current or "challenge" in current:
            raise CaptchaError("linkedin_scraper", page.url)
        if "add-phone" in current or "email-verification" in current or "2step" in current:
            # Try to dismiss "skip" button
            for skip_sel in ["a[data-control-name='dismiss']", "button:has-text('Skip')", "a:has-text('Skip')"]:
                try:
                    skip_btn = page.locator(skip_sel).first
                    if await skip_btn.count() > 0:
                        await skip_btn.click()
                        await asyncio.sleep(2)
                        break
                except Exception:
                    continue

        # Final check
        if self._is_auth_page(page.url.lower()):
            raise LoginError("linkedin_scraper", "linkedin")

        logger.info("linkedin_login_success", landed_on=page.url[:60])

    # ── Search + profile extraction ───────────────────────────────────────────

    async def _search_and_extract(
        self, page, factory, search_term: str, context: dict[str, Any]
    ) -> list[dict[str, Any]]:
        inputs = context.get("target_inputs", {}) if isinstance(context, dict) else {}
        if not isinstance(inputs, dict):
            inputs = {}

        work = str(inputs.get("work", "") or "").strip()
        location_filter = str(inputs.get("location", "") or "").strip()

        # Build search keyword — include work context for disambiguation
        keyword_parts = [search_term]
        if work and work.lower() not in search_term.lower():
            keyword_parts.append(work)

        keyword = " ".join(keyword_parts)
        search_url = (
            f"https://www.linkedin.com/search/results/people/"
            f"?keywords={quote_plus(keyword)}&origin=GLOBAL_SEARCH_HEADER"
        )
        if location_filter:
            search_url += f"&geoUrn=&location={quote_plus(location_filter)}"

        logger.info("linkedin_search", keyword=keyword, location=location_filter or "any")
        await factory.human_goto(page, search_url)
        await asyncio.sleep(3)

        # If redirected to auth, abort
        if self._is_auth_page(page.url.lower()):
            logger.warning("linkedin_search_redirected_to_login")
            return []

        # Collect profile links from search results
        profile_urls = await self._collect_profile_links(page)
        if not profile_urls:
            logger.info("linkedin_no_profile_links_found")
            return []

        profiles: list[dict[str, Any]] = []
        for url in profile_urls[:MAX_PROFILES]:
            profile = await self._extract_profile(page, factory, url, context)
            if profile:
                profiles.append(profile)
            await asyncio.sleep(1)  # polite delay between profiles

        return profiles

    async def _collect_profile_links(self, page) -> list[str]:
        """Scrape /in/ profile URLs from a people-search results page."""
        try:
            await page.wait_for_selector("a[href*='/in/']", timeout=SEARCH_TIMEOUT)
        except Exception:
            pass

        profile_urls: list[str] = []
        seen: set[str] = set()

        links = await page.locator("a[href*='/in/']").all()
        for link in links:
            try:
                href = await link.get_attribute("href")
                if not href or "/in/" not in href:
                    continue
                # Normalize: strip query params, ensure absolute
                clean = href.split("?")[0].rstrip("/")
                if not clean.startswith("http"):
                    clean = f"https://www.linkedin.com{clean}"
                # Must look like a real profile URL: /in/<slug>
                match = re.search(r"/in/([a-zA-Z0-9_%-]+)", clean)
                if not match:
                    continue
                # Skip generic/marketing pages
                slug = match.group(1).lower()
                if slug in ("learning", "jobs", "company", "feed", "messaging"):
                    continue
                if clean not in seen:
                    seen.add(clean)
                    profile_urls.append(clean)
            except Exception:
                continue

        return profile_urls

    async def _extract_profile(
        self, page, factory, profile_url: str, context: dict[str, Any]
    ) -> dict[str, Any] | None:
        """Navigate to a LinkedIn /in/ profile and extract all structured data."""
        try:
            await factory.human_goto(page, profile_url)
            await asyncio.sleep(2)

            # Abort if redirected to login/checkpoint
            current = page.url.lower()
            if self._is_auth_page(current) or "/in/" not in current:
                logger.warning("linkedin_profile_redirect", url=page.url[:80])
                return None

            # Wait for the H1 (name) to appear — confirms we're on a real profile
            try:
                await page.wait_for_selector(", ".join(_SEL_PROFILE_H1), timeout=PROFILE_TIMEOUT)
            except Exception:
                logger.warning("linkedin_profile_h1_not_found", url=profile_url[:60])
                return None

            # Screenshot — ONLY on real /in/ pages
            screenshot_path = await self._take_profile_screenshot(page, factory, context, profile_url)

            # Extract core fields
            name = await self._first_text(page, _SEL_PROFILE_H1)
            headline = await self._first_text(page, _SEL_HEADLINE)
            location_text = await self._first_text(page, _SEL_LOCATION)
            about = await self._first_text(page, _SEL_ABOUT)

            # Profile image URL
            profile_image_url = await self._extract_profile_image(page)

            # Scroll to load experience/education
            await factory.human_scroll(page, distance=3000, steps=5)
            await asyncio.sleep(1)

            experience = await self._extract_section(page, "#experience")
            education = await self._extract_section(page, "#education")
            skills = await self._extract_skills(page)
            contact_info = await self._extract_contact_info(page, factory)
            certifications = await self._extract_section(page, "#licenses_and_certifications")

            # Discovered entities from profile
            discovered_emails: list[str] = []
            if contact_info.get("email"):
                discovered_emails.append(contact_info["email"])

            return {
                "name": name,
                "headline": headline,
                "location": location_text,
                "about": (about or "")[:1000],
                "profile_url": profile_url,
                "profile_image_url": profile_image_url,
                "experience": experience,
                "education": education,
                "skills": skills,
                "certifications": certifications,
                "contact_info": contact_info,
                "screenshot_path": str(screenshot_path) if screenshot_path else None,
                "discovered_emails": discovered_emails,
            }

        except Exception as exc:
            logger.warning("linkedin_profile_extract_failed", url=profile_url[:60], error=str(exc))
            return None

    # ── Data extraction helpers ───────────────────────────────────────────────

    async def _extract_profile_image(self, page) -> str | None:
        """Extract the profile photo URL from the page."""
        for sel in _SEL_CONNECT:
            try:
                img = page.locator(sel).first
                if await img.count() > 0:
                    src = await img.get_attribute("src")
                    if src and src.startswith("http") and "media" in src:
                        return src
            except Exception:
                continue
        # Fallback: og:image meta
        try:
            meta = page.locator("meta[property='og:image']").first
            if await meta.count() > 0:
                content = await meta.get_attribute("content")
                if content and content.startswith("http"):
                    return content
        except Exception:
            pass
        return None

    async def _extract_section(self, page, section_id: str) -> list[dict[str, Any]]:
        """Extract experience, education, or certification section items."""
        items: list[dict[str, Any]] = []
        try:
            # LinkedIn renders sections with pvs-list
            section_locator = page.locator(f"{section_id} ~ .pvs-list__outer-container, {section_id} + div .pvs-list")
            entry_locator = section_locator.locator(".pvs-list__item--line-separated").first
            if await entry_locator.count() == 0:
                # Try alternate container
                entry_locator = page.locator(f"{section_id} ~ div li.artdeco-list__item")

            entries = await page.locator(
                f"{section_id} ~ .pvs-list__outer-container li, "
                f"{section_id} ~ div li.artdeco-list__item"
            ).all()

            for entry in entries[:8]:
                try:
                    texts = []
                    for span in await entry.locator("span[aria-hidden='true']").all():
                        t = (await span.inner_text()).strip()
                        if t and t not in texts:
                            texts.append(t)
                    if texts:
                        items.append({"text": " | ".join(texts[:3])})
                except Exception:
                    continue
        except Exception:
            pass
        return items

    async def _extract_skills(self, page) -> list[str]:
        """Extract skills from the skills section."""
        skills: list[str] = []
        try:
            skill_items = await page.locator(
                "#skills ~ .pvs-list__outer-container span[aria-hidden='true'], "
                ".pv-skill-categories-section li"
            ).all()
            for item in skill_items[:30]:
                text = (await item.inner_text()).strip()
                if text and len(text) > 1 and text not in skills:
                    skills.append(text)
        except Exception:
            pass
        return skills

    async def _extract_contact_info(self, page, factory) -> dict[str, Any]:
        """Open the contact info modal and extract email/phone/websites."""
        info: dict[str, Any] = {}
        try:
            # Click "Contact info" link
            contact_link = page.locator("a[href*='/overlay/contact-info/'], a:has-text('Contact info')").first
            if await contact_link.count() > 0:
                await factory.human_click(page, "a[href*='/overlay/contact-info/']")
                await asyncio.sleep(2)

                modal = page.locator(".pv-contact-info")
                if await modal.count() > 0:
                    # Email
                    email_el = modal.locator("section.ci-email a")
                    if await email_el.count() > 0:
                        info["email"] = (await email_el.inner_text()).strip()
                    # Phone
                    phone_el = modal.locator("section.ci-phone span.t-14")
                    if await phone_el.count() > 0:
                        info["phone"] = (await phone_el.inner_text()).strip()
                    # Websites
                    website_els = await modal.locator("section.ci-websites a").all()
                    info["websites"] = [(await el.get_attribute("href") or "").strip() for el in website_els if el]

                # Close modal
                close_btn = page.locator("button[aria-label='Dismiss']").first
                if await close_btn.count() > 0:
                    await close_btn.click()
        except Exception as exc:
            logger.debug("linkedin_contact_info_error", error=str(exc))
        return info

    async def _take_profile_screenshot(
        self, page, factory, context: dict[str, Any], profile_url: str
    ) -> Path | None:
        """Take screenshot ONLY when we're on a real /in/ profile page."""
        if "/in/" not in page.url:
            return None
        try:
            request_id = str(context.get("request_id", "adhoc"))
            screenshots_dir = Path(settings.data_dir) / "requests" / request_id / "screenshots"
            screenshots_dir.mkdir(parents=True, exist_ok=True)
            slug = re.sub(r"[^a-z0-9-]", "_", profile_url.rstrip("/").split("/")[-1].lower())[:40]
            screenshot_path = screenshots_dir / f"linkedin_{slug}.png"
            await factory.take_screenshot(page, str(screenshot_path))
            return screenshot_path
        except Exception:
            return None

    # ── Static helpers ────────────────────────────────────────────────────────

    @staticmethod
    def _is_auth_page(url: str) -> bool:
        """Return True if the URL is a LinkedIn auth/checkpoint page."""
        return any(token in url for token in _LOGIN_URL_TOKENS)

    @staticmethod
    def _select_search_term(target: str, target_type: TargetType, context: dict[str, Any]) -> str:
        """Build a LinkedIn people-search keyword from available target inputs."""
        inputs = context.get("target_inputs", {}) if isinstance(context, dict) else {}
        if not isinstance(inputs, dict):
            inputs = {}

        if target_type == TargetType.PERSON:
            base = str(inputs.get("name") or target).strip()
        elif target_type == TargetType.EMAIL:
            candidates = [
                inputs.get("name"),
                *(context.get("discovered_names", []) or []),
            ]
            base = next((str(c).strip() for c in candidates if c and str(c).strip()), "")
            if not base:
                local = str(inputs.get("email") or target).split("@", 1)[0]
                base = local.replace(".", " ").replace("_", " ").replace("-", " ").strip()
        else:
            base = str(target).strip()

        return base

    async def _first_text(self, page, selectors: list[str]) -> str | None:
        """Return the inner text of the first matching selector."""
        for sel in selectors:
            try:
                el = page.locator(sel).first
                if await el.count() > 0:
                    text = (await el.inner_text()).strip()
                    if text:
                        return text
            except Exception:
                continue
        return None

    async def _wait_for_any(self, page, selectors: list[str], timeout_ms: int = 10000):
        """Wait for the first selector that appears and return its locator element."""
        combined = ", ".join(selectors)
        try:
            await page.wait_for_selector(combined, timeout=timeout_ms)
        except Exception:
            return None
        for sel in selectors:
            try:
                el = page.locator(sel).first
                if await el.count() > 0:
                    return el
            except Exception:
                continue
        return None

    async def _dismiss_cookies(self, page, factory) -> None:
        """Dismiss LinkedIn cookie/GDPR banners that block the login form."""
        for sel in [
            "button[action-type='ACCEPT']",
            "button:has-text('Accept cookies')",
            "button:has-text('Accept all')",
            "button:has-text('Allow all')",
        ]:
            try:
                btn = page.locator(sel).first
                if await btn.count() > 0:
                    await btn.click()
                    await asyncio.sleep(1)
                    return
            except Exception:
                continue
