"""
Instagram profile scraper using Playwright browser automation.

Extracts: full name, bio, follower/following/post counts, profile image,
post thumbnails, external URL, and saves a screenshot.

Login flow:
1. Load saved session (if exists) — avoids logging in every run.
2. Navigate to instagram.com — if not on /accounts/login/, we're in.
3. If not logged in: fill credentials, submit, handle dialogs.
4. Save session state for next run.
5. For each candidate username, navigate directly to instagram.com/<username>/
6. Parse profile data from page content; screenshot on real profile pages only.

Candidate usernames are built from:
- Direct username input
- Discovered instagram usernames from search modules
- Name-derived variants (johndoe, john.doe, john_doe, etc.)
- Work-context variants (johndoe.acme, johndoe_acme)
"""

from __future__ import annotations

import asyncio
import re
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from app.core.config import settings
from app.core.constants import ModulePhase, TargetType
from app.core.exceptions import CaptchaError, LoginError
from app.core.logging import get_logger
from app.modules.base import BaseModule, ModuleMetadata, ModuleResult

logger = get_logger(__name__)

PROFILE_TIMEOUT = 15_000  # ms
LOGIN_TIMEOUT = 25_000  # ms
MAX_CANDIDATES = 10  # max usernames to try
MAX_POST_IMAGES = 50  # max post images to collect

_SEL_USERNAME = ["input[name='username']", "input[aria-label='Phone number, username, or email']"]
_SEL_PASSWORD = ["input[name='password']", "input[aria-label='Password']"]
_SEL_SUBMIT = ["button[type='submit']", "button:has-text('Log in')"]
_INSTA_RESERVED = {
    "p",
    "reel",
    "explore",
    "accounts",
    "stories",
    "direct",
    "channels",
    "tv",
    "ar",
    "about",
    "legal",
    "privacy",
    "safety",
    "help",
    "press",
    "api",
    "blog",
    "jobs",
    "developers",
}


class InstagramScraper(BaseModule):
    """Playwright-based Instagram profile scraper with login persistence."""

    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            name="instagram_scraper",
            display_name="Instagram Scraper",
            description="Extract Instagram profile data, posts, images, and follower stats",
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

    # ── Entry point ───────────────────────────────────────────────────────────

    async def run(self, target: str, target_type: TargetType, context: dict) -> ModuleResult:
        start = time.monotonic()

        if not settings.instagram_username or not settings.instagram_password:
            return ModuleResult(
                module_name=self.metadata().name,
                target=target,
                success=False,
                errors=[
                    "Instagram credentials not configured (INSTAGRAM_USERNAME / INSTAGRAM_PASSWORD)"
                ],
            )

        candidates = self._select_candidate_usernames(target, target_type, context)
        if not candidates:
            return ModuleResult(
                module_name=self.metadata().name,
                target=target,
                success=False,
                errors=["No candidate usernames could be derived for this target"],
            )

        page = None
        factory = None
        try:
            from app.engine.browser import BrowserFactory

            factory = await BrowserFactory.create()
            page = await factory.new_page(persist_session="instagram")

            logged_in = await self._ensure_logged_in(page, factory)
            if not logged_in:
                return ModuleResult(
                    module_name=self.metadata().name,
                    target=target,
                    success=False,
                    errors=[
                        "Instagram login failed — check INSTAGRAM_USERNAME / INSTAGRAM_PASSWORD"
                    ],
                )

            profile = None
            matched_username = None
            attempted: list[str] = []
            for username in candidates[:MAX_CANDIDATES]:
                attempted.append(username)
                profile = await self._scrape_profile(page, factory, username, context)
                if profile:
                    matched_username = username
                    break
                await asyncio.sleep(1)

            elapsed = int((time.monotonic() - start) * 1000)
            return ModuleResult(
                module_name=self.metadata().name,
                target=target,
                success=bool(profile),
                data={
                    **(profile or {}),
                    "attempted_usernames": attempted,
                    "matched_username": matched_username,
                    "total_candidates": len(candidates),
                },
                errors=[]
                if profile
                else [f"No Instagram profile found for: {', '.join(attempted)}"],
                execution_time_ms=elapsed,
            )

        except (LoginError, CaptchaError) as exc:
            return ModuleResult(
                module_name=self.metadata().name, target=target, success=False, errors=[str(exc)]
            )
        except Exception as exc:
            logger.error("instagram_scraper_error", error=str(exc))
            return ModuleResult(
                module_name=self.metadata().name, target=target, success=False, errors=[str(exc)]
            )
        finally:
            if page is not None and factory is not None:
                try:
                    await factory.close_page(page, save_session=True)
                except Exception as close_exc:
                    logger.debug("instagram_page_close_error", error=str(close_exc))

    # ── Login ─────────────────────────────────────────────────────────────────

    async def _ensure_logged_in(self, page, factory) -> bool:
        if await self._is_logged_in(page):
            logger.info("instagram_session_active")
            return True
        logger.info("instagram_session_expired_attempting_login")
        try:
            await self._do_login(page, factory)
        except (LoginError, CaptchaError):
            raise
        except Exception as exc:
            raise LoginError("instagram_scraper", "instagram") from exc
        return await self._is_logged_in(page)

    async def _is_logged_in(self, page) -> bool:
        try:
            await page.goto(
                "https://www.instagram.com/", timeout=15000, wait_until="domcontentloaded"
            )
            await asyncio.sleep(2)
            url = page.url.lower()
            if "accounts/login" in url:
                return False
            # Check for the home feed nav icon
            for sel in ["nav", "svg[aria-label='Home']", "a[href='/']"]:
                try:
                    el = page.locator(sel).first
                    if await el.count() > 0:
                        return True
                except Exception:
                    continue
            return "instagram.com" in url and "login" not in url
        except Exception:
            return False

    async def _do_login(self, page, factory) -> None:
        logger.info("instagram_login_start")
        await factory.human_goto(page, "https://www.instagram.com/accounts/login/")
        await asyncio.sleep(3)

        await self._dismiss_cookies(page, factory)

        # Username
        username_el = await self._wait_for_any(page, _SEL_USERNAME, LOGIN_TIMEOUT)
        if username_el is None:
            raise LoginError("instagram_scraper", "instagram")
        await username_el.click()
        await username_el.fill("")
        await factory.human_type(page, _SEL_USERNAME[0], settings.instagram_username)

        # Password
        password_el = await self._wait_for_any(page, _SEL_PASSWORD, 5000)
        if password_el is None:
            raise LoginError("instagram_scraper", "instagram")
        await password_el.click()
        await password_el.fill("")
        await factory.human_type(
            page, _SEL_PASSWORD[0], settings.instagram_password.get_secret_value()
        )

        # Submit
        submit_el = await self._wait_for_any(page, _SEL_SUBMIT, 5000)
        if submit_el is None:
            raise LoginError("instagram_scraper", "instagram")
        await submit_el.click()
        await asyncio.sleep(6)

        if "accounts/login" in page.url:
            raise LoginError("instagram_scraper", "instagram")

        # Handle post-login modals
        await self._dismiss_post_login_dialogs(page)
        logger.info("instagram_login_success", url=page.url[:60])

    async def _dismiss_post_login_dialogs(self, page) -> None:
        """Dismiss 'Save Login Info', 'Turn on Notifications', 'Add to Home' prompts."""
        selectors = [
            "button:has-text('Not Now')",
            "button:has-text('Not now')",
            "button:has-text('Skip')",
            "button:has-text('Later')",
            "button:has-text('Cancel')",
        ]
        for _ in range(3):
            await asyncio.sleep(2)
            dismissed = False
            for sel in selectors:
                try:
                    btn = page.locator(sel).first
                    if await btn.count() > 0:
                        await btn.click()
                        dismissed = True
                        await asyncio.sleep(1)
                        break
                except Exception:
                    continue
            if not dismissed:
                break

    # ── Profile scraping ─────────────────────────────────────────────────────

    async def _scrape_profile(
        self, page, factory, username: str, context: dict[str, Any]
    ) -> dict[str, Any] | None:
        profile_url = f"https://www.instagram.com/{username}/"
        try:
            await factory.human_goto(page, profile_url)
            await asyncio.sleep(3)
        except Exception as exc:
            logger.debug("instagram_goto_failed", username=username, error=str(exc))
            return None

        # Check if profile is unavailable
        if await self._is_unavailable(page):
            logger.debug("instagram_profile_unavailable", username=username)
            return None

        # Take screenshot ONLY of real profile pages
        screenshot_path = await self._capture_screenshot(page, factory, context, username)

        # Core profile fields
        full_name = await self._extract_full_name(page)
        bio = await self._extract_bio(page)
        ext_url = await self._extract_external_url(page)
        profile_image_url = await self._extract_profile_image(page)

        # Follower/following/post counts
        followers, following, posts_count = await self._extract_stats(page)

        # Scroll and collect post images
        await factory.human_scroll(page, distance=4000, steps=8)
        await asyncio.sleep(1)
        post_data, image_urls, post_urls = await self._collect_posts(page)

        # Build discovered_image_urls list for the AI vision module
        discovered_images: list[dict[str, str]] = []
        if profile_image_url:
            discovered_images.append(
                {
                    "url": profile_image_url,
                    "platform": "instagram",
                    "description": f"{username} profile picture",
                }
            )
        for url in image_urls:
            if url != profile_image_url:
                discovered_images.append(
                    {
                        "url": url,
                        "platform": "instagram",
                        "description": f"{username} post image",
                    }
                )

        logger.info(
            "instagram_profile_extracted",
            username=username,
            followers=followers,
            posts=posts_count,
        )

        return {
            "username": username,
            "profile_url": profile_url,
            "full_name": full_name or None,
            "bio": (bio or "").strip(),
            "followers": followers,
            "following": following,
            "posts_count": posts_count,
            "external_url": ext_url,
            "profile_image_url": profile_image_url,
            "posts": post_data,
            "post_urls": post_urls,
            "screenshot_path": str(screenshot_path) if screenshot_path else None,
            "discovered_image_urls": discovered_images,
        }

    # ── Data extraction helpers ───────────────────────────────────────────────

    async def _extract_full_name(self, page) -> str | None:
        selectors = [
            "header h1",
            "header h2",
            "section h1",
            "span.x1lliihq",  # Instagram's obfuscated class for display name
        ]
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

    async def _extract_bio(self, page) -> str | None:
        selectors = [
            "header section div span._ap3a",
            "header section div span.x1lliihq",
            "header section div.-vDIg span",
            "header section div span",
        ]
        for sel in selectors:
            try:
                el = page.locator(sel).first
                if await el.count() > 0:
                    text = (await el.inner_text()).strip()
                    if text and len(text) > 3:
                        return text
            except Exception:
                continue
        return None

    async def _extract_profile_image(self, page) -> str | None:
        """Get the profile picture URL from og:image meta or header img."""
        # og:image is most reliable
        try:
            meta = page.locator("meta[property='og:image']").first
            if await meta.count() > 0:
                content = await meta.get_attribute("content")
                if content and content.startswith("http"):
                    return content
        except Exception:
            pass

        # Fallback: header img element
        for sel in ["header img[alt*='profile picture']", "header img", "section img"]:
            try:
                img = page.locator(sel).first
                if await img.count() > 0:
                    src = await img.get_attribute("src")
                    if src and src.startswith("http"):
                        return src
            except Exception:
                continue
        return None

    async def _extract_external_url(self, page) -> str | None:
        try:
            link = page.locator("header a[href^='http']:not([href*='instagram'])").first
            if await link.count() > 0:
                return await link.get_attribute("href")
        except Exception:
            pass
        return None

    async def _extract_stats(self, page) -> tuple[int, int, int]:
        """Extract follower, following, and post counts."""
        followers = following = posts_count = 0
        try:
            stat_items = await page.locator("header section ul li").all()
            for item in stat_items:
                try:
                    text = (await item.inner_text()).strip().lower()
                    count = self._parse_count(text)
                    if "post" in text:
                        posts_count = count
                    elif "follower" in text:
                        followers = count
                    elif "following" in text:
                        following = count
                except Exception:
                    continue
        except Exception:
            pass

        # Fallback: parse og:description e.g. "500 Posts, 10K Followers, 1K Following"
        if not any((followers, following, posts_count)):
            try:
                meta = page.locator("meta[property='og:description']").first
                if await meta.count() > 0:
                    description = await meta.get_attribute("content") or ""
                    followers, following, posts_count = self._parse_og_description(description)
            except Exception:
                pass

        return followers, following, posts_count

    async def _collect_posts(self, page) -> tuple[list[dict[str, Any]], list[str], list[str]]:
        """Collect post thumbnails and their URLs."""
        post_data: list[dict[str, Any]] = []
        image_urls: list[str] = []
        post_urls: list[str] = []
        try:
            # Collect post hrefs
            links = await page.locator("article a[href*='/p/'], article a[href*='/reel/']").all()
            for link in links[:MAX_POST_IMAGES]:
                href = await link.get_attribute("href")
                if href:
                    full = href if href.startswith("http") else f"https://www.instagram.com{href}"
                    if full not in post_urls:
                        post_urls.append(full)

            # Collect image thumbnails
            images = await page.locator("article img, main article img").all()
            for img in images[:MAX_POST_IMAGES]:
                src = await img.get_attribute("src") or ""
                alt = await img.get_attribute("alt") or ""
                if src and src.startswith("http"):
                    if src not in image_urls:
                        image_urls.append(src)
                    post_data.append({"image_url": src, "caption": alt[:200]})

            # Associate post URLs with post data
            for i, post_url in enumerate(post_urls[: len(post_data)]):
                post_data[i]["post_url"] = post_url

        except Exception as exc:
            logger.debug("instagram_posts_error", error=str(exc))
        return post_data, image_urls, post_urls

    async def _capture_screenshot(
        self, page, factory, context: dict[str, Any], username: str
    ) -> Path | None:
        try:
            request_id = str(context.get("request_id", "adhoc"))
            screenshots_dir = Path(settings.data_dir) / "requests" / request_id / "screenshots"
            screenshots_dir.mkdir(parents=True, exist_ok=True)
            safe_username = re.sub(r"[^a-z0-9_.-]", "_", username.lower())[:40]
            screenshot_path = screenshots_dir / f"instagram_{safe_username}.png"
            await factory.take_screenshot(page, str(screenshot_path))
            return screenshot_path
        except Exception:
            return None

    async def _is_unavailable(self, page) -> bool:
        """Return True if the profile doesn't exist or we're on a login redirect."""
        try:
            title = (await page.title()).lower()
            url = page.url.lower()
            body_text = (await page.locator("body").inner_text()).lower()
        except Exception:
            return True

        return (
            "accounts/login" in url
            or "page not found" in title
            or "sorry, this page" in body_text
            or "user not found" in body_text
            or "isn't available" in body_text
        )

    # ── Cookie banner ─────────────────────────────────────────────────────────

    async def _dismiss_cookies(self, page, factory) -> None:
        for sel in [
            "button:has-text('Allow all cookies')",
            "button:has-text('Accept all')",
            "button:has-text('Accept')",
            "button:has-text('Allow all')",
        ]:
            try:
                btn = page.locator(sel).first
                if await btn.count() > 0:
                    await factory.human_click(page, sel, wait_ms=(200, 700))
                    await asyncio.sleep(1)
                    return
            except Exception:
                continue

    # ── Username candidate generation ─────────────────────────────────────────

    @staticmethod
    def _select_candidate_usernames(
        target: str,
        target_type: TargetType,
        context: dict[str, Any],
    ) -> list[str]:
        candidates: list[str] = []
        seen: set[str] = set()

        def add(value: str | None) -> None:
            if not value:
                return
            normalized = value.strip().lstrip("@").strip("/").lower()
            # Skip reserved paths, empty strings, or things that look like emails
            if not normalized or normalized in seen or "@" in normalized:
                return
            if normalized in _INSTA_RESERVED:
                return
            if len(normalized) < 2 or len(normalized) > 30:
                return
            seen.add(normalized)
            candidates.append(normalized)

        inputs = context.get("target_inputs", {}) if isinstance(context, dict) else {}
        if not isinstance(inputs, dict):
            inputs = {}

        # 1. Direct username input (highest priority)
        if target_type == TargetType.USERNAME:
            add(target)
        add(inputs.get("username"))

        # 2. From discovered instagram profiles in previous modules
        for item in context.get("discovered_instagram_profiles", []) or []:
            if isinstance(item, dict):
                add(
                    item.get("username")
                    or InstagramScraper._username_from_url(str(item.get("url", "")))
                )
            elif isinstance(item, str):
                add(InstagramScraper._username_from_url(item))

        # 3. From search results (SerpAPI, etc.)
        module_results = context.get("module_results", {}) if isinstance(context, dict) else {}
        if isinstance(module_results, dict):
            for mod_name in ("serpapi_search", "duckduckgo", "bing_search"):
                result = module_results.get(mod_name)
                if isinstance(result, dict):
                    for u in InstagramScraper._usernames_from_search(result):
                        add(u)

        # 4. Discovered usernames from other modules
        for u in context.get("discovered_usernames", []) or []:
            add(str(u))

        # 5. Name-derived variants
        name_sources = [
            inputs.get("name"),
            *(context.get("discovered_names", []) or []),
            target if target_type == TargetType.PERSON else None,
        ]
        for name in name_sources:
            if not name:
                continue
            for variant in InstagramScraper._name_variants(str(name)):
                add(variant)

        # 6. Email local part
        email_val = str(
            inputs.get("email") or (target if target_type == TargetType.EMAIL else "")
        ).strip()
        if email_val and "@" in email_val:
            local = email_val.split("@", 1)[0]
            add(local)
            add(local.replace(".", ""))
            add(local.replace(".", "_"))
            add(local.replace("_", "."))

        # 7. Work-context variants (e.g. roshnijoshi.blackrock)
        work = str(inputs.get("work", "") or "").strip()
        if work:
            work_slug = re.sub(r"[^a-z0-9]", "", work.lower())[:10]
            name_val = str(
                inputs.get("name", "") or (target if target_type == TargetType.PERSON else "")
            ).strip()
            if name_val and work_slug:
                name_tokens = [t for t in re.split(r"\s+", name_val.lower()) if t]
                if name_tokens:
                    full = "".join(name_tokens)
                    add(f"{full}.{work_slug}")
                    add(f"{full}_{work_slug}")
                    if len(name_tokens) >= 2:
                        initial_last = f"{name_tokens[0][0]}{name_tokens[-1]}"
                        add(f"{initial_last}.{work_slug}")

        return candidates

    @staticmethod
    def _name_variants(name: str) -> list[str]:
        tokens = [t for t in re.split(r"\s+", name.strip().lower()) if t]
        if not tokens:
            return []
        variants = [
            "".join(tokens),
            ".".join(tokens),
            "_".join(tokens),
            "-".join(tokens),
        ]
        if len(tokens) >= 2:
            first, last = tokens[0], tokens[-1]
            variants += [
                f"{first}{last[0]}",
                f"{first[0]}{last}",
                f"{first}.{last}",
                f"{last}.{first}",
                f"{last}{first[0]}",
            ]
        return list(dict.fromkeys(v for v in variants if v))

    @staticmethod
    def _username_from_url(url: str) -> str | None:
        try:
            parsed = urlparse(url.strip())
        except Exception:
            return None
        if "instagram.com" not in parsed.netloc.lower():
            return None
        parts = [p for p in parsed.path.split("/") if p]
        if not parts:
            return None
        username = parts[0]
        if username in _INSTA_RESERVED:
            return None
        return username

    @staticmethod
    def _usernames_from_search(payload: dict[str, Any]) -> list[str]:
        candidates: list[str] = []
        seen: set[str] = set()

        def add_from_url(url: str | None) -> None:
            u = InstagramScraper._username_from_url(url or "")
            if u and u not in seen:
                seen.add(u)
                candidates.append(u)

        for item in payload.get("results", []) or []:
            if isinstance(item, dict):
                add_from_url(item.get("url") or item.get("link"))
        for items in (payload.get("dork_results") or {}).values():
            if isinstance(items, list):
                for item in items:
                    if isinstance(item, dict):
                        add_from_url(item.get("url") or item.get("link"))
        return candidates

    # ── Helpers ───────────────────────────────────────────────────────────────

    async def _wait_for_any(self, page, selectors: list[str], timeout_ms: int = 10000):
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

    @staticmethod
    def _parse_count(text: str) -> int:
        m = re.search(r"([\d,.]+)\s*([KkMm]?)", text)
        if not m:
            return 0
        num_str = m.group(1).replace(",", "")
        suffix = m.group(2).upper()
        try:
            base = float(num_str)
        except ValueError:
            return 0
        if suffix == "M":
            return int(base * 1_000_000)
        if suffix == "K":
            return int(base * 1_000)
        return int(base)

    @staticmethod
    def _parse_og_description(desc: str) -> tuple[int, int, int]:
        """Parse 'NNN Posts, NNN Followers, NNN Following' from og:description."""
        counts = [
            InstagramScraper._parse_count(m) for m in re.findall(r"([\d,.]+\s*[KkMm]?)", desc)
        ]
        if len(counts) >= 3:
            return counts[1], counts[2], counts[0]  # followers, following, posts
        return 0, 0, 0
