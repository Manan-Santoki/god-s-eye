"""
Facebook public profile scraper using Playwright.

Searches for a person/username on Facebook's public search.
Only accesses publicly-visible information — no credentials required
for basic search; optional login for broader results.

Target types: username, person
Phase: BROWSER_AUTH (4)
"""

from typing import Any

from app.modules.base import BaseModule, ModuleMetadata, ModuleResult
from app.core.constants import ModulePhase, TargetType
from app.core.logging import get_logger

logger = get_logger(__name__)


class FacebookScraper(BaseModule):
    """Scrape publicly-available Facebook profile information."""

    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            name="facebook_scraper",
            display_name="Facebook Profile Scraper",
            description="Extracts public profile data from Facebook search results",
            phase=ModulePhase.BROWSER_AUTH,
            target_types=[TargetType.USERNAME, TargetType.PERSON],
            requires_browser=True,
            requires_api_key=False,
            rate_limit_per_minute=5,
        )

    async def validate(self, target: str, target_type: TargetType, **kwargs: Any) -> bool:
        return bool(target and len(target.strip()) >= 2)

    async def run(
        self,
        target: str,
        target_type: TargetType,
        session: Any = None,
        **kwargs: Any,
    ) -> ModuleResult:
        from app.engine.browser import BrowserFactory

        results: dict[str, Any] = {
            "target": target,
            "profiles": [],
            "search_url": "",
            "found": False,
        }

        browser_factory = BrowserFactory()
        page = None

        try:
            page = await browser_factory.new_page()

            # Use Facebook's public search
            search_query = target.replace(" ", "%20")
            search_url = f"https://www.facebook.com/public/{search_query}"
            results["search_url"] = search_url

            await browser_factory.human_goto(page, search_url)
            await page.wait_for_timeout(2000)

            # Check if we're on a real page (not login wall)
            current_url = page.url
            if "login" in current_url or "checkpoint" in current_url:
                logger.info("facebook_login_wall_hit", target=target)
                # Fall back to search engine query
                results["note"] = "Facebook requires login for detailed search. Use web_search module for public info."
                return ModuleResult(
                    module_name=self.metadata().name,
                    target=target,
                    success=True,
                    data=results,
                )

            # Try to extract profile cards from public search
            profile_cards = await page.query_selector_all("[data-testid='browse-result-content']")

            if not profile_cards:
                # Try alternate selectors
                profile_cards = await page.query_selector_all(".publicGridItem, [role='article']")

            profiles = []
            for card in profile_cards[:10]:
                try:
                    profile: dict[str, Any] = {}

                    # Name
                    name_el = await card.query_selector("a[href*='/profile.php'], a[href*='facebook.com/']")
                    if name_el:
                        profile["name"] = (await name_el.inner_text()).strip()
                        profile["url"] = await name_el.get_attribute("href")

                    # Location / bio snippet
                    bio_el = await card.query_selector("[data-testid='result-subtitle'], .result-subtitle")
                    if bio_el:
                        profile["bio"] = (await bio_el.inner_text()).strip()

                    # Work / education
                    details_els = await card.query_selector_all("[data-testid='result-detail']")
                    details = []
                    for d in details_els:
                        text = (await d.inner_text()).strip()
                        if text:
                            details.append(text)
                    if details:
                        profile["details"] = details

                    if profile.get("name"):
                        profiles.append(profile)

                except Exception as e:
                    logger.debug("facebook_card_parse_error", error=str(e))

            results["profiles"] = profiles
            results["found"] = len(profiles) > 0
            results["profile_count"] = len(profiles)

            # Also check for direct profile match (username search)
            if target_type == TargetType.USERNAME:
                direct_url = f"https://www.facebook.com/{target}"
                try:
                    await browser_factory.human_goto(page, direct_url)
                    await page.wait_for_timeout(1500)

                    if "profile.php" in page.url or f"/{target}" in page.url:
                        title = await page.title()
                        og_desc = await page.query_selector("meta[property='og:description']")
                        og_img = await page.query_selector("meta[property='og:image']")

                        direct_profile: dict[str, Any] = {
                            "url": page.url,
                            "title": title,
                            "username": target,
                        }
                        if og_desc:
                            direct_profile["description"] = await og_desc.get_attribute("content") or ""
                        if og_img:
                            direct_profile["image_url"] = await og_img.get_attribute("content") or ""

                        results["direct_profile"] = direct_profile
                        results["found"] = True

                except Exception as e:
                    logger.debug("facebook_direct_profile_error", error=str(e))

            logger.info(
                "facebook_scrape_complete",
                target=target,
                profiles_found=len(profiles),
            )

            return ModuleResult(
                module_name=self.metadata().name,
                target=target,
                success=True,
                data=results,
                findings_count=len(profiles),
            )

        except Exception as e:
            logger.error("facebook_scraper_failed", target=target, error=str(e))
            return ModuleResult(
                module_name=self.metadata().name,
                target=target,
                success=False,
                error=str(e),
                data=results,
            )
        finally:
            if page:
                try:
                    await page.close()
                except Exception:
                    pass
