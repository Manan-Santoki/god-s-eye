"""
Capture screenshots of high-value discovered URLs.

This gives the scan a visual evidence trail even when a platform-specific
scraper is unavailable or login-gated.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from app.core.config import get_module_setting, settings
from app.core.constants import ModulePhase, TargetType
from app.core.logging import get_logger
from app.modules.base import BaseModule, ModuleMetadata, ModuleResult

logger = get_logger(__name__)


class WebSnapshotModule(BaseModule):
    """Capture screenshots of discovered public URLs."""

    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            name="web_snapshot",
            display_name="Web Snapshot Collector",
            description="Captures screenshots of discovered public profile and web pages",
            phase=ModulePhase.DEEP_ANALYSIS,
            supported_targets=[
                TargetType.PERSON,
                TargetType.EMAIL,
                TargetType.USERNAME,
                TargetType.DOMAIN,
                TargetType.COMPANY,
                TargetType.PHONE,
            ],
            requires_auth=False,
            requires_browser=True,
            enabled_by_default=True,
            priority=4,
            tags=["browser", "screenshot", "evidence", "web"],
        )

    async def run(self, target: str, target_type: TargetType, context: dict[str, Any]) -> ModuleResult:
        urls = self._collect_urls(context)
        if not urls:
            return ModuleResult(
                success=True,
                data={"screenshots": [], "total_urls_considered": 0, "total_snapshots": 0},
                warnings=["No discovered URLs available for screenshot capture"],
            )

        max_urls = max(1, int(get_module_setting("web", "web_snapshot", "max_urls", 5) or 5))
        selected = urls[:max_urls]

        from app.engine.browser import BrowserFactory

        factory = await BrowserFactory.create()
        screenshots: list[dict[str, Any]] = []
        warnings: list[str] = []

        for item in selected:
            page = None
            url = item["url"]
            try:
                page = await factory.new_page()
                await factory.human_goto(page, url)
                screenshot_path = self._build_screenshot_path(context, url, len(screenshots))
                await factory.take_screenshot(page, str(screenshot_path))
                title = ""
                try:
                    title = await page.title()
                except Exception:
                    title = ""
                screenshots.append(
                    {
                        "url": url,
                        "title": title or item.get("title", ""),
                        "source_module": item.get("source_module", ""),
                        "screenshot_path": str(screenshot_path),
                    }
                )
            except Exception as exc:
                logger.debug("web_snapshot_failed", url=url, error=str(exc))
                warnings.append(f"Screenshot failed for {url}: {exc}")
            finally:
                if page is not None:
                    try:
                        await factory.close_page(page, save_session=False)
                    except Exception:
                        pass

        return ModuleResult(
            success=True,
            data={
                "screenshots": screenshots,
                "total_urls_considered": len(urls),
                "total_snapshots": len(screenshots),
            },
            warnings=warnings,
        )

    @staticmethod
    def _collect_urls(context: dict[str, Any]) -> list[dict[str, Any]]:
        candidates: list[dict[str, Any]] = []
        seen: set[str] = set()

        def add(url: str, title: str = "", source_module: str = "") -> None:
            normalized = str(url).strip()
            if not normalized or normalized in seen:
                return
            parsed = urlparse(normalized)
            if parsed.scheme not in {"http", "https"}:
                return
            seen.add(normalized)
            candidates.append(
                {
                    "url": normalized,
                    "title": str(title).strip(),
                    "source_module": source_module,
                }
            )

        for item in context.get("discovered_urls", []) or []:
            if isinstance(item, dict):
                add(item.get("url", ""), item.get("title", ""), item.get("source_module", "context"))
            elif isinstance(item, str):
                add(item, "", "context")

        for key, source_module in (
            ("discovered_linkedin_profiles", "linkedin_profile"),
            ("discovered_instagram_profiles", "instagram_profile"),
        ):
            for item in context.get(key, []) or []:
                if isinstance(item, dict):
                    add(item.get("url", ""), item.get("slug") or item.get("username") or "", source_module)
                elif isinstance(item, str):
                    add(item, "", source_module)

        return candidates

    @staticmethod
    def _build_screenshot_path(context: dict[str, Any], url: str, index: int) -> Path:
        request_id = str(context.get("request_id", "adhoc"))
        screenshots_dir = Path(settings.data_dir) / "requests" / request_id / "screenshots"
        screenshots_dir.mkdir(parents=True, exist_ok=True)
        parsed = urlparse(url)
        slug = parsed.netloc.replace(".", "_")
        path_tail = "_".join(part for part in parsed.path.split("/") if part)[:60] or "root"
        return screenshots_dir / f"snapshot_{index:02d}_{slug}_{path_tail}.png"
