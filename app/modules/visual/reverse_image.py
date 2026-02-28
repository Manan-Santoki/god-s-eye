"""
Reverse image search using multiple engines via Playwright.

Engines:
1. Google Images — upload image, parse results
2. Yandex Images — best for face matching
3. TinEye API — exact match search (paid)
"""

import asyncio
import time
from pathlib import Path
from typing import Any

import aiohttp

from app.core.config import settings
from app.core.constants import ModulePhase, TargetType
from app.core.logging import get_logger
from app.modules.base import BaseModule, ModuleMetadata, ModuleResult

logger = get_logger(__name__)


class ReverseImageSearch(BaseModule):
    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            name="reverse_image_search",
            display_name="Reverse Image Search",
            description="Find where images appear across the web using Google, Yandex, and TinEye",
            supported_targets=[TargetType.PERSON],
            phase=ModulePhase.IMAGE_PROCESSING,
            requires_browser=True,
            requires_proxy=True,
            rate_limit_rpm=4,
            timeout_seconds=120,
            enabled_by_default=True,
        )

    async def validate(self, target: str, target_type: TargetType) -> bool:
        return target_type == TargetType.PERSON

    async def run(self, target: str, target_type: TargetType, context: dict) -> ModuleResult:
        start = time.monotonic()
        images = context.get("discovered_images", [])
        image_paths = self._collect_image_paths(images)

        if not image_paths:
            return ModuleResult(
                module_name=self.metadata().name,
                target=target,
                success=True,
                data={"message": "No images available for reverse search", "results": []},
            )

        # Use first 3 images for reverse search
        search_images = image_paths[:3]
        all_results: list[dict] = []

        for img_path in search_images:
            try:
                results = await asyncio.gather(
                    self._google_reverse(str(img_path)),
                    self._yandex_reverse(str(img_path)),
                    self._tineye_api(str(img_path)),
                    return_exceptions=True,
                )
                for engine_name, result in zip(
                    ["google", "yandex", "tineye"], results, strict=False
                ):
                    if isinstance(result, Exception):
                        logger.debug(f"reverse_search_{engine_name}_failed", error=str(result))
                    elif result:
                        all_results.extend(result)
            except Exception as e:
                logger.warning("reverse_image_error", error=str(e))

        elapsed = int((time.monotonic() - start) * 1000)
        return ModuleResult(
            module_name=self.metadata().name,
            target=target,
            success=True,
            data={
                "total_results": len(all_results),
                "results": all_results,
                "images_searched": len(search_images),
            },
            execution_time_ms=elapsed,
        )

    @staticmethod
    def _collect_image_paths(raw_images: list[Any]) -> list[Path]:
        """Resolve downloaded image entries into on-disk file paths."""
        paths: list[Path] = []
        for item in raw_images:
            if isinstance(item, str):
                path = Path(item)
            elif isinstance(item, dict):
                file_path = item.get("file_path") or item.get("path") or ""
                path = Path(str(file_path)) if file_path else None  # type: ignore[assignment]
            elif isinstance(item, Path):
                path = item
            else:
                continue

            if path and path.exists():
                paths.append(path)

        return paths

    async def _google_reverse(self, image_path: str) -> list[dict]:
        """Upload image to Google Images and parse results."""
        results = []
        try:
            from app.engine.browser import BrowserFactory

            factory = await BrowserFactory.create()
            page = await factory.new_page()

            await factory.human_goto(page, "https://images.google.com")

            # Click camera icon
            camera_btn = page.locator("[aria-label='Search by image']").first
            if await camera_btn.count():
                await camera_btn.click()
                await asyncio.sleep(1)

            # Upload file
            upload_input = page.locator("input[type='file']").first
            if await upload_input.count():
                await upload_input.set_input_files(image_path)
                await asyncio.sleep(3)

            # Parse results
            result_elements = await page.locator("div.g h3").all()
            for el in result_elements[:5]:
                text = await el.inner_text()
                parent = el.locator("..")
                link = await parent.locator("a").first.get_attribute("href")
                results.append(
                    {
                        "engine": "google",
                        "title": text,
                        "url": link,
                        "image_path": image_path,
                    }
                )
            await page.close()
        except Exception as e:
            logger.debug("google_reverse_error", error=str(e))
        return results

    async def _yandex_reverse(self, image_path: str) -> list[dict]:
        """Upload image to Yandex Images and parse results."""
        results = []
        try:
            from app.engine.browser import BrowserFactory

            factory = await BrowserFactory.create()
            page = await factory.new_page()

            await factory.human_goto(page, "https://yandex.com/images/")

            # Click camera/search-by-image button
            camera = page.locator(".cbir-button__icon, [class*='camera']").first
            if await camera.count():
                await camera.click()
                await asyncio.sleep(1)

            # Upload file
            upload_input = page.locator("input[type='file']").first
            if await upload_input.count():
                await upload_input.set_input_files(image_path)
                await asyncio.sleep(4)

            # Parse results
            result_els = await page.locator(".serp-item__title").all()
            for el in result_els[:5]:
                text = await el.inner_text()
                link_el = el.locator("a").first
                href = await link_el.get_attribute("href") if await link_el.count() else None
                results.append(
                    {
                        "engine": "yandex",
                        "title": text,
                        "url": href,
                        "image_path": image_path,
                    }
                )
            await page.close()
        except Exception as e:
            logger.debug("yandex_reverse_error", error=str(e))
        return results

    async def _tineye_api(self, image_path: str) -> list[dict]:
        """TinEye API reverse image search."""
        if not settings.has_api_key("tineye_api_key"):
            return []

        results = []
        try:
            with open(image_path, "rb") as f:
                image_data = f.read()

            async with aiohttp.ClientSession() as session:
                form = aiohttp.FormData()
                form.add_field("image", image_data, filename=Path(image_path).name)
                form.add_field("api_key", settings.tineye_api_key.get_secret_value())

                async with session.post(
                    "https://api.tineye.com/rest/search/",
                    data=form,
                    timeout=aiohttp.ClientTimeout(total=30),
                ) as resp:
                    if resp.status != 200:
                        return []
                    data = await resp.json()

            for match in data.get("results", {}).get("matches", [])[:5]:
                results.append(
                    {
                        "engine": "tineye",
                        "title": match.get("domain", ""),
                        "url": match.get("backlink"),
                        "image_url": match.get("image_url"),
                        "score": match.get("score"),
                        "image_path": image_path,
                    }
                )
        except Exception as e:
            logger.debug("tineye_api_error", error=str(e))

        return results
