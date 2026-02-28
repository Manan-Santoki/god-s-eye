"""
AI Vision Analyzer — extract intelligence from screenshots and images.

Reads screenshots captured by web_snapshot, linkedin_scraper, instagram_scraper
and image URLs discovered by serpapi_search / image_downloader.

Sends each image to an OpenRouter vision model (e.g. claude-3-5-sonnet,
gpt-4-vision-preview) and extracts structured OSINT data:
  - Names, usernames, email addresses visible in the image
  - Profile bio / headline text
  - Location, employer, education clues
  - Social handles and URLs visible on-screen
  - Any PII or sensitive text that could identify the target

Requires: OPENROUTER_API_KEY  (or ANTHROPIC_API_KEY / OPENAI_API_KEY as fallback)
Phase:    IMAGE_PROCESSING (5)
"""

from __future__ import annotations

import asyncio
import base64
import json
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import aiohttp

from app.core.config import get_module_setting, settings
from app.core.constants import ModulePhase, TargetType
from app.core.logging import get_logger
from app.modules.base import BaseModule, ModuleMetadata, ModuleResult

logger = get_logger(__name__)

_VISION_PROMPT = """You are an expert OSINT analyst. Carefully examine this image and extract all intelligence useful for identifying the target person or entity.

Extract and return a JSON object with these fields (omit fields if not present):
{
  "names": ["full names visible"],
  "usernames": ["@handles or usernames"],
  "emails": ["email addresses"],
  "phones": ["phone numbers"],
  "locations": ["cities, countries, addresses"],
  "employers": ["company or organization names"],
  "job_titles": ["job titles or roles"],
  "education": ["schools or degrees"],
  "bio_text": "verbatim bio or headline text",
  "social_links": ["any URLs or social media links visible"],
  "profile_photo_description": "brief description of any person's appearance",
  "platform": "which platform this appears to be (LinkedIn, Instagram, GitHub, etc.)",
  "visible_content_summary": "brief summary of all useful information visible",
  "confidence": "high|medium|low"
}

Be thorough. Include anything that could help identify or locate the subject.
Return ONLY the JSON object, no markdown, no explanation."""


class AIVisionAnalyzerModule(BaseModule):
    """Extract intelligence from screenshots and images using a vision model."""

    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            name="ai_vision_analyzer",
            display_name="AI Vision Analyzer",
            description=(
                "Uses an OpenRouter vision model to extract names, usernames, "
                "emails, locations, and other OSINT data from captured screenshots "
                "and discovered profile images."
            ),
            phase=ModulePhase.IMAGE_PROCESSING,
            supported_targets=[
                TargetType.PERSON,
                TargetType.EMAIL,
                TargetType.USERNAME,
                TargetType.DOMAIN,
                TargetType.COMPANY,
                TargetType.PHONE,
            ],
            requires_auth=False,
            enabled_by_default=True,
            priority=2,
            tags=["ai", "vision", "ocr", "image", "screenshot", "openrouter"],
        )

    async def validate(self, target: str, target_type: TargetType, **kwargs: Any) -> bool:
        return bool(self._resolve_api_key())

    async def run(
        self,
        target: str,
        target_type: TargetType,
        context: dict[str, Any],
        **kwargs: Any,
    ) -> ModuleResult:
        if not settings.enable_ai_vision:
            return ModuleResult(
                success=True,
                data={"analyses": [], "total_images": 0},
                warnings=["AI vision disabled (enable_ai_vision=false)"],
            )

        api_key = self._resolve_api_key()
        if not api_key:
            return ModuleResult(
                success=False,
                data={"analyses": [], "total_images": 0},
                errors=["No vision-capable API key configured (OPENROUTER_API_KEY, ANTHROPIC_API_KEY, or OPENAI_API_KEY)"],
            )

        images = self._collect_images(context)
        if not images:
            return ModuleResult(
                success=True,
                data={"analyses": [], "total_images": 0},
                warnings=["No screenshots or images found in scan context for analysis"],
            )

        max_images = max(1, int(get_module_setting("visual", "ai_vision_analyzer", "max_images", 10) or 10))
        selected = images[:max_images]

        start = time.monotonic()
        analyses: list[dict[str, Any]] = []
        errors: list[str] = []
        warnings: list[str] = []

        semaphore = asyncio.Semaphore(3)
        tasks = [self._analyze_image(api_key, item, semaphore) for item in selected]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for item, result in zip(selected, results):
            if isinstance(result, Exception):
                errors.append(f"Vision analysis failed for {item.get('url', item.get('path', '?'))}: {result}")
            elif result is not None:
                analyses.append(result)

        # Flatten discovered entities from all analyses
        discovered_names: list[str] = []
        discovered_usernames: list[str] = []
        discovered_emails: list[str] = []
        discovered_phones: list[str] = []
        discovered_locations: list[str] = []

        for analysis in analyses:
            extracted = analysis.get("extracted", {})
            if not isinstance(extracted, dict):
                continue
            for v in extracted.get("names", []) or []:
                if v and v not in discovered_names:
                    discovered_names.append(v)
            for v in extracted.get("usernames", []) or []:
                if v and v not in discovered_usernames:
                    discovered_usernames.append(v.lstrip("@"))
            for v in extracted.get("emails", []) or []:
                if v and v not in discovered_emails:
                    discovered_emails.append(v)
            for v in extracted.get("phones", []) or []:
                if v and v not in discovered_phones:
                    discovered_phones.append(v)
            for v in extracted.get("locations", []) or []:
                if v and v not in discovered_locations:
                    discovered_locations.append(v)

        elapsed = int((time.monotonic() - start) * 1000)
        logger.info(
            "ai_vision_complete",
            target=target,
            images_analyzed=len(analyses),
            names_found=len(discovered_names),
            emails_found=len(discovered_emails),
        )

        return ModuleResult(
            success=True,
            module_name=self.metadata().name,
            target=target,
            execution_time_ms=elapsed,
            findings_count=len(analyses),
            data={
                "total_images": len(selected),
                "analyses": analyses,
                "discovered_names": discovered_names,
                "discovered_usernames": discovered_usernames,
                "discovered_emails": discovered_emails,
                "discovered_phones": discovered_phones,
                "discovered_locations": discovered_locations,
            },
            errors=errors,
            warnings=warnings,
        )

    # ── Image collection ──────────────────────────────────────────────────────

    def _collect_images(self, context: dict[str, Any]) -> list[dict[str, Any]]:
        """Gather all images and screenshots from the scan context."""
        images: list[dict[str, Any]] = []
        seen: set[str] = set()

        def add_path(path: str, source: str, url: str = "") -> None:
            key = path or url
            if not key or key in seen:
                return
            seen.add(key)
            images.append({"path": path, "url": url, "source": source})

        def add_url(url: str, source: str) -> None:
            if not url or url in seen:
                return
            try:
                parsed = urlparse(url)
                if parsed.scheme not in {"http", "https"}:
                    return
            except Exception:
                return
            seen.add(url)
            images.append({"path": "", "url": url, "source": source})

        module_results = context.get("module_results", {})

        # Screenshots from web_snapshot
        web_snap = module_results.get("web_snapshot", {})
        for shot in (web_snap.get("screenshots") or []):
            if isinstance(shot, dict):
                add_path(shot.get("screenshot_path", ""), "web_snapshot", shot.get("url", ""))

        # Screenshots from linkedin_scraper
        li = module_results.get("linkedin_scraper", {})
        for shot in (li.get("screenshots") or []):
            if isinstance(shot, dict):
                add_path(shot.get("path", "") or shot.get("screenshot_path", ""), "linkedin_scraper")
        if li.get("screenshot_path"):
            add_path(li["screenshot_path"], "linkedin_scraper")
        # LinkedIn profiles list may contain individual screenshot_path fields
        for profile in (li.get("profiles") or []):
            if isinstance(profile, dict) and profile.get("screenshot_path"):
                add_path(profile["screenshot_path"], "linkedin_scraper", profile.get("profile_url", ""))

        # Screenshots from instagram_scraper
        ig = module_results.get("instagram_scraper", {})
        for shot in (ig.get("screenshots") or []):
            if isinstance(shot, dict):
                add_path(shot.get("path", "") or shot.get("screenshot_path", ""), "instagram_scraper")
        if ig.get("screenshot_path"):
            add_path(ig["screenshot_path"], "instagram_scraper")

        # Profile images downloaded by image_downloader
        img_dl = module_results.get("image_downloader", {})
        for img in (img_dl.get("downloaded_images") or []):
            if isinstance(img, dict):
                add_path(img.get("local_path", ""), "image_downloader", img.get("url", ""))
            elif isinstance(img, str):
                add_path(img, "image_downloader")

        # Image URLs from SerpAPI image search (use URL directly for vision)
        serp = module_results.get("serpapi_search", {})
        for img in (serp.get("image_search_results") or [])[:5]:
            if isinstance(img, dict):
                url = img.get("thumbnail") or img.get("original") or ""
                add_url(url, "serpapi_image_search")

        # Images in discovered_image_urls context key
        for item in (context.get("discovered_image_urls") or []):
            if isinstance(item, dict):
                add_url(item.get("url", ""), item.get("platform", "discovered"))
            elif isinstance(item, str):
                add_url(item, "discovered")

        # Screenshots directory scan (belt-and-suspenders)
        request_id = str(context.get("request_id", "")).strip()
        if request_id:
            screenshots_dir = Path(settings.data_dir) / "requests" / request_id / "screenshots"
            if screenshots_dir.exists():
                for png_file in sorted(screenshots_dir.glob("*.png"))[:10]:
                    add_path(str(png_file), "screenshots_dir")

        return images

    # ── Vision API ────────────────────────────────────────────────────────────

    async def _analyze_image(
        self,
        api_key: str,
        item: dict[str, Any],
        semaphore: asyncio.Semaphore,
    ) -> dict[str, Any] | None:
        async with semaphore:
            image_path = item.get("path", "")
            image_url = item.get("url", "")
            source = item.get("source", "unknown")

            try:
                image_content = await self._build_image_content(image_path, image_url)
                if image_content is None:
                    return None

                extracted = await self._call_vision_api(api_key, image_content)
                return {
                    "source": source,
                    "path": image_path,
                    "url": image_url,
                    "extracted": extracted,
                    "success": True,
                }
            except Exception as exc:
                logger.debug("ai_vision_image_failed", source=source, error=str(exc))
                return {
                    "source": source,
                    "path": image_path,
                    "url": image_url,
                    "extracted": {},
                    "success": False,
                    "error": str(exc)[:200],
                }

    @staticmethod
    async def _build_image_content(path: str, url: str) -> dict[str, Any] | None:
        """Build the OpenAI-compatible image content block."""
        if path and Path(path).exists():
            try:
                data = Path(path).read_bytes()
                if not data:
                    return None
                suffix = Path(path).suffix.lower()
                mime = {".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg",
                        ".gif": "image/gif", ".webp": "image/webp"}.get(suffix, "image/png")
                b64 = base64.b64encode(data).decode()
                return {"type": "image_url", "image_url": {"url": f"data:{mime};base64,{b64}"}}
            except Exception:
                pass

        if url and url.startswith("http"):
            try:
                async with aiohttp.ClientSession(
                    timeout=aiohttp.ClientTimeout(total=15),
                    headers={"User-Agent": "GOD_EYE/1.0"},
                ) as session:
                    async with session.get(url) as resp:
                        if resp.status != 200:
                            return None
                        content_type = resp.headers.get("Content-Type", "image/jpeg")
                        data = await resp.read()
                        if not data or len(data) < 100:
                            return None
                        b64 = base64.b64encode(data).decode()
                        mime = content_type.split(";")[0].strip() or "image/jpeg"
                        return {"type": "image_url", "image_url": {"url": f"data:{mime};base64,{b64}"}}
            except Exception:
                # Fall back to passing the URL directly
                if url.startswith("http"):
                    return {"type": "image_url", "image_url": {"url": url}}

        return None

    async def _call_vision_api(self, api_key: str, image_content: dict[str, Any]) -> dict[str, Any]:
        """Call the vision model via OpenRouter (or direct Anthropic/OpenAI API)."""
        provider = settings.ai_provider.lower()
        model = self._resolve_vision_model()

        messages = [
            {
                "role": "user",
                "content": [
                    image_content,
                    {"type": "text", "text": _VISION_PROMPT},
                ],
            }
        ]

        if provider in ("openrouter", "openai"):
            return await self._call_openai_compat(api_key, model, messages, provider)
        if provider == "anthropic":
            return await self._call_anthropic(api_key, image_content)

        return await self._call_openai_compat(api_key, model, messages, "openrouter")

    async def _call_openai_compat(
        self,
        api_key: str,
        model: str,
        messages: list[dict[str, Any]],
        provider: str,
    ) -> dict[str, Any]:
        if provider == "openrouter":
            base_url = str(settings.openrouter_base_url).rstrip("/")
            headers = {
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            }
            if settings.openrouter_site_url:
                headers["HTTP-Referer"] = str(settings.openrouter_site_url)
            if settings.openrouter_app_name:
                headers["X-Title"] = str(settings.openrouter_app_name)
        else:
            base_url = "https://api.openai.com/v1"
            headers = {
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            }

        payload = {
            "model": model,
            "messages": messages,
            "max_tokens": 1000,
            "temperature": 0.1,
        }

        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=60),
            headers=headers,
        ) as session:
            async with session.post(f"{base_url}/chat/completions", json=payload) as resp:
                if resp.status not in {200, 201}:
                    text = await resp.text()
                    raise ValueError(f"Vision API error {resp.status}: {text[:300]}")
                data = await resp.json(content_type=None)

        content = ""
        try:
            content = data["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError):
            pass

        return self._parse_vision_response(content)

    async def _call_anthropic(self, api_key: str, image_content: dict[str, Any]) -> dict[str, Any]:
        """Call Anthropic Messages API directly with vision."""
        # Convert OpenAI image format to Anthropic format
        img_url = image_content.get("image_url", {}).get("url", "")
        if img_url.startswith("data:"):
            mime, b64data = img_url.split(";base64,", 1)
            mime = mime.replace("data:", "")
            anthropic_image = {
                "type": "image",
                "source": {"type": "base64", "media_type": mime, "data": b64data},
            }
        else:
            anthropic_image = {
                "type": "image",
                "source": {"type": "url", "url": img_url},
            }

        payload = {
            "model": "claude-3-5-sonnet-20241022",
            "max_tokens": 1000,
            "messages": [
                {
                    "role": "user",
                    "content": [
                        anthropic_image,
                        {"type": "text", "text": _VISION_PROMPT},
                    ],
                }
            ],
        }

        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=60),
            headers={
                "x-api-key": api_key,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
        ) as session:
            async with session.post("https://api.anthropic.com/v1/messages", json=payload) as resp:
                if resp.status not in {200, 201}:
                    text = await resp.text()
                    raise ValueError(f"Anthropic vision error {resp.status}: {text[:300]}")
                data = await resp.json(content_type=None)

        content = ""
        try:
            content = data["content"][0]["text"]
        except (KeyError, IndexError, TypeError):
            pass

        return self._parse_vision_response(content)

    @staticmethod
    def _parse_vision_response(content: str) -> dict[str, Any]:
        """Parse JSON from the vision model response."""
        if not content:
            return {}
        # Strip markdown code fences if present
        clean = content.strip()
        if clean.startswith("```"):
            lines = clean.split("\n")
            clean = "\n".join(lines[1:-1] if lines[-1].startswith("```") else lines[1:])

        try:
            parsed = json.loads(clean)
            if isinstance(parsed, dict):
                return parsed
        except (json.JSONDecodeError, ValueError):
            pass

        # Best-effort extraction if JSON parse fails
        return {"visible_content_summary": content[:500], "confidence": "low"}

    # ── Key resolution ────────────────────────────────────────────────────────

    def _resolve_api_key(self) -> str:
        """Return the best available API key for vision calls."""
        or_key = self._get_secret(settings.openrouter_api_key)
        if or_key:
            return or_key
        if settings.ai_provider == "anthropic":
            return self._get_secret(settings.anthropic_api_key) or ""
        if settings.ai_provider == "openai":
            return self._get_secret(settings.openai_api_key) or ""
        return ""

    def _resolve_vision_model(self) -> str:
        configured = get_module_setting("visual", "ai_vision_analyzer", "model", None)
        if configured:
            return str(configured)
        if settings.ai_provider == "openrouter":
            return settings.openrouter_vision_model or "anthropic/claude-3-5-sonnet"
        if settings.ai_provider == "openai":
            return "gpt-4o"
        return "anthropic/claude-3-5-sonnet"
