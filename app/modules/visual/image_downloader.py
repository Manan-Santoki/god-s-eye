"""
Image download and deduplication module.

Downloads images from URLs discovered during earlier scan phases (from
context["discovered_image_urls"]) with the following features:

  - Async concurrent download via aiohttp with asyncio.Semaphore(5)
  - MD5 hash-based exact deduplication (skip already-seen images)
  - Perceptual hash via imagehash library for visual similarity detection
  - Images saved to: data/requests/{request_id}/images/
  - Basic image metadata extraction with Pillow (width, height, format)

Each URL entry in context["discovered_image_urls"] should be a dict with
keys: url, platform, description (all optional except url).

Phase: IMAGE_PROCESSING (no API key required).
"""

from __future__ import annotations

import asyncio
import hashlib
import mimetypes
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import aiohttp

from app.core.config import settings
from app.core.constants import ModulePhase, TargetType
from app.core.exceptions import APIError, RateLimitError
from app.core.logging import get_logger
from app.modules.base import BaseModule, ModuleMetadata, ModuleResult

logger = get_logger(__name__)

# Lazy imports — may not be installed
try:
    from PIL import Image as PILImage
    _PILLOW_AVAILABLE = True
except ImportError:
    _PILLOW_AVAILABLE = False

try:
    import imagehash
    _IMAGEHASH_AVAILABLE = True
except ImportError:
    _IMAGEHASH_AVAILABLE = False

# Concurrent download semaphore limit
_DOWNLOAD_SEMAPHORE = 5

# Supported image MIME types for download
_ALLOWED_MIME_TYPES = frozenset({
    "image/jpeg", "image/png", "image/gif", "image/webp",
    "image/tiff", "image/bmp", "image/heic", "image/heif",
    "image/svg+xml",
})

# Maximum file size to download (20 MB)
_MAX_FILE_SIZE_BYTES = 20 * 1024 * 1024

# Supported image file extensions for filename sanitisation
_IMAGE_EXTENSIONS = frozenset({
    ".jpg", ".jpeg", ".png", ".gif", ".webp", ".tiff", ".tif",
    ".bmp", ".heic", ".heif", ".svg",
})

_USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)


class ImageDownloaderModule(BaseModule):
    """
    Async image downloader with MD5 + perceptual hash deduplication.

    Downloads images from context["discovered_image_urls"], deduplicates by
    MD5 hash, computes perceptual hashes for visual similarity, saves to the
    session's images directory, and extracts Pillow metadata.
    """

    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            name="image_downloader",
            display_name="Image Downloader & Deduplicator",
            description=(
                "Downloads images from discovered URLs with concurrent async I/O. "
                "Deduplicates via MD5 hash, computes perceptual hashes for visual "
                "similarity, and saves to the session images directory."
            ),
            phase=ModulePhase.IMAGE_PROCESSING,
            supported_targets=[
                TargetType.PERSON,
                TargetType.USERNAME,
                TargetType.EMAIL,
                TargetType.DOMAIN,
                TargetType.COMPANY,
            ],
            requires_auth=False,
            rate_limit_rpm=60,
            timeout_seconds=120,
            enabled_by_default=True,
            tags=["image", "download", "deduplication", "perceptual-hash", "no-key"],
        )

    async def run(
        self,
        target: str,
        target_type: TargetType,
        context: dict[str, Any],
    ) -> ModuleResult:
        # Collect image URL entries from context
        raw_urls = context.get("discovered_image_urls", [])
        if not raw_urls:
            return ModuleResult(
                success=True,
                data={
                    "downloaded": [],
                    "skipped_duplicates": 0,
                    "total_bytes_downloaded": 0,
                },
                warnings=["No image URLs found in context['discovered_image_urls']"],
            )

        url_entries = self._normalise_url_entries(raw_urls)

        # Determine output directory using request_id from context
        request_id = context.get("request_id", "default")
        images_dir = settings.data_dir / "requests" / str(request_id) / "images"
        images_dir.mkdir(parents=True, exist_ok=True)

        start = time.monotonic()
        warnings: list[str] = []
        errors: list[str] = []

        logger.info(
            "image_downloader_start",
            url_count=len(url_entries),
            output_dir=str(images_dir),
        )

        # Shared state for deduplication across concurrent downloads
        seen_hashes: set[str] = set()
        semaphore = asyncio.Semaphore(_DOWNLOAD_SEMAPHORE)

        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(
                total=60,
                connect=10,
                sock_read=30,
            ),
            headers={"User-Agent": _USER_AGENT},
        ) as session:
            tasks = [
                self._download_image(
                    session=session,
                    entry=entry,
                    images_dir=images_dir,
                    seen_hashes=seen_hashes,
                    semaphore=semaphore,
                    warnings=warnings,
                    errors=errors,
                )
                for entry in url_entries
            ]
            results = await asyncio.gather(*tasks, return_exceptions=True)

        # Separate successful downloads from duplicates and errors
        downloaded: list[dict[str, Any]] = []
        skipped_duplicates = 0
        total_bytes = 0

        for result in results:
            if isinstance(result, Exception):
                errors.append(f"Download task failed unexpectedly: {result}")
            elif result is None:
                # Skipped duplicate
                skipped_duplicates += 1
            elif isinstance(result, dict):
                downloaded.append(result)
                total_bytes += result.get("file_size_bytes", 0)

        elapsed_ms = int((time.monotonic() - start) * 1000)
        logger.info(
            "image_downloader_complete",
            downloaded=len(downloaded),
            skipped_duplicates=skipped_duplicates,
            total_bytes=total_bytes,
            elapsed_ms=elapsed_ms,
        )

        # Populate context for downstream modules (EXIF extractor, face recognition)
        context["discovered_images"] = [
            {"file_path": d["file_path"], "url": d["original_url"], "platform": d["platform"]}
            for d in downloaded
        ]

        return ModuleResult(
            success=True,
            data={
                "downloaded": downloaded,
                "skipped_duplicates": skipped_duplicates,
                "total_bytes_downloaded": total_bytes,
            },
            errors=errors,
            warnings=warnings,
        )

    # ── Download logic ────────────────────────────────────────────────────────

    async def _download_image(
        self,
        session: aiohttp.ClientSession,
        entry: dict[str, Any],
        images_dir: Path,
        seen_hashes: set[str],
        semaphore: asyncio.Semaphore,
        warnings: list[str],
        errors: list[str],
    ) -> dict[str, Any] | None:
        """
        Download a single image with deduplication and metadata extraction.

        Args:
            session: Shared aiohttp session.
            entry: Dict with "url", "platform", "description" keys.
            images_dir: Directory to save the downloaded image.
            seen_hashes: Shared set of MD5 hashes for deduplication.
            semaphore: Semaphore limiting concurrent downloads to 5.
            warnings / errors: Mutable lists for accumulating messages.

        Returns:
            Download result dict, None (duplicate), or raises on hard error.
        """
        url = entry.get("url", "")
        platform = entry.get("platform", "unknown")
        description = entry.get("description", "")

        if not url:
            return None

        async with semaphore:
            try:
                logger.debug("image_download_start", url=url[:80])

                async with session.get(url, allow_redirects=True) as resp:
                    if resp.status == 404:
                        warnings.append(f"Image not found (404): {url[:80]}")
                        return None

                    if resp.status == 429:
                        warnings.append(f"Rate limited downloading: {url[:80]}")
                        return None

                    if resp.status != 200:
                        warnings.append(
                            f"HTTP {resp.status} downloading: {url[:80]}"
                        )
                        return None

                    # Check content type
                    content_type = resp.headers.get("Content-Type", "").split(";")[0].strip()
                    if (
                        content_type
                        and content_type not in _ALLOWED_MIME_TYPES
                        and not content_type.startswith("image/")
                    ):
                        warnings.append(
                            f"Skipping non-image content-type '{content_type}': {url[:80]}"
                        )
                        return None

                    # Check content length header
                    content_length = int(resp.headers.get("Content-Length", 0) or 0)
                    if content_length > _MAX_FILE_SIZE_BYTES:
                        warnings.append(
                            f"Image too large ({content_length / 1024 / 1024:.1f} MB): {url[:80]}"
                        )
                        return None

                    # Stream download and compute MD5 incrementally
                    raw_bytes = b""
                    md5_hash = hashlib.md5()
                    total_bytes = 0

                    async for chunk in resp.content.iter_chunked(8192):
                        raw_bytes += chunk
                        md5_hash.update(chunk)
                        total_bytes += len(chunk)
                        if total_bytes > _MAX_FILE_SIZE_BYTES:
                            warnings.append(f"Image exceeded size limit mid-download: {url[:80]}")
                            return None

                hash_md5 = md5_hash.hexdigest()

                # Deduplication check (thread-safe — asyncio single-threaded)
                if hash_md5 in seen_hashes:
                    logger.debug("image_duplicate_skipped", md5=hash_md5, url=url[:80])
                    return None
                seen_hashes.add(hash_md5)

            except asyncio.TimeoutError:
                warnings.append(f"Timeout downloading image: {url[:80]}")
                return None
            except aiohttp.ClientError as exc:
                warnings.append(f"Network error downloading {url[:80]}: {exc}")
                return None
            except Exception as exc:
                errors.append(f"Unexpected error downloading {url[:80]}: {exc}")
                return None

        # ── Save image to disk ────────────────────────────────────────────
        file_name = self._build_filename(url, hash_md5, content_type)
        file_path = images_dir / file_name

        try:
            file_path.write_bytes(raw_bytes)
        except OSError as exc:
            errors.append(f"Failed to save image to {file_path}: {exc}")
            return None

        logger.debug("image_saved", path=str(file_path), bytes=total_bytes)

        # ── Extract image metadata with Pillow ────────────────────────────
        width = height = 0
        img_format = ""
        hash_perceptual = ""

        if _PILLOW_AVAILABLE and raw_bytes:
            try:
                import io
                with PILImage.open(io.BytesIO(raw_bytes)) as img:
                    width = img.width
                    height = img.height
                    img_format = img.format or ""

                    # Compute perceptual hash for visual similarity
                    if _IMAGEHASH_AVAILABLE:
                        try:
                            phash = imagehash.phash(img)
                            hash_perceptual = str(phash)
                        except Exception:
                            hash_perceptual = ""
            except Exception as exc:
                logger.debug("pillow_metadata_failed", url=url[:80], error=str(exc))

        return {
            "file_path": str(file_path),
            "original_url": url,
            "platform": platform,
            "description": description,
            "hash_md5": hash_md5,
            "hash_perceptual": hash_perceptual,
            "width": width,
            "height": height,
            "format": img_format,
            "file_size_bytes": total_bytes,
            "content_type": content_type,
        }

    # ── Utilities ─────────────────────────────────────────────────────────────

    @staticmethod
    def _normalise_url_entries(raw: list[Any]) -> list[dict[str, Any]]:
        """
        Normalise mixed URL entry formats to canonical dicts.

        Accepts strings (plain URLs) or dicts with url/platform/description keys.
        """
        entries: list[dict[str, Any]] = []
        for item in raw:
            if isinstance(item, str):
                entries.append({"url": item, "platform": "unknown", "description": ""})
            elif isinstance(item, dict) and item.get("url"):
                entries.append({
                    "url": item["url"],
                    "platform": item.get("platform") or "unknown",
                    "description": item.get("description") or "",
                })
        return entries

    @staticmethod
    def _build_filename(url: str, md5_hash: str, content_type: str) -> str:
        """
        Build a safe, unique filename for a downloaded image.

        Uses the last 12 chars of the MD5 hash as a suffix to ensure uniqueness.
        Falls back to .jpg extension when content-type is unknown.
        """
        # Try to infer extension from URL path
        try:
            path = urlparse(url).path
            suffix = Path(path).suffix.lower()
            if suffix not in _IMAGE_EXTENSIONS:
                suffix = ""
        except Exception:
            suffix = ""

        # Fall back to content-type extension
        if not suffix and content_type:
            guessed = mimetypes.guess_extension(content_type)
            if guessed:
                suffix = guessed
                # Normalise common aliases
                if suffix == ".jpe":
                    suffix = ".jpg"

        if not suffix:
            suffix = ".jpg"

        # Use first 16 chars of MD5 + suffix for unique, short filenames
        return f"{md5_hash[:16]}{suffix}"
