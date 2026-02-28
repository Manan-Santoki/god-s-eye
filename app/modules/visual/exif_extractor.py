"""
EXIF metadata extractor module.

Extracts EXIF metadata from all image files discovered during the scan
(listed in context["discovered_images"]). Uses:
  - exifread library for full EXIF tag extraction
  - Pillow (PIL) for supplementary metadata (format, dimensions, mode)
  - geopy Nominatim for reverse geocoding GPS coordinates to a street address

For each image the module produces: camera make/model, capture datetime,
GPS coordinates (decimal degrees), GPS altitude, software, image dimensions,
orientation, flash, ISO, focal length, aperture, exposure time, and a
reverse-geocoded address string.

Phase: IMAGE_PROCESSING (no API key required).
"""

from __future__ import annotations

import asyncio
import time
from pathlib import Path
from typing import Any

from app.core.config import settings
from app.core.constants import ModulePhase, TargetType
from app.core.exceptions import APIError, RateLimitError
from app.core.logging import get_logger
from app.modules.base import BaseModule, ModuleMetadata, ModuleResult

logger = get_logger(__name__)

# Lazy imports — these libraries may not be installed
try:
    import exifread
    _EXIFREAD_AVAILABLE = True
except ImportError:
    _EXIFREAD_AVAILABLE = False

try:
    from PIL import Image as PILImage
    _PILLOW_AVAILABLE = True
except ImportError:
    _PILLOW_AVAILABLE = False

try:
    from geopy.geocoders import Nominatim
    from geopy.exc import GeocoderTimedOut, GeocoderServiceError
    _GEOPY_AVAILABLE = True
except ImportError:
    _GEOPY_AVAILABLE = False


class EXIFExtractorModule(BaseModule):
    """
    EXIF metadata extraction and GPS reverse-geocoding module.

    Processes images from context["discovered_images"] (list of file path
    strings or dicts with "file_path" key) and extracts rich EXIF metadata.
    GPS coordinates are converted from DMS IFDRational format to decimal
    degrees and reverse-geocoded to a street address via Nominatim.
    """

    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            name="exif_extractor",
            display_name="EXIF Metadata Extractor",
            description=(
                "Extracts EXIF metadata (camera, GPS, timestamps, settings) from "
                "discovered images. Reverse-geocodes GPS coordinates to street "
                "addresses using Nominatim. No API key required."
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
            timeout_seconds=60,
            enabled_by_default=True,
            tags=["image", "exif", "gps", "metadata", "no-key", "geolocation"],
        )

    async def run(
        self,
        target: str,
        target_type: TargetType,
        context: dict[str, Any],
    ) -> ModuleResult:
        missing_libs: list[str] = []
        if not _EXIFREAD_AVAILABLE:
            missing_libs.append("exifread")
        if not _PILLOW_AVAILABLE:
            missing_libs.append("Pillow")

        if missing_libs:
            return ModuleResult.fail(
                f"Required libraries not installed: {', '.join(missing_libs)}. "
                f"Run: pip install {' '.join(missing_libs)}"
            )

        # Collect image paths from context
        raw_images = context.get("discovered_images", [])
        image_paths = self._collect_image_paths(raw_images)

        if not image_paths:
            return ModuleResult(
                success=True,
                data={
                    "images_processed": [],
                    "images_with_gps": [],
                    "total_processed": 0,
                },
                warnings=["No images found in context['discovered_images']"],
            )

        start = time.monotonic()
        warnings: list[str] = []
        errors: list[str] = []

        logger.info("exif_extractor_start", image_count=len(image_paths))

        # Setup Nominatim geocoder (if available)
        geocoder = None
        if _GEOPY_AVAILABLE:
            try:
                geocoder = Nominatim(user_agent="god_eye/1.0")
            except Exception as exc:
                warnings.append(f"Nominatim geocoder init failed: {exc}")

        # Process all images in a thread pool (I/O + CPU bound operations)
        loop = asyncio.get_event_loop()
        tasks = [
            loop.run_in_executor(
                None, self._process_image, path, geocoder
            )
            for path in image_paths
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Collect results
        images_processed: list[dict[str, Any]] = []
        images_with_gps: list[dict[str, Any]] = []

        for path, result in zip(image_paths, results):
            if isinstance(result, Exception):
                errors.append(f"EXIF extraction failed for {path}: {result}")
                images_processed.append({
                    "file_path": str(path),
                    "has_exif": False,
                    "error": str(result),
                    "metadata": {},
                })
            else:
                images_processed.append(result)
                if result.get("metadata", {}).get("gps_latitude") is not None:
                    images_with_gps.append(result)

        elapsed_ms = int((time.monotonic() - start) * 1000)
        logger.info(
            "exif_extractor_complete",
            total=len(images_processed),
            with_gps=len(images_with_gps),
            elapsed_ms=elapsed_ms,
        )

        return ModuleResult(
            success=True,
            data={
                "images_processed": images_processed,
                "images_with_gps": images_with_gps,
                "total_processed": len(images_processed),
            },
            errors=errors,
            warnings=warnings,
        )

    # ── Core processing ───────────────────────────────────────────────────────

    def _process_image(
        self,
        file_path: Path,
        geocoder: Any,
    ) -> dict[str, Any]:
        """
        Extract EXIF metadata from a single image file.

        Runs synchronously (called via run_in_executor from the async runner).
        Uses exifread for EXIF tags and Pillow for basic image properties.

        Args:
            file_path: Absolute path to the image file.
            geocoder: Nominatim geocoder instance or None.

        Returns:
            Dict with file_path, has_exif, and metadata sub-dict.
        """
        result: dict[str, Any] = {
            "file_path": str(file_path),
            "has_exif": False,
            "metadata": {},
        }

        if not file_path.exists():
            result["error"] = "File not found"
            return result

        metadata: dict[str, Any] = {}

        # ── Pillow basic metadata ──────────────────────────────────────────
        if _PILLOW_AVAILABLE:
            try:
                with PILImage.open(file_path) as img:
                    metadata["image_width"] = img.width
                    metadata["image_height"] = img.height
                    metadata["format"] = img.format or ""
                    metadata["mode"] = img.mode or ""
            except Exception as exc:
                logger.debug("pillow_open_failed", path=str(file_path), error=str(exc))

        # ── exifread EXIF extraction ───────────────────────────────────────
        try:
            with open(file_path, "rb") as f:
                tags = exifread.process_file(f, details=False, strict=False)
        except Exception as exc:
            logger.debug("exifread_failed", path=str(file_path), error=str(exc))
            result["metadata"] = metadata
            return result

        if not tags:
            result["metadata"] = metadata
            return result

        result["has_exif"] = True

        # ── Standard EXIF fields ──────────────────────────────────────────
        metadata["make"] = _tag_str(tags, "Image Make")
        metadata["model"] = _tag_str(tags, "Image Model")
        metadata["datetime_original"] = _tag_str(tags, "EXIF DateTimeOriginal")
        metadata["software"] = _tag_str(tags, "Image Software")
        metadata["orientation"] = _tag_str(tags, "Image Orientation")
        metadata["flash"] = _tag_str(tags, "EXIF Flash")
        metadata["iso_speed"] = _tag_int(tags, "EXIF ISOSpeedRatings")
        metadata["focal_length"] = _tag_rational(tags, "EXIF FocalLength")
        metadata["aperture"] = _tag_rational(tags, "EXIF FNumber")
        metadata["exposure_time"] = _tag_str(tags, "EXIF ExposureTime")
        metadata["gps_altitude"] = _tag_rational(tags, "GPS GPSAltitude")

        # Override image dimensions from EXIF if available
        if _tag_int(tags, "EXIF ExifImageWidth"):
            metadata["image_width"] = _tag_int(tags, "EXIF ExifImageWidth")
        if _tag_int(tags, "EXIF ExifImageLength"):
            metadata["image_height"] = _tag_int(tags, "EXIF ExifImageLength")

        # ── GPS coordinates ───────────────────────────────────────────────
        gps_lat = _extract_gps_decimal(
            tags,
            "GPS GPSLatitude",
            "GPS GPSLatitudeRef",
        )
        gps_lon = _extract_gps_decimal(
            tags,
            "GPS GPSLongitude",
            "GPS GPSLongitudeRef",
        )

        metadata["gps_latitude"] = gps_lat
        metadata["gps_longitude"] = gps_lon
        metadata["gps_address"] = ""

        # ── Reverse geocoding ─────────────────────────────────────────────
        if gps_lat is not None and gps_lon is not None and geocoder is not None:
            try:
                location = geocoder.reverse(
                    f"{gps_lat},{gps_lon}",
                    exactly_one=True,
                    language="en",
                    timeout=10,
                )
                if location:
                    metadata["gps_address"] = location.address or ""
                    logger.debug(
                        "gps_geocoded",
                        path=str(file_path),
                        lat=gps_lat,
                        lon=gps_lon,
                        address=metadata["gps_address"][:80],
                    )
            except Exception as exc:
                logger.debug(
                    "gps_geocode_failed",
                    path=str(file_path),
                    error=str(exc),
                )

        result["metadata"] = metadata
        return result

    # ── Utilities ─────────────────────────────────────────────────────────────

    @staticmethod
    def _collect_image_paths(raw: list[Any]) -> list[Path]:
        """
        Resolve image paths from various context formats.

        Accepts:
          - List of strings (file paths)
          - List of dicts with "file_path" key
          - List of dicts with "path" key
        """
        paths: list[Path] = []
        for item in raw:
            if isinstance(item, str):
                p = Path(item)
                if p.suffix.lower() in {
                    ".jpg", ".jpeg", ".png", ".tiff", ".tif",
                    ".heic", ".heif", ".webp", ".bmp", ".gif",
                }:
                    paths.append(p)
            elif isinstance(item, dict):
                path_str = item.get("file_path") or item.get("path") or ""
                if path_str:
                    p = Path(str(path_str))
                    if p.suffix.lower() in {
                        ".jpg", ".jpeg", ".png", ".tiff", ".tif",
                        ".heic", ".heif", ".webp", ".bmp", ".gif",
                    }:
                        paths.append(p)
            elif isinstance(item, Path):
                paths.append(item)
        return paths


# ── EXIF tag helper functions ─────────────────────────────────────────────────

def _tag_str(tags: dict[str, Any], key: str) -> str:
    """Extract an EXIF tag value as a plain string."""
    tag = tags.get(key)
    if tag is None:
        return ""
    return str(tag.values[0] if hasattr(tag, "values") and tag.values else tag).strip()


def _tag_int(tags: dict[str, Any], key: str) -> int | None:
    """Extract an EXIF tag value as an integer."""
    tag = tags.get(key)
    if tag is None:
        return None
    try:
        val = tag.values[0] if hasattr(tag, "values") and tag.values else tag
        return int(val)
    except (TypeError, ValueError, AttributeError):
        return None


def _tag_rational(tags: dict[str, Any], key: str) -> float | None:
    """Extract an EXIF rational tag value as a float."""
    tag = tags.get(key)
    if tag is None:
        return None
    try:
        val = tag.values[0] if hasattr(tag, "values") and tag.values else tag
        if hasattr(val, "num") and hasattr(val, "den") and val.den != 0:
            return val.num / val.den
        return float(val)
    except (TypeError, ValueError, ZeroDivisionError, AttributeError):
        return None


def _ifd_rational_to_float(rational: Any) -> float:
    """
    Convert an exifread IFDRational (or similar) value to a float.

    Handles both Ratio objects (num/den attributes) and plain numerics.
    """
    if hasattr(rational, "num") and hasattr(rational, "den"):
        if rational.den == 0:
            return 0.0
        return rational.num / rational.den
    try:
        return float(rational)
    except (TypeError, ValueError):
        return 0.0


def _extract_gps_decimal(
    tags: dict[str, Any],
    coord_key: str,
    ref_key: str,
) -> float | None:
    """
    Convert a GPS coordinate EXIF tag from DMS (degrees/minutes/seconds)
    IFDRational format to decimal degrees.

    Args:
        tags: exifread tags dict.
        coord_key: EXIF tag key for the coordinate, e.g. "GPS GPSLatitude".
        ref_key: EXIF tag key for the hemisphere reference, e.g. "GPS GPSLatitudeRef".

    Returns:
        Decimal degrees float, or None if the tag is absent or malformed.
        South/West hemispheres produce negative values.
    """
    coord_tag = tags.get(coord_key)
    ref_tag = tags.get(ref_key)

    if coord_tag is None:
        return None

    try:
        values = coord_tag.values
        if len(values) < 3:
            return None

        degrees = _ifd_rational_to_float(values[0])
        minutes = _ifd_rational_to_float(values[1])
        seconds = _ifd_rational_to_float(values[2])

        decimal = degrees + (minutes / 60.0) + (seconds / 3600.0)

        # South latitude and West longitude are negative
        if ref_tag is not None:
            ref = str(ref_tag.values).upper().strip()
            if ref in ("S", "W"):
                decimal = -decimal

        return round(decimal, 7)

    except (TypeError, ValueError, AttributeError, IndexError, ZeroDivisionError):
        return None
