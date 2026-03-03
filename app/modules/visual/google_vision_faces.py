"""
Google Cloud Vision face detection module.

Uses the Google Cloud Vision API to detect faces in images and extract:
  - Detection confidence
  - Emotion likelihoods (joy, sorrow, anger, surprise)
  - Bounding polygon
  - Head pose angles (roll, pan, tilt)

Complements the InsightFace face_recognition module by providing a secondary
face detection signal from Google's cloud-based model.

Phase: IMAGE_PROCESSING (requires GOOGLE_VISION_API_KEY).
"""

from __future__ import annotations

import asyncio
import base64
import time
from pathlib import Path
from typing import Any

import aiohttp

from app.core.config import settings
from app.core.constants import ModulePhase, TargetType
from app.core.logging import get_logger
from app.modules.base import BaseModule, ModuleMetadata, ModuleResult

logger = get_logger(__name__)

_VISION_API_URL = "https://vision.googleapis.com/v1/images:annotate"
_MAX_IMAGES = 30
_CONCURRENT_LIMIT = 5

_IMAGE_EXTENSIONS = frozenset(
    {".jpg", ".jpeg", ".png", ".tiff", ".tif", ".bmp", ".webp"}
)


class GoogleVisionFacesModule(BaseModule):
    """
    Google Cloud Vision face detection module.

    Sends images to the Vision API FACE_DETECTION feature and returns
    structured face annotation data including emotions and pose angles.
    """

    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            name="google_vision_faces",
            display_name="Google Cloud Vision Face Detection",
            description=(
                "Uses Google Cloud Vision API to detect faces in images, "
                "extracting detection confidence, emotion likelihoods, "
                "bounding polygons, and head pose angles."
            ),
            phase=ModulePhase.IMAGE_PROCESSING,
            supported_targets=[
                TargetType.PERSON,
                TargetType.USERNAME,
            ],
            requires_auth=True,
            rate_limit_rpm=60,
            timeout_seconds=120,
            enabled_by_default=True,
            tags=["image", "face", "detection", "google", "cloud-vision"],
        )

    async def validate(
        self,
        target: str,
        target_type: TargetType,
        context: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> bool:
        """Only run if GOOGLE_VISION_API_KEY is configured."""
        return settings.has_api_key("google_vision_api_key")

    async def run(
        self,
        target: str,
        target_type: TargetType,
        context: dict[str, Any],
    ) -> ModuleResult:
        api_key = _get_api_key()
        if not api_key:
            return ModuleResult.fail(
                "GOOGLE_VISION_API_KEY is not configured",
                module_name="google_vision_faces",
            )

        # Prefer user-confirmed images, fall back to all discovered images
        raw_images = context.get("confirmed_face_images") or context.get(
            "discovered_images", []
        )
        image_paths = self._collect_image_paths(raw_images)

        if not image_paths:
            return ModuleResult(
                success=True,
                data={
                    "faces_detected": [],
                    "total_images_processed": 0,
                },
                warnings=["No images available for Google Vision face detection"],
            )

        # Cap to max images
        image_paths = image_paths[:_MAX_IMAGES]

        start = time.monotonic()
        semaphore = asyncio.Semaphore(_CONCURRENT_LIMIT)
        warnings: list[str] = []

        logger.info(
            "google_vision_faces_start",
            total_images=len(image_paths),
        )

        async def detect_one(path: Path) -> dict[str, Any] | None:
            async with semaphore:
                return await self._detect_faces(path, api_key)

        tasks = [detect_one(path) for path in image_paths]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        faces_detected: list[dict[str, Any]] = []
        for path, result in zip(image_paths, results, strict=False):
            if isinstance(result, Exception):
                warnings.append(f"Vision API failed for {path.name}: {result}")
                continue
            if result and result.get("faces"):
                faces_detected.append(result)

        elapsed_ms = int((time.monotonic() - start) * 1000)
        logger.info(
            "google_vision_faces_complete",
            images_processed=len(image_paths),
            images_with_faces=len(faces_detected),
            elapsed_ms=elapsed_ms,
        )

        return ModuleResult(
            success=True,
            data={
                "faces_detected": faces_detected,
                "total_images_processed": len(image_paths),
                "images_with_faces": len(faces_detected),
            },
            warnings=warnings,
        )

    async def _detect_faces(
        self,
        image_path: Path,
        api_key: str,
    ) -> dict[str, Any] | None:
        """Send a single image to Google Vision API for face detection."""
        try:
            image_bytes = image_path.read_bytes()
        except Exception as exc:
            logger.warning("vision_image_read_failed", path=str(image_path), error=str(exc))
            return None

        b64_content = base64.b64encode(image_bytes).decode("ascii")

        payload = {
            "requests": [
                {
                    "image": {"content": b64_content},
                    "features": [{"type": "FACE_DETECTION", "maxResults": 20}],
                }
            ]
        }

        url = f"{_VISION_API_URL}?key={api_key}"

        async with aiohttp.ClientSession() as session:
            async with session.post(
                url,
                json=payload,
                timeout=aiohttp.ClientTimeout(total=30),
            ) as resp:
                if resp.status != 200:
                    body = await resp.text()
                    logger.warning(
                        "vision_api_error",
                        status=resp.status,
                        path=str(image_path),
                        body=body[:200],
                    )
                    return None

                data = await resp.json()

        responses = data.get("responses", [])
        if not responses:
            return None

        face_annotations = responses[0].get("faceAnnotations", [])
        if not face_annotations:
            return None

        faces: list[dict[str, Any]] = []
        for ann in face_annotations:
            face = {
                "detection_confidence": ann.get("detectionConfidence", 0.0),
                "joy_likelihood": ann.get("joyLikelihood", "UNKNOWN"),
                "sorrow_likelihood": ann.get("sorrowLikelihood", "UNKNOWN"),
                "anger_likelihood": ann.get("angerLikelihood", "UNKNOWN"),
                "surprise_likelihood": ann.get("surpriseLikelihood", "UNKNOWN"),
                "roll_angle": ann.get("rollAngle", 0.0),
                "pan_angle": ann.get("panAngle", 0.0),
                "tilt_angle": ann.get("tiltAngle", 0.0),
            }

            # Bounding polygon
            bounding = ann.get("boundingPoly", {}).get("vertices", [])
            if bounding:
                face["bounding_poly"] = [
                    {"x": v.get("x", 0), "y": v.get("y", 0)} for v in bounding
                ]

            faces.append(face)

        return {
            "file_path": str(image_path),
            "filename": image_path.name,
            "face_count": len(faces),
            "faces": faces,
        }

    @staticmethod
    def _collect_image_paths(raw: list[Any]) -> list[Path]:
        """Resolve image paths from context entries (strings, Paths, or dicts)."""
        paths: list[Path] = []
        for item in raw:
            if isinstance(item, str):
                p = Path(item)
            elif isinstance(item, Path):
                p = item
            elif isinstance(item, dict):
                path_str = item.get("file_path") or item.get("path") or ""
                p = Path(str(path_str)) if path_str else None  # type: ignore[assignment]
            else:
                continue

            if p and p.suffix.lower() in _IMAGE_EXTENSIONS and p.exists():
                paths.append(p)

        return paths


def _get_api_key() -> str | None:
    """Extract the Google Vision API key from settings."""
    key = settings.google_vision_api_key
    if key is None:
        return None
    return key.get_secret_value() if hasattr(key, "get_secret_value") else str(key)
