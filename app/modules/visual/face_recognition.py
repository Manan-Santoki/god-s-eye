"""
InsightFace face recognition module.

Uses InsightFace's buffalo_l model to:
  1. Detect and embed faces in a reference image (from context["reference_image"]
     or the first downloaded image in context["discovered_images"]).
  2. Compare each face in discovered images against reference embeddings
     using cosine similarity.
  3. Classify matches: similarity > 0.6 = MATCH, > 0.4 = POSSIBLE_MATCH.

All image processing runs synchronously in a thread pool executor to avoid
blocking the async event loop.

Handles missing InsightFace installation gracefully — returns a failed
ModuleResult with an informative message rather than crashing.

Phase: IMAGE_PROCESSING (no API key required; GPU accelerated if available).
"""

from __future__ import annotations

import asyncio
import time
from pathlib import Path
from typing import Any

import numpy as np

from app.core.constants import ModulePhase, TargetType
from app.core.logging import get_logger
from app.modules.base import BaseModule, ModuleMetadata, ModuleResult

logger = get_logger(__name__)

# Lazy InsightFace import — may not be installed
try:
    from insightface.app import FaceAnalysis

    _INSIGHTFACE_AVAILABLE = True
except ImportError:
    _INSIGHTFACE_AVAILABLE = False

# Similarity thresholds
_MATCH_THRESHOLD = 0.6
_POSSIBLE_MATCH_THRESHOLD = 0.4

# InsightFace model name
_MODEL_NAME = "buffalo_l"

# Image file extensions to process
_IMAGE_EXTENSIONS = frozenset(
    {
        ".jpg",
        ".jpeg",
        ".png",
        ".tiff",
        ".tif",
        ".bmp",
        ".webp",
    }
)


class FaceRecognitionModule(BaseModule):
    """
    InsightFace face recognition module.

    Generates 512-dimensional face embeddings using the buffalo_l model and
    computes cosine similarity to identify faces matching a reference image
    across all discovered images.
    """

    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            name="face_recognition",
            display_name="Face Recognition (InsightFace)",
            description=(
                "Uses InsightFace buffalo_l model to detect faces and compare "
                "them against a reference image using cosine similarity. "
                "Classifies MATCH (>0.6) and POSSIBLE_MATCH (>0.4)."
            ),
            phase=ModulePhase.IMAGE_PROCESSING,
            supported_targets=[
                TargetType.PERSON,
                TargetType.USERNAME,
            ],
            requires_auth=False,
            rate_limit_rpm=60,
            timeout_seconds=300,
            enabled_by_default=True,
            tags=["image", "face", "recognition", "biometric", "insightface", "no-key"],
        )

    async def run(
        self,
        target: str,
        target_type: TargetType,
        context: dict[str, Any],
    ) -> ModuleResult:
        # Graceful handling of missing InsightFace
        if not _INSIGHTFACE_AVAILABLE:
            return ModuleResult.fail(
                "InsightFace is not installed. Run: pip install insightface onnxruntime"
            )

        try:
            import cv2 as _cv2  # noqa: F401 — OpenCV required by InsightFace
        except ImportError:
            return ModuleResult.fail(
                "OpenCV is not installed. Run: pip install opencv-python-headless"
            )

        # Collect image paths from context
        raw_images = context.get("discovered_images", [])
        image_paths = self._collect_image_paths(raw_images)

        if not image_paths:
            return ModuleResult(
                success=True,
                data={
                    "reference_faces": 0,
                    "matches": [],
                    "possible_matches": [],
                    "total_images_scanned": 0,
                },
                warnings=["No images found in context['discovered_images']"],
            )

        # Determine reference image
        reference_image_path = context.get("reference_image")
        if reference_image_path:
            reference_path = Path(str(reference_image_path))
        else:
            # Fall back to first downloaded image
            reference_path = image_paths[0]
            logger.debug(
                "face_recognition_reference_fallback",
                path=str(reference_path),
            )

        start = time.monotonic()
        warnings: list[str] = []
        errors: list[str] = []

        logger.info(
            "face_recognition_start",
            reference=str(reference_path),
            total_images=len(image_paths),
        )

        loop = asyncio.get_event_loop()

        # Load the InsightFace model in a thread pool
        try:
            face_app = await loop.run_in_executor(None, self._load_model)
        except Exception as exc:
            logger.exception("insightface_model_load_failed", error=str(exc))
            return ModuleResult.fail(f"Failed to load InsightFace model: {exc}")

        # Extract reference embeddings
        try:
            reference_embeddings, ref_face_count = await loop.run_in_executor(
                None, self._extract_embeddings, face_app, reference_path
            )
        except Exception as exc:
            logger.exception("reference_embedding_failed", error=str(exc))
            return ModuleResult.fail(f"Failed to extract reference face embeddings: {exc}")

        if not reference_embeddings:
            return ModuleResult(
                success=True,
                data={
                    "reference_faces": 0,
                    "matches": [],
                    "possible_matches": [],
                    "total_images_scanned": 0,
                },
                warnings=[f"No faces detected in reference image: {reference_path.name}"],
            )

        logger.info(
            "face_recognition_reference_embedded",
            reference=reference_path.name,
            face_count=ref_face_count,
        )

        # Process all candidate images concurrently in thread pool
        scan_images = [p for p in image_paths if p != reference_path]
        tasks = [
            loop.run_in_executor(
                None,
                self._compare_image,
                face_app,
                img_path,
                reference_embeddings,
            )
            for img_path in scan_images
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Collect match results
        matches: list[dict[str, Any]] = []
        possible_matches: list[dict[str, Any]] = []

        for img_path, result in zip(scan_images, results, strict=False):
            if isinstance(result, Exception):
                errors.append(f"Face detection failed for {img_path.name}: {result}")
                continue
            if not result:
                continue

            for face_result in result:
                similarity = face_result.get("similarity", 0.0)
                if similarity >= _MATCH_THRESHOLD:
                    face_result["match_type"] = "MATCH"
                    matches.append(face_result)
                elif similarity >= _POSSIBLE_MATCH_THRESHOLD:
                    face_result["match_type"] = "POSSIBLE_MATCH"
                    possible_matches.append(face_result)

        # Sort by similarity descending
        matches.sort(key=lambda x: x.get("similarity", 0), reverse=True)
        possible_matches.sort(key=lambda x: x.get("similarity", 0), reverse=True)

        elapsed_ms = int((time.monotonic() - start) * 1000)
        logger.info(
            "face_recognition_complete",
            reference_faces=ref_face_count,
            images_scanned=len(scan_images),
            matches=len(matches),
            possible_matches=len(possible_matches),
            elapsed_ms=elapsed_ms,
        )

        return ModuleResult(
            success=True,
            data={
                "reference_faces": ref_face_count,
                "matches": matches,
                "possible_matches": possible_matches,
                "total_images_scanned": len(scan_images),
            },
            errors=errors,
            warnings=warnings,
        )

    # ── InsightFace helpers ───────────────────────────────────────────────────

    def _load_model(self) -> Any:
        """
        Load the InsightFace FaceAnalysis model with buffalo_l weights.

        Runs synchronously — must be called via run_in_executor.
        Prepares the model for 640x640 input (standard detection size).
        """
        logger.debug("insightface_loading_model", model=_MODEL_NAME)
        app = FaceAnalysis(
            name=_MODEL_NAME,
            providers=["CUDAExecutionProvider", "CPUExecutionProvider"],
        )
        # ctx_id=0 uses GPU if available, ctx_id=-1 forces CPU
        app.prepare(ctx_id=0, det_size=(640, 640))
        logger.debug("insightface_model_loaded")
        return app

    def _extract_embeddings(
        self,
        face_app: Any,
        image_path: Path,
    ) -> tuple[list[Any], int]:
        """
        Detect faces in an image and return their 512-dim embedding vectors.

        Args:
            face_app: Loaded InsightFace FaceAnalysis instance.
            image_path: Path to the image file.

        Returns:
            Tuple of (list of embedding arrays, face count).
        """
        import cv2

        if not image_path.exists():
            raise FileNotFoundError(f"Image not found: {image_path}")

        img = cv2.imread(str(image_path))
        if img is None:
            raise ValueError(f"OpenCV could not read image: {image_path.name}")

        faces = face_app.get(img)
        if not faces:
            return [], 0

        embeddings = []
        for face in faces:
            if face.embedding is not None:
                # Normalise the embedding vector to unit length for cosine similarity
                emb = np.array(face.embedding, dtype=np.float32)
                norm = np.linalg.norm(emb)
                if norm > 0:
                    emb = emb / norm
                embeddings.append(emb)

        return embeddings, len(faces)

    def _compare_image(
        self,
        face_app: Any,
        image_path: Path,
        reference_embeddings: list[Any],
    ) -> list[dict[str, Any]]:
        """
        Detect faces in a candidate image and compute cosine similarity
        against all reference embeddings.

        Returns a list of result dicts — one per detected face (only faces
        above POSSIBLE_MATCH threshold are included).
        """
        import cv2

        if not image_path.exists():
            return []

        img = cv2.imread(str(image_path))
        if img is None:
            return []

        faces = face_app.get(img)
        if not faces:
            return []

        results: list[dict[str, Any]] = []

        for face in faces:
            if face.embedding is None:
                continue

            # Normalise candidate embedding
            emb = np.array(face.embedding, dtype=np.float32)
            norm = np.linalg.norm(emb)
            if norm > 0:
                emb = emb / norm

            # Cosine similarity = dot product of two unit vectors
            max_similarity = 0.0
            for ref_emb in reference_embeddings:
                similarity = float(np.dot(emb, ref_emb))
                if similarity > max_similarity:
                    max_similarity = similarity

            if max_similarity >= _POSSIBLE_MATCH_THRESHOLD:
                # Extract bounding box for reference
                bbox = face.bbox.tolist() if hasattr(face, "bbox") and face.bbox is not None else []

                results.append(
                    {
                        "file_path": str(image_path),
                        "similarity": round(max_similarity, 4),
                        "confidence": self._similarity_to_confidence(max_similarity),
                        "match_type": "",  # Set by caller
                        "face_bbox": bbox,
                        "age": int(face.age) if hasattr(face, "age") and face.age else None,
                        "gender": _decode_gender(face) if hasattr(face, "gender") else None,
                    }
                )

        return results

    # ── Utilities ─────────────────────────────────────────────────────────────

    @staticmethod
    def _collect_image_paths(raw: list[Any]) -> list[Path]:
        """
        Resolve image paths from context["discovered_images"] entries.

        Accepts strings, Path objects, or dicts with "file_path" / "path" keys.
        """
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

    @staticmethod
    def _similarity_to_confidence(similarity: float) -> str:
        """
        Convert a cosine similarity score to a human-readable confidence label.
        """
        if similarity >= 0.8:
            return "high"
        if similarity >= 0.6:
            return "medium"
        if similarity >= 0.4:
            return "low"
        return "very_low"


def _decode_gender(face: Any) -> str:
    """
    Extract gender prediction from InsightFace face object.

    InsightFace encodes gender as 0=female, 1=male in some model versions.
    """
    try:
        gender = face.gender
        if gender is None:
            return ""
        if isinstance(gender, (int, float)):
            return "male" if int(gender) == 1 else "female"
        return str(gender)
    except Exception:
        return ""
