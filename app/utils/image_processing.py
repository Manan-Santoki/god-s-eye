"""
Image processing utilities: hashing, resizing, format conversion.
"""

import hashlib
from pathlib import Path
from typing import Any


def compute_md5(file_path: str | Path) -> str:
    """Compute MD5 hash of a file for deduplication."""
    h = hashlib.md5()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def compute_perceptual_hash(file_path: str | Path) -> str | None:
    """Compute perceptual hash for visual similarity detection."""
    try:
        import imagehash
        from PIL import Image
        img = Image.open(str(file_path))
        return str(imagehash.phash(img))
    except Exception:
        return None


def get_image_dimensions(file_path: str | Path) -> tuple[int, int] | None:
    """Return (width, height) of an image."""
    try:
        from PIL import Image
        img = Image.open(str(file_path))
        return img.size
    except Exception:
        return None


def get_image_format(file_path: str | Path) -> str | None:
    """Return image format (JPEG, PNG, etc.)."""
    try:
        from PIL import Image
        img = Image.open(str(file_path))
        return img.format
    except Exception:
        return None


def is_image_file(file_path: str | Path) -> bool:
    """Check if a file is a valid image."""
    try:
        from PIL import Image
        Image.open(str(file_path)).verify()
        return True
    except Exception:
        return False


def resize_image(
    input_path: str | Path,
    output_path: str | Path,
    max_width: int = 800,
    max_height: int = 800,
) -> bool:
    """Resize image to fit within max dimensions, preserving aspect ratio."""
    try:
        from PIL import Image
        img = Image.open(str(input_path))
        img.thumbnail((max_width, max_height), Image.LANCZOS)
        img.save(str(output_path))
        return True
    except Exception:
        return False


def image_to_base64(file_path: str | Path) -> str | None:
    """Convert image to base64 string for API embedding."""
    import base64
    try:
        with open(file_path, "rb") as f:
            return base64.b64encode(f.read()).decode()
    except Exception:
        return None


def get_image_metadata(file_path: str | Path) -> dict[str, Any]:
    """Get all basic image metadata without EXIF."""
    path = Path(file_path)
    result: dict[str, Any] = {
        "file_path": str(path),
        "file_size_bytes": path.stat().st_size if path.exists() else 0,
        "hash_md5": compute_md5(path) if path.exists() else None,
        "hash_perceptual": compute_perceptual_hash(path),
    }

    dims = get_image_dimensions(path)
    if dims:
        result["width"], result["height"] = dims

    fmt = get_image_format(path)
    if fmt:
        result["format"] = fmt

    return result
