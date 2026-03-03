"""
Face selection UI for GOD_EYE.

Provides interactive face confirmation during Phase 5 (IMAGE_PROCESSING).
After images are downloaded, displays them to the user so they can select
which images actually show the target person — improving face recognition
accuracy by eliminating group photos and unrelated search results.

Supports three display modes:
  - Tkinter GUI: scrollable grid with thumbnails and checkboxes (default on desktop)
  - Rich terminal: text-based listing with index selection (fallback)
  - API/headless: generates base64 thumbnail payloads for WebSocket delivery

This is NOT a BaseModule — it's a UI interaction component invoked by the
orchestrator's interaction callback.
"""

from __future__ import annotations

import base64
import io
import os
import platform
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from app.core.logging import get_logger

logger = get_logger(__name__)


@dataclass
class FaceSelectorResult:
    """Result of a face selection interaction."""

    confirmed_indices: list[int] = field(default_factory=list)
    confirmed_paths: list[str] = field(default_factory=list)
    skipped: bool = False


def select_faces(
    images: list[dict[str, Any]],
    mode: str = "auto",
) -> FaceSelectorResult:
    """
    Top-level dispatcher for face selection UI.

    Args:
        images: List of image dicts with keys like file_path, platform, url.
        mode: One of "auto", "tkinter", "rich", "disabled".

    Returns:
        FaceSelectorResult with user's selection.
    """
    if not images:
        return FaceSelectorResult(skipped=True)

    if mode == "disabled":
        return FaceSelectorResult(
            confirmed_indices=list(range(len(images))),
            confirmed_paths=[
                str(img.get("file_path", img.get("path", ""))) for img in images
            ],
            skipped=True,
        )

    if mode == "tkinter" or (mode == "auto" and _can_use_tkinter()):
        try:
            return select_faces_tkinter(images)
        except Exception as exc:
            logger.warning("tkinter_face_selector_failed", error=str(exc))
            # Fall through to Rich

    if mode in ("rich", "auto"):
        return select_faces_rich(images)

    # Unknown mode — use all images
    return FaceSelectorResult(
        confirmed_indices=list(range(len(images))),
        confirmed_paths=[
            str(img.get("file_path", img.get("path", ""))) for img in images
        ],
        skipped=True,
    )


def select_faces_tkinter(images: list[dict[str, Any]]) -> FaceSelectorResult:
    """
    Tkinter GUI for face selection.

    Shows a scrollable grid of image thumbnails with checkboxes.
    User can check/uncheck images and click Confirm or Skip.
    """
    import tkinter as tk
    from tkinter import ttk

    try:
        from PIL import Image, ImageTk
    except ImportError:
        logger.warning("pillow_not_available_for_tkinter")
        raise RuntimeError("Pillow is required for Tkinter face selector")

    result = FaceSelectorResult()
    check_vars: list[tk.BooleanVar] = []

    root = tk.Tk()
    root.title("GOD_EYE — Select Target Face Images")
    root.geometry("800x600")
    root.minsize(640, 400)

    # Header
    header = tk.Label(
        root,
        text="Select images that show the TARGET person",
        font=("Helvetica", 14, "bold"),
        pady=10,
    )
    header.pack(fill=tk.X)

    sub_header = tk.Label(
        root,
        text="Uncheck images that show other people or are irrelevant.",
        font=("Helvetica", 10),
        fg="gray",
    )
    sub_header.pack(fill=tk.X)

    # Scrollable frame
    canvas = tk.Canvas(root)
    scrollbar = ttk.Scrollbar(root, orient=tk.VERTICAL, command=canvas.yview)
    scroll_frame = ttk.Frame(canvas)

    scroll_frame.bind(
        "<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
    )
    canvas.create_window((0, 0), window=scroll_frame, anchor="nw")
    canvas.configure(yscrollcommand=scrollbar.set)

    canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=10, pady=5)
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    # Thumbnail grid
    columns = 5
    thumb_size = (120, 120)
    photo_refs: list[Any] = []  # prevent GC of PhotoImage objects

    for idx, img_info in enumerate(images):
        row = idx // columns
        col = idx % columns

        frame = ttk.Frame(scroll_frame, padding=5)
        frame.grid(row=row, column=col, padx=5, pady=5, sticky="n")

        file_path = str(img_info.get("file_path", img_info.get("path", "")))
        platform_name = str(img_info.get("platform", "unknown"))
        filename = Path(file_path).name if file_path else f"image_{idx}"

        # Load thumbnail
        try:
            pil_img = Image.open(file_path)
            pil_img.thumbnail(thumb_size, Image.LANCZOS)
            photo = ImageTk.PhotoImage(pil_img)
            photo_refs.append(photo)
            label = tk.Label(frame, image=photo)
            label.pack()
        except Exception:
            label = tk.Label(
                frame,
                text="[No preview]",
                width=15,
                height=7,
                relief="sunken",
            )
            label.pack()

        # Platform label
        plat_label = tk.Label(frame, text=platform_name, font=("Helvetica", 8), fg="blue")
        plat_label.pack()

        # Filename label (truncated)
        name_label = tk.Label(
            frame,
            text=filename[:18] + "..." if len(filename) > 18 else filename,
            font=("Helvetica", 8),
        )
        name_label.pack()

        # Checkbox (default checked)
        var = tk.BooleanVar(value=True)
        check_vars.append(var)
        cb = ttk.Checkbutton(frame, variable=var)
        cb.pack()

    # Buttons
    btn_frame = ttk.Frame(root, padding=10)
    btn_frame.pack(fill=tk.X)

    def on_confirm():
        for idx, var in enumerate(check_vars):
            if var.get():
                result.confirmed_indices.append(idx)
                file_path = str(
                    images[idx].get("file_path", images[idx].get("path", ""))
                )
                result.confirmed_paths.append(file_path)
        result.skipped = False
        root.destroy()

    def on_skip():
        result.confirmed_indices = list(range(len(images)))
        result.confirmed_paths = [
            str(img.get("file_path", img.get("path", ""))) for img in images
        ]
        result.skipped = True
        root.destroy()

    confirm_btn = ttk.Button(btn_frame, text="Confirm Selection", command=on_confirm)
    confirm_btn.pack(side=tk.LEFT, padx=10)

    skip_btn = ttk.Button(btn_frame, text="Skip (use all)", command=on_skip)
    skip_btn.pack(side=tk.LEFT, padx=10)

    root.mainloop()
    return result


def select_faces_rich(images: list[dict[str, Any]]) -> FaceSelectorResult:
    """
    Rich terminal fallback for face selection.

    Displays a table of images and prompts user for comma-separated indices.
    """
    from rich.console import Console
    from rich.prompt import Prompt
    from rich.table import Table

    console = Console()

    table = Table(title="Downloaded Images — Select Target Faces")
    table.add_column("Index", style="cyan", justify="right")
    table.add_column("Filename", style="white")
    table.add_column("Platform", style="green")

    for idx, img_info in enumerate(images):
        file_path = str(img_info.get("file_path", img_info.get("path", "")))
        filename = Path(file_path).name if file_path else f"image_{idx}"
        platform_name = str(img_info.get("platform", "unknown"))
        table.add_row(str(idx), filename, platform_name)

    console.print(table)
    console.print(
        '\n[bold]Enter image indices[/bold] (comma-separated), '
        '"all" to use all, or "skip" to skip selection:'
    )

    answer = Prompt.ask("Selection", default="all")
    answer = answer.strip().lower()

    if answer == "skip":
        return FaceSelectorResult(
            confirmed_indices=list(range(len(images))),
            confirmed_paths=[
                str(img.get("file_path", img.get("path", ""))) for img in images
            ],
            skipped=True,
        )

    if answer == "all":
        return FaceSelectorResult(
            confirmed_indices=list(range(len(images))),
            confirmed_paths=[
                str(img.get("file_path", img.get("path", ""))) for img in images
            ],
            skipped=False,
        )

    # Parse comma-separated indices
    indices: list[int] = []
    paths: list[str] = []
    for part in answer.split(","):
        part = part.strip()
        if part.isdigit():
            idx = int(part)
            if 0 <= idx < len(images):
                indices.append(idx)
                file_path = str(
                    images[idx].get("file_path", images[idx].get("path", ""))
                )
                paths.append(file_path)

    if not indices:
        console.print("[yellow]No valid indices selected. Using all images.[/yellow]")
        return FaceSelectorResult(
            confirmed_indices=list(range(len(images))),
            confirmed_paths=[
                str(img.get("file_path", img.get("path", ""))) for img in images
            ],
            skipped=True,
        )

    return FaceSelectorResult(
        confirmed_indices=indices,
        confirmed_paths=paths,
        skipped=False,
    )


def _can_use_tkinter() -> bool:
    """Check if Tkinter GUI is available in the current environment."""
    # macOS always has a display
    if platform.system() == "Darwin":
        try:
            import tkinter as _tk  # noqa: F401

            return True
        except ImportError:
            return False

    # Linux/other — need DISPLAY or WAYLAND_DISPLAY
    if not (os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")):
        return False

    try:
        import tkinter as _tk  # noqa: F401

        return True
    except ImportError:
        return False


def build_thumbnail_payloads(
    images: list[dict[str, Any]],
    thumb_size: tuple[int, int] = (120, 120),
) -> list[dict[str, Any]]:
    """
    Generate base64 JPEG thumbnails for API/WebSocket delivery.

    Returns a list of dicts with: index, filename, platform, thumbnail_b64, original_path.
    Missing or unreadable files get thumbnail_b64=None.
    """
    try:
        from PIL import Image
    except ImportError:
        logger.warning("pillow_not_available_for_thumbnails")
        return [
            {
                "index": idx,
                "filename": Path(
                    str(img.get("file_path", img.get("path", "")))
                ).name,
                "platform": str(img.get("platform", "unknown")),
                "thumbnail_b64": None,
                "original_path": str(img.get("file_path", img.get("path", ""))),
            }
            for idx, img in enumerate(images)
        ]

    payloads: list[dict[str, Any]] = []
    for idx, img_info in enumerate(images):
        file_path = str(img_info.get("file_path", img_info.get("path", "")))
        filename = Path(file_path).name if file_path else f"image_{idx}"
        platform_name = str(img_info.get("platform", "unknown"))

        thumbnail_b64: str | None = None
        try:
            pil_img = Image.open(file_path)
            pil_img.thumbnail(thumb_size, Image.LANCZOS)
            buf = io.BytesIO()
            pil_img.convert("RGB").save(buf, format="JPEG", quality=75)
            thumbnail_b64 = base64.b64encode(buf.getvalue()).decode("ascii")
        except Exception as exc:
            logger.debug("thumbnail_generation_failed", path=file_path, error=str(exc))

        payloads.append(
            {
                "index": idx,
                "filename": filename,
                "platform": platform_name,
                "thumbnail_b64": thumbnail_b64,
                "original_path": file_path,
            }
        )

    return payloads
