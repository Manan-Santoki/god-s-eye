"""
Sherlock CLI wrapper module.

Runs Sherlock as a subprocess to check a username across hundreds of social
media platforms. Parses the JSON output and categorises results by platform type.

Phase: FAST_API (subprocess-based, no direct API auth required).
"""

from __future__ import annotations

import asyncio
import json
import os
import tempfile
import time
from pathlib import Path
from typing import Any

from app.core.constants import ModulePhase, TargetType
from app.core.logging import get_logger
from app.modules.base import BaseModule, ModuleMetadata, ModuleResult

logger = get_logger(__name__)

# Default subprocess timeout in seconds
_SUBPROCESS_TIMEOUT = 120

# Platform category classification by platform name (lowercase)
_PLATFORM_CATEGORIES: dict[str, str] = {
    # Professional
    "github": "professional",
    "gitlab": "professional",
    "linkedin": "professional",
    "stackoverflow": "professional",
    "hackerrank": "professional",
    "hackerone": "professional",
    "bugcrowd": "professional",
    "codepen": "professional",
    "replit": "professional",
    "kaggle": "professional",
    "researchgate": "professional",
    "academia": "professional",
    "orcid": "professional",
    "npm": "professional",
    "pypi": "professional",
    "dockerhub": "professional",
    "bitbucket": "professional",
    # Social
    "instagram": "social",
    "twitter": "social",
    "facebook": "social",
    "reddit": "social",
    "tiktok": "social",
    "snapchat": "social",
    "pinterest": "social",
    "tumblr": "social",
    "vk": "social",
    "mastodon": "social",
    "threads": "social",
    "bluesky": "social",
    "diaspora": "social",
    "mewe": "social",
    "minds": "social",
    "gab": "social",
    # Creative
    "deviantart": "creative",
    "behance": "creative",
    "artstation": "creative",
    "dribbble": "creative",
    "flickr": "creative",
    "500px": "creative",
    "unsplash": "creative",
    "fiverr": "creative",
    "etsy": "creative",
    "bandcamp": "creative",
    "soundcloud": "creative",
    "mixcloud": "creative",
    "wattpad": "creative",
    "medium": "creative",
    "substack": "creative",
    "ko-fi": "creative",
    "patreon": "creative",
    # Gaming
    "steam": "gaming",
    "twitch": "gaming",
    "playstation": "gaming",
    "xbox": "gaming",
    "roblox": "gaming",
    "minecraft": "gaming",
    "chess": "gaming",
    "lichess": "gaming",
    "speedrun": "gaming",
    "itch.io": "gaming",
    "kongregate": "gaming",
    "faceit": "gaming",
    "battlenet": "gaming",
    "epicgames": "gaming",
    "origin": "gaming",
    "ubisoft": "gaming",
}

_DEFAULT_CATEGORY = "other"


def _classify_platform(platform_name: str) -> str:
    """
    Return the category string for a given platform name.

    Performs case-insensitive substring matching against known platform names.
    Falls back to "other" if no match is found.
    """
    lower = platform_name.lower()
    # Exact match first
    if lower in _PLATFORM_CATEGORIES:
        return _PLATFORM_CATEGORIES[lower]
    # Substring match (handles variants like "GitHub" -> "github")
    for key, category in _PLATFORM_CATEGORIES.items():
        if key in lower or lower in key:
            return category
    return _DEFAULT_CATEGORY


class SherlockWrapperModule(BaseModule):
    """
    Sherlock username checker wrapper.

    Invokes Sherlock as a Python subprocess, captures JSON output, and
    parses the results into a structured format with platform categorisation.
    """

    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            name="sherlock_wrapper",
            display_name="Sherlock Username Checker",
            description=(
                "Runs Sherlock CLI to check a username across hundreds of "
                "platforms and categorises found profiles by type."
            ),
            phase=ModulePhase.FAST_API,
            supported_targets=[TargetType.USERNAME],
            requires_auth=False,
            enabled_by_default=True,
            tags=["username", "sherlock", "social", "enumeration"],
        )

    async def run(
        self,
        target: str,
        target_type: TargetType,
        context: dict[str, Any],
    ) -> ModuleResult:
        username = target.strip()
        start = time.monotonic()
        warnings: list[str] = []

        logger.info("sherlock_start", username=username)

        # ── Run Sherlock in a temporary directory ────────────────────────────
        with tempfile.TemporaryDirectory(prefix="god_eye_sherlock_") as tmpdir:
            output_path = Path(tmpdir) / f"{username}.json"
            raw_json = await self._run_sherlock(
                username=username,
                output_path=output_path,
                warnings=warnings,
            )

        if raw_json is None:
            elapsed = int((time.monotonic() - start) * 1000)
            return ModuleResult.fail(
                "Sherlock subprocess failed or timed out. "
                "Ensure sherlock-project is installed: pip install sherlock-project"
            )

        # ── Parse and categorise results ─────────────────────────────────────
        platforms, not_found = self._parse_results(raw_json)
        total_found = len(platforms)

        elapsed = int((time.monotonic() - start) * 1000)
        logger.info(
            "sherlock_complete",
            username=username,
            total_found=total_found,
            elapsed_ms=elapsed,
        )

        return ModuleResult.ok(
            data={
                "username": username,
                "total_found": total_found,
                "platforms": platforms,
                "not_found": not_found,
            },
            warnings=warnings,
        )

    # ── Subprocess execution ─────────────────────────────────────────────────

    async def _run_sherlock(
        self,
        username: str,
        output_path: Path,
        warnings: list[str],
    ) -> dict[str, Any] | None:
        """
        Run the Sherlock subprocess asynchronously.

        Command: python -m sherlock_project {username} --json {output_path} --timeout 15

        Returns the parsed JSON dict from the output file, or None on failure.
        """
        cmd = [
            "python",
            "-m",
            "sherlock_project",
            username,
            "--json",
            str(output_path),
            "--timeout",
            "15",
            "--print-found",
        ]

        logger.debug("sherlock_subprocess", cmd=" ".join(cmd))

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env={**os.environ},
            )

            try:
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(), timeout=_SUBPROCESS_TIMEOUT
                )
            except TimeoutError:
                proc.kill()
                await proc.communicate()
                warnings.append(
                    f"Sherlock timed out after {_SUBPROCESS_TIMEOUT}s. Results may be incomplete."
                )
                # Attempt to read partial JSON output
                if output_path.exists():
                    return self._read_json_output(output_path, warnings)
                return None

            if proc.returncode not in (0, 1):
                # Sherlock exits 0 on success, 1 when no results found
                err_text = stderr.decode("utf-8", errors="replace")[:500]
                warnings.append(f"Sherlock exited with code {proc.returncode}: {err_text}")

            if output_path.exists():
                return self._read_json_output(output_path, warnings)

            # No output file — log stderr for debugging
            err_text = stderr.decode("utf-8", errors="replace")
            logger.warning("sherlock_no_output", stderr=err_text[:500])
            warnings.append("Sherlock produced no JSON output file")
            return {}

        except FileNotFoundError:
            warnings.append("Sherlock not found. Install with: pip install sherlock-project")
            logger.error("sherlock_not_installed")
            return None
        except Exception as exc:
            warnings.append(f"Sherlock subprocess error: {exc}")
            logger.exception("sherlock_subprocess_error", error=str(exc))
            return None

    @staticmethod
    def _read_json_output(
        output_path: Path,
        warnings: list[str],
    ) -> dict[str, Any] | None:
        """Read and parse the Sherlock JSON output file."""
        try:
            content = output_path.read_text(encoding="utf-8")
            if not content.strip():
                return {}
            return json.loads(content)
        except json.JSONDecodeError as exc:
            warnings.append(f"Failed to parse Sherlock JSON output: {exc}")
            logger.warning("sherlock_json_parse_error", error=str(exc))
            return None
        except OSError as exc:
            warnings.append(f"Failed to read Sherlock output file: {exc}")
            return None

    # ── Result parsing ───────────────────────────────────────────────────────

    @staticmethod
    def _parse_results(
        raw: dict[str, Any],
    ) -> tuple[list[dict[str, Any]], list[str]]:
        """
        Parse Sherlock JSON output into found platform list and not-found list.

        Sherlock JSON format:
            {
                "platform_name": {
                    "url_user": "https://...",
                    "status": "Claimed" | "Available" | "Unknown" | "Error",
                    ...
                },
                ...
            }

        Returns:
            (platforms_found, not_found_names)
        """
        platforms: list[dict[str, Any]] = []
        not_found: list[str] = []

        for platform_name, info in raw.items():
            if not isinstance(info, dict):
                continue

            status = info.get("status", "")
            url = info.get("url_user") or info.get("url_main") or ""

            if status.lower() in ("claimed", "found"):
                category = _classify_platform(platform_name)
                platforms.append(
                    {
                        "platform": platform_name,
                        "url": url,
                        "category": category,
                        "status": status,
                    }
                )
            else:
                not_found.append(platform_name)

        # Sort found platforms by category then name for consistent output
        platforms.sort(key=lambda p: (p["category"], p["platform"].lower()))
        not_found.sort()
        return platforms, not_found
