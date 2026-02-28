"""
Maigret username intelligence wrapper.

Maigret checks 3000+ sites for username presence and enriches results
with profile data. Requires `pip install maigret` or the CLI tool.

Falls back to subprocess if the Python library is not importable.

Target types: username
Phase: FAST_API (1)
"""

import asyncio
import json
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from app.modules.base import BaseModule, ModuleMetadata, ModuleResult
from app.core.constants import ModulePhase, TargetType
from app.core.logging import get_logger

logger = get_logger(__name__)


class MaigretWrapper(BaseModule):
    """Check 3000+ social sites for username using Maigret."""

    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            name="maigret_wrapper",
            display_name="Maigret Username Intelligence",
            description="Checks 3000+ websites for username presence using the Maigret library",
            phase=ModulePhase.FAST_API,
            target_types=[TargetType.USERNAME],
            requires_browser=False,
            requires_api_key=False,
            rate_limit_per_minute=2,  # Maigret is slow; limit parallel runs
        )

    async def validate(self, target: str, target_type: TargetType, **kwargs: Any) -> bool:
        # Username: 2-50 chars, no spaces, basic chars only
        import re
        return bool(target and re.match(r"^[a-zA-Z0-9._\-]{2,50}$", target))

    async def run(
        self,
        target: str,
        target_type: TargetType,
        session: Any = None,
        **kwargs: Any,
    ) -> ModuleResult:
        results: dict[str, Any] = {
            "username": target,
            "sites_checked": 0,
            "sites_found": 0,
            "profiles": [],
            "method": "unknown",
        }

        # Try Python library first
        try:
            return await self._run_library(target, results)
        except ImportError:
            logger.info("maigret_library_not_installed", fallback="subprocess")

        # Fall back to CLI subprocess
        try:
            return await self._run_subprocess(target, results)
        except FileNotFoundError:
            logger.warning("maigret_not_installed", msg="Install: pip install maigret")
            return ModuleResult(
                module_name=self.metadata().name,
                target=target,
                success=False,
                error="Maigret not installed. Run: pip install maigret",
                data=results,
            )

    async def _run_library(self, username: str, results: dict) -> ModuleResult:
        """Use Maigret Python library directly."""
        import maigret
        from maigret.result import QueryStatus

        results["method"] = "library"

        # Run in thread pool — Maigret is sync
        loop = asyncio.get_event_loop()

        def _maigret_sync():
            import maigret.settings
            sites_db = maigret.MaigretDatabase().load_from_path(
                maigret.settings.MAIGRET_DB_FILE
            ) if hasattr(maigret, "settings") else None

            # Use top 300 sites for speed; full run takes minutes
            result = maigret.search(
                username=username,
                site_dict=sites_db,
                top_sites=300,
                timeout=5,
            )
            return result

        try:
            raw = await asyncio.wait_for(
                loop.run_in_executor(None, _maigret_sync),
                timeout=120,
            )
        except asyncio.TimeoutError:
            logger.warning("maigret_library_timeout", username=username)
            raw = {}

        profiles = []
        for site_name, site_result in raw.items():
            status = getattr(site_result, "status", None)
            if status and str(status) in ("QueryStatus.CLAIMED", "CLAIMED"):
                profile_url = getattr(site_result, "url_user", "")
                profiles.append({
                    "site": site_name,
                    "url": profile_url,
                    "username": username,
                })

        results["profiles"] = profiles
        results["sites_found"] = len(profiles)
        results["sites_checked"] = len(raw)

        return ModuleResult(
            module_name=self.metadata().name,
            target=username,
            success=True,
            data=results,
            findings_count=len(profiles),
        )

    async def _run_subprocess(self, username: str, results: dict) -> ModuleResult:
        """Run Maigret as a subprocess and parse JSON output."""
        results["method"] = "subprocess"

        with tempfile.TemporaryDirectory() as tmpdir:
            output_file = Path(tmpdir) / f"{username}.json"

            cmd = [
                "maigret",
                username,
                "--json",
                str(output_file),
                "--timeout",
                "5",
                "--top-sites",
                "300",
                "--no-progressbar",
            ]

            try:
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                _, _ = await asyncio.wait_for(proc.communicate(), timeout=150)
            except asyncio.TimeoutError:
                logger.warning("maigret_subprocess_timeout", username=username)

            # Parse JSON output
            if output_file.exists():
                with open(output_file) as f:
                    data = json.load(f)

                profiles = []
                for site_name, site_data in data.items():
                    if isinstance(site_data, dict):
                        status = site_data.get("status", {})
                        status_name = status.get("name", "") if isinstance(status, dict) else str(status)
                        if "CLAIMED" in status_name.upper():
                            profiles.append({
                                "site": site_name,
                                "url": site_data.get("url_user", ""),
                                "username": username,
                                "extra": {
                                    k: v for k, v in site_data.items()
                                    if k not in ("status", "url_user") and isinstance(v, (str, int, bool))
                                },
                            })

                results["profiles"] = profiles
                results["sites_found"] = len(profiles)
                results["sites_checked"] = len(data)

        logger.info(
            "maigret_complete",
            username=username,
            sites_found=results["sites_found"],
            sites_checked=results["sites_checked"],
        )

        return ModuleResult(
            module_name=self.metadata().name,
            target=username,
            success=True,
            data=results,
            findings_count=results["sites_found"],
        )
