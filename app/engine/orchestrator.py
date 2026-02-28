"""
Main scan orchestrator — the heart of GOD_EYE.

Manages the full scan lifecycle:
1. Receive scan parameters
2. Discover available modules (filtered by target type + API key availability)
3. Execute modules in 8 phases (sequential phases, parallel within each phase)
4. Collect results, update progress, pass context to next phase
5. Trigger AI correlation and report generation

Usage:
    orchestrator = Orchestrator()
    session = await orchestrator.run_scan(
        target="john@example.com",
        target_type=TargetType.EMAIL,
        options={"phases": [1, 2, 3], "modules": ["hibp", "sherlock"]},
    )
"""

import asyncio
import time
from typing import Any

from rich.console import Console
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TaskID,
    TextColumn,
    TimeElapsedColumn,
)
from rich.table import Table

from app.core.config import settings
from app.core.constants import ModulePhase, ScanStatus, TargetType
from app.core.exceptions import GodEyeError
from app.core.logging import get_audit_logger, get_logger
from app.database.sqlite_cache import get_cache
from app.engine.session import ScanSession

logger = get_logger(__name__)
audit_logger = get_audit_logger()

console = Console()

PHASE_NAMES = {
    ModulePhase.FAST_API: "Fast API Calls",
    ModulePhase.BREACH_DB: "Breach Databases",
    ModulePhase.SEARCH_ENGINE: "Search Engines",
    ModulePhase.BROWSER_AUTH: "Browser Automation",
    ModulePhase.IMAGE_PROCESSING: "Image Analysis",
    ModulePhase.DEEP_ANALYSIS: "Deep Recon",
    ModulePhase.AI_CORRELATION: "AI Correlation",
    ModulePhase.REPORT_GEN: "Report Generation",
}


class Orchestrator:
    """
    Phase-based scan orchestrator.

    Phases run sequentially. Within each phase, all compatible modules
    run in parallel using asyncio.gather().

    Error isolation: a module failure never stops other modules or the scan.
    """

    def __init__(self) -> None:
        self._module_registry: dict[str, Any] | None = None

    def _get_registry(self) -> dict[str, Any]:
        """Lazy-load the module registry to avoid circular imports."""
        if self._module_registry is None:
            from app.modules import get_registry
            self._module_registry = get_registry()
        return self._module_registry

    async def run_scan(
        self,
        target: str,
        target_type: TargetType,
        target_inputs: dict[str, str] | None = None,
        phases: list[int] | None = None,
        module_filter: list[str] | None = None,
        show_progress: bool = True,
    ) -> ScanSession:
        """
        Execute a full OSINT scan.

        Args:
            target: The primary search target string.
            target_type: The type of target (email, username, etc.)
            target_inputs: Additional target data (e.g., {"email": "john@x.com", "username": "john"})
            phases: Optional list of phase numbers to run (default: all phases 1-8).
            module_filter: Optional list of module names to run (default: all enabled).
            show_progress: Show Rich progress bar in terminal.

        Returns:
            Completed ScanSession with all results.
        """
        session = ScanSession(target=target, target_type=target_type, target_inputs=target_inputs)
        session.start()

        # Audit log
        cache = await get_cache()
        await cache.audit(
            action="scan_started",
            request_id=session.request_id,
            target=target,
            details={"target_type": target_type.value},
        )
        await cache.save_scan(session.request_id, session.to_metadata().model_dump(mode="json"))

        try:
            # Determine which phases to run
            active_phases = sorted(phases or [p.value for p in ModulePhase])

            # Discover and filter modules
            registry = self._get_registry()
            available_modules = self._select_modules(
                registry, target_type, module_filter, active_phases
            )

            logger.info(
                "scan_modules_selected",
                request_id=session.request_id,
                total=sum(len(v) for v in available_modules.values()),
                phases=list(available_modules.keys()),
            )

            # Show pre-scan summary
            if show_progress:
                self._show_scan_summary(session, available_modules)

            # Run phases
            with self._build_progress() as progress:
                for phase_num in active_phases:
                    phase = ModulePhase(phase_num)
                    phase_modules = available_modules.get(phase_num, [])

                    if not phase_modules:
                        continue

                    task_id = progress.add_task(
                        f"[cyan]{PHASE_NAMES.get(phase, f'Phase {phase_num}')}",
                        total=len(phase_modules),
                    )

                    await self._run_phase(
                        session=session,
                        phase=phase,
                        modules=phase_modules,
                        progress=progress,
                        task_id=task_id,
                    )

            session.complete()

        except asyncio.CancelledError:
            session.status = ScanStatus.CANCELLED
            session.save_metadata()
            logger.info("scan_cancelled", request_id=session.request_id)
        except Exception as e:
            session.fail(str(e))
            logger.exception("scan_error", request_id=session.request_id, error=str(e))

        await cache.update_scan_status(
            session.request_id,
            session.status.value,
            completed_at=session.completed_at,
            total_findings=session.total_findings,
            risk_score=session.context.get("risk_score"),
            risk_level=session.context.get("risk_level"),
        )
        await cache.audit(
            action="scan_completed",
            request_id=session.request_id,
            target=target,
            details={"status": session.status.value, "findings": session.total_findings},
        )

        return session

    def _select_modules(
        self,
        registry: dict[str, Any],
        target_type: TargetType,
        module_filter: list[str] | None,
        active_phases: list[int],
    ) -> dict[int, list[Any]]:
        """
        Select modules to run based on target type, enabled status, and API availability.

        Returns a dict keyed by phase number, with list of module instances per phase.
        """
        selected: dict[int, list[Any]] = {}

        for name, module_cls in registry.items():
            try:
                module = module_cls()
                meta = module.metadata()

                # Filter by phase
                if meta.phase.value not in active_phases:
                    continue

                # Filter by target type
                if target_type not in meta.supported_targets:
                    continue

                # Filter by explicit module list
                if module_filter and name not in module_filter:
                    continue

                # Check if module is enabled in config.yaml
                from app.core.config import get_module_setting
                category = name.split("_")[0] if "_" in name else "misc"
                if not get_module_setting(category, name, "enabled", meta.enabled_by_default):
                    continue

                # Check API key availability
                if meta.requires_auth:
                    key_attr = f"{name}_api_key"
                    if not settings.has_api_key(key_attr) and not self._has_any_key_for_module(name):
                        logger.debug("module_skipped_no_key", module=name)
                        continue

                phase = meta.phase.value
                if phase not in selected:
                    selected[phase] = []
                selected[phase].append(module)

            except Exception as e:
                logger.warning("module_init_failed", module=name, error=str(e))

        return selected

    def _has_any_key_for_module(self, module_name: str) -> bool:
        """Check if any API key relevant to a module is configured."""
        # Map module names to their key attribute names
        key_map = {
            "hibp": "hibp_api_key",
            "dehashed": "dehashed_api_key",
            "hunter": "hunter_io_api_key",
            "intelx": "intelx_api_key",
            "google_cse": "google_cse_api_key",
            "bing": "bing_api_key",
            "shodan": "shodan_api_key",
            "github": "github_token",
            "twitter": "twitter_bearer_token",
            "reddit": "reddit_client_id",
            "youtube": "youtube_api_key",
            "whois": "whoisxml_api_key",
            "securitytrails": "securitytrails_api_key",
            "ipinfo": "ipinfo_token",
            "abuseipdb": "abuseipdb_api_key",
            "censys": "censys_api_id",
            "numverify": "numverify_api_key",
            "opencorporates": "opencorporates_api_token",
            "virustotal": "virustotal_api_key",
            "anthropic": "anthropic_api_key",
            "openai": "openai_api_key",
        }
        for key, attr in key_map.items():
            if key in module_name:
                return settings.has_api_key(attr)
        return False

    async def _run_phase(
        self,
        session: ScanSession,
        phase: ModulePhase,
        modules: list[Any],
        progress: Progress,
        task_id: TaskID,
    ) -> None:
        """
        Run all modules in a phase concurrently.

        Each module receives a copy of the current context dict.
        Results are collected and merged back into the session.
        """
        semaphore = asyncio.Semaphore(settings.max_concurrent_modules)
        if phase == ModulePhase.BROWSER_AUTH:
            semaphore = asyncio.Semaphore(settings.max_concurrent_browsers)

        logger.info(
            "phase_started",
            phase=phase.name,
            modules=[m.metadata().name for m in modules],
        )

        async def run_one(module: Any) -> None:
            async with semaphore:
                meta = module.metadata()
                try:
                    start = time.monotonic()
                    result = await module.run(
                        target=session.target,
                        target_type=session.target_type,
                        context=dict(session.context),
                    )
                    elapsed = int((time.monotonic() - start) * 1000)

                    if result.success:
                        session.modules_executed.append(meta.name)
                        session.total_findings += len(result.data) if isinstance(result.data, (list, dict)) else 1
                        # Save raw output
                        session.save_module_result(meta.name, result.data)
                        # Update shared context
                        session.context["module_results"][meta.name] = result.data
                        # Extract discovered entities
                        self._extract_entities(session, meta.name, result.data)
                        logger.info(
                            "module_success",
                            module=meta.name,
                            elapsed_ms=elapsed,
                        )
                    else:
                        session.modules_failed.append(meta.name)
                        logger.warning(
                            "module_failed",
                            module=meta.name,
                            errors=result.errors,
                        )

                except Exception as e:
                    session.modules_failed.append(meta.name)
                    logger.error("module_exception", module=meta.name, error=str(e))
                finally:
                    progress.advance(task_id)

        # Run all modules in this phase concurrently
        await asyncio.gather(
            *[run_one(m) for m in modules],
            return_exceptions=True,  # Never let one module failure kill the phase
        )

        session.save_metadata()
        logger.info("phase_completed", phase=phase.name)

    def _extract_entities(self, session: ScanSession, module_name: str, data: dict) -> None:
        """Extract discovered entities from module results and add to context."""
        if not isinstance(data, dict):
            return

        # Email extraction
        for key in ("email", "emails", "associated_emails", "dehashed_records"):
            if emails := data.get(key):
                if isinstance(emails, str):
                    session.add_discovered("email", emails)
                elif isinstance(emails, list):
                    for item in emails:
                        if isinstance(item, str):
                            session.add_discovered("email", item)
                        elif isinstance(item, dict):
                            if email := item.get("email") or item.get("address"):
                                session.add_discovered("email", email)

        # Username extraction
        for key in ("username", "usernames", "platforms", "handle"):
            if unames := data.get(key):
                if isinstance(unames, str):
                    session.add_discovered("username", unames)
                elif isinstance(unames, list):
                    for item in unames:
                        if isinstance(item, str):
                            session.add_discovered("username", item)
                        elif isinstance(item, dict):
                            if u := item.get("username") or item.get("handle"):
                                session.add_discovered("username", u)

        # Domain extraction
        if domain := data.get("domain"):
            session.add_discovered("domain", domain)

        # IP extraction
        for key in ("ip", "ip_address", "ips", "ip_addresses"):
            if ips := data.get(key):
                if isinstance(ips, str):
                    session.add_discovered("ip", ips)
                elif isinstance(ips, list):
                    for ip in ips:
                        if isinstance(ip, str):
                            session.add_discovered("ip", ip)

        # Image extraction
        if images := data.get("downloaded_images") or data.get("image_paths"):
            if isinstance(images, list):
                session.add_discovered("image", images)

        # Name extraction
        if name := data.get("name") or data.get("display_name"):
            session.add_discovered("name", str(name))

    def _show_scan_summary(
        self, session: ScanSession, modules_by_phase: dict[int, list]
    ) -> None:
        """Display a Rich table summarizing the upcoming scan."""
        table = Table(title=f"[bold cyan]GOD_EYE Scan — {session.request_id}[/bold cyan]")
        table.add_column("Phase", style="cyan")
        table.add_column("Modules", style="white")
        table.add_column("Count", style="green")

        for phase_num, modules in sorted(modules_by_phase.items()):
            phase = ModulePhase(phase_num)
            names = ", ".join(m.metadata().display_name for m in modules)
            table.add_row(
                PHASE_NAMES.get(phase, f"Phase {phase_num}"),
                names[:60] + ("..." if len(names) > 60 else ""),
                str(len(modules)),
            )

        console.print(table)
        console.print(f"[dim]Target: [bold]{session.target}[/bold] | Type: {session.target_type.value}[/dim]\n")

    def _build_progress(self) -> Progress:
        """Build a Rich progress display."""
        return Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
            console=console,
            transient=False,
        )
