"""
Main scan orchestrator — the heart of GOD_EYE.

Manages the full scan lifecycle:
1. Receive scan parameters
2. Discover available modules (filtered by target type + API key availability)
3. Execute modules in 8 phases (sequential phases, parallel within each phase)
4. Collect results, update progress, pass context to next phase
5. Trigger correlation, risk scoring, timeline generation, graph sync, and reports
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Awaitable, Callable
from typing import Any
from urllib.parse import urlparse

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

from app.ai.correlation_engine import CorrelationEngine
from app.ai.report_generator import ReportGenerator
from app.ai.risk_scorer import RiskScorer
from app.ai.timeline_builder import TimelineBuilder
from app.core.config import get_module_setting, settings
from app.core.constants import ModulePhase, ScanStatus, TargetType
from app.core.logging import get_audit_logger, get_logger
from app.database.sqlite_cache import get_cache
from app.engine.session import ScanSession
from app.modules.base import ModuleResult
from app.utils.target_resolution import (
    build_target_candidates,
    candidate_type_set,
    choose_execution_target,
)

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
    ModulePhase.AI_CORRELATION: "Correlation & Risk",
    ModulePhase.REPORT_GEN: "Report Generation",
}

MODULE_CONFIG_ALIASES: dict[str, str] = {
    "hunter_io": "hunter",
    "sherlock_wrapper": "sherlock",
    "maigret_wrapper": "maigret",
    "github_api": "github",
    "reddit_api": "reddit",
    "twitter_api": "twitter",
    "youtube_api": "youtube",
    "linkedin_scraper": "linkedin",
    "instagram_scraper": "instagram",
    "facebook_scraper": "facebook",
    "whois_lookup": "whois",
    "dns_recon": "dns",
    "subdomain_enum": "subdomains",
    "certificate_search": "certificates",
    "shodan_search": "shodan",
    "image_downloader": "downloader",
    "exif_extractor": "exif",
    "reverse_image_search": "reverse_image",
    "crawl4ai_crawler": "crawl4ai",
}

ProgressCallback = Callable[[dict[str, Any]], Awaitable[None]]

MULTI_TARGET_MODULES = frozenset(
    {
        "dns_recon",
        "whois_lookup",
        "certificate_search",
        "subdomain_enum",
        "ip_lookup",
        "shodan_search",
        "geolocation",
    }
)


class Orchestrator:
    """
    Phase-based scan orchestrator.

    Phases run sequentially. Within each phase, all compatible modules
    run in parallel using asyncio.gather().

    Error isolation: a module failure never stops other modules or the scan.
    """

    def __init__(self, progress_callback: ProgressCallback | None = None) -> None:
        self._module_registry: dict[str, Any] | None = None
        self._progress_callback = progress_callback

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
        request_id: str | None = None,
        enable_ai_correlation: bool | None = None,
        enable_ai_reports: bool | None = None,
    ) -> ScanSession:
        """
        Execute a full OSINT scan.

        Returns a ScanSession populated with module results, correlation data,
        generated reports, and final metadata.
        """
        session = ScanSession(
            target=target,
            target_type=target_type,
            target_inputs=target_inputs,
            request_id=request_id,
        )
        session.context["enable_ai_correlation"] = (
            settings.enable_ai_correlation
            if enable_ai_correlation is None
            else enable_ai_correlation
        )
        session.context["enable_ai_reports"] = (
            settings.enable_ai_reports if enable_ai_reports is None else enable_ai_reports
        )
        session.start()

        cache = await get_cache()
        await cache.audit(
            action="scan_started",
            request_id=session.request_id,
            target=target,
            details={"target_type": target_type.value},
        )
        await cache.save_scan(session.request_id, session.to_metadata().model_dump(mode="json"))
        await self._publish_progress(
            session,
            status=session.status.value,
            phase=0,
            phase_name="initializing",
            completed_modules=0,
            total_modules=0,
        )

        try:
            active_phases = sorted(set(phases or [phase.value for phase in ModulePhase]))
            registry = self._get_registry()
            available_modules = self._select_modules(
                registry=registry,
                target=target,
                target_type=target_type,
                target_inputs=session.target_inputs,
                module_filter=module_filter,
                active_phases=active_phases,
            )

            logger.info(
                "scan_modules_selected",
                request_id=session.request_id,
                total=sum(len(v) for v in available_modules.values()),
                phases=active_phases,
            )

            if show_progress:
                self._show_scan_summary(session, available_modules, active_phases)

            with self._build_progress(disable=not show_progress) as progress:
                for phase_num in active_phases:
                    phase = ModulePhase(phase_num)

                    if phase == ModulePhase.AI_CORRELATION:
                        task_id = progress.add_task(
                            f"[cyan]{PHASE_NAMES[phase]}",
                            total=3,
                        )
                        await self._run_ai_phase(session, progress, task_id)
                        continue

                    if phase == ModulePhase.REPORT_GEN:
                        task_id = progress.add_task(
                            f"[cyan]{PHASE_NAMES[phase]}",
                            total=1,
                        )
                        await self._run_report_phase(session, progress, task_id)
                        continue

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

            await self._sync_graph(session)
            if session.status != ScanStatus.CANCELLED:
                session.complete()
            await self._publish_progress(
                session,
                status=session.status.value,
                phase=999,
                phase_name="completed",
                completed_modules=len(session.modules_executed),
                total_modules=len(session.modules_executed) + len(session.modules_failed),
            )
        except asyncio.CancelledError:
            session.status = ScanStatus.CANCELLED
            session.completed_at = session.completed_at or session.started_at
            session.save_metadata()
            logger.info("scan_cancelled", request_id=session.request_id)
            await self._publish_progress(
                session,
                status=session.status.value,
                phase=999,
                phase_name="cancelled",
            )
        except Exception as exc:
            session.fail(str(exc))
            logger.exception("scan_error", request_id=session.request_id, error=str(exc))
            await self._publish_progress(
                session,
                status=session.status.value,
                phase=999,
                phase_name="failed",
                error=str(exc),
            )

        await cache.update_scan_status(
            session.request_id,
            session.status.value,
            completed_at=session.completed_at,
            total_findings=session.total_findings,
            risk_score=session.context.get("risk_score"),
            risk_level=session.context.get("risk_level"),
        )
        await cache.save_scan(session.request_id, session.to_metadata().model_dump(mode="json"))
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
        target: str,
        target_type: TargetType,
        target_inputs: dict[str, str],
        module_filter: list[str] | None,
        active_phases: list[int],
    ) -> dict[int, list[Any]]:
        """Select modules to run based on target type, config, and auth availability."""
        selected: dict[int, list[Any]] = {}
        requested = {name.strip() for name in module_filter or []}
        available_target_types = candidate_type_set(target, target_type, target_inputs, {})

        for name, module_cls in registry.items():
            try:
                module = module_cls()
                meta = module.metadata()

                if meta.phase.value not in active_phases:
                    continue
                if available_target_types.isdisjoint(set(meta.supported_targets)):
                    continue

                config_names = set(self._module_config_names(module_cls, meta))
                if requested and requested.isdisjoint({meta.name, *config_names}):
                    continue
                if not self._is_module_enabled(module_cls, meta):
                    continue
                if meta.requires_auth and not self._has_any_key_for_module(meta.name):
                    logger.debug("module_skipped_no_key", module=meta.name)
                    continue

                selected.setdefault(meta.phase.value, []).append(module)
            except Exception as exc:
                logger.warning("module_init_failed", module=name, error=str(exc))

        for modules in selected.values():
            modules.sort(key=lambda module: module.metadata().priority)
        return selected

    def _module_config_names(self, module_cls: type[Any], meta: Any) -> list[str]:
        """Generate config.yaml name candidates for a module."""
        module_path_name = module_cls.__module__.split(".")[-1]
        names = [
            module_path_name,
            meta.name,
            MODULE_CONFIG_ALIASES.get(module_path_name, ""),
            MODULE_CONFIG_ALIASES.get(meta.name, ""),
        ]
        derived: list[str] = []
        for name in names:
            if not name:
                continue
            derived.append(name)
            for suffix in (
                "_api",
                "_scraper",
                "_wrapper",
                "_lookup",
                "_search",
                "_recon",
                "_extractor",
                "_crawler",
            ):
                if name.endswith(suffix):
                    derived.append(name[: -len(suffix)])
        return [name for name in dict.fromkeys(derived) if name]

    def _is_module_enabled(self, module_cls: type[Any], meta: Any) -> bool:
        """Resolve config.yaml enable/disable flags using both old and new names."""
        module_parts = module_cls.__module__.split(".")
        category = module_parts[2] if len(module_parts) > 2 else "misc"
        for candidate in self._module_config_names(module_cls, meta):
            enabled = get_module_setting(category, candidate, "enabled", None)
            if enabled is not None:
                return bool(enabled)
        return bool(meta.enabled_by_default)

    def _has_any_key_for_module(self, module_name: str) -> bool:
        """Check if any API key relevant to a module is configured."""
        key_map = {
            "hibp": "hibp_api_key",
            "dehashed": "dehashed_api_key",
            "hunter": "hunter_io_api_key",
            "intelx": "intelx_api_key",
            "serpapi": "serpapi_api_key",
            "bing": "bing_api_key",
            "shodan": "shodan_api_key",
            "shodan_search": "shodan_api_key",
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
        }
        if "linkedin" in module_name:
            return bool(settings.linkedin_email and settings.linkedin_password)
        if "instagram" in module_name:
            return bool(settings.instagram_username and settings.instagram_password)
        if "facebook" in module_name:
            return bool(settings.facebook_email and settings.facebook_password)
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
        """Run all modules in a phase concurrently."""
        semaphore = asyncio.Semaphore(settings.max_concurrent_modules)
        if phase == ModulePhase.BROWSER_AUTH:
            semaphore = asyncio.Semaphore(settings.max_concurrent_browsers)

        completed_modules = 0
        completed_lock = asyncio.Lock()

        logger.info(
            "phase_started",
            request_id=session.request_id,
            phase=phase.name,
            modules=[module.metadata().name for module in modules],
        )
        await self._publish_progress(
            session,
            status=session.status.value,
            phase=phase.value,
            phase_name=phase.name,
            completed_modules=0,
            total_modules=len(modules),
        )

        async def run_one(module: Any) -> None:
            nonlocal completed_modules
            async with semaphore:
                meta = module.metadata()
                result = await self._execute_module(session, module)
                if result is None:
                    session.modules_skipped.append(meta.name)
                elif result.success:
                    session.modules_executed.append(meta.name)
                    session.total_findings += result.findings_count
                    await session.save_module_result(meta.name, result.data)
                    session.context["module_results"][meta.name] = result.data
                    self._merge_discovered_context(session, result.data)
                    self._extract_entities(session, meta.name, result.data)
                    logger.info("module_success", module=meta.name, findings=result.findings_count)
                else:
                    session.modules_failed.append(meta.name)
                    session.context["module_results"][meta.name] = result.data
                    logger.warning("module_failed", module=meta.name, errors=result.errors)

                async with completed_lock:
                    completed_modules += 1
                    progress.advance(task_id)
                    await self._publish_progress(
                        session,
                        status=session.status.value,
                        phase=phase.value,
                        phase_name=phase.name,
                        module=meta.name,
                        module_success=result.success if result else False,
                        completed_modules=completed_modules,
                        total_modules=len(modules),
                    )

        image_preload_modules = []
        remaining_modules = modules
        if phase == ModulePhase.IMAGE_PROCESSING:
            image_preload_modules = [
                module for module in modules if module.metadata().name == "image_downloader"
            ]
            remaining_modules = [
                module for module in modules if module.metadata().name != "image_downloader"
            ]

        for module in image_preload_modules:
            await run_one(module)

        await asyncio.gather(
            *(run_one(module) for module in remaining_modules), return_exceptions=False
        )
        session.save_metadata()
        logger.info("phase_completed", request_id=session.request_id, phase=phase.name)

    async def _execute_module(self, session: ScanSession, module: Any) -> ModuleResult | None:
        """Validate and execute a single module."""
        meta = module.metadata()
        execution_plan = self._build_execution_plan(session, meta)
        if not execution_plan:
            return None

        if len(execution_plan) == 1:
            execution_target, execution_type, context = execution_plan[0]
            return await self._execute_single_target_module(
                module,
                meta,
                execution_target,
                execution_type,
                context,
                session.target_inputs,
            )

        results: list[tuple[str, ModuleResult | None]] = []
        for execution_target, execution_type, context in execution_plan:
            result = await self._execute_single_target_module(
                module,
                meta,
                execution_target,
                execution_type,
                context,
                session.target_inputs,
            )
            results.append((execution_target, result))

        return self._aggregate_multi_target_results(meta, results)

    async def _execute_single_target_module(
        self,
        module: Any,
        meta: Any,
        execution_target: str,
        execution_type: TargetType,
        context: dict[str, Any],
        target_inputs: dict[str, str],
    ) -> ModuleResult | None:
        try:
            is_valid = await module.validate(
                execution_target,
                execution_type,
                context=context,
                target_inputs=target_inputs,
            )
            if not is_valid:
                logger.info(
                    "module_skipped_validation",
                    module=meta.name,
                    target=execution_target,
                    target_type=execution_type.value,
                )
                return None

            start = time.monotonic()
            result = await module.run(
                target=execution_target,
                target_type=execution_type,
                context=context,
                target_inputs=target_inputs,
            )
            elapsed = int((time.monotonic() - start) * 1000)
            result.execution_time_ms = result.execution_time_ms or elapsed
            result.target = execution_target
            return result
        except Exception as exc:
            logger.error("module_exception", module=meta.name, error=str(exc))
            return ModuleResult.fail(
                str(exc),
                module_name=meta.name,
                target=execution_target,
            )

    def _build_execution_plan(
        self,
        session: ScanSession,
        meta: Any,
    ) -> list[tuple[str, TargetType, dict[str, Any]]]:
        execution_target, execution_type, context = self._build_execution_context(session, meta)
        if meta.name not in MULTI_TARGET_MODULES:
            return [(execution_target, execution_type, context)]

        candidates = build_target_candidates(
            primary_target=session.target,
            primary_type=session.target_type,
            target_inputs=session.target_inputs,
            context=session.context,
        )

        _ip_preferred_modules = {"ip_lookup", "shodan_search", "geolocation"}
        if meta.name in _ip_preferred_modules:
            ip_targets = candidates.get(TargetType.IP, [])
            if ip_targets:
                max_ips = max(
                    1,
                    int(get_module_setting("network", meta.name, "max_targets", 20) or 20),
                )
                return [
                    self._build_context_for_target(meta, session, target, TargetType.IP, candidates)
                    for target in ip_targets[:max_ips]
                ]

        domain_targets = candidates.get(TargetType.DOMAIN, [])
        if not domain_targets:
            return [(execution_target, execution_type, context)]

        max_targets = max(
            1,
            int(
                get_module_setting(
                    "domain", "permutator", "max_registered_domains_to_deep_scan", 25
                )
                or 25
            ),
        )
        return [
            self._build_context_for_target(meta, session, target, TargetType.DOMAIN, candidates)
            for target in domain_targets[:max_targets]
        ]

    def _build_context_for_target(
        self,
        meta: Any,
        session: ScanSession,
        execution_target: str,
        execution_type: TargetType,
        candidates: dict[TargetType, list[str]],
    ) -> tuple[str, TargetType, dict[str, Any]]:
        context = dict(session.context)
        context["resolved_targets"] = {
            target_type.value: values for target_type, values in candidates.items()
        }
        context["module_execution_target"] = {
            "module": meta.name,
            "target": execution_target,
            "target_type": execution_type.value,
        }
        return execution_target, execution_type, context

    def _build_execution_context(
        self,
        session: ScanSession,
        meta: Any,
    ) -> tuple[str, TargetType, dict[str, Any]]:
        """Choose the best execution target for a module and annotate context."""
        context = dict(session.context)
        candidates = build_target_candidates(
            primary_target=session.target,
            primary_type=session.target_type,
            target_inputs=session.target_inputs,
            context=session.context,
        )
        execution_target, execution_type = choose_execution_target(
            module_name=meta.name,
            supported_targets=list(meta.supported_targets),
            candidates=candidates,
            primary_target=session.target,
            primary_type=session.target_type,
        )
        context["resolved_targets"] = {
            target_type.value: values for target_type, values in candidates.items()
        }
        context["module_execution_target"] = {
            "module": meta.name,
            "target": execution_target,
            "target_type": execution_type.value,
        }
        return execution_target, execution_type, context

    def _aggregate_multi_target_results(
        self,
        meta: Any,
        results: list[tuple[str, ModuleResult | None]],
    ) -> ModuleResult:
        successes: list[dict[str, Any]] = []
        failures: list[dict[str, Any]] = []
        aggregated_errors: list[str] = []
        aggregated_warnings: list[str] = []
        discovered_payloads: dict[str, list[Any]] = {}
        total_findings = 0
        total_elapsed = 0

        for target, result in results:
            if result is None:
                continue
            total_elapsed += result.execution_time_ms
            total_findings += result.findings_count
            aggregated_warnings.extend(result.warnings)
            if result.success:
                successes.append(
                    {
                        "target": target,
                        "data": result.data,
                    }
                )
                if isinstance(result.data, dict):
                    for key, value in result.data.items():
                        if not key.startswith("discovered_"):
                            continue
                        bucket = discovered_payloads.setdefault(key, [])
                        if isinstance(value, list):
                            for item in value:
                                if item not in bucket:
                                    bucket.append(item)
                        elif value not in bucket:
                            bucket.append(value)
            else:
                failures.append({"target": target, "errors": result.errors})
                aggregated_errors.extend(result.errors)

        return ModuleResult(
            success=bool(successes),
            module_name=meta.name,
            target="multiple",
            execution_time_ms=total_elapsed,
            findings_count=total_findings,
            data={
                "targets_scanned": [item["target"] for item in successes]
                + [item["target"] for item in failures],
                "successful_targets": [item["target"] for item in successes],
                "failed_targets": failures,
                "results_by_target": {item["target"]: item["data"] for item in successes},
                **discovered_payloads,
            },
            errors=aggregated_errors,
            warnings=aggregated_warnings,
        )

    async def _run_ai_phase(
        self, session: ScanSession, progress: Progress, task_id: TaskID
    ) -> None:
        """Run correlation, timeline, and risk scoring."""
        steps = [
            ("correlation", CorrelationEngine().run),
            ("timeline", TimelineBuilder().run),
            ("risk_scoring", RiskScorer().run),
        ]
        completed_steps = 0
        await self._publish_progress(
            session,
            status=session.status.value,
            phase=ModulePhase.AI_CORRELATION.value,
            phase_name=ModulePhase.AI_CORRELATION.name,
            completed_modules=0,
            total_modules=len(steps),
        )

        for step_name, handler in steps:
            try:
                result = await handler(session)
                if step_name == "correlation":
                    session.context["correlation"] = result
                elif step_name == "timeline":
                    session.context["timeline"] = [event.model_dump() for event in result]
                elif step_name == "risk_scoring":
                    session.context["risk_assessment"] = result.model_dump()
            except Exception as exc:
                session.modules_failed.append(step_name)
                logger.error("ai_phase_failed", step=step_name, error=str(exc))
            finally:
                completed_steps += 1
                progress.advance(task_id)
                await self._publish_progress(
                    session,
                    status=session.status.value,
                    phase=ModulePhase.AI_CORRELATION.value,
                    phase_name=ModulePhase.AI_CORRELATION.name,
                    module=step_name,
                    completed_modules=completed_steps,
                    total_modules=len(steps),
                )
        session.save_metadata()

    async def _run_report_phase(
        self, session: ScanSession, progress: Progress, task_id: TaskID
    ) -> None:
        """Generate report artifacts for the session."""
        await self._publish_progress(
            session,
            status=session.status.value,
            phase=ModulePhase.REPORT_GEN.value,
            phase_name=ModulePhase.REPORT_GEN.name,
            completed_modules=0,
            total_modules=1,
        )
        try:
            paths = await ReportGenerator().generate_all(session)
            session.context["report_paths"] = {fmt: str(path) for fmt, path in paths.items()}
        except Exception as exc:
            session.modules_failed.append("report_generation")
            logger.error("report_phase_failed", request_id=session.request_id, error=str(exc))
        finally:
            progress.advance(task_id)
            await self._publish_progress(
                session,
                status=session.status.value,
                phase=ModulePhase.REPORT_GEN.value,
                phase_name=ModulePhase.REPORT_GEN.name,
                module="report_generation",
                completed_modules=1,
                total_modules=1,
            )
            session.save_metadata()

    async def _sync_graph(self, session: ScanSession) -> None:
        """Persist the discovered graph to Neo4j on a best-effort basis."""
        try:
            from app.database.neo4j_client import Neo4jClient

            client = Neo4jClient()
            await client.connect()
        except Exception as exc:
            logger.info("graph_sync_skipped", request_id=session.request_id, error=str(exc))
            return

        try:
            primary_node_id = await self._create_primary_node(client, session)

            for email in session.context.get("discovered_emails", []):
                email_id = await client.create_email(email, {"request_id": session.request_id})
                if primary_node_id and session.target_type != TargetType.EMAIL:
                    await client.link_nodes(
                        primary_node_id, email_id, "HAS_EMAIL", {"request_id": session.request_id}
                    )

            for username in session.context.get("discovered_usernames", []):
                username_id = await client.create_username(
                    username,
                    "unknown",
                    {"request_id": session.request_id},
                )
                if primary_node_id and session.target_type != TargetType.USERNAME:
                    await client.link_nodes(
                        primary_node_id,
                        username_id,
                        "HAS_USERNAME",
                        {"request_id": session.request_id},
                    )

            for domain in session.context.get("discovered_domains", []):
                domain_id = await client.create_domain(domain, {"request_id": session.request_id})
                if primary_node_id and session.target_type != TargetType.DOMAIN:
                    await client.link_nodes(
                        primary_node_id, domain_id, "HAS_DOMAIN", {"request_id": session.request_id}
                    )

            for ip in session.context.get("discovered_ips", []):
                ip_id = await client.create_ip(ip, {"request_id": session.request_id})
                if primary_node_id and session.target_type != TargetType.IP:
                    await client.link_nodes(
                        primary_node_id, ip_id, "HAS_IP", {"request_id": session.request_id}
                    )

            target_email_id = None
            if session.target_type == TargetType.EMAIL:
                target_email_id = primary_node_id
            elif session.target_inputs.get("email"):
                target_email_id = await client.create_email(
                    session.target_inputs["email"],
                    {"request_id": session.request_id},
                )
                if primary_node_id:
                    await client.link_nodes(
                        primary_node_id,
                        target_email_id,
                        "HAS_EMAIL",
                        {"request_id": session.request_id},
                    )

            for module_data in session.context.get("module_results", {}).values():
                if not isinstance(module_data, dict):
                    continue
                breach_entries = (
                    module_data.get("breaches") or module_data.get("breach_details") or []
                )
                for breach in breach_entries if isinstance(breach_entries, list) else []:
                    if not isinstance(breach, dict):
                        continue
                    breach_name = breach.get("name") or breach.get("Name")
                    if not breach_name:
                        continue
                    breach_id = await client.create_breach(
                        breach_name,
                        {
                            "request_id": session.request_id,
                            "breach_date": breach.get("breach_date") or breach.get("BreachDate"),
                        },
                    )
                    if target_email_id:
                        await client.link_nodes(
                            target_email_id,
                            breach_id,
                            "EXPOSED_IN",
                            {"request_id": session.request_id},
                        )
        except Exception as exc:
            logger.warning("graph_sync_failed", request_id=session.request_id, error=str(exc))
        finally:
            await client.disconnect()

    async def _create_primary_node(self, client: Any, session: ScanSession) -> str | None:
        """Create the primary graph node for the scan target."""
        if session.target_type == TargetType.PERSON:
            return await client.create_person(session.target, request_id=session.request_id)
        if session.target_type == TargetType.EMAIL:
            return await client.create_email(session.target, {"request_id": session.request_id})
        if session.target_type == TargetType.USERNAME:
            return await client.create_username(
                session.target, "unknown", {"request_id": session.request_id}
            )
        if session.target_type == TargetType.DOMAIN:
            return await client.create_domain(session.target, {"request_id": session.request_id})
        if session.target_type == TargetType.IP:
            return await client.create_ip(session.target, {"request_id": session.request_id})
        if session.target_type == TargetType.COMPANY:
            return await client.create_company(session.target, {"request_id": session.request_id})
        return None

    async def _publish_progress(self, session: ScanSession, **payload: Any) -> None:
        """Emit progress updates to any caller-provided callback."""
        if self._progress_callback is None:
            return
        data = {
            "request_id": session.request_id,
            "target": session.target,
            "target_type": session.target_type.value,
            "findings": session.total_findings,
            "risk_score": session.context.get("risk_score"),
            **payload,
        }
        await self._progress_callback(data)

    def _extract_entities(
        self, session: ScanSession, module_name: str, data: dict[str, Any]
    ) -> None:
        """Extract discovered entities from module results and add them to context."""
        if not isinstance(data, dict):
            return

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

        for key in ("username", "usernames", "platforms", "handle", "found_platforms"):
            if usernames := data.get(key):
                if isinstance(usernames, str):
                    session.add_discovered("username", usernames)
                elif isinstance(usernames, list):
                    for item in usernames:
                        if isinstance(item, str):
                            session.add_discovered("username", item)
                        elif isinstance(item, dict):
                            if username := item.get("username") or item.get("handle"):
                                session.add_discovered("username", username)

        for key in (
            "domain",
            "domains",
            "discovered_domains",
            "registered_domain",
            "registrar_domain",
        ):
            if domains := data.get(key):
                if isinstance(domains, str):
                    session.add_discovered("domain", domains)
                elif isinstance(domains, list):
                    for d in domains:
                        if isinstance(d, str):
                            session.add_discovered("domain", d)
                        elif isinstance(d, dict):
                            if dv := d.get("domain") or d.get("name"):
                                session.add_discovered("domain", dv)

        for key in ("ip", "ip_address", "ips", "ip_addresses", "discovered_ips", "a_records"):
            if ips := data.get(key):
                if isinstance(ips, str):
                    session.add_discovered("ip", ips)
                elif isinstance(ips, list):
                    for ip in ips:
                        if isinstance(ip, str):
                            session.add_discovered("ip", ip)

        for key in ("phone", "phone_number", "phones"):
            if phones := data.get(key):
                if isinstance(phones, str):
                    session.add_discovered("phone", phones)
                elif isinstance(phones, list):
                    for ph in phones:
                        if isinstance(ph, str):
                            session.add_discovered("phone", ph)

        for key in ("location", "city", "country"):
            if loc := data.get(key):
                if isinstance(loc, str):
                    session.add_discovered("location", loc)

        if images := data.get("downloaded_images") or data.get("image_paths"):
            if isinstance(images, list):
                session.add_discovered("image", images)

        if name := data.get("name") or data.get("display_name"):
            session.add_discovered("name", str(name))

        self._extract_entities_from_urls(session, data)

    def _extract_entities_from_urls(self, session: ScanSession, payload: Any) -> None:
        """Walk nested module payloads and derive entities from discovered profile URLs."""
        if isinstance(payload, dict):
            for value in payload.values():
                self._extract_entities_from_urls(session, value)
            return

        if isinstance(payload, list):
            for item in payload:
                self._extract_entities_from_urls(session, item)
            return

        if not isinstance(payload, str) or "http" not in payload:
            return

        self._extract_profile_entities_from_url(session, payload)

    def _extract_profile_entities_from_url(self, session: ScanSession, value: str) -> None:
        """Extract usernames and profile URLs from known social platform URL shapes."""
        try:
            parsed = urlparse(value.strip())
        except Exception:
            return

        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            return

        host = parsed.netloc.lower()
        parts = [part for part in parsed.path.split("/") if part]
        if not parts:
            return

        session.add_discovered("domain", parsed.netloc)

        first = parts[0]

        if "instagram.com" in host:
            if first not in {"p", "reel", "explore", "accounts", "stories", "direct", "channels"}:
                session.add_discovered("username", first)
                self._append_discovered_profile_url(
                    session,
                    "discovered_instagram_profiles",
                    {"url": value, "username": first},
                )
            return

        if "linkedin.com" in host:
            if first == "in" and len(parts) >= 2:
                session.add_discovered("username", parts[1])
                self._append_discovered_profile_url(
                    session,
                    "discovered_linkedin_profiles",
                    {"url": value, "slug": parts[1]},
                )
            return

        if "github.com" in host and first not in {
            "features",
            "topics",
            "orgs",
            "organizations",
            "settings",
            "marketplace",
            "pricing",
        }:
            session.add_discovered("username", first)
            return

        if ("twitter.com" in host or "x.com" in host) and first not in {
            "home",
            "search",
            "explore",
            "i",
            "settings",
            "messages",
            "compose",
        }:
            session.add_discovered("username", first.lstrip("@"))
            return

        if "reddit.com" in host and first in {"u", "user"} and len(parts) >= 2:
            session.add_discovered("username", parts[1])
            return

        if "facebook.com" in host and first not in {
            "public",
            "profile.php",
            "login",
            "watch",
            "marketplace",
        }:
            session.add_discovered("username", first)
            return

        if "youtube.com" in host and first.startswith("@"):
            session.add_discovered("username", first.lstrip("@"))

    @staticmethod
    def _append_discovered_profile_url(
        session: ScanSession,
        key: str,
        item: dict[str, Any],
    ) -> None:
        existing = session.context.setdefault(key, [])
        if isinstance(existing, list) and item not in existing:
            existing.append(item)

    def _merge_discovered_context(self, session: ScanSession, data: dict[str, Any]) -> None:
        """Persist explicit discovered_* payloads that modules return for later phases."""
        if not isinstance(data, dict):
            return

        for key, value in data.items():
            if not key.startswith("discovered_"):
                continue
            existing = session.context.setdefault(key, [])
            if not isinstance(existing, list):
                existing = []
                session.context[key] = existing

            if isinstance(value, list):
                for item in value:
                    if item and item not in existing:
                        existing.append(item)
            elif value and value not in existing:
                existing.append(value)

    def _show_scan_summary(
        self,
        session: ScanSession,
        modules_by_phase: dict[int, list[Any]],
        active_phases: list[int],
    ) -> None:
        """Display a Rich table summarizing the upcoming scan."""
        table = Table(title=f"[bold cyan]GOD_EYE Scan — {session.request_id}[/bold cyan]")
        table.add_column("Phase", style="cyan")
        table.add_column("Modules", style="white")
        table.add_column("Count", style="green")

        for phase_num in active_phases:
            phase = ModulePhase(phase_num)
            if phase in (ModulePhase.AI_CORRELATION, ModulePhase.REPORT_GEN):
                names = (
                    "Correlation, Timeline, Risk Scoring"
                    if phase == ModulePhase.AI_CORRELATION
                    else "Report Generator"
                )
                count = 3 if phase == ModulePhase.AI_CORRELATION else 1
            else:
                phase_modules = modules_by_phase.get(phase_num, [])
                if not phase_modules:
                    continue
                names = ", ".join(module.metadata().display_name for module in phase_modules)
                count = len(phase_modules)

            table.add_row(
                PHASE_NAMES.get(phase, f"Phase {phase_num}"),
                names[:60] + ("..." if len(names) > 60 else ""),
                str(count),
            )

        console.print(table)
        console.print(
            f"[dim]Target: [bold]{session.target}[/bold] | Type: {session.target_type.value}[/dim]\n"
        )

    def _build_progress(self, disable: bool = False) -> Progress:
        """Build a Rich progress display."""
        return Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
            console=console,
            transient=False,
            disable=disable,
        )
