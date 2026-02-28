"""
Subdomain enumeration module using three methods:
1. crt.sh certificate transparency logs
2. SecurityTrails API
3. DNS brute force against common subdomain list

All three methods run in parallel, results are merged and deduplicated.
Each discovered subdomain is verified with a live DNS lookup.
"""

import asyncio
import time
from typing import Any

import aiohttp
import dns.resolver
import dns.exception
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type

from app.core.config import settings
from app.core.constants import TargetType, ModulePhase, COMMON_SUBDOMAINS
from app.core.exceptions import APIError, RateLimitError
from app.core.logging import get_logger
from app.modules.base import BaseModule, ModuleMetadata, ModuleResult

logger = get_logger(__name__)


class SubdomainEnum(BaseModule):
    """Enumerate subdomains using crt.sh, SecurityTrails, and DNS brute force."""

    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            name="subdomain_enum",
            display_name="Subdomain Enumeration",
            description="Discover subdomains via certificate logs, SecurityTrails API, and DNS brute force",
            supported_targets=[TargetType.DOMAIN],
            phase=ModulePhase.DEEP_ANALYSIS,
            requires_auth=False,
            requires_proxy=False,
            requires_browser=False,
            rate_limit_rpm=30,
            timeout_seconds=120,
            priority=3,
            enabled_by_default=True,
        )

    async def validate(self, target: str, target_type: TargetType) -> bool:
        return target_type == TargetType.DOMAIN and "." in target and " " not in target

    async def run(self, target: str, target_type: TargetType, context: dict) -> ModuleResult:
        start = time.monotonic()
        domain = target.lower().strip().lstrip("www.")

        try:
            # Run all three methods in parallel
            crt_task = self._crt_sh(domain)
            st_task = self._securitytrails(domain)
            bf_task = self._brute_force(domain)

            results = await asyncio.gather(crt_task, st_task, bf_task, return_exceptions=True)

            all_subdomains: set[str] = set()
            methods_used: list[str] = []

            for i, (method_name, result) in enumerate(
                zip(["crt.sh", "securitytrails", "bruteforce"], results)
            ):
                if isinstance(result, Exception):
                    logger.warning(f"subdomain_method_failed", method=method_name, error=str(result))
                elif isinstance(result, set):
                    all_subdomains.update(result)
                    methods_used.append(method_name)

            # Verify each subdomain is alive (DNS resolves)
            verified = await self._verify_subdomains(list(all_subdomains), domain)

            elapsed = int((time.monotonic() - start) * 1000)
            alive = [s for s in verified if s.get("is_alive")]

            return ModuleResult(
                module_name=self.metadata().name,
                target=target,
                success=True,
                data={
                    "domain": domain,
                    "subdomains": verified,
                    "total_found": len(verified),
                    "alive_count": len(alive),
                    "methods_used": methods_used,
                },
                execution_time_ms=elapsed,
            )

        except Exception as e:
            logger.error("subdomain_enum_failed", domain=domain, error=str(e))
            return ModuleResult(
                module_name=self.metadata().name,
                target=target,
                success=False,
                errors=[str(e)],
            )

    async def _crt_sh(self, domain: str) -> set[str]:
        """Query crt.sh certificate transparency logs."""
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        subdomains: set[str] = set()

        async with aiohttp.ClientSession() as session:
            async with session.get(
                url,
                timeout=aiohttp.ClientTimeout(total=30),
                headers={"User-Agent": "god_eye/1.0"},
            ) as resp:
                if resp.status != 200:
                    return subdomains
                data = await resp.json(content_type=None)

        for entry in data:
            name = entry.get("name_value", "")
            for line in name.splitlines():
                line = line.strip().lstrip("*.")
                if line.endswith(f".{domain}") or line == domain:
                    subdomains.add(line.lower())

        logger.debug("crt_sh_found", domain=domain, count=len(subdomains))
        return subdomains

    async def _securitytrails(self, domain: str) -> set[str]:
        """Query SecurityTrails API for subdomains."""
        if not settings.has_api_key("securitytrails_api_key"):
            return set()

        url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
        headers = {"APIKEY": settings.securitytrails_api_key.get_secret_value()}
        subdomains: set[str] = set()

        async with aiohttp.ClientSession() as session:
            async with session.get(
                url,
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=30),
            ) as resp:
                if resp.status == 401:
                    raise APIError("securitytrails", 401, "Invalid API key")
                if resp.status == 429:
                    raise RateLimitError("securitytrails")
                if resp.status != 200:
                    return subdomains
                data = await resp.json()

        for sub in data.get("subdomains", []):
            subdomains.add(f"{sub}.{domain}".lower())

        logger.debug("securitytrails_found", domain=domain, count=len(subdomains))
        return subdomains

    async def _brute_force(self, domain: str) -> set[str]:
        """DNS brute force using common subdomain prefixes."""
        found: set[str] = set()
        semaphore = asyncio.Semaphore(20)
        resolver = dns.resolver.Resolver()
        resolver.timeout = 2
        resolver.lifetime = 2

        async def check(prefix: str) -> None:
            subdomain = f"{prefix}.{domain}"
            async with semaphore:
                try:
                    loop = asyncio.get_event_loop()
                    await loop.run_in_executor(
                        None, resolver.resolve, subdomain, "A"
                    )
                    found.add(subdomain)
                except Exception:
                    pass

        await asyncio.gather(*[check(p) for p in COMMON_SUBDOMAINS])
        logger.debug("bruteforce_found", domain=domain, count=len(found))
        return found

    async def _verify_subdomains(
        self, subdomains: list[str], root_domain: str
    ) -> list[dict[str, Any]]:
        """Verify each subdomain with a live DNS lookup."""
        semaphore = asyncio.Semaphore(20)
        resolver = dns.resolver.Resolver()
        resolver.timeout = 3
        resolver.lifetime = 3
        results: list[dict[str, Any]] = []

        async def verify(sub: str) -> dict[str, Any]:
            async with semaphore:
                # Determine source
                source = "brute_force" if sub.split(".")[0] in COMMON_SUBDOMAINS else "passive"
                try:
                    loop = asyncio.get_event_loop()
                    answers = await loop.run_in_executor(
                        None, resolver.resolve, sub, "A"
                    )
                    ips = [str(r) for r in answers]
                    return {
                        "name": sub,
                        "is_alive": True,
                        "ip_addresses": ips,
                        "source": source,
                    }
                except Exception:
                    return {
                        "name": sub,
                        "is_alive": False,
                        "ip_addresses": [],
                        "source": source,
                    }

        tasks = [verify(s) for s in subdomains if s != root_domain]
        batch = await asyncio.gather(*tasks)
        return list(batch)


SubdomainEnumModule = SubdomainEnum
