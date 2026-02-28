"""
Shodan OSINT module.

Queries the Shodan API for host intelligence, service banners, vulnerability
data, and DNS resolution for a given IP address or domain.

For domain targets, the module first resolves the domain to IP addresses
via Shodan's DNS resolve endpoint, then looks up each resolved IP.

Shodan data extracted per host:
  - ip, hostnames, ISP, org, ASN, city, country
  - Open ports and service banners (product, version, transport)
  - Known CVEs (vulnerabilities)
  - Tags (e.g., "vpn", "cloud", "tor")

Phase: DEEP_ANALYSIS (requires Shodan API key).
"""

from __future__ import annotations

import asyncio
import time
from typing import Any

import aiohttp
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

from app.core.config import settings
from app.core.constants import ModulePhase, TargetType
from app.core.exceptions import APIError, AuthenticationError, RateLimitError
from app.core.logging import get_logger
from app.modules.base import BaseModule, ModuleMetadata, ModuleResult

logger = get_logger(__name__)

_SHODAN_BASE = "https://api.shodan.io"
_HOST_URL = f"{_SHODAN_BASE}/shodan/host/{{ip}}"
_DNS_RESOLVE_URL = f"{_SHODAN_BASE}/dns/resolve"

# Maximum IPs to look up when resolving a domain (avoid excessive API calls)
_MAX_IP_LOOKUPS = 3


class ShodanSearchModule(BaseModule):
    """
    Shodan host intelligence and vulnerability scanner.

    Queries Shodan for port/service/CVE data for IP addresses and domains.
    Automatically resolves domains to IPs via Shodan's DNS API before lookup.
    """

    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            name="shodan_search",
            display_name="Shodan Intelligence",
            description=(
                "Queries Shodan for host intelligence: open ports, service banners, "
                "ISP/ASN, geolocation, CVEs, and tags. Resolves domains to IPs "
                "automatically using Shodan's DNS API."
            ),
            phase=ModulePhase.DEEP_ANALYSIS,
            supported_targets=[
                TargetType.IP,
                TargetType.DOMAIN,
            ],
            requires_auth=True,
            rate_limit_rpm=60,
            timeout_seconds=30,
            enabled_by_default=True,
            tags=["shodan", "ip", "domain", "ports", "cve", "banners", "network", "recon"],
        )

    async def run(
        self,
        target: str,
        target_type: TargetType,
        context: dict[str, Any],
    ) -> ModuleResult:
        api_key = self._get_secret(settings.shodan_api_key)
        if not api_key:
            logger.warning("shodan_skipped", reason="SHODAN_API_KEY not configured")
            return ModuleResult.fail("API key not configured: set SHODAN_API_KEY in .env")

        target = target.strip()
        start = time.monotonic()
        warnings: list[str] = []
        errors: list[str] = []

        logger.info("shodan_start", target=target, target_type=target_type)

        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=settings.request_timeout_seconds),
            headers={"User-Agent": "god_eye/1.0"},
        ) as session:
            # ── Resolve domain to IPs if needed ─────────────────────────────
            if target_type == TargetType.DOMAIN:
                resolved_ips = await self._resolve_domain(
                    session, target, api_key, warnings, errors
                )
                if not resolved_ips:
                    return ModuleResult(
                        success=True,
                        data={
                            "host_info": {},
                            "services": [],
                            "resolved_ips": [],
                            "total_ports": 0,
                            "cve_count": 0,
                        },
                        warnings=[f"Could not resolve domain '{target}' via Shodan DNS"],
                        errors=errors,
                    )
                ips_to_query = resolved_ips[:_MAX_IP_LOOKUPS]
            else:
                resolved_ips = [target]
                ips_to_query = [target]

            # ── Query each IP concurrently ───────────────────────────────────
            host_tasks = [
                self._get_host_info(session, ip, api_key, warnings, errors) for ip in ips_to_query
            ]
            host_results = await asyncio.gather(*host_tasks, return_exceptions=True)

        # Collect successful host records
        all_hosts: list[dict[str, Any]] = []
        for ip, result in zip(ips_to_query, host_results, strict=False):
            if isinstance(result, Exception):
                errors.append(f"Shodan host lookup failed for {ip}: {result}")
            elif result:
                all_hosts.append(result)

        if not all_hosts:
            return ModuleResult(
                success=len(errors) == 0,
                data={
                    "host_info": {},
                    "services": [],
                    "resolved_ips": resolved_ips,
                    "total_ports": 0,
                    "cve_count": 0,
                },
                errors=errors,
                warnings=warnings,
            )

        # Use the first (primary) host as the primary result
        primary_host = all_hosts[0]
        all_services: list[dict[str, Any]] = []
        for host in all_hosts:
            all_services.extend(host.get("services", []))

        total_ports = sum(len(h.get("ports", [])) for h in all_hosts)
        all_cves: list[str] = []
        for host in all_hosts:
            all_cves.extend(host.get("vulns", []))
        cve_count = len(set(all_cves))

        elapsed_ms = int((time.monotonic() - start) * 1000)
        logger.info(
            "shodan_complete",
            target=target,
            ips_queried=len(ips_to_query),
            total_ports=total_ports,
            cve_count=cve_count,
            elapsed_ms=elapsed_ms,
        )

        return ModuleResult(
            success=True,
            data={
                "host_info": {
                    "ip": primary_host.get("ip", ""),
                    "isp": primary_host.get("isp", ""),
                    "org": primary_host.get("org", ""),
                    "city": primary_host.get("city", ""),
                    "country": primary_host.get("country_name", ""),
                    "ports": primary_host.get("ports", []),
                    "vulns": list(set(all_cves)),
                    "hostnames": primary_host.get("hostnames", []),
                    "tags": primary_host.get("tags", []),
                    "asn": primary_host.get("asn", ""),
                    "all_hosts": all_hosts,
                },
                "services": all_services,
                "resolved_ips": resolved_ips,
                "total_ports": total_ports,
                "cve_count": cve_count,
            },
            errors=errors,
            warnings=warnings,
        )

    # ── DNS Resolution ────────────────────────────────────────────────────────

    @retry(
        retry=retry_if_exception_type(RateLimitError),
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=2, min=5, max=30),
        reraise=True,
    )
    async def _resolve_domain(
        self,
        session: aiohttp.ClientSession,
        domain: str,
        api_key: str,
        warnings: list[str],
        errors: list[str],
    ) -> list[str]:
        """
        Resolve a domain to IP addresses via Shodan's DNS resolve endpoint.

        Returns a list of IP address strings (may be empty if resolution fails).
        """
        params = {
            "hostnames": domain,
            "key": api_key,
        }
        logger.debug("shodan_dns_resolve", domain=domain)

        async with session.get(_DNS_RESOLVE_URL, params=params) as resp:
            if resp.status == 429:
                raise RateLimitError("Shodan")
            if resp.status in (401, 403):
                raise AuthenticationError("Shodan", "Invalid API key")
            if resp.status == 404:
                return []
            if resp.status != 200:
                body = await resp.text()
                raise APIError("Shodan", resp.status, body[:200])

            data = await resp.json(content_type=None)

        if not isinstance(data, dict):
            return []

        # Shodan DNS resolve returns {domain: ip, ...}
        ips: list[str] = []
        for _hostname, ip in data.items():
            if ip and isinstance(ip, str):
                ips.append(ip)

        logger.debug("shodan_dns_resolved", domain=domain, ips=ips)
        return ips

    # ── Host Lookup ───────────────────────────────────────────────────────────

    @retry(
        retry=retry_if_exception_type(RateLimitError),
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=2, min=5, max=30),
        reraise=True,
    )
    async def _get_host_info(
        self,
        session: aiohttp.ClientSession,
        ip: str,
        api_key: str,
        warnings: list[str],
        errors: list[str],
    ) -> dict[str, Any] | None:
        """
        Fetch full host intelligence from Shodan for a single IP.

        Args:
            session: Active aiohttp session.
            ip: IP address to look up.
            api_key: Shodan API key.
            warnings / errors: Mutable lists for accumulating messages.

        Returns:
            Normalised host dict, or None if not found / error.
        """
        url = _HOST_URL.format(ip=ip)
        params = {"key": api_key}

        logger.debug("shodan_host_lookup", ip=ip)

        async with session.get(url, params=params) as resp:
            if resp.status == 429:
                retry_after_raw = resp.headers.get("Retry-After", "60")
                try:
                    retry_after = int(retry_after_raw)
                except ValueError:
                    retry_after = 60
                raise RateLimitError("Shodan", retry_after=retry_after)

            if resp.status in (401, 403):
                raise AuthenticationError("Shodan", "Invalid API key")

            if resp.status == 404:
                warnings.append(f"Shodan: no data found for IP {ip}")
                return None

            if resp.status != 200:
                body = await resp.text()
                raise APIError("Shodan", resp.status, body[:300])

            data = await resp.json(content_type=None)

        return self._parse_host(data, ip)

    # ── Parsing ───────────────────────────────────────────────────────────────

    def _parse_host(self, raw: dict[str, Any], ip: str) -> dict[str, Any]:
        """
        Normalise a raw Shodan host response into a structured output dict.

        Extracts host metadata and flattens the list of service banner objects
        into a structured services list.
        """
        # Extract top-level host metadata
        ports: list[int] = sorted(raw.get("ports", []))
        vulns_raw = raw.get("vulns") or {}
        # vulns can be a dict {CVE-ID: {cvss, ...}} or a list of CVE strings
        if isinstance(vulns_raw, dict):
            vuln_ids = list(vulns_raw.keys())
        elif isinstance(vulns_raw, list):
            vuln_ids = [str(v) for v in vulns_raw]
        else:
            vuln_ids = []

        # Parse service banners from the "data" array
        services: list[dict[str, Any]] = []
        for banner in raw.get("data") or []:
            if not isinstance(banner, dict):
                continue
            service = self._parse_service_banner(banner)
            if service:
                services.append(service)

        return {
            "ip": raw.get("ip_str") or ip,
            "hostnames": raw.get("hostnames") or [],
            "domains": raw.get("domains") or [],
            "country_code": raw.get("country_code") or "",
            "country_name": raw.get("country_name") or "",
            "city": raw.get("city") or "",
            "region_code": raw.get("region_code") or "",
            "latitude": raw.get("latitude"),
            "longitude": raw.get("longitude"),
            "isp": raw.get("isp") or "",
            "org": raw.get("org") or "",
            "asn": raw.get("asn") or "",
            "os": raw.get("os") or "",
            "ports": ports,
            "vulns": vuln_ids,
            "tags": raw.get("tags") or [],
            "last_update": raw.get("last_update") or "",
            "services": services,
        }

    @staticmethod
    def _parse_service_banner(banner: dict[str, Any]) -> dict[str, Any] | None:
        """
        Extract structured service information from a Shodan banner object.

        Banners contain port, transport protocol, and optional product/version
        data from the service detection.
        """
        port = banner.get("port")
        if port is None:
            return None

        transport = banner.get("transport") or "tcp"
        product = banner.get("product") or ""
        version = banner.get("version") or ""
        banner_data = banner.get("data") or ""

        # Extract CPE (Common Platform Enumeration) identifiers
        cpe = banner.get("cpe") or []
        if isinstance(cpe, str):
            cpe = [cpe]

        # Collect CVEs from the banner-level vulns
        banner_vulns_raw = banner.get("vulns") or {}
        banner_cves: list[str] = (
            list(banner_vulns_raw.keys()) if isinstance(banner_vulns_raw, dict) else []
        )

        return {
            "port": int(port),
            "transport": transport,
            "product": product,
            "version": version,
            "module": banner.get("_shodan", {}).get("module", "")
            if isinstance(banner.get("_shodan"), dict)
            else "",
            "banner": str(banner_data)[:500] if banner_data else "",
            "cpe": cpe,
            "cves": banner_cves,
            "hostname": banner.get("hostnames", [None])[0] if banner.get("hostnames") else "",
            "timestamp": banner.get("timestamp") or "",
        }
