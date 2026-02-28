"""
IP geolocation and reputation module.

Queries three APIs in parallel and merges results:
  1. IPinfo        — geolocation, ASN, ISP, hostname
  2. AbuseIPDB     — abuse reports, confidence score, usage type
  3. VirusTotal    — malware/suspicious detection stats

All API calls are made concurrently with asyncio.gather().
Missing API keys cause partial results, not failures.
"""

from __future__ import annotations

import asyncio
import socket
from typing import Any

import aiohttp
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential

from app.core.config import settings
from app.core.constants import ModulePhase, TargetType
from app.core.exceptions import APIError, RateLimitError
from app.core.logging import get_logger
from app.modules.base import BaseModule, ModuleMetadata, ModuleResult

logger = get_logger(__name__)

_IPINFO_URL = "https://ipinfo.io/{ip}"
_ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
_VIRUSTOTAL_URL = "https://www.virustotal.com/api/v3/ip_addresses/{ip}"

# Usage type keywords that suggest a VPN/proxy/hosting service
_VPN_USAGE_TYPES = frozenset({
    "vpn", "proxy", "hosting", "data center", "datacenter", "cdn",
    "tor exit node", "anonymizer",
})

# Autonomous System Number prefixes that are known for VPN/hosting
_HOSTING_ASN_KEYWORDS = frozenset({
    "digitalocean", "linode", "vultr", "hetzner", "ovh", "aws",
    "google cloud", "azure", "cloudflare", "fastly", "akamai",
    "leaseweb", "choopa", "as-choopa", "tzulo", "m247",
})


class IPLookupModule(BaseModule):
    """IP geolocation + reputation module (IPinfo + AbuseIPDB + VirusTotal)."""

    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            name="ip_lookup",
            display_name="IP Lookup & Reputation",
            description=(
                "Queries IPinfo for geolocation/ASN, AbuseIPDB for abuse reports, "
                "and VirusTotal for malware detections. All three run in parallel."
            ),
            phase=ModulePhase.DEEP_ANALYSIS,
            supported_targets=[
                TargetType.IP,
                TargetType.DOMAIN,
            ],
            requires_auth=False,  # Works without keys (degraded but functional)
            enabled_by_default=True,
            tags=["ip", "geolocation", "reputation", "abuse", "virustotal", "asn"],
        )

    async def run(
        self,
        target: str,
        target_type: TargetType,
        context: dict[str, Any],
    ) -> ModuleResult:
        raw_target = target.strip()
        if not raw_target or "/" in raw_target:
            return ModuleResult.fail(f"'{raw_target}' does not look like a valid IP address")

        if target_type == TargetType.DOMAIN:
            resolved_ips = await self._resolve_domain_ips(raw_target)
            if not resolved_ips:
                return ModuleResult(
                    success=True,
                    data={
                        "domain": raw_target,
                        "resolved_ips": [],
                        "lookups": [],
                        "total_ips": 0,
                        "discovered_ips": [],
                    },
                    warnings=[f"No IP addresses resolved for domain '{raw_target}'"],
                )

            lookups: list[dict[str, Any]] = []
            errors: list[str] = []
            warnings: list[str] = []
            for ip in resolved_ips:
                lookup = await self._lookup_ip(ip, errors, warnings)
                if lookup.success:
                    lookups.append(lookup.data)
                else:
                    errors.extend(lookup.errors)

            return ModuleResult(
                success=True,
                data={
                    "domain": raw_target,
                    "resolved_ips": resolved_ips,
                    "lookups": lookups,
                    "total_ips": len(resolved_ips),
                    "discovered_ips": resolved_ips,
                },
                errors=errors,
                warnings=warnings,
            )

        ip = raw_target
        return await self._lookup_ip(ip, [], [])

    async def _lookup_ip(
        self,
        ip: str,
        errors: list[str],
        warnings: list[str],
    ) -> ModuleResult:
        # Basic sanity check — not a full validator, just quick guard
        if not ip or "/" in ip:
            return ModuleResult.fail(f"'{ip}' does not look like a valid IP address")

        ipinfo_token = self._get_secret(settings.ipinfo_token)
        abuseipdb_key = self._get_secret(settings.abuseipdb_api_key)
        virustotal_key = self._get_secret(settings.virustotal_api_key)

        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=settings.request_timeout_seconds),
            headers={"User-Agent": "GOD_EYE/1.0"},
        ) as session:
            # Build concurrent task list
            ipinfo_task = self._fetch_ipinfo(session, ip, ipinfo_token, errors, warnings)
            abuse_task = self._fetch_abuseipdb(session, ip, abuseipdb_key, errors, warnings)
            vt_task = self._fetch_virustotal(session, ip, virustotal_key, errors, warnings)

            ipinfo_data, abuse_data, vt_data = await asyncio.gather(
                ipinfo_task, abuse_task, vt_task,
                return_exceptions=True,
            )

        # Unpack results (exceptions become empty dicts)
        if isinstance(ipinfo_data, Exception):
            errors.append(f"IPinfo failed: {ipinfo_data}")
            ipinfo_data = {}

        if isinstance(abuse_data, Exception):
            errors.append(f"AbuseIPDB failed: {abuse_data}")
            abuse_data = {}

        if isinstance(vt_data, Exception):
            errors.append(f"VirusTotal failed: {vt_data}")
            vt_data = {}

        # ── Merge and enrich ──────────────────────────────────────────
        merged = self._merge(
            ip=ip,
            ipinfo=ipinfo_data,  # type: ignore[arg-type]
            abuse=abuse_data,  # type: ignore[arg-type]
            vt=vt_data,  # type: ignore[arg-type]
        )

        logger.info(
            "ip_lookup_complete",
            ip=ip,
            country=merged.get("country"),
            abuse_score=merged.get("abuse_score"),
            vt_malicious=merged.get("vt_stats", {}).get("malicious"),
            is_vpn=merged.get("is_vpn"),
        )

        return ModuleResult(
            success=True,
            data=merged,
            errors=errors,
            warnings=warnings,
        )

    async def _resolve_domain_ips(self, domain: str) -> list[str]:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._resolve_domain_ips_sync, domain)

    @staticmethod
    def _resolve_domain_ips_sync(domain: str) -> list[str]:
        found: list[str] = []
        try:
            for family, _, _, _, sockaddr in socket.getaddrinfo(domain, None):
                ip = sockaddr[0]
                if ip not in found:
                    found.append(ip)
        except Exception:
            return []
        return found[:5]

    # ── IPinfo ──────────────────────────────────────────────────────────────

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10),
        retry=retry_if_exception_type(RateLimitError),
        reraise=True,
    )
    async def _fetch_ipinfo(
        self,
        session: aiohttp.ClientSession,
        ip: str,
        token: str | None,
        errors: list[str],
        warnings: list[str],
    ) -> dict[str, Any]:
        """
        Fetch geolocation data from IPinfo.

        Returns normalised dict with hostname, city, region, country, etc.
        Free tier works without a token (60k req/month).
        """
        url = _IPINFO_URL.format(ip=ip)
        params: dict[str, str] = {}
        if token:
            params["token"] = token

        logger.debug("ipinfo_fetch", ip=ip)

        async with session.get(url, params=params) as resp:
            if resp.status == 429:
                raise RateLimitError("IPinfo")
            if resp.status == 401:
                warnings.append("IPinfo: invalid or expired token — using unauthenticated")
                # Retry without token
                async with session.get(_IPINFO_URL.format(ip=ip)) as anon_resp:
                    if anon_resp.status != 200:
                        return {}
                    data = await anon_resp.json(content_type=None)
            elif resp.status == 404:
                return {}
            elif resp.status != 200:
                raise APIError("IPinfo", resp.status, await resp.text())
            else:
                data = await resp.json(content_type=None)

        if not isinstance(data, dict):
            return {}

        # Parse "loc" field: "37.3861,-122.0839"
        lat, lon = "", ""
        if loc := data.get("loc"):
            parts = str(loc).split(",")
            if len(parts) == 2:
                lat, lon = parts[0].strip(), parts[1].strip()

        # Parse "org" field: "AS15169 Google LLC"
        org_raw = data.get("org", "")
        asn, org = "", org_raw
        if org_raw and org_raw.startswith("AS"):
            parts = org_raw.split(" ", 1)
            asn = parts[0]
            org = parts[1] if len(parts) > 1 else ""

        return {
            "hostname": data.get("hostname") or "",
            "city": data.get("city") or "",
            "region": data.get("region") or "",
            "country": data.get("country") or "",
            "country_name": data.get("country_name") or "",
            "lat": lat,
            "lon": lon,
            "org": org,
            "asn": asn,
            "postal": data.get("postal") or "",
            "timezone": data.get("timezone") or "",
        }

    # ── AbuseIPDB ────────────────────────────────────────────────────────────

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10),
        retry=retry_if_exception_type(RateLimitError),
        reraise=True,
    )
    async def _fetch_abuseipdb(
        self,
        session: aiohttp.ClientSession,
        ip: str,
        api_key: str | None,
        errors: list[str],
        warnings: list[str],
    ) -> dict[str, Any]:
        """
        Query AbuseIPDB for abuse reports and confidence score.

        Returns partial data even when rate-limited or key is missing.
        """
        if not api_key:
            warnings.append("AbuseIPDB: ABUSEIPDB_API_KEY not configured — skipping")
            return {}

        params: dict[str, Any] = {
            "ipAddress": ip,
            "maxAgeInDays": 90,
            "verbose": "",
        }
        headers = {
            "Key": api_key,
            "Accept": "application/json",
        }

        logger.debug("abuseipdb_fetch", ip=ip)

        async with session.get(
            _ABUSEIPDB_URL,
            params=params,
            headers=headers,
        ) as resp:
            if resp.status == 429:
                raise RateLimitError("AbuseIPDB")
            if resp.status == 401:
                warnings.append("AbuseIPDB: invalid API key")
                return {}
            if resp.status == 422:
                # Unprocessable entity — usually a private/reserved IP
                warnings.append(f"AbuseIPDB: IP {ip} is private or invalid")
                return {}
            if resp.status == 404:
                return {}
            if resp.status != 200:
                body = await resp.text()
                raise APIError("AbuseIPDB", resp.status, body[:200])

            payload = await resp.json(content_type=None)

        data = payload.get("data") or {}

        return {
            "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
            "country_code": data.get("countryCode") or "",
            "usage_type": data.get("usageType") or "",
            "isp": data.get("isp") or "",
            "domain": data.get("domain") or "",
            "total_reports": data.get("totalReports", 0),
            "last_reported_at": data.get("lastReportedAt") or "",
            "is_whitelisted": data.get("isWhitelisted", False),
            "is_tor": data.get("isTor", False),
        }

    # ── VirusTotal ───────────────────────────────────────────────────────────

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10),
        retry=retry_if_exception_type(RateLimitError),
        reraise=True,
    )
    async def _fetch_virustotal(
        self,
        session: aiohttp.ClientSession,
        ip: str,
        api_key: str | None,
        errors: list[str],
        warnings: list[str],
    ) -> dict[str, Any]:
        """
        Fetch VirusTotal IP report for malicious/suspicious detection stats.

        Returns dict with country, as_owner, network, and last_analysis_stats.
        """
        if not api_key:
            warnings.append("VirusTotal: VIRUSTOTAL_API_KEY not configured — skipping")
            return {}

        url = _VIRUSTOTAL_URL.format(ip=ip)
        headers = {"x-apikey": api_key}

        logger.debug("virustotal_fetch", ip=ip)

        async with session.get(url, headers=headers) as resp:
            if resp.status == 429:
                raise RateLimitError("VirusTotal")
            if resp.status == 401:
                warnings.append("VirusTotal: invalid API key")
                return {}
            if resp.status == 404:
                return {}
            if resp.status == 400:
                warnings.append(f"VirusTotal: invalid IP format for '{ip}'")
                return {}
            if resp.status != 200:
                body = await resp.text()
                raise APIError("VirusTotal", resp.status, body[:200])

            payload = await resp.json(content_type=None)

        attrs = (payload.get("data") or {}).get("attributes") or {}
        last_analysis = attrs.get("last_analysis_stats") or {}

        return {
            "country": attrs.get("country") or "",
            "as_owner": attrs.get("as_owner") or "",
            "network": attrs.get("network") or "",
            "regional_internet_registry": attrs.get("regional_internet_registry") or "",
            "last_analysis_stats": {
                "malicious": last_analysis.get("malicious", 0),
                "suspicious": last_analysis.get("suspicious", 0),
                "harmless": last_analysis.get("harmless", 0),
                "undetected": last_analysis.get("undetected", 0),
                "timeout": last_analysis.get("timeout", 0),
            },
            "reputation": attrs.get("reputation", 0),
            "last_analysis_date": attrs.get("last_analysis_date") or "",
        }

    # ── Merge & enrich ───────────────────────────────────────────────────────

    def _merge(
        self,
        ip: str,
        ipinfo: dict[str, Any],
        abuse: dict[str, Any],
        vt: dict[str, Any],
    ) -> dict[str, Any]:
        """
        Merge results from all three sources into a unified output dict.

        Derives is_vpn, is_tor, is_proxy from heuristics when direct flags
        are not available.
        """
        # Prefer AbuseIPDB country (alpha-2) over IPinfo
        country = (
            abuse.get("country_code")
            or ipinfo.get("country")
            or vt.get("country")
            or ""
        )

        isp = (
            abuse.get("isp")
            or ipinfo.get("org")
            or vt.get("as_owner")
            or ""
        )
        asn = ipinfo.get("asn") or ""

        usage_type = abuse.get("usage_type") or ""
        abuse_score = abuse.get("abuse_confidence_score", 0)

        # Derive flags
        is_tor = bool(abuse.get("is_tor", False))
        is_vpn = is_tor or self._classify_vpn(usage_type, isp, asn)
        is_proxy = "proxy" in usage_type.lower() or "proxy" in isp.lower()

        vt_stats = vt.get("last_analysis_stats") or {}

        return {
            "ip": ip,
            "hostname": ipinfo.get("hostname") or "",
            "city": ipinfo.get("city") or "",
            "region": ipinfo.get("region") or "",
            "country": country,
            "country_name": ipinfo.get("country_name") or "",
            "lat": ipinfo.get("lat") or "",
            "lon": ipinfo.get("lon") or "",
            "isp": isp,
            "asn": asn,
            "org": ipinfo.get("org") or vt.get("as_owner") or "",
            "network": vt.get("network") or "",
            "timezone": ipinfo.get("timezone") or "",
            "postal": ipinfo.get("postal") or "",
            # Abuse / reputation
            "abuse_score": abuse_score,
            "total_abuse_reports": abuse.get("total_reports", 0),
            "last_reported_at": abuse.get("last_reported_at") or "",
            "usage_type": usage_type,
            "is_vpn": is_vpn,
            "is_tor": is_tor,
            "is_proxy": is_proxy,
            # VirusTotal
            "vt_stats": vt_stats,
            "vt_reputation": vt.get("reputation", 0),
            # Sources availability
            "sources": {
                "ipinfo": bool(ipinfo),
                "abuseipdb": bool(abuse),
                "virustotal": bool(vt),
            },
        }

    @staticmethod
    def _classify_vpn(usage_type: str, isp: str, asn: str) -> bool:
        """
        Heuristically decide if an IP is likely a VPN/proxy/hosting endpoint.

        Checks usage type string and ISP/ASN names against known keywords.
        """
        combined = f"{usage_type} {isp} {asn}".lower()
        if any(keyword in combined for keyword in _VPN_USAGE_TYPES):
            return True
        if any(keyword in combined for keyword in _HOSTING_ASN_KEYWORDS):
            return True
        return False
