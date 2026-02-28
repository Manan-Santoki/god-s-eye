"""
Certificate Transparency log search module.

Queries crt.sh for all SSL/TLS certificates ever issued for a domain.
Extracts unique subdomains from certificate Subject Alternative Names (SANs)
and common names, which is a highly effective passive subdomain enumeration
technique.

No API key required.
"""

from __future__ import annotations

import asyncio
import re
from typing import Any
from urllib.parse import quote

import aiohttp
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential

from app.core.config import settings
from app.core.constants import ModulePhase, TargetType
from app.core.exceptions import APIError, RateLimitError
from app.core.logging import get_logger
from app.modules.base import BaseModule, ModuleMetadata, ModuleResult

logger = get_logger(__name__)

_CRTSH_URL = "https://crt.sh/"

# Pattern to validate and normalise discovered subdomain hostnames
_HOSTNAME_RE = re.compile(
    r"^(\*\.)?([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)


class CertificateSearchModule(BaseModule):
    """Certificate Transparency (crt.sh) subdomain enumeration module."""

    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            name="certificate_search",
            display_name="Certificate Transparency Search",
            description=(
                "Searches crt.sh Certificate Transparency logs for all certificates "
                "issued for a domain. Extracts subdomains from SANs."
            ),
            phase=ModulePhase.DEEP_ANALYSIS,
            supported_targets=[
                TargetType.DOMAIN,
                TargetType.EMAIL,
                TargetType.COMPANY,
            ],
            requires_auth=False,
            enabled_by_default=True,
            tags=["domain", "ssl", "tls", "certificates", "subdomains", "ct-log", "no-key"],
        )

    async def run(
        self,
        target: str,
        target_type: TargetType,
        context: dict[str, Any],
    ) -> ModuleResult:
        domain = self._extract_domain(target)

        errors: list[str] = []
        warnings: list[str] = []

        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=settings.request_timeout_seconds * 2),
            headers={
                "User-Agent": "GOD_EYE/1.0 Certificate-Transparency-Scanner",
                "Accept": "application/json",
            },
        ) as session:
            try:
                raw_certs = await self._fetch_crtsh(session, domain)
            except RateLimitError:
                return ModuleResult.fail("crt.sh rate-limited (HTTP 429)")
            except APIError as exc:
                return ModuleResult.fail(str(exc))

        if not raw_certs:
            return ModuleResult(
                success=True,
                data={
                    "domain": domain,
                    "certificates": [],
                    "discovered_subdomains": [],
                    "total_certs": 0,
                },
                warnings=["No certificates found in CT logs for this domain"],
            )

        # Process certificates
        certificates, discovered_subdomains = self._process_certificates(
            raw_certs=raw_certs,
            domain=domain,
            warnings=warnings,
        )

        logger.info(
            "certificate_search_complete",
            domain=domain,
            total_certs=len(certificates),
            unique_subdomains=len(discovered_subdomains),
        )

        return ModuleResult(
            success=True,
            data={
                "domain": domain,
                "certificates": certificates,
                "discovered_subdomains": discovered_subdomains,
                "total_certs": len(certificates),
            },
            errors=errors,
            warnings=warnings,
        )

    # ── crt.sh API ──────────────────────────────────────────────────────────

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=2, min=3, max=30),
        retry=retry_if_exception_type(RateLimitError),
        reraise=True,
    )
    async def _fetch_crtsh(
        self,
        session: aiohttp.ClientSession,
        domain: str,
    ) -> list[dict[str, Any]]:
        """
        Fetch all CT log entries for %.{domain} from crt.sh JSON API.

        Uses the wildcard query (%.domain) to match all subdomains.

        Returns raw list of certificate entry dicts from crt.sh.

        Raises:
            RateLimitError: On HTTP 429.
            APIError: On other non-200 errors.
        """
        # crt.sh uses %.domain to match all subdomains
        query = f"%.{domain}"
        params = {
            "q": query,
            "output": "json",
        }

        logger.debug("crtsh_fetch", domain=domain)

        async with session.get(_CRTSH_URL, params=params) as resp:
            if resp.status == 429:
                raise RateLimitError("crtsh")
            if resp.status == 503:
                # crt.sh occasionally overloaded
                raise RateLimitError("crtsh")
            if resp.status == 404:
                return []
            if resp.status != 200:
                body = await resp.text()
                raise APIError("crtsh", resp.status, body[:200])

            # crt.sh returns application/json but sometimes with bad content-type
            data = await resp.json(content_type=None)

        if not isinstance(data, list):
            return []

        return data

    # ── Processing ──────────────────────────────────────────────────────────

    def _process_certificates(
        self,
        raw_certs: list[dict[str, Any]],
        domain: str,
        warnings: list[str],
    ) -> tuple[list[dict[str, Any]], list[str]]:
        """
        Process raw crt.sh entries into structured certificate records.

        Returns:
            Tuple of (certificates list, unique_subdomains list).
        """
        seen_serials: set[str] = set()
        certificates: list[dict[str, Any]] = []
        all_subdomains: set[str] = set()

        for entry in raw_certs:
            if not isinstance(entry, dict):
                continue

            serial = str(entry.get("serial_number") or entry.get("id") or "")

            # Deduplicate by serial number
            if serial and serial in seen_serials:
                continue
            if serial:
                seen_serials.add(serial)

            # name_value can be a multi-line string with multiple SANs
            name_value: str = str(entry.get("name_value") or "")
            san_domains: list[str] = []

            for name in name_value.replace(",", "\n").splitlines():
                name = name.strip().lower()
                if not name:
                    continue
                # Normalise wildcard entries
                if name.startswith("*."):
                    base = name[2:]
                    san_domains.append(name)  # Keep wildcard notation
                    if self._is_valid_hostname(base):
                        all_subdomains.add(base)
                elif self._is_valid_hostname(name):
                    san_domains.append(name)
                    all_subdomains.add(name)

            issuer = str(entry.get("issuer_name") or "")
            common_name = str(entry.get("common_name") or "")

            certificates.append(
                {
                    "serial": serial,
                    "issuer": issuer,
                    "common_name": common_name,
                    "san_domains": san_domains,
                    "not_before": str(entry.get("not_before") or ""),
                    "not_after": str(entry.get("not_after") or ""),
                    "logged_at": str(entry.get("entry_timestamp") or ""),
                }
            )

        # Sort certificates newest-first by not_before
        try:
            certificates.sort(
                key=lambda c: c.get("not_before") or "",
                reverse=True,
            )
        except Exception:
            pass  # Non-fatal if sorting fails

        # Filter subdomains to only include those belonging to the target domain
        target_subdomains = sorted(
            {
                sub
                for sub in all_subdomains
                if sub == domain or sub.endswith(f".{domain}")
            }
        )

        return certificates, target_subdomains

    @staticmethod
    def _is_valid_hostname(hostname: str) -> bool:
        """Return True if the string looks like a valid domain hostname."""
        return bool(_HOSTNAME_RE.match(hostname)) and len(hostname) <= 253

    @staticmethod
    def _extract_domain(target: str) -> str:
        """Strip email prefix or URL scheme to get a bare domain."""
        target = target.strip().lower()
        if "@" in target:
            return target.split("@", 1)[1]
        for scheme in ("https://", "http://"):
            if target.startswith(scheme):
                target = target[len(scheme):]
        return target.split("/")[0].split("?")[0]
