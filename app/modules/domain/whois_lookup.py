"""
WHOIS lookup module.

Two-tier lookup strategy:
  1. WhoisXML API (JSON, structured, reliable) — used when API key is configured.
  2. python-whois library (local WHOIS protocol) — fallback when no API key.

Extracts registrar, dates, registrant identity, nameservers, and privacy flags.
"""

from __future__ import annotations

import asyncio
from typing import Any

import aiohttp
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential

from app.core.config import settings
from app.core.constants import ModulePhase, TargetType
from app.core.exceptions import APIError, RateLimitError
from app.core.logging import get_logger
from app.modules.base import BaseModule, ModuleMetadata, ModuleResult

logger = get_logger(__name__)

_WHOISXML_URL = "https://www.whoisxmlapi.com/whoisserver/WhoisService"

# Keywords that indicate WHOIS privacy protection
_PRIVACY_KEYWORDS = {
    "redacted",
    "privacy",
    "private",
    "protected",
    "withheld",
    "not disclosed",
    "data protected",
    "gdpr",
    "proxy",
    "whoisguard",
    "perfect privacy",
    "domains by proxy",
    "contact privacy",
    "identity protect",
}


class WhoisLookupModule(BaseModule):
    """WHOIS domain registration lookup (WhoisXML API + python-whois fallback)."""

    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            name="whois_lookup",
            display_name="WHOIS Lookup",
            description=(
                "Retrieves domain registration details via WhoisXML API (primary) "
                "or python-whois (fallback). Extracts registrar, dates, registrant, "
                "nameservers, and privacy status."
            ),
            phase=ModulePhase.DEEP_ANALYSIS,
            supported_targets=[
                TargetType.DOMAIN,
                TargetType.EMAIL,
                TargetType.COMPANY,
            ],
            requires_auth=False,  # Falls back to local whois
            enabled_by_default=True,
            tags=["domain", "whois", "registration", "registrant"],
        )

    async def run(
        self,
        target: str,
        target_type: TargetType,
        context: dict[str, Any],
    ) -> ModuleResult:
        domain = self._extract_domain(target)
        api_key = self._get_secret(settings.whoisxml_api_key)

        errors: list[str] = []
        warnings: list[str] = []
        whois_data: dict[str, Any] = {}

        if api_key:
            # Primary: WhoisXML API
            try:
                whois_data = await self._fetch_whoisxml(domain, api_key)
                logger.debug("whois_source", source="whoisxml_api", domain=domain)
            except RateLimitError:
                warnings.append("WhoisXML API rate-limited — falling back to local WHOIS")
                whois_data = await self._fetch_local_whois(domain, errors)
            except APIError as exc:
                warnings.append(f"WhoisXML API error ({exc}) — falling back to local WHOIS")
                whois_data = await self._fetch_local_whois(domain, errors)
        else:
            # Fallback: local python-whois
            logger.debug("whois_source", source="python_whois_fallback", domain=domain)
            whois_data = await self._fetch_local_whois(domain, errors)

        if not whois_data:
            return ModuleResult.fail(f"WHOIS lookup returned no data for '{domain}'")

        # Determine WHOIS privacy
        has_privacy = self._detect_privacy(whois_data)

        logger.info(
            "whois_lookup_complete",
            domain=domain,
            registrar=whois_data.get("registrar"),
            has_privacy=has_privacy,
        )

        return ModuleResult(
            success=True,
            data={
                "domain": domain,
                "registrar": whois_data.get("registrar", ""),
                "registration_date": whois_data.get("registration_date", ""),
                "expiration_date": whois_data.get("expiration_date", ""),
                "updated_date": whois_data.get("updated_date", ""),
                "registrant_name": whois_data.get("registrant_name", ""),
                "registrant_org": whois_data.get("registrant_org", ""),
                "registrant_email": whois_data.get("registrant_email", ""),
                "registrant_country": whois_data.get("registrant_country", ""),
                "registrant_state": whois_data.get("registrant_state", ""),
                "registrant_city": whois_data.get("registrant_city", ""),
                "admin_email": whois_data.get("admin_email", ""),
                "tech_email": whois_data.get("tech_email", ""),
                "nameservers": whois_data.get("nameservers", []),
                "status": whois_data.get("status", []),
                "dnssec": whois_data.get("dnssec", ""),
                "has_whois_privacy": has_privacy,
            },
            errors=errors,
            warnings=warnings,
        )

    # ── WhoisXML API ────────────────────────────────────────────────────────

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10),
        retry=retry_if_exception_type(RateLimitError),
        reraise=True,
    )
    async def _fetch_whoisxml(
        self,
        domain: str,
        api_key: str,
    ) -> dict[str, Any]:
        """
        Fetch WHOIS data from WhoisXML API.

        Returns a normalised dict of WHOIS fields.
        """
        params: dict[str, str] = {
            "apiKey": api_key,
            "domainName": domain,
            "outputFormat": "JSON",
            "da": "2",  # include domain availability
        }

        logger.debug("whoisxml_fetch", domain=domain)

        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=settings.request_timeout_seconds),
        ) as session:
            async with session.get(_WHOISXML_URL, params=params) as resp:
                if resp.status == 429:
                    raise RateLimitError("WhoisXML")
                if resp.status == 401:
                    raise APIError("WhoisXML", 401, "Invalid API key")
                if resp.status == 404:
                    return {}
                if resp.status != 200:
                    body = await resp.text()
                    raise APIError("WhoisXML", resp.status, body[:200])

                payload = await resp.json(content_type=None)

        record = payload.get("WhoisRecord") or payload.get("whoisRecord") or {}
        if not record:
            return {}

        registrant = record.get("registrant") or {}
        admin = record.get("administrativeContact") or {}
        tech = record.get("technicalContact") or {}
        record.get("audit") or {}
        registry_data = record.get("registryData") or {}

        # Normalise nameservers
        nameservers: list[str] = []
        ns_raw = record.get("nameServers") or registry_data.get("nameServers") or {}
        if isinstance(ns_raw, dict):
            nameservers = [h.lower() for h in (ns_raw.get("hostNames") or [])]
        elif isinstance(ns_raw, list):
            nameservers = [str(ns).lower() for ns in ns_raw]

        # Status list
        status_raw = record.get("status") or registry_data.get("status") or ""
        if isinstance(status_raw, str):
            status = [s.strip() for s in status_raw.split(",") if s.strip()]
        elif isinstance(status_raw, list):
            status = [str(s) for s in status_raw]
        else:
            status = []

        return {
            "registrar": record.get("registrarName") or "",
            "registration_date": (
                record.get("createdDate") or registry_data.get("createdDate") or ""
            ),
            "expiration_date": (
                record.get("expiresDate") or registry_data.get("expiresDate") or ""
            ),
            "updated_date": (record.get("updatedDate") or registry_data.get("updatedDate") or ""),
            "registrant_name": registrant.get("name") or "",
            "registrant_org": registrant.get("organization") or "",
            "registrant_email": registrant.get("email") or "",
            "registrant_country": registrant.get("country") or "",
            "registrant_state": registrant.get("state") or "",
            "registrant_city": registrant.get("city") or "",
            "admin_email": admin.get("email") or "",
            "tech_email": tech.get("email") or "",
            "nameservers": nameservers,
            "status": status,
            "dnssec": record.get("dnssec") or "",
        }

    # ── Local python-whois fallback ──────────────────────────────────────────

    async def _fetch_local_whois(
        self,
        domain: str,
        errors: list[str],
    ) -> dict[str, Any]:
        """
        Perform a local WHOIS lookup using the python-whois library.

        Runs in an executor thread since python-whois is synchronous.
        """
        loop = asyncio.get_event_loop()
        try:
            result = await loop.run_in_executor(None, self._run_local_whois, domain)
            return result
        except Exception as exc:
            errors.append(f"Local WHOIS failed: {exc}")
            return {}

    def _run_local_whois(self, domain: str) -> dict[str, Any]:
        """
        Synchronous python-whois query.

        Returns a normalised dict or empty dict on failure.
        """
        try:
            import whois  # type: ignore[import-untyped]
        except ImportError:
            raise RuntimeError("python-whois is not installed. Run: pip install python-whois")

        logger.debug("local_whois_query", domain=domain)

        try:
            w = whois.whois(domain)
        except Exception as exc:
            raise RuntimeError(f"python-whois error: {exc}") from exc

        if not w:
            return {}

        def _first(val: Any) -> str:
            """Return first element if list, else str, else empty."""
            if val is None:
                return ""
            if isinstance(val, list):
                return str(val[0]) if val else ""
            return str(val)

        def _to_list(val: Any) -> list[str]:
            if val is None:
                return []
            if isinstance(val, list):
                return [str(v) for v in val]
            return [str(val)]

        return {
            "registrar": _first(w.registrar),
            "registration_date": _first(w.creation_date),
            "expiration_date": _first(w.expiration_date),
            "updated_date": _first(w.updated_date),
            "registrant_name": _first(w.name),
            "registrant_org": _first(w.org),
            "registrant_email": _first(w.emails),
            "registrant_country": _first(w.country),
            "registrant_state": _first(w.state),
            "registrant_city": _first(w.city),
            "admin_email": "",
            "tech_email": "",
            "nameservers": [ns.lower() for ns in _to_list(w.name_servers)],
            "status": _to_list(w.status),
            "dnssec": _first(w.dnssec),
        }

    # ── Helpers ──────────────────────────────────────────────────────────────

    @staticmethod
    def _detect_privacy(data: dict[str, Any]) -> bool:
        """
        Check WHOIS fields for privacy-protection keywords.

        Returns True if any registrant field looks redacted or privacy-protected.
        """
        fields_to_check = [
            "registrant_name",
            "registrant_org",
            "registrant_email",
            "registrant_country",
        ]
        combined = " ".join(str(data.get(f, "")).lower() for f in fields_to_check)
        return any(kw in combined for kw in _PRIVACY_KEYWORDS)

    @staticmethod
    def _extract_domain(target: str) -> str:
        """Strip email prefix or URL scheme to get a bare domain."""
        target = target.strip()
        if "@" in target:
            return target.split("@", 1)[1]
        for scheme in ("https://", "http://"):
            if target.startswith(scheme):
                target = target[len(scheme) :]
        return target.split("/")[0].split("?")[0]
