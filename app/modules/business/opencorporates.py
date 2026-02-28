"""
OpenCorporates company and officer lookup module.

Queries the OpenCorporates API (https://api.opencorporates.com/v0.4) to find
corporate registration records for companies and officers (directors, etc.)
associated with the target.

For each company found in the initial search, a secondary detail request
fetches full structured data including registered address, current status,
incorporation date, and officer list.

Phase: DEEP_ANALYSIS (works without API token at reduced rate; token increases rate limits).
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
from app.core.exceptions import APIError, RateLimitError
from app.core.logging import get_logger
from app.modules.base import BaseModule, ModuleMetadata, ModuleResult

logger = get_logger(__name__)

_OC_BASE = "https://api.opencorporates.com/v0.4"
_COMPANY_SEARCH_URL = f"{_OC_BASE}/companies/search"
_OFFICER_SEARCH_URL = f"{_OC_BASE}/officers/search"

# Maximum company detail lookups to avoid excessive API calls
_MAX_DETAIL_LOOKUPS = 5
# Maximum results to request per search page
_SEARCH_PAGE_SIZE = 10


class OpenCorporatesModule(BaseModule):
    """
    OpenCorporates company and officer intelligence module.

    Searches for corporate registrations matching a company or person name
    and retrieves full structured details for each match, including officers,
    registered address, and incorporation date.
    """

    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            name="opencorporates",
            display_name="OpenCorporates Business Registry",
            description=(
                "Searches OpenCorporates for company registrations and officer "
                "records. Fetches full details including jurisdiction, status, "
                "address, incorporation date, and directors."
            ),
            phase=ModulePhase.DEEP_ANALYSIS,
            supported_targets=[
                TargetType.COMPANY,
                TargetType.PERSON,
                TargetType.DOMAIN,
            ],
            requires_auth=False,  # Works unauthenticated; token improves rate limits
            rate_limit_rpm=20,
            timeout_seconds=30,
            enabled_by_default=True,
            tags=["business", "company", "opencorporates", "officers", "corporate", "registry"],
        )

    async def run(
        self,
        target: str,
        target_type: TargetType,
        context: dict[str, Any],
    ) -> ModuleResult:
        api_token = self._get_secret(settings.opencorporates_api_token)
        term = target.strip()
        start = time.monotonic()
        warnings: list[str] = []
        errors: list[str] = []

        if not api_token:
            warnings.append(
                "OPENCORPORATES_API_TOKEN not configured — using unauthenticated "
                "access (strict rate limits apply)"
            )

        logger.info(
            "opencorporates_start",
            target=term,
            target_type=target_type,
            authenticated=bool(api_token),
        )

        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=settings.request_timeout_seconds),
            headers={
                "User-Agent": "god_eye/1.0",
                "Accept": "application/json",
            },
        ) as session:
            # Run company search and officer search concurrently
            company_task = self._search_companies(session, term, api_token, warnings, errors)
            officer_task = self._search_officers(session, term, api_token, warnings, errors)

            company_results, officer_results = await asyncio.gather(
                company_task,
                officer_task,
                return_exceptions=True,
            )

        # Unpack exceptions
        if isinstance(company_results, Exception):
            errors.append(f"Company search failed: {company_results}")
            company_results = []

        if isinstance(officer_results, Exception):
            errors.append(f"Officer search failed: {officer_results}")
            officer_results = []

        # For top companies, fetch detailed records (limited to avoid flooding API)
        companies_to_detail = company_results[:_MAX_DETAIL_LOOKUPS]  # type: ignore[index]
        if companies_to_detail:
            async with aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=settings.request_timeout_seconds),
                headers={
                    "User-Agent": "god_eye/1.0",
                    "Accept": "application/json",
                },
            ) as session:
                detail_tasks = [
                    self._get_company_details(
                        session,
                        c["jurisdiction_code"],
                        c["company_number"],
                        api_token,
                        warnings,
                        errors,
                    )
                    for c in companies_to_detail
                    if c.get("jurisdiction_code") and c.get("company_number")
                ]
                detail_results = await asyncio.gather(*detail_tasks, return_exceptions=True)

            # Merge detail data back into company records
            for i, detail in enumerate(detail_results):
                if isinstance(detail, Exception):
                    errors.append(f"Company detail fetch failed: {detail}")
                elif isinstance(detail, dict) and detail:
                    # Merge detailed fields into the company record
                    companies_to_detail[i].update(detail)

        total_companies = len(company_results)  # type: ignore[arg-type]

        elapsed_ms = int((time.monotonic() - start) * 1000)
        logger.info(
            "opencorporates_complete",
            target=term,
            total_companies=total_companies,
            officers_found=len(officer_results),  # type: ignore[arg-type]
            elapsed_ms=elapsed_ms,
        )

        return ModuleResult(
            success=True,
            data={
                "companies": company_results,
                "officers_found": officer_results,
                "total_companies": total_companies,
            },
            errors=errors,
            warnings=warnings,
        )

    # ── Company search ────────────────────────────────────────────────────────

    @retry(
        retry=retry_if_exception_type(RateLimitError),
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=2, min=5, max=30),
        reraise=True,
    )
    async def _search_companies(
        self,
        session: aiohttp.ClientSession,
        name: str,
        api_token: str | None,
        warnings: list[str],
        errors: list[str],
    ) -> list[dict[str, Any]]:
        """
        Search OpenCorporates for companies matching a name.

        Returns normalised list of company records.
        """
        params: dict[str, Any] = {
            "q": name,
            "per_page": _SEARCH_PAGE_SIZE,
            "format": "json",
        }
        if api_token:
            params["api_token"] = api_token

        logger.debug("oc_company_search", name=name)

        async with session.get(_COMPANY_SEARCH_URL, params=params) as resp:
            if resp.status == 429:
                raise RateLimitError("OpenCorporates")
            if resp.status in (401, 403):
                warnings.append(
                    "OpenCorporates authentication failed — using unauthenticated access"
                )
                return []
            if resp.status == 404:
                return []
            if resp.status != 200:
                body = await resp.text()
                raise APIError("OpenCorporates", resp.status, body[:300])

            data = await resp.json(content_type=None)

        # Navigate the nested OpenCorporates response structure
        results_obj = data.get("results") or {}
        companies_raw = results_obj.get("companies") or []

        companies: list[dict[str, Any]] = []
        for item in companies_raw:
            company_data = item.get("company") or item
            parsed = self._parse_company(company_data)
            if parsed:
                companies.append(parsed)

        return companies

    # ── Officer search ────────────────────────────────────────────────────────

    @retry(
        retry=retry_if_exception_type(RateLimitError),
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=2, min=5, max=30),
        reraise=True,
    )
    async def _search_officers(
        self,
        session: aiohttp.ClientSession,
        name: str,
        api_token: str | None,
        warnings: list[str],
        errors: list[str],
    ) -> list[dict[str, Any]]:
        """
        Search OpenCorporates for officers (directors, secretaries, etc.) by name.

        Returns normalised list of officer records including associated companies.
        """
        params: dict[str, Any] = {
            "q": name,
            "per_page": _SEARCH_PAGE_SIZE,
            "format": "json",
        }
        if api_token:
            params["api_token"] = api_token

        logger.debug("oc_officer_search", name=name)

        async with session.get(_OFFICER_SEARCH_URL, params=params) as resp:
            if resp.status == 429:
                raise RateLimitError("OpenCorporates")
            if resp.status in (401, 403):
                warnings.append("OpenCorporates officer search: authentication failed")
                return []
            if resp.status == 404:
                return []
            if resp.status != 200:
                body = await resp.text()
                raise APIError("OpenCorporates", resp.status, body[:300])

            data = await resp.json(content_type=None)

        results_obj = data.get("results") or {}
        officers_raw = results_obj.get("officers") or []

        officers: list[dict[str, Any]] = []
        for item in officers_raw:
            officer_data = item.get("officer") or item
            parsed = self._parse_officer(officer_data)
            if parsed:
                officers.append(parsed)

        return officers

    # ── Company details ───────────────────────────────────────────────────────

    @retry(
        retry=retry_if_exception_type(RateLimitError),
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=2, min=5, max=30),
        reraise=True,
    )
    async def _get_company_details(
        self,
        session: aiohttp.ClientSession,
        jurisdiction_code: str,
        company_number: str,
        api_token: str | None,
        warnings: list[str],
        errors: list[str],
    ) -> dict[str, Any]:
        """
        Fetch full company details from OpenCorporates.

        Args:
            session: Active aiohttp session.
            jurisdiction_code: e.g. "gb" (UK), "us_de" (Delaware), "de" (Germany).
            company_number: Company registration number.
            api_token: Optional API token for authentication.
            warnings / errors: Mutable lists for accumulating messages.

        Returns:
            Dict with detailed company fields (officers, registered_address, etc.)
        """
        url = f"{_OC_BASE}/companies/{jurisdiction_code}/{company_number}"
        params: dict[str, Any] = {"format": "json"}
        if api_token:
            params["api_token"] = api_token

        logger.debug(
            "oc_company_detail",
            jurisdiction=jurisdiction_code,
            number=company_number,
        )

        async with session.get(url, params=params) as resp:
            if resp.status == 429:
                raise RateLimitError("OpenCorporates")
            if resp.status in (401, 403):
                warnings.append(
                    f"OpenCorporates detail fetch for {company_number} failed: auth error"
                )
                return {}
            if resp.status == 404:
                return {}
            if resp.status != 200:
                body = await resp.text()
                raise APIError("OpenCorporates", resp.status, body[:300])

            data = await resp.json(content_type=None)

        company_data = (data.get("results") or {}).get("company") or {}
        return self._parse_company_detail(company_data)

    # ── Parsing helpers ───────────────────────────────────────────────────────

    @staticmethod
    def _parse_company(raw: dict[str, Any]) -> dict[str, Any] | None:
        """
        Normalise a raw OpenCorporates company object from search results.

        Returns None if the entry lacks a name (invalid/empty record).
        """
        name = raw.get("name") or ""
        if not name:
            return None

        return {
            "name": name,
            "jurisdiction_code": raw.get("jurisdiction_code") or "",
            "company_number": raw.get("company_number") or "",
            "company_type": raw.get("company_type") or "",
            "current_status": raw.get("current_status") or "",
            "incorporation_date": raw.get("incorporation_date") or "",
            "dissolution_date": raw.get("dissolution_date") or "",
            "registered_address": _extract_address(raw.get("registered_address")),
            "opencorporates_url": raw.get("opencorporates_url") or "",
            # Detail fields populated later by _get_company_details
            "officers": [],
        }

    @staticmethod
    def _parse_company_detail(raw: dict[str, Any]) -> dict[str, Any]:
        """
        Extract detailed fields from a full company record response.

        Merges into the record from _parse_company via dict.update().
        """
        officers_raw = raw.get("officers") or []
        officers: list[dict[str, Any]] = []
        for item in officers_raw:
            officer_data = item.get("officer") if isinstance(item, dict) else item
            if not isinstance(officer_data, dict):
                continue
            officers.append(
                {
                    "name": officer_data.get("name") or "",
                    "role": officer_data.get("position") or "",
                    "start_date": officer_data.get("start_date") or "",
                    "end_date": officer_data.get("end_date") or "",
                    "nationality": officer_data.get("nationality") or "",
                    "occupation": officer_data.get("occupation") or "",
                }
            )

        return {
            "name": raw.get("name") or "",
            "jurisdiction_code": raw.get("jurisdiction_code") or "",
            "company_number": raw.get("company_number") or "",
            "company_type": raw.get("company_type") or "",
            "current_status": raw.get("current_status") or "",
            "incorporation_date": raw.get("incorporation_date") or "",
            "dissolution_date": raw.get("dissolution_date") or "",
            "registered_address": _extract_address(raw.get("registered_address")),
            "opencorporates_url": raw.get("opencorporates_url") or "",
            "officers": officers,
            "branch": raw.get("branch") or "",
            "agent_name": raw.get("agent_name") or "",
            "agent_address": raw.get("agent_address") or "",
            "registry_url": raw.get("registry_url") or "",
            "alternative_names": [
                a.get("company_name", "") if isinstance(a, dict) else str(a)
                for a in (raw.get("alternative_names") or [])
            ],
            "filings_count": raw.get("number_of_employees") or 0,
        }

    @staticmethod
    def _parse_officer(raw: dict[str, Any]) -> dict[str, Any] | None:
        """
        Normalise a raw OpenCorporates officer entry from officer search results.
        """
        name = raw.get("name") or ""
        if not name:
            return None

        # Extract the associated company info
        company_raw = raw.get("company") or {}
        company_name = company_raw.get("name") or ""
        company_jurisdiction = company_raw.get("jurisdiction_code") or ""
        company_number = company_raw.get("company_number") or ""

        return {
            "name": name,
            "role": raw.get("position") or "",
            "start_date": raw.get("start_date") or "",
            "end_date": raw.get("end_date") or "",
            "nationality": raw.get("nationality") or "",
            "occupation": raw.get("occupation") or "",
            "company_name": company_name,
            "company_jurisdiction": company_jurisdiction,
            "company_number": company_number,
            "opencorporates_url": raw.get("opencorporates_url") or "",
        }


def _extract_address(raw: Any) -> str:
    """
    Convert an OpenCorporates address object (or string) to a plain string.

    OpenCorporates can return addresses as nested objects or plain strings.
    """
    if not raw:
        return ""
    if isinstance(raw, str):
        return raw.strip()
    if isinstance(raw, dict):
        parts = [
            raw.get("street_address") or "",
            raw.get("locality") or "",
            raw.get("region") or "",
            raw.get("postal_code") or "",
            raw.get("country") or "",
        ]
        return ", ".join(p for p in parts if p).strip(", ")
    return str(raw)
