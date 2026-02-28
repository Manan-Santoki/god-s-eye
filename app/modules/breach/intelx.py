"""
Intelligence X (IntelX) breach and leak search module.

Implements the IntelX two-step asynchronous search protocol:
  1. POST /intelligent/search — submit a search term, receive a search UUID.
  2. GET  /intelligent/search/result?id={uuid} — poll for results.

Polls up to 3 times with 3-second delays between each poll (max 10s wait).
Records include type, name, date, bucket, and a preview snippet.

Phase: BREACH_DB (requires IntelX API key).
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

_INTELX_BASE = "https://2.intelx.io"
_SEARCH_ENDPOINT = f"{_INTELX_BASE}/intelligent/search"
_RESULT_ENDPOINT = f"{_INTELX_BASE}/intelligent/search/result"

# IntelX media type 0 = all, sort 2 = most relevant first
_DEFAULT_SEARCH_BODY = {
    "maxresults": 20,
    "media": 0,
    "sort": 2,
    "terminate": [],
}

# Polling parameters: up to 3 polls with 3 s delay (~10 s total wait)
_POLL_MAX_ATTEMPTS = 3
_POLL_DELAY_SECONDS = 3.0

# IntelX record type codes mapped to human-readable labels
_RECORD_TYPES: dict[int, str] = {
    0: "unknown",
    1: "url",
    2: "domain",
    3: "email",
    4: "phone",
    5: "name",
    6: "address",
    13: "paste",
    14: "leak",
    15: "document",
    100: "file",
    200: "credential",
}


class IntelXModule(BaseModule):
    """
    Intelligence X breach and leak search module.

    Submits a two-step asynchronous search to IntelX and polls for results.
    Supports searching by email, username, domain, IP, or phone number.
    """

    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            name="intelx",
            display_name="Intelligence X Search",
            description=(
                "Searches Intelligence X for leaked data records (pastes, leaks, "
                "documents) matching the target. Uses the two-step async search "
                "protocol: submit → poll → retrieve."
            ),
            phase=ModulePhase.BREACH_DB,
            supported_targets=[
                TargetType.EMAIL,
                TargetType.USERNAME,
                TargetType.DOMAIN,
                TargetType.IP,
                TargetType.PHONE,
                TargetType.PERSON,
            ],
            requires_auth=True,
            rate_limit_rpm=10,
            timeout_seconds=45,
            enabled_by_default=True,
            tags=["breach", "intelx", "intelligence-x", "leak", "paste", "data-leak"],
        )

    async def run(
        self,
        target: str,
        target_type: TargetType,
        context: dict[str, Any],
    ) -> ModuleResult:
        api_key = self._get_secret(settings.intelx_api_key)
        if not api_key:
            logger.warning("intelx_skipped", reason="INTELX_API_KEY not configured")
            return ModuleResult.fail("API key not configured: set INTELX_API_KEY in .env")

        term = target.strip()
        start = time.monotonic()
        warnings: list[str] = []
        errors: list[str] = []

        logger.info("intelx_start", term=term, target_type=target_type)

        headers = {
            "x-key": api_key,
            "Content-Type": "application/json",
            "User-Agent": "god_eye/1.0",
        }

        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=settings.request_timeout_seconds * 2),
            headers=headers,
        ) as session:
            # Step 1: Submit the search and receive a search UUID
            try:
                search_id = await self._submit_search(session, term)
            except AuthenticationError:
                return ModuleResult.fail(
                    "IntelX authentication failed — check INTELX_API_KEY"
                )
            except RateLimitError as exc:
                return ModuleResult.fail(
                    f"IntelX rate limited (retry after {exc.retry_after}s)"
                )
            except APIError as exc:
                return ModuleResult.fail(f"IntelX search submission failed: {exc}")
            except Exception as exc:
                logger.exception("intelx_submit_unexpected", error=str(exc))
                return ModuleResult.fail(f"Unexpected error submitting IntelX search: {exc}")

            if not search_id:
                return ModuleResult.fail("IntelX returned empty search ID")

            logger.debug("intelx_search_submitted", search_id=search_id)

            # Step 2: Poll for results (up to 3 times with 3 s delays)
            records: list[dict[str, Any]] = []
            total_records = 0
            poll_success = False

            for attempt in range(1, _POLL_MAX_ATTEMPTS + 1):
                await asyncio.sleep(_POLL_DELAY_SECONDS)
                try:
                    result_data = await self._fetch_results(session, search_id)
                    records = result_data.get("records", [])
                    total_records = result_data.get("total", len(records))
                    poll_success = True
                    logger.debug(
                        "intelx_poll_success",
                        attempt=attempt,
                        records_found=len(records),
                    )
                    break
                except RateLimitError as exc:
                    msg = f"IntelX rate limited on poll attempt {attempt}"
                    logger.warning("intelx_poll_rate_limited", attempt=attempt)
                    warnings.append(msg)
                    if attempt == _POLL_MAX_ATTEMPTS:
                        errors.append(msg)
                except APIError as exc:
                    msg = f"IntelX poll attempt {attempt} failed: {exc}"
                    logger.warning("intelx_poll_error", attempt=attempt, error=str(exc))
                    if attempt == _POLL_MAX_ATTEMPTS:
                        errors.append(msg)
                except Exception as exc:
                    msg = f"Unexpected error on IntelX poll attempt {attempt}: {exc}"
                    logger.exception("intelx_poll_unexpected", attempt=attempt, error=str(exc))
                    if attempt == _POLL_MAX_ATTEMPTS:
                        errors.append(msg)

        # Normalise all retrieved records
        normalised_records = [
            self._parse_record(r) for r in records if isinstance(r, dict)
        ]

        elapsed_ms = int((time.monotonic() - start) * 1000)
        logger.info(
            "intelx_complete",
            term=term,
            search_id=search_id,
            total_records=total_records,
            records_returned=len(normalised_records),
            elapsed_ms=elapsed_ms,
        )

        return ModuleResult(
            success=poll_success or len(normalised_records) > 0,
            data={
                "search_id": search_id,
                "total_records": total_records,
                "records": normalised_records,
                "records_returned": len(normalised_records),
            },
            errors=errors,
            warnings=warnings,
        )

    # ── Step 1: Submit search ─────────────────────────────────────────────────

    @retry(
        retry=retry_if_exception_type(RateLimitError),
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=2, min=5, max=30),
        reraise=True,
    )
    async def _submit_search(
        self,
        session: aiohttp.ClientSession,
        term: str,
    ) -> str:
        """
        POST to the IntelX search endpoint to initiate an async search.

        Args:
            session: Active aiohttp session with API key header pre-configured.
            term: The search term (email, domain, username, etc.).

        Returns:
            The search UUID string returned by IntelX.

        Raises:
            AuthenticationError: On HTTP 401/403.
            RateLimitError: On HTTP 429.
            APIError: On other non-200 responses.
        """
        body = {**_DEFAULT_SEARCH_BODY, "term": term}

        logger.debug("intelx_submit_search", term=term)

        async with session.post(_SEARCH_ENDPOINT, json=body) as resp:
            if resp.status == 200:
                data = await resp.json(content_type=None)
                return str(data.get("id", ""))

            if resp.status in (401, 403):
                raise AuthenticationError("IntelX", "Invalid or expired API key")

            if resp.status == 429:
                retry_after_raw = resp.headers.get("Retry-After", "60")
                try:
                    retry_after = int(retry_after_raw)
                except ValueError:
                    retry_after = 60
                raise RateLimitError("IntelX", retry_after=retry_after)

            body_text = await resp.text()
            raise APIError("IntelX", resp.status, body_text[:300])

    # ── Step 2: Fetch results ─────────────────────────────────────────────────

    @retry(
        retry=retry_if_exception_type(RateLimitError),
        stop=stop_after_attempt(2),
        wait=wait_exponential(multiplier=2, min=3, max=15),
        reraise=True,
    )
    async def _fetch_results(
        self,
        session: aiohttp.ClientSession,
        search_id: str,
    ) -> dict[str, Any]:
        """
        GET results for a previously submitted IntelX search.

        Args:
            session: Active aiohttp session.
            search_id: UUID returned by _submit_search().

        Returns:
            Dict with "records" list and "total" count.

        Raises:
            RateLimitError: On HTTP 429.
            APIError: On other unexpected responses.
        """
        params = {
            "id": search_id,
            "limit": 20,
        }

        logger.debug("intelx_fetch_results", search_id=search_id)

        async with session.get(_RESULT_ENDPOINT, params=params) as resp:
            if resp.status == 200:
                data = await resp.json(content_type=None)
                if not isinstance(data, dict):
                    return {"records": [], "total": 0}
                # IntelX wraps records under "records" key
                records = data.get("records") or []
                total = data.get("found", len(records))
                return {"records": records, "total": total}

            if resp.status == 204:
                # Search still in progress / no results yet
                return {"records": [], "total": 0}

            if resp.status in (401, 403):
                raise AuthenticationError("IntelX", "API key rejected on result fetch")

            if resp.status == 429:
                retry_after_raw = resp.headers.get("Retry-After", "30")
                try:
                    retry_after = int(retry_after_raw)
                except ValueError:
                    retry_after = 30
                raise RateLimitError("IntelX", retry_after=retry_after)

            if resp.status == 404:
                # Search ID not found or expired
                return {"records": [], "total": 0}

            body = await resp.text()
            raise APIError("IntelX", resp.status, body[:300])

    # ── Record normalisation ──────────────────────────────────────────────────

    def _parse_record(self, raw: dict[str, Any]) -> dict[str, Any]:
        """
        Normalise a raw IntelX record into a consistent output schema.

        Maps numeric type codes to human-readable labels and extracts
        available metadata fields.
        """
        record_type_code = raw.get("type", 0)
        record_type = _RECORD_TYPES.get(record_type_code, "unknown")

        # Attempt to extract a preview from the record content
        preview = ""
        if isinstance(raw.get("content"), str):
            preview = raw["content"][:300]
        elif isinstance(raw.get("preview"), str):
            preview = raw["preview"][:300]

        return {
            "type": record_type,
            "type_code": record_type_code,
            "name": raw.get("name") or raw.get("systemid") or "",
            "bucket": raw.get("bucket") or "",
            "date": raw.get("date") or raw.get("added") or "",
            "preview": preview,
            "size": raw.get("size", 0),
            "media": raw.get("media", 0),
            "storageid": raw.get("storageid") or "",
        }
