"""
DeHashed breach database module.

Queries the DeHashed API (https://api.dehashed.com) for credential records
associated with an email address, username, or person name.

Authentication uses HTTP Basic Auth: base64(dehashed_email:dehashed_api_key).
Returns structured entries with all available fields (email, username,
password, hashed_password, name, ip_address, phone, database_name) and
aggregated statistics.

Phase: BREACH_DB (requires DeHashed account email + API key).
"""

from __future__ import annotations

import base64
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

_DEHASHED_BASE = "https://api.dehashed.com"
_SEARCH_ENDPOINT = f"{_DEHASHED_BASE}/search"

# Supported query field prefixes for DeHashed
_QUERY_FIELD_MAP: dict[TargetType, str] = {
    TargetType.EMAIL: "email",
    TargetType.USERNAME: "username",
    TargetType.PERSON: "name",
}


class DeHashedModule(BaseModule):
    """
    DeHashed breach database lookup module.

    Searches the DeHashed API for leaked credential records matching the
    target. Supports email, username, and person name queries.  Identifies
    whether plaintext passwords are present in the dataset.
    """

    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            name="dehashed",
            display_name="DeHashed Breach Database",
            description=(
                "Searches DeHashed for leaked credentials matching an email, "
                "username, or person name. Returns entries with passwords, "
                "hashed credentials, and originating database names."
            ),
            phase=ModulePhase.BREACH_DB,
            supported_targets=[
                TargetType.EMAIL,
                TargetType.USERNAME,
                TargetType.PERSON,
            ],
            requires_auth=True,
            rate_limit_rpm=5,  # DeHashed free tier is very restricted
            timeout_seconds=30,
            enabled_by_default=True,
            tags=["breach", "dehashed", "credentials", "passwords", "data-leak"],
        )

    async def run(
        self,
        target: str,
        target_type: TargetType,
        context: dict[str, Any],
    ) -> ModuleResult:
        # Validate credentials
        dehashed_email = settings.dehashed_email
        dehashed_key = self._get_secret(settings.dehashed_api_key)

        if not dehashed_email or not dehashed_key:
            logger.warning("dehashed_skipped", reason="DeHashed credentials not configured")
            return ModuleResult.fail(
                "API key not configured: set DEHASHED_EMAIL and DEHASHED_API_KEY in .env"
            )

        # Build Basic Auth header: base64(email:api_key)
        credentials = f"{dehashed_email}:{dehashed_key}"
        encoded = base64.b64encode(credentials.encode()).decode()
        auth_header = f"Basic {encoded}"

        # Determine query field based on target type
        query_field = _QUERY_FIELD_MAP.get(target_type, "email")
        query = f'{query_field}:"{target.strip()}"'

        start = time.monotonic()
        warnings: list[str] = []
        errors: list[str] = []

        logger.info("dehashed_start", target=target, query_field=query_field)

        headers = {
            "Authorization": auth_header,
            "Accept": "application/json",
        }

        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=settings.request_timeout_seconds),
            headers=headers,
        ) as session:
            try:
                raw_data = await self._search(session, query, warnings)
            except AuthenticationError:
                return ModuleResult.fail("DeHashed authentication failed — check credentials")
            except RateLimitError as exc:
                return ModuleResult.fail(
                    f"DeHashed rate limited (retry after {exc.retry_after}s)"
                )
            except APIError as exc:
                return ModuleResult.fail(f"DeHashed API error: {exc}")
            except Exception as exc:
                logger.exception("dehashed_unexpected", error=str(exc))
                return ModuleResult.fail(f"Unexpected error querying DeHashed: {exc}")

        # ── Parse and aggregate results ───────────────────────────────────────
        total = raw_data.get("total", 0)
        raw_entries: list[dict[str, Any]] = raw_data.get("entries") or []

        entries = [self._parse_entry(e) for e in raw_entries if isinstance(e, dict)]

        # Flag any record with a plaintext password
        has_plaintext_passwords = any(
            bool(e.get("password")) for e in entries
        )

        # Collect unique database names seen in results
        unique_databases = sorted(
            {e["database_name"] for e in entries if e.get("database_name")}
        )

        elapsed_ms = int((time.monotonic() - start) * 1000)
        logger.info(
            "dehashed_complete",
            target=target,
            total=total,
            entries_returned=len(entries),
            has_plaintext=has_plaintext_passwords,
            unique_databases=len(unique_databases),
            elapsed_ms=elapsed_ms,
        )

        return ModuleResult(
            success=True,
            data={
                "total": total,
                "entries": entries,
                "has_plaintext_passwords": has_plaintext_passwords,
                "unique_databases": unique_databases,
                "query_field": query_field,
            },
            errors=errors,
            warnings=warnings,
        )

    # ── API call ─────────────────────────────────────────────────────────────

    @retry(
        retry=retry_if_exception_type(RateLimitError),
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=2, min=5, max=60),
        reraise=True,
    )
    async def _search(
        self,
        session: aiohttp.ClientSession,
        query: str,
        warnings: list[str],
    ) -> dict[str, Any]:
        """
        Execute a DeHashed search query.

        Args:
            session: Active aiohttp session with Auth header pre-configured.
            query: DeHashed query string, e.g. 'email:"user@example.com"'.
            warnings: Mutable list to accumulate non-fatal warnings.

        Returns:
            Raw parsed JSON response dict from DeHashed.

        Raises:
            AuthenticationError: On HTTP 401/403.
            RateLimitError: On HTTP 429 — triggers tenacity retry.
            APIError: On other unexpected HTTP responses.
        """
        params = {
            "query": query,
            "size": 100,  # Maximum page size allowed by the API
            "page": 1,
        }

        logger.debug("dehashed_search", query=query)

        async with session.get(_SEARCH_ENDPOINT, params=params) as resp:
            if resp.status == 200:
                data = await resp.json(content_type=None)
                return data if isinstance(data, dict) else {}

            if resp.status in (401, 403):
                raise AuthenticationError(
                    "DeHashed",
                    "Invalid credentials (email or API key)"
                )

            if resp.status == 429:
                retry_after_raw = resp.headers.get("Retry-After", "60")
                try:
                    retry_after = int(retry_after_raw)
                except ValueError:
                    retry_after = 60
                raise RateLimitError("DeHashed", retry_after=retry_after)

            if resp.status == 400:
                body = await resp.text()
                warnings.append(f"DeHashed rejected query: {body[:200]}")
                return {"total": 0, "entries": []}

            if resp.status == 404:
                # No results found
                return {"total": 0, "entries": []}

            body = await resp.text()
            raise APIError("DeHashed", resp.status, body[:300])

    # ── Parsing ──────────────────────────────────────────────────────────────

    @staticmethod
    def _parse_entry(raw: dict[str, Any]) -> dict[str, Any]:
        """
        Normalise a raw DeHashed entry into a consistent schema.

        All fields are optional in the API response; missing fields default
        to empty strings or None.
        """
        return {
            "id": str(raw.get("id") or ""),
            "email": raw.get("email") or "",
            "username": raw.get("username") or "",
            "password": raw.get("password") or "",
            "hashed_password": raw.get("hashed_password") or "",
            "name": raw.get("name") or "",
            "ip_address": raw.get("ip_address") or "",
            "phone": raw.get("phone") or "",
            "database_name": raw.get("database_name") or "",
            "address": raw.get("address") or "",
            "vin": raw.get("vin") or "",
            "obtained_from": raw.get("obtained_from") or "",
        }
