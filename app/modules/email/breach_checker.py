"""
Have I Been Pwned (HIBP) breach and paste checker module.

Queries the HIBP v3 API for breach and paste history associated with an email
address. Respects rate limits, uses exponential backoff via tenacity, and
parses full breach details including data classes, verification status, and
pwn counts.

Phase: BREACH_DB (requires HIBP API key).
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

_HIBP_BASE = "https://haveibeenpwned.com/api/v3"
_USER_AGENT = "god_eye/1.0"
# HIBP enforces a minimum 1500 ms between requests on the same key
_RATE_LIMIT_DELAY = 1.5


class HIBPBreachCheckerModule(BaseModule):
    """
    Have I Been Pwned breach and paste checker.

    Retrieves full breach details (name, date, data classes, pwn count, etc.)
    and paste appearances for a given email address.
    """

    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            name="hibp_breach_checker",
            display_name="Have I Been Pwned",
            description=(
                "Checks the HIBP v3 API for breach history and paste appearances "
                "associated with the target email address."
            ),
            phase=ModulePhase.BREACH_DB,
            supported_targets=[TargetType.EMAIL],
            requires_auth=True,
            rate_limit_rpm=40,  # Conservative — HIBP enforces 1.5s between requests
            enabled_by_default=True,
            tags=["email", "breach", "hibp", "passwords", "pastes"],
        )

    async def run(
        self,
        target: str,
        target_type: TargetType,
        context: dict[str, Any],
    ) -> ModuleResult:
        api_key = self._get_secret(settings.hibp_api_key)
        if not api_key:
            logger.warning("hibp_skipped", reason="HIBP_API_KEY not configured")
            return ModuleResult.fail("API key not configured: set HIBP_API_KEY in .env")

        target = target.strip().lower()
        start = time.monotonic()
        warnings: list[str] = []

        logger.info("hibp_start", target=target)

        headers = {
            "hibp-api-key": api_key,
            "user-agent": _USER_AGENT,
        }

        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=settings.request_timeout_seconds),
            headers=headers,
        ) as session:
            # ── Breach check ────────────────────────────────────────────────
            breaches, breach_err = await self._get_breaches(session, target, warnings)

            # Respect HIBP 1.5 s rate limit between calls
            await asyncio.sleep(_RATE_LIMIT_DELAY)

            # ── Paste check ─────────────────────────────────────────────────
            pastes, paste_err = await self._get_pastes(session, target, warnings)

        errors: list[str] = []
        if breach_err:
            errors.append(breach_err)
        if paste_err:
            errors.append(paste_err)

        # ── Aggregate statistics ─────────────────────────────────────────────
        total_breaches = len(breaches)
        paste_appearances = len(pastes)
        passwords_exposed = sum(
            1
            for b in breaches
            if any(
                dc.lower() in ("passwords", "password hints") for dc in b.get("data_classes", [])
            )
        )
        breach_dates = [b["breach_date"] for b in breaches if b.get("breach_date")]
        earliest_breach = min(breach_dates) if breach_dates else None
        latest_breach = max(breach_dates) if breach_dates else None

        elapsed = int((time.monotonic() - start) * 1000)
        logger.info(
            "hibp_complete",
            target=target,
            total_breaches=total_breaches,
            paste_appearances=paste_appearances,
            elapsed_ms=elapsed,
        )

        success = len(errors) == 0 or total_breaches > 0 or paste_appearances > 0
        return ModuleResult(
            success=success,
            data={
                "total_breaches": total_breaches,
                "breach_details": breaches,
                "paste_appearances": paste_appearances,
                "pastes": pastes,
                "passwords_exposed": passwords_exposed,
                "earliest_breach": earliest_breach,
                "latest_breach": latest_breach,
            },
            errors=errors,
            warnings=warnings,
        )

    # ── Private helpers ──────────────────────────────────────────────────────

    async def _get_breaches(
        self,
        session: aiohttp.ClientSession,
        email: str,
        warnings: list[str],
    ) -> tuple[list[dict[str, Any]], str | None]:
        """
        Fetch full breach details for the email from HIBP.

        Returns (breaches_list, error_string_or_None).
        """
        url = f"{_HIBP_BASE}/breachedaccount/{email}"
        params = {"truncateResponse": "false"}
        try:
            raw = await self._fetch_with_retry(session, url, params)
            if raw is None:
                # 404 = clean (not found in any breach)
                return [], None
            breaches = [self._parse_breach(b) for b in raw]
            return breaches, None
        except RateLimitError as exc:
            msg = f"HIBP rate limited (retry after {exc.retry_after}s)"
            logger.warning("hibp_rate_limited", retry_after=exc.retry_after)
            warnings.append(msg)
            return [], msg
        except AuthenticationError:
            msg = "HIBP authentication failed — check HIBP_API_KEY"
            logger.error("hibp_auth_failed")
            return [], msg
        except APIError as exc:
            msg = f"HIBP breach API error: {exc}"
            logger.error("hibp_breach_error", error=str(exc))
            return [], msg
        except Exception as exc:
            msg = f"Unexpected error querying HIBP breaches: {exc}"
            logger.exception("hibp_breach_unexpected", error=str(exc))
            return [], msg

    async def _get_pastes(
        self,
        session: aiohttp.ClientSession,
        email: str,
        warnings: list[str],
    ) -> tuple[list[dict[str, Any]], str | None]:
        """
        Fetch paste history for the email from HIBP.

        Returns (pastes_list, error_string_or_None).
        """
        url = f"{_HIBP_BASE}/pasteaccount/{email}"
        try:
            raw = await self._fetch_with_retry(session, url, {})
            if raw is None:
                return [], None
            pastes = [self._parse_paste(p) for p in raw]
            return pastes, None
        except RateLimitError as exc:
            msg = f"HIBP paste API rate limited (retry after {exc.retry_after}s)"
            warnings.append(msg)
            return [], None  # Non-critical — return empty pastes, not an error
        except AuthenticationError:
            msg = "HIBP authentication failed for paste endpoint"
            return [], msg
        except APIError as exc:
            msg = f"HIBP paste API error: {exc}"
            logger.warning("hibp_paste_error", error=str(exc))
            return [], msg
        except Exception as exc:
            msg = f"Unexpected error querying HIBP pastes: {exc}"
            logger.exception("hibp_paste_unexpected", error=str(exc))
            return [], msg

    @retry(
        retry=retry_if_exception_type(RateLimitError),
        stop=stop_after_attempt(4),
        wait=wait_exponential(multiplier=2, min=_RATE_LIMIT_DELAY, max=60),
        reraise=True,
    )
    async def _fetch_with_retry(
        self,
        session: aiohttp.ClientSession,
        url: str,
        params: dict[str, str],
    ) -> list[dict[str, Any]] | None:
        """
        Make a single GET request to the HIBP API with retry on rate limit.

        Returns:
            Parsed JSON list, or None when HTTP 404 (not found).

        Raises:
            RateLimitError: On HTTP 429 (triggers tenacity retry).
            AuthenticationError: On HTTP 401 (not retried).
            APIError: On other non-200 responses.
        """
        logger.debug("hibp_fetch", url=url)
        async with session.get(url, params=params) as resp:
            if resp.status == 200:
                return await resp.json()
            if resp.status == 404:
                return None  # Clean — no data found
            if resp.status == 429:
                retry_after_raw = resp.headers.get("Retry-After", "60")
                try:
                    retry_after = int(retry_after_raw)
                except ValueError:
                    retry_after = 60
                raise RateLimitError("HIBP", retry_after=retry_after)
            if resp.status in (401, 403):
                raise AuthenticationError("HIBP", "Invalid or missing API key")
            body = await resp.text()
            raise APIError("HIBP", resp.status, body[:300])

    @staticmethod
    def _parse_breach(raw: dict[str, Any]) -> dict[str, Any]:
        """Normalise a raw HIBP breach object into a consistent schema."""
        return {
            "source": "hibp",
            "name": raw.get("Name", ""),
            "title": raw.get("Title", ""),
            "domain": raw.get("Domain", ""),
            "breach_date": raw.get("BreachDate"),
            "added_date": raw.get("AddedDate"),
            "modified_date": raw.get("ModifiedDate"),
            "pwn_count": raw.get("PwnCount", 0),
            "description": raw.get("Description", ""),
            "data_classes": raw.get("DataClasses", []),
            "is_verified": raw.get("IsVerified", False),
            "is_fabricated": raw.get("IsFabricated", False),
            "is_sensitive": raw.get("IsSensitive", False),
            "is_retired": raw.get("IsRetired", False),
            "is_spam_list": raw.get("IsSpamList", False),
            "logo_path": raw.get("LogoPath"),
        }

    @staticmethod
    def _parse_paste(raw: dict[str, Any]) -> dict[str, Any]:
        """Normalise a raw HIBP paste object into a consistent schema."""
        return {
            "source": raw.get("Source", ""),
            "paste_id": raw.get("Id", ""),
            "title": raw.get("Title"),
            "date": raw.get("Date"),
            "email_count": raw.get("EmailCount", 0),
        }
