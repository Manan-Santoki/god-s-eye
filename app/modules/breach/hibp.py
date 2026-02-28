"""
Have I Been Pwned (HIBP) dedicated breach module.

Standalone HIBP module for the breach package. Queries the HIBP v3 API for:
  - Full breach history (breachedaccount endpoint with truncateResponse=false)
  - Paste appearances (pasteaccount endpoint)

Respects HIBP's mandatory 1.5-second inter-request delay, handles Retry-After
headers on 429 responses, and uses tenacity for exponential backoff.

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


class HIBPModule(BaseModule):
    """
    Have I Been Pwned standalone breach and paste checker.

    Retrieves full breach details (name, date, data classes, pwn count,
    verification status) and paste appearances for a given email address.
    Enforces the mandatory 1.5 s inter-request delay between breach and
    paste API calls.
    """

    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            name="hibp",
            display_name="Have I Been Pwned (HIBP)",
            description=(
                "Queries the HIBP v3 API for complete breach history and paste "
                "appearances for an email address. Returns data classes, pwn counts, "
                "verification status, and earliest/latest breach dates."
            ),
            phase=ModulePhase.BREACH_DB,
            supported_targets=[TargetType.EMAIL],
            requires_auth=True,
            rate_limit_rpm=40,  # HIBP enforces 1.5 s between requests = ~40 rpm
            timeout_seconds=30,
            enabled_by_default=True,
            tags=["email", "breach", "hibp", "passwords", "pastes", "data-leak"],
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

        email = target.strip().lower()
        start = time.monotonic()
        warnings: list[str] = []
        errors: list[str] = []

        logger.info("hibp_start", email=email)

        headers = {
            "hibp-api-key": api_key,
            "user-agent": _USER_AGENT,
        }

        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=settings.request_timeout_seconds),
            headers=headers,
        ) as session:
            # ── Breach check ────────────────────────────────────────────────
            breaches, breach_err = await self._get_breaches(session, email, warnings)
            if breach_err:
                errors.append(breach_err)

            # HIBP enforces 1.5 s between requests on the same API key
            await asyncio.sleep(_RATE_LIMIT_DELAY)

            # ── Paste check ─────────────────────────────────────────────────
            pastes, paste_err = await self._get_pastes(session, email, warnings)
            if paste_err:
                errors.append(paste_err)

        # ── Aggregate statistics ─────────────────────────────────────────────
        total_breaches = len(breaches)
        paste_appearances = len(pastes)

        # Count breaches where Passwords or Password Hints were part of the leak
        passwords_exposed = sum(
            1
            for b in breaches
            if any(
                dc.lower() in ("passwords", "password hints")
                for dc in b.get("data_classes", [])
            )
        )

        # Earliest and latest breach dates (ISO date strings, e.g. "2016-10-01")
        breach_dates = [b["breach_date"] for b in breaches if b.get("breach_date")]
        earliest_breach = min(breach_dates) if breach_dates else None
        latest_breach = max(breach_dates) if breach_dates else None

        is_clean = total_breaches == 0 and paste_appearances == 0

        elapsed_ms = int((time.monotonic() - start) * 1000)
        logger.info(
            "hibp_complete",
            email=email,
            total_breaches=total_breaches,
            paste_appearances=paste_appearances,
            passwords_exposed=passwords_exposed,
            is_clean=is_clean,
            elapsed_ms=elapsed_ms,
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
                "is_clean": is_clean,
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
        Fetch full breach records for the email from HIBP.

        Returns (breaches_list, error_string_or_None).
        404 = not found in any breach (clean) — returns empty list, no error.
        """
        url = f"{_HIBP_BASE}/breachedaccount/{email}"
        params = {"truncateResponse": "false"}
        try:
            raw = await self._fetch_with_retry(session, url, params)
            if raw is None:
                return [], None
            breaches = [self._parse_breach(b) for b in raw]
            logger.debug("hibp_breaches_found", email=email, count=len(breaches))
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
        Fetch paste appearances for the email from HIBP.

        Returns (pastes_list, error_string_or_None).
        404 = no pastes found — returns empty list, no error.
        """
        url = f"{_HIBP_BASE}/pasteaccount/{email}"
        try:
            raw = await self._fetch_with_retry(session, url, {})
            if raw is None:
                return [], None
            pastes = [self._parse_paste(p) for p in raw]
            logger.debug("hibp_pastes_found", email=email, count=len(pastes))
            return pastes, None
        except RateLimitError as exc:
            msg = f"HIBP paste API rate limited (retry after {exc.retry_after}s)"
            logger.warning("hibp_paste_rate_limited", retry_after=exc.retry_after)
            warnings.append(msg)
            return [], None  # Non-critical — pastes are supplementary
        except AuthenticationError:
            msg = "HIBP authentication failed for paste endpoint"
            logger.error("hibp_paste_auth_failed")
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
            Parsed JSON list, or None when HTTP 404 (email not in any breach/paste).

        Raises:
            RateLimitError: On HTTP 429 — triggers tenacity retry with backoff.
                            Reads Retry-After header to set the correct wait time.
            AuthenticationError: On HTTP 401/403 — not retried, caller handles.
            APIError: On other non-200 responses.
        """
        logger.debug("hibp_fetch", url=url)
        async with session.get(url, params=params) as resp:
            if resp.status == 200:
                return await resp.json(content_type=None)
            if resp.status == 404:
                # Clean result — email not found in any breach or paste
                return None
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
        """Normalise a raw HIBP breach object into a consistent output schema."""
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
        """Normalise a raw HIBP paste object into a consistent output schema."""
        return {
            "source": raw.get("Source", ""),
            "paste_id": raw.get("Id", ""),
            "title": raw.get("Title"),
            "date": raw.get("Date"),
            "email_count": raw.get("EmailCount", 0),
        }
