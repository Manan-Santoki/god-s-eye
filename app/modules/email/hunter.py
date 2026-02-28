"""
Hunter.io email discovery and verification module.

Uses the Hunter.io v2 API for:
  - Domain search: find all email addresses associated with a domain
  - Email verification: validate deliverability, SMTP reachability, MX records

If the target is an email address, it performs direct verification and also
fetches additional emails from the target's domain. If the target is a domain,
only domain search is performed.

Phase: FAST_API (requires Hunter.io API key).
"""

from __future__ import annotations

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

_HUNTER_BASE = "https://api.hunter.io/v2"


class HunterIOModule(BaseModule):
    """
    Hunter.io email discovery and verification module.

    Searches for professional email addresses by domain and verifies the
    deliverability and authenticity of a given email address.
    """

    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            name="hunter_io",
            display_name="Hunter.io Email Discovery",
            description=(
                "Discovers professional email addresses for a domain and verifies "
                "deliverability using the Hunter.io v2 API."
            ),
            phase=ModulePhase.FAST_API,
            supported_targets=[TargetType.EMAIL, TargetType.DOMAIN],
            requires_auth=True,
            enabled_by_default=True,
            tags=["email", "discovery", "hunter", "verification", "domain"],
        )

    async def run(
        self,
        target: str,
        target_type: TargetType,
        context: dict[str, Any],
    ) -> ModuleResult:
        api_key = self._get_secret(settings.hunter_io_api_key)
        if not api_key:
            logger.warning("hunter_skipped", reason="HUNTER_IO_API_KEY not configured")
            return ModuleResult.fail("API key not configured: set HUNTER_IO_API_KEY in .env")

        target = target.strip().lower()
        start = time.monotonic()
        warnings: list[str] = []
        errors: list[str] = []

        logger.info("hunter_start", target=target, target_type=target_type)

        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=settings.request_timeout_seconds),
            headers={"User-Agent": "god_eye/1.0"},
        ) as session:
            associated_emails: list[dict[str, Any]] = []
            verification: dict[str, Any] | None = None
            organization: str | None = None
            domain_pattern: str | None = None
            domain: str | None = None

            if target_type == TargetType.EMAIL:
                # Extract domain from email address
                domain = target.split("@", 1)[1] if "@" in target else None

                # Run email verification and domain search concurrently
                verify_result, domain_result = await self._run_email_checks(
                    session, target, domain, api_key, errors, warnings
                )

                verification = verify_result
                if domain_result:
                    associated_emails = domain_result.get("emails", [])
                    organization = domain_result.get("organization")
                    domain_pattern = domain_result.get("pattern")

            elif target_type == TargetType.DOMAIN:
                domain = target
                domain_result = await self._search_domain(
                    session, domain, api_key, errors, warnings
                )
                if domain_result:
                    associated_emails = domain_result.get("emails", [])
                    organization = domain_result.get("organization")
                    domain_pattern = domain_result.get("pattern")

        elapsed = int((time.monotonic() - start) * 1000)
        logger.info(
            "hunter_complete",
            target=target,
            emails_found=len(associated_emails),
            has_verification=verification is not None,
            elapsed_ms=elapsed,
        )

        success = len(errors) == 0
        return ModuleResult(
            success=success,
            data={
                "associated_emails": associated_emails,
                "verification": verification,
                "organization": organization,
                "domain": domain,
                "domain_pattern": domain_pattern,
            },
            errors=errors,
            warnings=warnings,
        )

    # ── Orchestration helpers ────────────────────────────────────────────────

    async def _run_email_checks(
        self,
        session: aiohttp.ClientSession,
        email: str,
        domain: str | None,
        api_key: str,
        errors: list[str],
        warnings: list[str],
    ) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
        """Run email verification and optional domain search concurrently."""
        import asyncio

        verify_coro = self._verify_email(session, email, api_key, errors, warnings)
        domain_coro = (
            self._search_domain(session, domain, api_key, errors, warnings)
            if domain
            else self._noop()
        )
        verify_result, domain_result = await asyncio.gather(
            verify_coro, domain_coro, return_exceptions=False
        )
        return verify_result, domain_result

    @staticmethod
    async def _noop() -> None:
        return None

    # ── API callers ──────────────────────────────────────────────────────────

    async def _search_domain(
        self,
        session: aiohttp.ClientSession,
        domain: str | None,
        api_key: str,
        errors: list[str],
        warnings: list[str],
    ) -> dict[str, Any] | None:
        """
        GET /domain-search — find all known emails for a domain.

        Returns a normalised dict with 'emails', 'organization', and 'pattern'.
        """
        if not domain:
            return None

        url = f"{_HUNTER_BASE}/domain-search"
        params = {"domain": domain, "api_key": api_key, "limit": 100}
        try:
            data = await self._get_json(session, url, params)
            raw_data = data.get("data", {})
            emails = [self._parse_email_entry(e) for e in raw_data.get("emails", [])]
            return {
                "emails": emails,
                "organization": raw_data.get("organization"),
                "pattern": raw_data.get("pattern"),
                "webmail": raw_data.get("webmail", False),
                "disposable": raw_data.get("disposable", False),
                "accept_all": raw_data.get("accept_all", False),
            }
        except RateLimitError:
            warnings.append("Hunter.io rate limited on domain search")
            return None
        except AuthenticationError:
            errors.append("Hunter.io authentication failed — check HUNTER_IO_API_KEY")
            return None
        except APIError as exc:
            errors.append(f"Hunter.io domain search error: {exc}")
            return None
        except Exception as exc:
            errors.append(f"Unexpected error in Hunter.io domain search: {exc}")
            logger.exception("hunter_domain_search_error", domain=domain, error=str(exc))
            return None

    async def _verify_email(
        self,
        session: aiohttp.ClientSession,
        email: str,
        api_key: str,
        errors: list[str],
        warnings: list[str],
    ) -> dict[str, Any] | None:
        """
        GET /email-verifier — verify a single email address.

        Returns a normalised verification dict.
        """
        url = f"{_HUNTER_BASE}/email-verifier"
        params = {"email": email, "api_key": api_key}
        try:
            data = await self._get_json(session, url, params)
            raw_data = data.get("data", {})
            return {
                "status": raw_data.get(
                    "status"
                ),  # "valid", "invalid", "accept_all", "webmail", "disposable", "unknown"
                "score": raw_data.get("score", 0),  # 0–100 confidence score
                "regexp": raw_data.get("regexp", False),  # Passes regex check
                "gibberish": raw_data.get("gibberish", False),
                "disposable": raw_data.get("disposable", False),
                "webmail": raw_data.get("webmail", False),
                "mx_records": raw_data.get("mx_records", False),
                "smtp_server": raw_data.get("smtp_server", False),
                "smtp_check": raw_data.get("smtp_check", False),
                "accept_all": raw_data.get("accept_all", False),
                "block": raw_data.get("block", False),
                "sources": raw_data.get("sources", []),
            }
        except RateLimitError:
            warnings.append("Hunter.io rate limited on email verification")
            return None
        except AuthenticationError:
            errors.append("Hunter.io authentication failed on email verifier")
            return None
        except APIError as exc:
            warnings.append(f"Hunter.io email verification error: {exc}")
            return None
        except Exception as exc:
            warnings.append(f"Unexpected error in Hunter.io email verification: {exc}")
            logger.exception("hunter_verify_error", email=email, error=str(exc))
            return None

    @retry(
        retry=retry_if_exception_type(RateLimitError),
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=30),
        reraise=True,
    )
    async def _get_json(
        self,
        session: aiohttp.ClientSession,
        url: str,
        params: dict[str, Any],
    ) -> dict[str, Any]:
        """
        Perform a GET request and return the parsed JSON.

        Raises:
            RateLimitError: On HTTP 429 (triggers tenacity retry).
            AuthenticationError: On HTTP 401/403.
            APIError: On other non-200 responses.
        """
        logger.debug("hunter_fetch", url=url)
        async with session.get(url, params=params) as resp:
            if resp.status == 200:
                return await resp.json()
            if resp.status == 429:
                retry_after_raw = resp.headers.get("Retry-After", "60")
                try:
                    retry_after = int(retry_after_raw)
                except ValueError:
                    retry_after = 60
                raise RateLimitError("HunterIO", retry_after=retry_after)
            if resp.status in (401, 403):
                raise AuthenticationError("HunterIO", "Invalid API key")
            if resp.status == 404:
                return {"data": {}}
            body = await resp.text()
            raise APIError("HunterIO", resp.status, body[:300])

    @staticmethod
    def _parse_email_entry(raw: dict[str, Any]) -> dict[str, Any]:
        """Normalise a Hunter.io email entry into a consistent schema."""
        sources = raw.get("sources", [])
        return {
            "email": raw.get("value", ""),
            "type": raw.get("type", ""),  # "personal" or "generic"
            "confidence": raw.get("confidence", 0),
            "first_name": raw.get("first_name"),
            "last_name": raw.get("last_name"),
            "position": raw.get("position"),
            "seniority": raw.get("seniority"),
            "department": raw.get("department"),
            "linkedin_url": raw.get("linkedin"),
            "twitter_handle": raw.get("twitter"),
            "phone_number": raw.get("phone_number"),
            "verification_status": (raw.get("verification") or {}).get("status"),
            "verification_date": (raw.get("verification") or {}).get("date"),
            "sources_count": len(sources),
            "first_seen": sources[0].get("extracted_on") if sources else None,
        }


HunterModule = HunterIOModule
