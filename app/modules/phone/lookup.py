"""
Phone number carrier lookup module.

Attempts to retrieve detailed carrier, country, and line-type information
from external lookup APIs:

  1. Numverify (primary):   GET http://apilayer.net/api/validate?access_key={key}&number={phone}
  2. Twilio Lookup (fallback): GET https://lookups.twilio.com/v1/PhoneNumbers/{phone}?Type=carrier
                               (Basic auth: account_sid:auth_token)

If Numverify fails (no key, API error, etc.), falls back to Twilio Lookup.
If both fail, returns an error result rather than raising an exception.

Phase: FAST_API.
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

_NUMVERIFY_URL = "http://apilayer.net/api/validate"
_TWILIO_LOOKUP_BASE = "https://lookups.twilio.com/v1/PhoneNumbers"


class PhoneLookupModule(BaseModule):
    """
    Phone number carrier and type lookup module.

    Uses Numverify as the primary source and Twilio Lookup as the fallback.
    Gracefully handles missing API keys and API failures.
    """

    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            name="phone_lookup",
            display_name="Phone Carrier Lookup",
            description=(
                "Looks up phone number carrier, country, and line type via "
                "Numverify API with Twilio Lookup as fallback."
            ),
            phase=ModulePhase.FAST_API,
            supported_targets=[TargetType.PHONE],
            requires_auth=True,
            enabled_by_default=True,
            tags=["phone", "carrier", "lookup", "numverify", "twilio"],
        )

    async def run(
        self,
        target: str,
        target_type: TargetType,
        context: dict[str, Any],
    ) -> ModuleResult:
        numverify_key = self._get_secret(settings.numverify_api_key)
        twilio_sid = settings.twilio_account_sid
        twilio_token = self._get_secret(settings.twilio_auth_token)

        if not numverify_key and not (twilio_sid and twilio_token):
            logger.warning(
                "phone_lookup_skipped",
                reason="Neither NUMVERIFY_API_KEY nor TWILIO credentials configured",
            )
            return ModuleResult.fail(
                "API key not configured: set NUMVERIFY_API_KEY or "
                "TWILIO_ACCOUNT_SID + TWILIO_AUTH_TOKEN in .env"
            )

        phone = target.strip()
        # Normalize: ensure starts with + for E.164 (best effort)
        if not phone.startswith("+") and phone.isdigit():
            phone = f"+{phone}"

        start = time.monotonic()
        warnings: list[str] = []

        logger.info("phone_lookup_start", target=phone)

        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=settings.request_timeout_seconds),
            headers={"User-Agent": "god_eye/1.0"},
        ) as session:
            result_data: dict[str, Any] | None = None

            # ── Try Numverify first ──────────────────────────────────────────
            if numverify_key:
                result_data, nv_error = await self._lookup_numverify(
                    session, phone, numverify_key, warnings
                )
                if nv_error:
                    warnings.append(f"Numverify failed: {nv_error}. Trying Twilio fallback.")
                    result_data = None

            # ── Fall back to Twilio ──────────────────────────────────────────
            if result_data is None and twilio_sid and twilio_token:
                result_data, twilio_error = await self._lookup_twilio(
                    session, phone, twilio_sid, twilio_token, warnings
                )
                if twilio_error:
                    warnings.append(f"Twilio fallback failed: {twilio_error}")
                    result_data = None

        elapsed = int((time.monotonic() - start) * 1000)

        if result_data is None:
            logger.warning("phone_lookup_all_failed", target=phone)
            return ModuleResult(
                success=False,
                data={},
                errors=["All phone lookup providers failed — see warnings for details"],
                warnings=warnings,
            )

        logger.info(
            "phone_lookup_complete",
            target=phone,
            provider=result_data.get("_provider"),
            elapsed_ms=elapsed,
        )

        # Remove internal metadata field before returning
        result_data.pop("_provider", None)

        return ModuleResult(
            success=True,
            data=result_data,
            warnings=warnings,
        )

    # ── Numverify ────────────────────────────────────────────────────────────

    async def _lookup_numverify(
        self,
        session: aiohttp.ClientSession,
        phone: str,
        api_key: str,
        warnings: list[str],
    ) -> tuple[dict[str, Any] | None, str | None]:
        """
        Query Numverify for phone number details.

        Numverify returns JSON with format=1 (clean number formatting).
        Returns (result_dict, error_string_or_None).
        """
        params = {
            "access_key": api_key,
            "number": phone,
            "format": "1",
        }
        try:
            data = await self._get_json_numverify(session, _NUMVERIFY_URL, params)

            # Numverify returns {"success": false, "error": {...}} on failure
            if not data.get("valid", False) and "error" in data:
                err = data["error"]
                err_msg = f"Numverify error {err.get('code', '?')}: {err.get('info', 'unknown')}"
                # Code 101 = invalid API key
                if err.get("code") == 101:
                    return None, "Invalid Numverify API key"
                return None, err_msg

            result: dict[str, Any] = {
                "valid": data.get("valid", False),
                "number": data.get("number", phone),
                "local_format": data.get("local_format"),
                "international_format": data.get("international_format"),
                "country_prefix": data.get("country_prefix"),
                "country_code": data.get("country_code"),
                "country": data.get("country_name"),
                "location": data.get("location"),
                "carrier": data.get("carrier"),
                "line_type": self._normalise_line_type(data.get("line_type", "")),
                "is_voip": (data.get("line_type") or "").lower() == "voip",
                "provider": "numverify",
            }
            result["_provider"] = "numverify"
            return result, None

        except RateLimitError:
            return None, "Numverify rate limited"
        except AuthenticationError:
            return None, "Numverify authentication failed — check NUMVERIFY_API_KEY"
        except APIError as exc:
            return None, f"Numverify API error: {exc}"
        except Exception as exc:
            logger.exception("numverify_error", phone=phone, error=str(exc))
            return None, f"Unexpected Numverify error: {exc}"

    @retry(
        retry=retry_if_exception_type(RateLimitError),
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=20),
        reraise=True,
    )
    async def _get_json_numverify(
        self,
        session: aiohttp.ClientSession,
        url: str,
        params: dict[str, Any],
    ) -> dict[str, Any]:
        """GET request to Numverify API with retry on rate limit."""
        logger.debug("numverify_fetch", url=url)
        async with session.get(url, params=params) as resp:
            if resp.status == 429:
                raise RateLimitError("Numverify")
            if resp.status == 401:
                raise AuthenticationError("Numverify", "Invalid access key")
            if resp.status != 200:
                body = await resp.text()
                raise APIError("Numverify", resp.status, body[:300])
            return await resp.json(content_type=None)

    # ── Twilio Lookup ─────────────────────────────────────────────────────────

    async def _lookup_twilio(
        self,
        session: aiohttp.ClientSession,
        phone: str,
        account_sid: str,
        auth_token: str,
        warnings: list[str],
    ) -> tuple[dict[str, Any] | None, str | None]:
        """
        Query Twilio Lookup API for carrier and line type.

        Uses HTTP Basic Auth (account_sid:auth_token).
        Returns (result_dict, error_string_or_None).
        """
        # URL-encode the phone number (handle + prefix)
        from urllib.parse import quote

        encoded_phone = quote(phone, safe="")
        url = f"{_TWILIO_LOOKUP_BASE}/{encoded_phone}"
        params = {"Type": "carrier"}

        # Build Basic Auth header
        credentials = base64.b64encode(f"{account_sid}:{auth_token}".encode()).decode("ascii")
        auth_headers = {
            "Authorization": f"Basic {credentials}",
            "User-Agent": "god_eye/1.0",
        }

        try:
            data = await self._get_json_twilio(session, url, params, auth_headers)

            carrier_info = data.get("carrier") or {}
            line_type = carrier_info.get("type", "")
            result: dict[str, Any] = {
                "valid": True,
                "number": data.get("phone_number", phone),
                "local_format": data.get("national_format"),
                "international_format": data.get("phone_number"),
                "country_prefix": None,
                "country_code": data.get("country_code"),
                "country": data.get("country_code"),  # Twilio only returns country code
                "location": None,
                "carrier": carrier_info.get("name"),
                "line_type": self._normalise_line_type(line_type),
                "is_voip": line_type.lower() == "voip",
                "provider": "twilio",
            }
            result["_provider"] = "twilio"
            return result, None

        except AuthenticationError:
            return (
                None,
                "Twilio authentication failed — check TWILIO_ACCOUNT_SID and TWILIO_AUTH_TOKEN",
            )
        except RateLimitError:
            return None, "Twilio rate limited"
        except APIError as exc:
            if exc.status_code == 404:
                return None, f"Twilio: phone number not found — {phone}"
            return None, f"Twilio API error: {exc}"
        except Exception as exc:
            logger.exception("twilio_error", phone=phone, error=str(exc))
            return None, f"Unexpected Twilio error: {exc}"

    @retry(
        retry=retry_if_exception_type(RateLimitError),
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=20),
        reraise=True,
    )
    async def _get_json_twilio(
        self,
        session: aiohttp.ClientSession,
        url: str,
        params: dict[str, Any],
        headers: dict[str, str],
    ) -> dict[str, Any]:
        """GET request to Twilio Lookup API with retry on rate limit."""
        logger.debug("twilio_fetch", url=url)
        async with session.get(url, params=params, headers=headers) as resp:
            if resp.status == 429:
                raise RateLimitError("Twilio")
            if resp.status in (401, 403):
                raise AuthenticationError("Twilio", "Invalid credentials")
            if resp.status == 404:
                raise APIError("Twilio", 404, "Phone number not found")
            if resp.status != 200:
                body = await resp.text()
                raise APIError("Twilio", resp.status, body[:300])
            return await resp.json()

    # ── Normalisation ────────────────────────────────────────────────────────

    @staticmethod
    def _normalise_line_type(raw: str) -> str:
        """
        Normalise carrier line type strings from different providers to a
        consistent uppercase format.

        Maps various provider-specific strings to:
        MOBILE | FIXED_LINE | VOIP | TOLL_FREE | PREMIUM_RATE | UNKNOWN
        """
        mapping: dict[str, str] = {
            "mobile": "MOBILE",
            "cell": "MOBILE",
            "wireless": "MOBILE",
            "landline": "FIXED_LINE",
            "fixed_line": "FIXED_LINE",
            "fixed line": "FIXED_LINE",
            "voip": "VOIP",
            "toll_free": "TOLL_FREE",
            "tollfree": "TOLL_FREE",
            "toll-free": "TOLL_FREE",
            "premium_rate": "PREMIUM_RATE",
            "premium-rate": "PREMIUM_RATE",
        }
        return mapping.get(raw.lower().strip(), "UNKNOWN")
