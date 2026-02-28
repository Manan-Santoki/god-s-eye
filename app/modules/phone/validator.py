"""
Phone number validation and intelligence module.

Uses the phonenumbers library to parse, validate, and extract metadata from
a phone number. Provides country, carrier, line type, and all standard
format representations.

Phase: FAST_API (no external API required — all local computation).
"""

from __future__ import annotations

import time
from typing import Any

from app.core.constants import ModulePhase, TargetType
from app.core.logging import get_logger
from app.modules.base import BaseModule, ModuleMetadata, ModuleResult

logger = get_logger(__name__)


class PhoneValidatorModule(BaseModule):
    """
    Phone number format validation and metadata extraction.

    Parses the phone number with the phonenumbers library and extracts
    country code, country name, carrier, line type, and all standard formats.
    """

    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            name="phone_validator",
            display_name="Phone Number Validator",
            description=(
                "Validates phone number format and extracts country, carrier, "
                "line type and format variants using the phonenumbers library."
            ),
            phase=ModulePhase.FAST_API,
            supported_targets=[TargetType.PHONE],
            requires_auth=False,
            enabled_by_default=True,
            tags=["phone", "validation", "carrier", "geo", "format"],
        )

    async def run(
        self,
        target: str,
        target_type: TargetType,
        context: dict[str, Any],
    ) -> ModuleResult:
        start = time.monotonic()
        target = target.strip()

        logger.info("phone_validator_start", target=target)

        # Import inside run to avoid hard dependency at import time
        try:
            import phonenumbers
            from phonenumbers import (
                carrier as pn_carrier,
                geocoder as pn_geocoder,
                number_type as pn_number_type,
                PhoneNumberFormat,
                PhoneNumberType,
            )
        except ImportError:
            return ModuleResult.fail(
                "phonenumbers library not installed. "
                "Run: pip install phonenumbers"
            )

        # ── Parse ────────────────────────────────────────────────────────────
        parsed = None
        parse_error: str | None = None

        # Try to parse with explicit country hint from context if available
        default_region = context.get("phone_region") or context.get("country_code")

        for number_str in [target, f"+{target.lstrip('+')}"]:
            try:
                parsed = phonenumbers.parse(number_str, default_region)
                break
            except phonenumbers.NumberParseException as exc:
                parse_error = str(exc)

        if parsed is None:
            elapsed = int((time.monotonic() - start) * 1000)
            logger.warning("phone_parse_failed", target=target, error=parse_error)
            return ModuleResult.ok(
                data={
                    "is_valid": False,
                    "country_code": None,
                    "country": None,
                    "carrier": None,
                    "line_type": None,
                    "international_format": None,
                    "national_format": None,
                    "e164_format": None,
                    "rfc3966_format": None,
                    "is_possible": False,
                },
                warnings=[f"Could not parse phone number: {parse_error}"],
            )

        # ── Validate ─────────────────────────────────────────────────────────
        is_valid = phonenumbers.is_valid_number(parsed)
        is_possible = phonenumbers.is_possible_number(parsed)

        # ── Country ──────────────────────────────────────────────────────────
        country_code_int = parsed.country_code  # e.g. 1 for US
        region_code = phonenumbers.region_code_for_number(parsed)  # e.g. "US"

        country_name = pn_geocoder.description_for_number(parsed, "en")

        # ── Carrier ──────────────────────────────────────────────────────────
        carrier_name = pn_carrier.name_for_number(parsed, "en") or None

        # ── Line type ────────────────────────────────────────────────────────
        num_type = pn_number_type(parsed)
        line_type = self._line_type_str(num_type, PhoneNumberType)

        # ── Formats ──────────────────────────────────────────────────────────
        international_fmt = phonenumbers.format_number(
            parsed, PhoneNumberFormat.INTERNATIONAL
        )
        national_fmt = phonenumbers.format_number(
            parsed, PhoneNumberFormat.NATIONAL
        )
        e164_fmt = phonenumbers.format_number(
            parsed, PhoneNumberFormat.E164
        )
        rfc3966_fmt = phonenumbers.format_number(
            parsed, PhoneNumberFormat.RFC3966
        )

        elapsed = int((time.monotonic() - start) * 1000)
        logger.info(
            "phone_validator_complete",
            target=target,
            is_valid=is_valid,
            country=region_code,
            line_type=line_type,
            elapsed_ms=elapsed,
        )

        return ModuleResult.ok(
            data={
                "is_valid": is_valid,
                "is_possible": is_possible,
                "country_code": region_code,              # ISO 3166-1 alpha-2, e.g. "US"
                "country_dial_code": f"+{country_code_int}",  # e.g. "+1"
                "country": country_name or region_code,   # Human-readable country name
                "carrier": carrier_name,                  # May be None for landlines or VoIP
                "line_type": line_type,                   # "MOBILE", "FIXED_LINE", "VOIP", etc.
                "international_format": international_fmt,  # "+1 800 555 0199"
                "national_format": national_fmt,           # "(800) 555-0199"
                "e164_format": e164_fmt,                   # "+18005550199"
                "rfc3966_format": rfc3966_fmt,             # "tel:+1-800-555-0199"
                "raw_input": target,
            }
        )

    @staticmethod
    def _line_type_str(num_type: Any, PhoneNumberType: Any) -> str:
        """Map a PhoneNumberType enum value to a human-readable string."""
        mapping = {
            PhoneNumberType.MOBILE: "MOBILE",
            PhoneNumberType.FIXED_LINE: "FIXED_LINE",
            PhoneNumberType.FIXED_LINE_OR_MOBILE: "FIXED_LINE_OR_MOBILE",
            PhoneNumberType.TOLL_FREE: "TOLL_FREE",
            PhoneNumberType.PREMIUM_RATE: "PREMIUM_RATE",
            PhoneNumberType.SHARED_COST: "SHARED_COST",
            PhoneNumberType.VOIP: "VOIP",
            PhoneNumberType.PERSONAL_NUMBER: "PERSONAL_NUMBER",
            PhoneNumberType.PAGER: "PAGER",
            PhoneNumberType.UAN: "UAN",
            PhoneNumberType.VOICEMAIL: "VOICEMAIL",
            PhoneNumberType.UNKNOWN: "UNKNOWN",
        }
        return mapping.get(num_type, "UNKNOWN")
