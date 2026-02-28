"""
Email format and DNS validation module.

Validates email format via regex, checks DNS MX records, SPF, and DMARC
records using dnspython, detects disposable email providers, and identifies
the email service provider from MX hostnames.

Phase: FAST_API (no external API required — all local/DNS).
"""

from __future__ import annotations

import asyncio
import re
import time
from typing import Any

import dns.asyncresolver
import dns.exception
import dns.rdatatype

from app.core.constants import (
    DISPOSABLE_EMAIL_DOMAINS_SAMPLE,
    ModulePhase,
    TargetType,
)
from app.core.logging import get_logger
from app.modules.base import BaseModule, ModuleMetadata, ModuleResult

logger = get_logger(__name__)

# RFC 5322-compliant email regex (practical subset)
_EMAIL_REGEX = re.compile(
    r"^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+"
    r"@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
    r"(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*"
    r"\.[a-zA-Z]{2,}$"
)

# MX hostname substrings -> provider name mapping (checked in order)
_MX_PROVIDER_MAP: list[tuple[str, str]] = [
    ("google.com", "Google (Gmail)"),
    ("googlemail.com", "Google (Gmail)"),
    ("aspmx.l.google", "Google (Workspace)"),
    ("outlook.com", "Microsoft (Outlook/Hotmail)"),
    ("hotmail.com", "Microsoft (Outlook/Hotmail)"),
    ("protection.outlook.com", "Microsoft (Exchange Online)"),
    ("mail.protection.outlook.com", "Microsoft (Exchange Online)"),
    ("protonmail.ch", "ProtonMail"),
    ("proton.me", "ProtonMail"),
    ("mailgun.org", "Mailgun"),
    ("sendgrid.net", "SendGrid"),
    ("amazonses.com", "Amazon SES"),
    ("yahoodns.net", "Yahoo Mail"),
    ("yahoo.com", "Yahoo Mail"),
    ("zoho.com", "Zoho Mail"),
    ("icloud.com", "Apple (iCloud Mail)"),
    ("apple.com", "Apple (iCloud Mail)"),
    ("fastmail.com", "Fastmail"),
    ("fastmail.fm", "Fastmail"),
    ("yandex.ru", "Yandex Mail"),
    ("yandex.net", "Yandex Mail"),
    ("mailchimp.com", "Mailchimp"),
    ("mimecast.com", "Mimecast"),
    ("barracudanetworks.com", "Barracuda"),
    ("pphosted.com", "Proofpoint"),
]


class EmailValidatorModule(BaseModule):
    """
    Email format validation and DNS-based intelligence module.

    Checks email syntax, MX records, SPF policy, DMARC policy, disposable
    domain membership, and infers the email service provider.
    """

    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            name="email_validator",
            display_name="Email Validator",
            description=(
                "Validates email format, DNS MX/SPF/DMARC records, "
                "detects disposable domains and identifies the email provider."
            ),
            phase=ModulePhase.FAST_API,
            supported_targets=[TargetType.EMAIL],
            requires_auth=False,
            enabled_by_default=True,
            tags=["email", "dns", "validation", "spf", "dmarc"],
        )

    async def run(
        self,
        target: str,
        target_type: TargetType,
        context: dict[str, Any],
    ) -> ModuleResult:
        start = time.monotonic()
        target = target.strip().lower()

        logger.info("email_validator_start", target=target)

        # ── Format validation ────────────────────────────────────────────────
        is_valid_format = bool(_EMAIL_REGEX.match(target))
        if not is_valid_format:
            logger.warning("email_invalid_format", target=target)
            elapsed = int((time.monotonic() - start) * 1000)
        return ModuleResult.ok(
            data={
                "email": target,
                "is_valid_format": False,
                "has_mx_records": False,
                "mx_records": [],
                "has_spf": False,
                    "spf_record": None,
                    "has_dmarc": False,
                    "dmarc_record": None,
                    "is_disposable": False,
                    "email_provider": None,
                    "domain": None,
                },
                warnings=["Email format is invalid — skipping DNS checks."],
            )

        domain = target.split("@", 1)[1]

        # ── Run DNS lookups concurrently ─────────────────────────────────────
        mx_task = asyncio.create_task(self._get_mx_records(domain))
        spf_task = asyncio.create_task(self._get_spf_record(domain))
        dmarc_task = asyncio.create_task(self._get_dmarc_record(domain))

        mx_records, spf_record, dmarc_record = await asyncio.gather(
            mx_task, spf_task, dmarc_task, return_exceptions=False
        )

        has_mx = bool(mx_records)
        has_spf = spf_record is not None
        has_dmarc = dmarc_record is not None
        is_disposable = domain in DISPOSABLE_EMAIL_DOMAINS_SAMPLE
        provider = self._detect_provider(mx_records)

        elapsed = int((time.monotonic() - start) * 1000)
        logger.info(
            "email_validator_complete",
            target=target,
            domain=domain,
            has_mx=has_mx,
            has_spf=has_spf,
            has_dmarc=has_dmarc,
            is_disposable=is_disposable,
            provider=provider,
            elapsed_ms=elapsed,
        )

        return ModuleResult.ok(
            data={
                "email": target,
                "is_valid_format": True,
                "has_mx_records": has_mx,
                "mx_records": mx_records,
                "has_spf": has_spf,
                "spf_record": spf_record,
                "has_dmarc": has_dmarc,
                "dmarc_record": dmarc_record,
                "is_disposable": is_disposable,
                "email_provider": provider,
                "domain": domain,
            }
        )

    # ── DNS helpers ──────────────────────────────────────────────────────────

    async def _get_mx_records(self, domain: str) -> list[dict[str, Any]]:
        """
        Query MX records for the domain.

        Returns a list of dicts with 'priority' and 'host' keys, sorted by
        priority (ascending).
        """
        try:
            resolver = dns.asyncresolver.Resolver()
            resolver.timeout = 5
            resolver.lifetime = 10
            answers = await resolver.resolve(domain, "MX")
            records = [
                {
                    "priority": rdata.preference,
                    "host": str(rdata.exchange).rstrip("."),
                }
                for rdata in answers
            ]
            return sorted(records, key=lambda r: r["priority"])
        except (dns.exception.DNSException, Exception) as exc:
            logger.debug("mx_lookup_failed", domain=domain, error=str(exc))
            return []

    async def _get_spf_record(self, domain: str) -> str | None:
        """
        Query TXT records for the domain and return the SPF record if found.

        SPF records begin with "v=spf1".
        """
        try:
            resolver = dns.asyncresolver.Resolver()
            resolver.timeout = 5
            resolver.lifetime = 10
            answers = await resolver.resolve(domain, "TXT")
            for rdata in answers:
                txt = "".join(s.decode("utf-8", errors="replace") for s in rdata.strings)
                if txt.startswith("v=spf1"):
                    return txt
        except (dns.exception.DNSException, Exception) as exc:
            logger.debug("spf_lookup_failed", domain=domain, error=str(exc))
        return None

    async def _get_dmarc_record(self, domain: str) -> str | None:
        """
        Query TXT records on _dmarc.{domain} and return the DMARC record.

        DMARC records begin with "v=DMARC1".
        """
        dmarc_host = f"_dmarc.{domain}"
        try:
            resolver = dns.asyncresolver.Resolver()
            resolver.timeout = 5
            resolver.lifetime = 10
            answers = await resolver.resolve(dmarc_host, "TXT")
            for rdata in answers:
                txt = "".join(s.decode("utf-8", errors="replace") for s in rdata.strings)
                if txt.upper().startswith("V=DMARC1"):
                    return txt
        except (dns.exception.DNSException, Exception) as exc:
            logger.debug("dmarc_lookup_failed", host=dmarc_host, error=str(exc))
        return None

    def _detect_provider(self, mx_records: list[dict[str, Any]]) -> str | None:
        """
        Infer email provider from MX hostnames.

        Iterates through known provider substrings and returns the first match.
        Returns None if the provider cannot be determined or there are no MX records.
        """
        for record in mx_records:
            host = record.get("host", "").lower()
            for mx_substring, provider_name in _MX_PROVIDER_MAP:
                if mx_substring in host:
                    return provider_name
        return None
