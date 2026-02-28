"""
DNS reconnaissance module.

Performs comprehensive DNS enumeration using dnspython:
  - A, AAAA, MX, NS, TXT, SOA, CNAME record queries
  - SPF and DMARC policy extraction
  - Email provider detection from MX records
  - Reverse DNS (PTR) lookups on discovered A records

No API key required — uses system/local DNS resolver.
"""

from __future__ import annotations

import asyncio
import socket
from typing import Any

import dns.exception
import dns.rdatatype
import dns.resolver

from app.core.constants import ModulePhase, TargetType
from app.core.logging import get_logger
from app.modules.base import BaseModule, ModuleMetadata, ModuleResult

logger = get_logger(__name__)

# Map of MX hostname substrings -> human-readable provider names
_MX_PROVIDERS: dict[str, str] = {
    "google.com": "Google Workspace",
    "googlemail.com": "Google Workspace",
    "aspmx.l.google.com": "Google Workspace",
    "outlook.com": "Microsoft 365",
    "protection.outlook.com": "Microsoft 365",
    "mail.protection.outlook.com": "Microsoft 365",
    "hotmail.com": "Microsoft 365",
    "yahoodns.net": "Yahoo Mail",
    "yahoo.com": "Yahoo Mail",
    "mxbiz.yahoo.com": "Yahoo Mail",
    "protonmail.ch": "ProtonMail",
    "proton.me": "ProtonMail",
    "fastmail.com": "Fastmail",
    "fastmail.fm": "Fastmail",
    "zoho.com": "Zoho Mail",
    "zohomail.com": "Zoho Mail",
    "mailgun.org": "Mailgun",
    "sendgrid.net": "SendGrid",
    "amazonses.com": "Amazon SES",
    "amazonaws.com": "Amazon SES",
    "icloud.com": "Apple iCloud",
    "me.com": "Apple iCloud",
    "mailchimp.com": "Mailchimp",
    "mandrill": "Mailchimp/Mandrill",
    "mimecast.com": "Mimecast",
    "pphosted.com": "Proofpoint",
    "barracudanetworks.com": "Barracuda",
}

_RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME"]


class DNSReconModule(BaseModule):
    """DNS reconnaissance — records, SPF, DMARC, email provider detection."""

    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            name="dns_recon",
            display_name="DNS Reconnaissance",
            description=(
                "Enumerates DNS records (A/AAAA/MX/NS/TXT/SOA/CNAME), "
                "detects SPF/DMARC policies, identifies email provider from MX, "
                "and performs reverse DNS lookups."
            ),
            phase=ModulePhase.FAST_API,
            supported_targets=[
                TargetType.DOMAIN,
                TargetType.EMAIL,
                TargetType.COMPANY,
            ],
            requires_auth=False,
            enabled_by_default=True,
            tags=["dns", "domain", "mx", "spf", "dmarc", "no-key"],
        )

    async def run(
        self,
        target: str,
        target_type: TargetType,
        context: dict[str, Any],
    ) -> ModuleResult:
        # Extract domain from email if needed
        domain = self._extract_domain(target)

        errors: list[str] = []
        warnings: list[str] = []

        # Run all record queries concurrently in a thread pool
        # (dnspython is synchronous, so we offload to executor)
        loop = asyncio.get_event_loop()

        tasks = {
            rtype: loop.run_in_executor(None, self._query_record, domain, rtype)
            for rtype in _RECORD_TYPES
        }

        # Also query DMARC subdomain
        tasks["DMARC"] = loop.run_in_executor(None, self._query_record, f"_dmarc.{domain}", "TXT")

        results = await asyncio.gather(*tasks.values(), return_exceptions=True)
        record_map: dict[str, list[str]] = {}
        for rtype, result in zip(tasks.keys(), results, strict=False):
            if isinstance(result, Exception):
                errors.append(f"{rtype} query failed: {result}")
                record_map[rtype] = []
            else:
                record_map[rtype] = result  # type: ignore[assignment]

        # Reverse DNS for A records
        a_records = record_map.get("A", [])
        ptr_records: dict[str, str] = {}
        if a_records:
            ptr_tasks = [
                loop.run_in_executor(None, self._reverse_dns, ip)
                for ip in a_records[:5]  # Limit to 5 IPs
            ]
            ptr_results = await asyncio.gather(*ptr_tasks, return_exceptions=True)
            for ip, ptr in zip(a_records[:5], ptr_results, strict=False):
                if not isinstance(ptr, Exception) and ptr:
                    ptr_records[ip] = ptr

        # ── Derive fields ───────────────────────────────────────────────
        txt_records = record_map.get("TXT", [])
        spf_record, has_spf = self._extract_spf(txt_records)

        dmarc_records = record_map.get("DMARC", [])
        dmarc_record, has_dmarc, dmarc_policy = self._extract_dmarc(dmarc_records)

        mx_records = record_map.get("MX", [])
        email_provider = self._detect_email_provider(mx_records)

        ns_records = record_map.get("NS", [])
        aaaa_records = record_map.get("AAAA", [])

        # Build full records dict (exclude internal DMARC key, add to TXT info)
        final_records: dict[str, list[str]] = {k: v for k, v in record_map.items() if k != "DMARC"}
        if dmarc_records:
            final_records["DMARC"] = dmarc_records

        logger.info(
            "dns_recon_complete",
            domain=domain,
            a_records=len(a_records),
            mx_records=len(mx_records),
            has_spf=has_spf,
            has_dmarc=has_dmarc,
            email_provider=email_provider,
        )

        return ModuleResult(
            success=True,
            data={
                "domain": domain,
                "records": final_records,
                "a_records": a_records,
                "aaaa_records": aaaa_records,
                "mx_records": mx_records,
                "nameservers": ns_records,
                "ptr_records": ptr_records,
                "has_spf": has_spf,
                "spf_record": spf_record,
                "has_dmarc": has_dmarc,
                "dmarc_record": dmarc_record,
                "dmarc_policy": dmarc_policy,
                "email_provider": email_provider,
            },
            errors=errors,
            warnings=warnings,
        )

    # ── DNS query helpers ───────────────────────────────────────────────────

    def _query_record(self, domain: str, rtype: str) -> list[str]:
        """
        Synchronous DNS query for a given record type.

        Returns a list of string representations of all records found.
        NXDOMAIN / NoAnswer returns an empty list (not an error).
        """
        resolver = dns.resolver.Resolver()
        resolver.lifetime = 5.0  # 5-second total query lifetime

        try:
            answers = resolver.resolve(domain, rtype)
            results: list[str] = []
            for rdata in answers:
                results.append(str(rdata).rstrip("."))
            return results
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            return []
        except dns.exception.Timeout:
            raise TimeoutError(f"DNS timeout querying {rtype} for {domain}")
        except Exception as exc:
            raise RuntimeError(f"DNS error ({rtype} {domain}): {exc}") from exc

    def _reverse_dns(self, ip: str) -> str:
        """
        Perform a reverse DNS lookup for an IP address.

        Returns the hostname string or empty string on failure.
        """
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
            return hostname
        except (socket.herror, socket.gaierror, OSError):
            return ""

    # ── Extraction helpers ──────────────────────────────────────────────────

    @staticmethod
    def _extract_spf(txt_records: list[str]) -> tuple[str, bool]:
        """
        Find the SPF record in a list of TXT record strings.

        Returns (spf_record_string, has_spf).
        """
        for record in txt_records:
            # TXT records may be returned with surrounding quotes
            clean = record.strip('"')
            if clean.startswith("v=spf1"):
                return clean, True
        return "", False

    @staticmethod
    def _extract_dmarc(dmarc_txt: list[str]) -> tuple[str, bool, str]:
        """
        Parse DMARC TXT records to extract the policy setting.

        Returns (raw_dmarc_string, has_dmarc, policy).
        Policy is one of: "none", "quarantine", "reject", or "".
        """
        for record in dmarc_txt:
            clean = record.strip('"')
            if "v=DMARC1" in clean:
                # Extract p= value
                policy = ""
                for part in clean.split(";"):
                    part = part.strip()
                    if part.startswith("p="):
                        policy = part[2:].lower()
                        break
                return clean, True, policy
        return "", False, ""

    @staticmethod
    def _detect_email_provider(mx_records: list[str]) -> str:
        """
        Identify the email provider from MX record hostnames.

        Returns the provider name string, or "Unknown" if not recognised.
        """
        for mx in mx_records:
            # MX records often include priority: "10 aspmx.l.google.com"
            hostname = mx.split()[-1].lower().rstrip(".")
            for pattern, provider in _MX_PROVIDERS.items():
                if pattern in hostname:
                    return provider
        return "Unknown" if mx_records else "None"

    @staticmethod
    def _extract_domain(target: str) -> str:
        """Strip email prefix or URL scheme to get a bare domain."""
        target = target.strip()
        if "@" in target:
            return target.split("@", 1)[1]
        # Strip http(s)://
        for scheme in ("https://", "http://"):
            if target.startswith(scheme):
                target = target[len(scheme) :]
        # Strip path
        return target.split("/")[0].split("?")[0]
