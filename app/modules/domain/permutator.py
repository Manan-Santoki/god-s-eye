"""
Generate likely owned domains from names/usernames and probe which ones exist.
"""

from __future__ import annotations

import asyncio
import re
import time
from typing import Any

import dns.exception
import dns.resolver

from app.core.config import get_module_setting
from app.core.constants import ModulePhase, TargetType
from app.core.logging import get_logger
from app.modules.base import BaseModule, ModuleMetadata, ModuleResult

logger = get_logger(__name__)

DEFAULT_TLDS = [
    # Generic TLDs
    "com",
    "net",
    "org",
    "info",
    "biz",
    "pro",
    # Developer/Tech
    "io",
    "ai",
    "app",
    "dev",
    "tech",
    "cloud",
    "sh",
    "ws",
    # Personal/Creative
    "me",
    "co",
    "xyz",
    "site",
    "online",
    "name",
    "link",
    "blog",
    "media",
    "studio",
    "design",
    "digital",
    # Geographic — global
    "us",
    "in",
    "uk",
    "co.uk",
    "au",
    "com.au",
    "ca",
    "eu",
    "de",
    "fr",
    "nl",
    "sg",
    "nz",
    # Business
    "services",
    "solutions",
    "consulting",
    "network",
    "store",
    "shop",
    # Misc
    "cc",
    "tv",
    "codes",
    "email",
]


class DomainPermutatorModule(BaseModule):
    """Generate and probe likely personal domains."""

    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            name="domain_permutator",
            display_name="Domain Permutator",
            description="Generates likely owned domains from names and usernames, then probes which are registered",
            phase=ModulePhase.FAST_API,
            supported_targets=[
                TargetType.PERSON,
                TargetType.EMAIL,
                TargetType.USERNAME,
                TargetType.COMPANY,
            ],
            requires_auth=False,
            enabled_by_default=True,
            priority=2,
            tags=["domain", "permutation", "dns", "discovery"],
        )

    async def validate(self, target: str, target_type: TargetType) -> bool:
        return target_type in {
            TargetType.PERSON,
            TargetType.EMAIL,
            TargetType.USERNAME,
            TargetType.COMPANY,
        }

    async def run(
        self, target: str, target_type: TargetType, context: dict[str, Any]
    ) -> ModuleResult:
        start = time.monotonic()
        labels = self._build_labels(target, target_type, context)
        tlds = self._get_tlds()
        max_candidates = max(
            1,
            int(get_module_setting("domain", "permutator", "max_candidates", 1000) or 1000),
        )
        candidates = self._build_domains(labels, tlds, max_candidates)

        if not candidates:
            return ModuleResult(
                success=True,
                data={
                    "candidate_labels": [],
                    "candidate_domains": [],
                    "registered_domains": [],
                    "total_candidates": 0,
                    "total_registered": 0,
                },
                warnings=["No domain permutation inputs were available"],
            )

        semaphore = asyncio.Semaphore(50)
        tasks = [self._probe_domain(domain, semaphore) for domain in candidates]
        results = await asyncio.gather(*tasks)
        registered_domains = [result for result in results if result.get("is_registered")]
        discovered_ips = sorted(
            {
                ip
                for result in registered_domains
                for ip in result.get("a_records", []) + result.get("aaaa_records", [])
            }
        )

        elapsed = int((time.monotonic() - start) * 1000)
        logger.info(
            "domain_permutator_complete",
            candidates=len(candidates),
            registered=len(registered_domains),
        )

        return ModuleResult(
            success=True,
            module_name=self.metadata().name,
            target=target,
            execution_time_ms=elapsed,
            findings_count=len(registered_domains),
            data={
                "candidate_labels": labels,
                "candidate_domains": candidates,
                "registered_domains": registered_domains,
                "total_candidates": len(candidates),
                "total_registered": len(registered_domains),
                "discovered_domains": [item["domain"] for item in registered_domains],
                "discovered_ips": discovered_ips,
            },
        )

    def _get_tlds(self) -> list[str]:
        raw = get_module_setting("domain", "permutator", "tlds", list(DEFAULT_TLDS))
        if isinstance(raw, list):
            values = [str(item).strip().lstrip(".").lower() for item in raw if str(item).strip()]
            return values or list(DEFAULT_TLDS)
        return list(DEFAULT_TLDS)

    def _build_labels(
        self,
        target: str,
        target_type: TargetType,
        context: dict[str, Any],
    ) -> list[str]:
        inputs = context.get("target_inputs", {}) if isinstance(context, dict) else {}
        if not isinstance(inputs, dict):
            inputs = {}

        names: list[str] = []
        usernames: list[str] = []
        if target_type == TargetType.PERSON:
            names.append(target)
        if target_type == TargetType.USERNAME:
            usernames.append(target)
        if target_type == TargetType.COMPANY:
            names.append(target)

        if target_type == TargetType.EMAIL and "@" in target:
            local_part = target.split("@", 1)[0]
            usernames.append(local_part)

        for value in (inputs.get("name"), inputs.get("company")):
            if value:
                names.append(str(value))
        for value in (inputs.get("username"),):
            if value:
                usernames.append(str(value))
        email_value = str(inputs.get("email") or "").strip()
        if email_value and "@" in email_value:
            usernames.append(email_value.split("@", 1)[0])

        for value in context.get("discovered_names", []) or []:
            names.append(str(value))
        for value in context.get("discovered_usernames", []) or []:
            usernames.append(str(value))

        labels: list[str] = []
        seen: set[str] = set()

        def add(value: str | None) -> None:
            if not value:
                return
            normalized = re.sub(r"[^a-z0-9-]", "", value.lower())
            normalized = normalized.strip("-")
            if len(normalized) < 3 or normalized in seen:
                return
            seen.add(normalized)
            labels.append(normalized)

        for username in usernames:
            cleaned = self._normalize_username(username)
            for variant in (
                cleaned,
                cleaned.replace(".", ""),
                cleaned.replace("_", ""),
                cleaned.replace("-", ""),
            ):
                add(variant)

        for name in names:
            tokens = [token for token in re.split(r"\s+", name.strip().lower()) if token]
            if not tokens:
                continue
            first = tokens[0]
            last = tokens[-1] if len(tokens) > 1 else ""
            middle = tokens[1] if len(tokens) > 2 else ""
            initials = "".join(token[0] for token in tokens if token)

            # Full name combos
            add("".join(tokens))
            add("-".join(tokens))
            add("_".join(tokens))
            add("".join(tokens[:2]))
            if first and last:
                add(f"{first}{last}")
                add(f"{first[0]}{last}")
                add(f"{first}{last[0]}")
                add(f"{last}{first}")
                add(f"{first[:2]}{last}")
                add(f"{first[:3]}{last}")
                add(f"{last}{first[0]}")
                add(f"{last}-{first}")
                add(f"{first}-{last}")
                add(f"{first[0]}-{last}")
                # Middle name variants
                if middle:
                    add(f"{first}{middle[0]}{last}")
                    add(f"{first}{middle}{last}")
            if initials and last:
                add(f"{initials}{last}")
                add(f"{initials}-{last}")
            if initials:
                add(initials)
            if len(tokens) >= 2:
                add("".join(token[:3] for token in tokens[:2]))
                add("".join(token[:2] for token in tokens[:2]))

        return labels

    @staticmethod
    def _normalize_username(value: str) -> str:
        return re.sub(r"[^a-z0-9._-]", "", value.strip().lower())

    @staticmethod
    def _build_domains(labels: list[str], tlds: list[str], max_candidates: int) -> list[str]:
        domains: list[str] = []
        for label in labels:
            for tld in tlds:
                domains.append(f"{label}.{tld}")
                if len(domains) >= max_candidates:
                    return domains
        return domains

    async def _probe_domain(
        self,
        domain: str,
        semaphore: asyncio.Semaphore,
    ) -> dict[str, Any]:
        async with semaphore:
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(None, self._probe_domain_sync, domain)

    def _probe_domain_sync(self, domain: str) -> dict[str, Any]:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 2
        resolver.lifetime = 2
        records: dict[str, list[str]] = {
            "A": [],
            "AAAA": [],
            "NS": [],
            "MX": [],
            "SOA": [],
        }
        is_registered = False

        for record_type in ("NS", "SOA", "A", "AAAA", "MX"):
            try:
                answers = resolver.resolve(domain, record_type)
                values = [str(answer).rstrip(".") for answer in answers]
                records[record_type] = values
                if values:
                    is_registered = True
            except dns.resolver.NXDOMAIN:
                continue
            except (dns.resolver.NoAnswer, dns.resolver.NoNameservers):
                continue
            except dns.exception.Timeout:
                continue
            except Exception:
                continue

        return {
            "domain": domain,
            "is_registered": is_registered,
            "a_records": records["A"],
            "aaaa_records": records["AAAA"],
            "nameservers": records["NS"],
            "mx_records": records["MX"],
            "soa_records": records["SOA"],
        }
