"""
Helpers for expanding a scan target into platform-specific candidates.
"""

from __future__ import annotations

import re
from collections import OrderedDict
from typing import Any

from app.core.constants import TargetType


def build_target_candidates(
    primary_target: str,
    primary_type: TargetType,
    target_inputs: dict[str, str] | None = None,
    context: dict[str, Any] | None = None,
) -> dict[TargetType, list[str]]:
    """Expand explicit and discovered scan inputs into candidate targets by type."""
    inputs = dict(target_inputs or {})
    ctx = dict(context or {})

    candidates: OrderedDict[TargetType, list[str]] = OrderedDict(
        (target_type, [])
        for target_type in (
            TargetType.PERSON,
            TargetType.EMAIL,
            TargetType.USERNAME,
            TargetType.DOMAIN,
            TargetType.PHONE,
            TargetType.IP,
            TargetType.COMPANY,
        )
    )

    def add(target_type: TargetType, value: Any) -> None:
        if not value:
            return
        normalized = str(value).strip()
        if not normalized:
            return
        bucket = candidates[target_type]
        if normalized not in bucket:
            bucket.append(normalized)

    add(primary_type, primary_target)

    for key, target_type in (
        ("name", TargetType.PERSON),
        ("email", TargetType.EMAIL),
        ("username", TargetType.USERNAME),
        ("domain", TargetType.DOMAIN),
        ("phone", TargetType.PHONE),
        ("ip", TargetType.IP),
        ("company", TargetType.COMPANY),
    ):
        add(target_type, inputs.get(key))

    for item in ctx.get("discovered_names", []) or []:
        add(TargetType.PERSON, item)
    for item in ctx.get("discovered_emails", []) or []:
        add(TargetType.EMAIL, item)
    for item in ctx.get("discovered_usernames", []) or []:
        add(TargetType.USERNAME, item)
    for item in ctx.get("discovered_domains", []) or []:
        add(TargetType.DOMAIN, item)
    for item in ctx.get("discovered_ips", []) or []:
        add(TargetType.IP, item)

    for email in list(candidates[TargetType.EMAIL]):
        if "@" not in email:
            continue
        local_part, domain = email.split("@", 1)
        add(TargetType.DOMAIN, domain)
        for variant in _username_variants_from_local_part(local_part):
            add(TargetType.USERNAME, variant)
        for person_name in _person_variants_from_local_part(local_part):
            add(TargetType.PERSON, person_name)

    for person_name in list(candidates[TargetType.PERSON]):
        for variant in _username_variants_from_name(person_name):
            add(TargetType.USERNAME, variant)

    return {target_type: values for target_type, values in candidates.items() if values}


def choose_execution_target(
    module_name: str,
    supported_targets: list[TargetType],
    candidates: dict[TargetType, list[str]],
    primary_target: str,
    primary_type: TargetType,
) -> tuple[str, TargetType]:
    """Choose the best execution target for a module from expanded candidates."""
    supported_target_set = set(supported_targets)
    preferred_order = [
        target_type
        for target_type in _MODULE_TARGET_PREFERENCES.get(module_name, [])
        if target_type in supported_target_set
    ]
    ordered_types: list[TargetType] = []
    for target_type in preferred_order + supported_targets:
        if target_type not in ordered_types:
            ordered_types.append(target_type)

    for target_type in ordered_types:
        values = candidates.get(target_type, [])
        if values:
            return values[0], target_type

    return primary_target, primary_type


def candidate_type_set(
    primary_target: str,
    primary_type: TargetType,
    target_inputs: dict[str, str] | None = None,
    context: dict[str, Any] | None = None,
) -> set[TargetType]:
    """Return the set of target types that can be scanned for this session."""
    return set(build_target_candidates(primary_target, primary_type, target_inputs, context))


def _username_variants_from_local_part(local_part: str) -> list[str]:
    cleaned = local_part.strip()
    if not cleaned:
        return []

    variants = [cleaned]
    separator_normalized = re.sub(r"[._\s]+", "-", cleaned)
    underscore_normalized = re.sub(r"[.\-\s]+", "_", cleaned)
    compact = re.sub(r"[^a-zA-Z0-9]", "", cleaned)

    for variant in (separator_normalized, underscore_normalized, compact):
        if variant:
            variants.append(variant)

    return list(dict.fromkeys(value for value in variants if value))


def _person_variants_from_local_part(local_part: str) -> list[str]:
    stripped = re.sub(r"\d+", "", local_part).strip("._- ")
    if not stripped:
        return []
    tokens = [token for token in re.split(r"[._-]+", stripped) if token]
    if len(tokens) < 2:
        return []
    return [" ".join(token.title() for token in tokens)]


def _username_variants_from_name(name: str) -> list[str]:
    tokens = [token for token in re.split(r"\s+", name.strip().lower()) if token]
    if not tokens:
        return []
    variants = [
        "".join(tokens),
        "-".join(tokens),
        "_".join(tokens),
    ]
    return list(dict.fromkeys(variant for variant in variants if variant))


_MODULE_TARGET_PREFERENCES: dict[str, list[TargetType]] = {
    "github_api": [TargetType.USERNAME],
    "social_checker": [TargetType.USERNAME],
    "sherlock_wrapper": [TargetType.USERNAME],
    "maigret_wrapper": [TargetType.USERNAME],
    "reddit_api": [TargetType.USERNAME],
    "twitter_api": [TargetType.USERNAME],
    "instagram_scraper": [TargetType.USERNAME, TargetType.PERSON],
    "linkedin_scraper": [TargetType.PERSON, TargetType.USERNAME],
    "facebook_scraper": [TargetType.PERSON, TargetType.USERNAME],
    "youtube_api": [TargetType.PERSON, TargetType.USERNAME],
    "whois_lookup": [TargetType.DOMAIN],
    "certificate_search": [TargetType.DOMAIN],
    "dns_recon": [TargetType.DOMAIN, TargetType.EMAIL],
    "subdomain_enum": [TargetType.DOMAIN],
    "phone_lookup": [TargetType.PHONE],
    "phone_validator": [TargetType.PHONE],
}
