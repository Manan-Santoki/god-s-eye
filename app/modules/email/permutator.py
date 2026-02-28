"""
Email permutation generator module.

Generates common email address format permutations from a person's name and
a target domain. Uses names discovered in earlier phases via the shared
context dict (context["discovered_names"]).

No external API is required — all computation is local.

Phase: FAST_API.
"""

from __future__ import annotations

import re
import time
import unicodedata
from typing import Any

from app.core.constants import ModulePhase, TargetType
from app.core.logging import get_logger
from app.modules.base import BaseModule, ModuleMetadata, ModuleResult

logger = get_logger(__name__)


def _normalize_name_part(part: str) -> str:
    """
    Normalize a name component to a safe ASCII string for email addresses.

    Steps:
      1. Decompose unicode to NFD form and strip combining diacritics (é -> e)
      2. Lowercase
      3. Remove all characters that are not alphanumeric or hyphen
    """
    nfd = unicodedata.normalize("NFD", part)
    ascii_str = "".join(c for c in nfd if unicodedata.category(c) != "Mn")
    ascii_str = ascii_str.lower()
    ascii_str = re.sub(r"[^a-z0-9]", "", ascii_str)
    return ascii_str


def _generate_permutations(
    first: str,
    last: str,
    domain: str,
) -> list[str]:
    """
    Generate all common email format permutations for a first/last name pair.

    Formats generated:
        john@, doe@, johndoe@, john.doe@, j.doe@, john.d@,
        jdoe@, doej@, john_doe@, john-doe@, j.d@, jd@

    Returns deduplicated list preserving generation order.
    """
    f = _normalize_name_part(first)
    l = _normalize_name_part(last)
    fi = f[0] if f else ""
    li = l[0] if l else ""

    templates: list[str] = []

    if f:
        templates.append(f"{f}@{domain}")                    # john@
    if l:
        templates.append(f"{l}@{domain}")                    # doe@
    if f and l:
        templates.append(f"{f}{l}@{domain}")                 # johndoe@
        templates.append(f"{f}.{l}@{domain}")                # john.doe@
        templates.append(f"{f}_{l}@{domain}")                # john_doe@
        templates.append(f"{f}-{l}@{domain}")                # john-doe@
    if fi and l:
        templates.append(f"{fi}.{l}@{domain}")               # j.doe@
        templates.append(f"{fi}{l}@{domain}")                # jdoe@
    if f and li:
        templates.append(f"{f}.{li}@{domain}")               # john.d@
    if l and fi:
        templates.append(f"{l}{fi}@{domain}")                # doej@
    if fi and li:
        templates.append(f"{fi}.{li}@{domain}")              # j.d@
        templates.append(f"{fi}{li}@{domain}")               # jd@

    # Deduplicate while preserving order
    seen: set[str] = set()
    result: list[str] = []
    for addr in templates:
        if addr not in seen:
            seen.add(addr)
            result.append(addr)
    return result


class EmailPermutatorModule(BaseModule):
    """
    Email permutation generator.

    Uses names from context["discovered_names"] (list of full name strings or
    dicts with 'first'/'last' keys) and the email domain to produce a
    comprehensive list of candidate email addresses.

    If no names are available in context, uses the local part of the target
    email to try to split first/last name.
    """

    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            name="email_permutator",
            display_name="Email Permutator",
            description=(
                "Generates candidate email address permutations from discovered "
                "person names and the target email domain. No API required."
            ),
            phase=ModulePhase.FAST_API,
            supported_targets=[TargetType.EMAIL, TargetType.PERSON],
            requires_auth=False,
            enabled_by_default=True,
            tags=["email", "permutation", "osint", "names"],
        )

    async def run(
        self,
        target: str,
        target_type: TargetType,
        context: dict[str, Any],
    ) -> ModuleResult:
        start = time.monotonic()
        target = target.strip().lower()
        warnings: list[str] = []

        logger.info("email_permutator_start", target=target)

        # ── Determine domain ─────────────────────────────────────────────────
        domain: str | None = None
        if target_type == TargetType.EMAIL and "@" in target:
            domain = target.split("@", 1)[1]
        elif target_type == TargetType.DOMAIN:
            domain = target

        if not domain:
            # Try to get domain from context
            domain = context.get("target_domain") or context.get("domain")

        if not domain:
            return ModuleResult.fail(
                "Cannot generate permutations: no domain available. "
                "Provide an email target or set context['target_domain']."
            )

        # ── Collect name pairs ───────────────────────────────────────────────
        name_pairs: list[tuple[str, str]] = self._extract_name_pairs(
            target=target,
            target_type=target_type,
            context=context,
            warnings=warnings,
        )

        if not name_pairs:
            return ModuleResult.fail(
                "Cannot generate permutations: no names found in context. "
                "Populate context['discovered_names'] with person name strings "
                "or dicts with 'first'/'last' keys."
            )

        # ── Generate permutations ────────────────────────────────────────────
        all_permutations: list[str] = []
        seen: set[str] = set()

        for first, last in name_pairs:
            for addr in _generate_permutations(first, last, domain):
                if addr not in seen:
                    seen.add(addr)
                    all_permutations.append(addr)

        total = len(all_permutations)
        elapsed = int((time.monotonic() - start) * 1000)
        logger.info(
            "email_permutator_complete",
            target=target,
            domain=domain,
            name_pairs=len(name_pairs),
            total_generated=total,
            elapsed_ms=elapsed,
        )

        return ModuleResult.ok(
            data={
                "permutations": all_permutations,
                "total_generated": total,
                "domain": domain,
                "name_pairs_used": [
                    {"first": f, "last": l} for f, l in name_pairs
                ],
            },
            warnings=warnings,
        )

    # ── Private helpers ──────────────────────────────────────────────────────

    def _extract_name_pairs(
        self,
        target: str,
        target_type: TargetType,
        context: dict[str, Any],
        warnings: list[str],
    ) -> list[tuple[str, str]]:
        """
        Build a list of (first_name, last_name) tuples from all available sources.

        Sources, in priority order:
          1. context["discovered_names"] — list of name strings or dicts
          2. context["person_name"] — single full name string
          3. The local part of the email address (fallback)
        """
        pairs: list[tuple[str, str]] = []
        seen_pairs: set[tuple[str, str]] = set()

        def add_pair(first: str, last: str) -> None:
            f = _normalize_name_part(first)
            l = _normalize_name_part(last)
            if f and l and (f, l) not in seen_pairs:
                seen_pairs.add((f, l))
                pairs.append((f, l))

        # Source 1: context["discovered_names"]
        discovered: list[Any] = context.get("discovered_names", [])
        for entry in discovered:
            if isinstance(entry, dict):
                first = entry.get("first") or entry.get("first_name", "")
                last = entry.get("last") or entry.get("last_name", "")
                if first and last:
                    add_pair(first, last)
                elif first or last:
                    combined = f"{first} {last}".strip()
                    f, l = self._split_full_name(combined)
                    if f and l:
                        add_pair(f, l)
            elif isinstance(entry, str) and entry.strip():
                f, l = self._split_full_name(entry)
                if f and l:
                    add_pair(f, l)

        # Source 2: context["person_name"]
        person_name = context.get("person_name", "")
        if person_name and isinstance(person_name, str):
            f, l = self._split_full_name(person_name)
            if f and l:
                add_pair(f, l)

        # Source 3: email local part fallback
        if not pairs and target_type == TargetType.EMAIL and "@" in target:
            local_part = target.split("@", 1)[0]
            f, l = self._split_local_part(local_part)
            if f and l:
                add_pair(f, l)
                warnings.append(
                    f"No names found in context — derived permutations from "
                    f"email local part '{local_part}' (may be inaccurate)."
                )

        return pairs

    @staticmethod
    def _split_full_name(name: str) -> tuple[str, str]:
        """
        Split a full name string into (first, last).

        Handles "John Doe", "John Michael Doe" (uses first word as first name,
        last word as last name, discards middle names).
        """
        parts = name.strip().split()
        if len(parts) >= 2:
            return parts[0], parts[-1]
        if len(parts) == 1:
            return parts[0], ""
        return "", ""

    @staticmethod
    def _split_local_part(local: str) -> tuple[str, str]:
        """
        Attempt to split an email local part into first/last name.

        Handles patterns: johndoe, john.doe, john_doe, john-doe, jdoe
        Returns ("", "") if no separator is found and the part is too short.
        """
        # Try common separators
        for sep in (".", "_", "-"):
            if sep in local:
                parts = local.split(sep, 1)
                return parts[0], parts[1]

        # Heuristic: split camelCase or try length-based split
        # e.g., "johndoe" → try to detect by checking if split at 4-5 chars makes sense
        # For safety, only do this if the local part is >4 chars
        if len(local) > 4:
            mid = len(local) // 2
            return local[:mid], local[mid:]
        return local, ""
