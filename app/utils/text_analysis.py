"""
Text analysis utilities for extracting entities from unstructured text.
"""

import re
from typing import Any

EMAIL_PATTERN = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b")
PHONE_PATTERN = re.compile(r"(?:\+\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}")
URL_PATTERN = re.compile(r"https?://[^\s<>\"{}|\\^`\[\]]+")
IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
USERNAME_VARIATIONS_RE = re.compile(r"^([a-z]+?)(\d{1,4})?$")


def extract_emails(text: str) -> list[str]:
    """Extract all email addresses from text."""
    return list(set(EMAIL_PATTERN.findall(text)))


def extract_phones(text: str) -> list[str]:
    """Extract phone numbers from text."""
    return list(set(PHONE_PATTERN.findall(text)))


def extract_urls(text: str) -> list[str]:
    """Extract all HTTP/HTTPS URLs from text."""
    return list(set(URL_PATTERN.findall(text)))


def extract_ips(text: str) -> list[str]:
    """Extract IP addresses from text."""
    import ipaddress

    candidates = IP_PATTERN.findall(text)
    valid = []
    for ip in candidates:
        try:
            ipaddress.ip_address(ip)
            valid.append(ip)
        except ValueError:
            pass
    return list(set(valid))


def extract_names(text: str) -> list[str]:
    """
    Extract probable person names from text.
    Uses spaCy NLP if available, falls back to capitalized word pairs.
    """
    names = []
    try:
        import spacy

        nlp = spacy.load("en_core_web_sm")
        doc = nlp(text[:5000])  # Limit to 5k chars for speed
        for ent in doc.ents:
            if ent.label_ == "PERSON":
                names.append(ent.text)
    except Exception:
        # Fallback: find capitalized word pairs (likely names)
        pattern = re.compile(r"\b([A-Z][a-z]+)\s+([A-Z][a-z]+)\b")
        names = [f"{m.group(1)} {m.group(2)}" for m in pattern.finditer(text)]

    # Deduplicate preserving order
    seen: set[str] = set()
    result = []
    for n in names:
        if n not in seen:
            seen.add(n)
            result.append(n)
    return result


def extract_locations(text: str) -> list[str]:
    """Extract location mentions from text using spaCy or regex."""
    locations = []
    try:
        import spacy

        nlp = spacy.load("en_core_web_sm")
        doc = nlp(text[:5000])
        for ent in doc.ents:
            if ent.label_ in ("GPE", "LOC", "FAC"):
                locations.append(ent.text)
    except Exception:
        # Fallback: look for common city/country patterns
        pass

    seen: set[str] = set()
    return [location for location in locations if not (location in seen or seen.add(location))]


def find_username_patterns(usernames: list[str]) -> dict[str, Any]:
    """
    Detect variations of the same base username.

    Example: ["john", "john123", "johndoe", "john_doe"] -> base "john"
    """
    if not usernames:
        return {}

    groups: dict[str, list[str]] = {}
    for username in usernames:
        lower = username.lower()
        # Try to find base name (strip trailing digits, underscores)
        base = re.sub(r"[\d_.\-]+$", "", lower).strip("_.-")
        if len(base) >= 3:
            groups.setdefault(base, []).append(username)

    # Only return groups with multiple variations
    patterns = {base: variants for base, variants in groups.items() if len(variants) > 1}
    return {
        "patterns": patterns,
        "likely_same_person": list(patterns.keys()),
        "total_groups": len(patterns),
    }


def detect_language(text: str) -> str:
    """Detect the primary language of text (basic heuristic)."""
    # Common word frequency approach
    english_words = {"the", "and", "is", "in", "to", "of", "a", "that", "it", "was"}
    words = set(text.lower().split()[:100])
    overlap = len(words & english_words)
    if overlap >= 3:
        return "en"
    return "unknown"


def summarize_findings(module_results: dict[str, Any]) -> dict[str, Any]:
    """Create a high-level summary of all module findings."""
    summary: dict[str, Any] = {
        "emails_found": [],
        "usernames_found": [],
        "ips_found": [],
        "domains_found": [],
        "breach_count": 0,
        "platforms_found": [],
        "has_face_matches": False,
        "has_exif_gps": False,
    }

    for _module_name, data in module_results.items():
        if not isinstance(data, dict):
            continue

        # Aggregate emails
        for key in ("email", "emails", "address"):
            if val := data.get(key):
                if isinstance(val, str):
                    summary["emails_found"].append(val)
                elif isinstance(val, list):
                    summary["emails_found"].extend(
                        v if isinstance(v, str) else v.get("email", "") for v in val
                    )

        # Breach count
        if bc := data.get("total_breaches") or data.get("breach_count"):
            summary["breach_count"] += int(bc)

        # Platforms
        if platforms := data.get("platforms") or data.get("found_platforms"):
            if isinstance(platforms, list):
                summary["platforms_found"].extend(
                    p if isinstance(p, str) else p.get("platform", "") for p in platforms
                )

        # Face matches
        if data.get("matches"):
            summary["has_face_matches"] = True

        # GPS
        if data.get("images_with_gps"):
            summary["has_exif_gps"] = True

    # Deduplicate
    summary["emails_found"] = list(set(filter(None, summary["emails_found"])))
    summary["platforms_found"] = list(set(filter(None, summary["platforms_found"])))

    return summary
