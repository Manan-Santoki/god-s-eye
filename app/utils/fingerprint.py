"""
Digital fingerprinting utilities for target identification and deduplication.

Provides deterministic fingerprints for:
- Target normalization across modules
- Cross-module entity deduplication
- Change detection between scan runs
"""

import hashlib
import json
import re
from typing import Any


def fingerprint_target(target: str, target_type: str) -> str:
    """
    Generate a stable fingerprint for a target.

    Used as a cache key and for deduplication.
    """
    normalized = _normalize(target, target_type)
    raw = f"{target_type}:{normalized}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def fingerprint_result(data: dict[str, Any]) -> str:
    """
    Generate a content fingerprint for a module result.

    Used for change detection between scan runs.
    """
    # Sort keys for determinism, exclude volatile fields
    stable = {k: v for k, v in data.items() if k not in ("timestamp", "duration_ms", "scan_id")}
    serialized = json.dumps(stable, sort_keys=True, default=str)
    return hashlib.sha256(serialized.encode()).hexdigest()[:32]


def fingerprint_person(
    name: str | None = None,
    email: str | None = None,
    username: str | None = None,
    phone: str | None = None,
) -> str:
    """
    Generate a person entity fingerprint from available identifiers.

    Allows matching person entities across different modules.
    """
    parts = []
    if name:
        parts.append(f"name:{name.lower().strip()}")
    if email:
        parts.append(f"email:{email.lower().strip()}")
    if username:
        parts.append(f"username:{username.lower().strip()}")
    if phone:
        cleaned = re.sub(r"[^\d+]", "", phone)
        parts.append(f"phone:{cleaned}")

    combined = "|".join(sorted(parts))
    return hashlib.sha256(combined.encode()).hexdigest()[:24]


def compute_similarity_score(profile_a: dict[str, Any], profile_b: dict[str, Any]) -> float:
    """
    Compute a similarity score (0.0 – 1.0) between two profile dicts.

    Uses field overlap weighted by field importance.
    """
    weights = {
        "email": 0.35,
        "username": 0.25,
        "name": 0.20,
        "phone": 0.15,
        "location": 0.05,
    }

    score = 0.0
    total_weight = 0.0

    for field, weight in weights.items():
        val_a = _get_normalized_field(profile_a, field)
        val_b = _get_normalized_field(profile_b, field)

        if val_a and val_b:
            total_weight += weight
            if val_a == val_b:
                score += weight
            elif _partial_match(val_a, val_b):
                score += weight * 0.5

    if total_weight == 0:
        return 0.0

    return round(score / total_weight, 3)


def extract_username_base(username: str) -> str:
    """
    Extract the base/root of a username by stripping common suffixes.

    Examples:
        "john_doe123" -> "john_doe"
        "JohnDoe_official" -> "johndoe"
        "j.smith99" -> "j.smith"
    """
    lower = username.lower()
    # Strip trailing numbers
    base = re.sub(r"\d{1,4}$", "", lower)
    # Strip common suffixes
    for suffix in ("_official", "_real", "_irl", "_xo", "_xx", "_backup", "_2", "_3"):
        if base.endswith(suffix):
            base = base[: -len(suffix)]
    return base.strip("._-") or lower


def deduplicate_profiles(
    profiles: list[dict[str, Any]], threshold: float = 0.7
) -> list[dict[str, Any]]:
    """
    Deduplicate a list of profiles by merging similar entries.

    Profiles with similarity >= threshold are merged (first profile wins,
    non-null fields from subsequent profiles fill in missing data).
    """
    if not profiles:
        return []

    clusters: list[list[dict[str, Any]]] = []
    used = set()

    for i, profile in enumerate(profiles):
        if i in used:
            continue
        cluster = [profile]
        used.add(i)
        for j, other in enumerate(profiles[i + 1 :], start=i + 1):
            if j in used:
                continue
            if compute_similarity_score(profile, other) >= threshold:
                cluster.append(other)
                used.add(j)
        clusters.append(cluster)

    merged = []
    for cluster in clusters:
        base = dict(cluster[0])
        for extra in cluster[1:]:
            for k, v in extra.items():
                if v and not base.get(k):
                    base[k] = v
        base["_merged_count"] = len(cluster)
        merged.append(base)

    return merged


def hash_file_stable(file_path: str, algorithm: str = "sha256") -> str:
    """Compute a stable cryptographic hash of a file."""
    h = hashlib.new(algorithm)
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


# ── Internal helpers ─────────────────────────────────────────────────────────


def _normalize(target: str, target_type: str) -> str:
    """Normalize a target for consistent fingerprinting."""
    t = target.strip().lower()
    if target_type == "email":
        # Normalize Gmail dots and plus-addressing
        local, _, domain = t.partition("@")
        if domain == "gmail.com":
            local = local.replace(".", "").split("+")[0]
        return f"{local}@{domain}"
    if target_type == "phone":
        return re.sub(r"[^\d+]", "", t)
    if target_type == "domain":
        return t.removeprefix("www.")
    return t


def _get_normalized_field(profile: dict, field: str) -> str | None:
    """Get and normalize a field value from a profile dict."""
    val = profile.get(field)
    if not val:
        return None
    return str(val).lower().strip()


def _partial_match(a: str, b: str) -> bool:
    """Check if strings have significant partial overlap."""
    if len(a) < 3 or len(b) < 3:
        return False
    # One contains the other
    return a in b or b in a
