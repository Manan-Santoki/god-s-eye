"""
Cross-reference all module outputs to find patterns and connections.

Loads raw_data/*.json files from the scan directory, extracts entities,
builds an entity map showing which modules found which entities, finds
connections between entities, scores each connection, and optionally uses
an LLM (Claude/GPT/Ollama) for deeper analysis.

Usage:
    engine = CorrelationEngine()
    result = await engine.run(session)
    # result: {"entity_map": ..., "connections": ..., "anomalies": ..., "summary": ...}
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from pathlib import Path
from typing import Any

from app.core.config import settings
from app.core.logging import get_logger
from app.engine.session import ScanSession

logger = get_logger(__name__)

# Regex patterns for entity extraction
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_USERNAME_CLEAN_RE = re.compile(r"[^a-z0-9]")


def _flatten_to_strings(obj: Any, depth: int = 0) -> list[str]:
    """Recursively flatten a nested JSON structure into a list of string values."""
    if depth > 10:
        return []
    results: list[str] = []
    if isinstance(obj, str):
        results.append(obj)
    elif isinstance(obj, (list, tuple)):
        for item in obj:
            results.extend(_flatten_to_strings(item, depth + 1))
    elif isinstance(obj, dict):
        for v in obj.values():
            results.extend(_flatten_to_strings(v, depth + 1))
    return results


def _extract_emails_from_data(data: Any) -> list[str]:
    """Extract all email addresses from a module result dict."""
    found: set[str] = set()
    for s in _flatten_to_strings(data):
        for m in _EMAIL_RE.findall(s):
            found.add(m.lower().strip())
    return sorted(found)


def _extract_ips_from_data(data: Any) -> list[str]:
    """Extract all IP addresses from a module result dict."""
    found: set[str] = set()
    for s in _flatten_to_strings(data):
        for m in _IP_RE.findall(s):
            # Basic validity: each octet 0-255
            parts = m.split(".")
            if all(0 <= int(p) <= 255 for p in parts):
                found.add(m)
    return sorted(found)


def _extract_usernames_from_data(data: Any) -> list[str]:
    """Extract likely usernames from module results."""
    found: set[str] = set()

    def _walk(obj: Any) -> None:
        if isinstance(obj, str):
            return
        if isinstance(obj, dict):
            for key in ("username", "handle", "login", "user", "screen_name", "nick"):
                val = obj.get(key)
                if isinstance(val, str) and val.strip():
                    found.add(val.strip().lower())
            for v in obj.values():
                _walk(v)
        elif isinstance(obj, list):
            for item in obj:
                _walk(item)

    _walk(data)
    return sorted(found)


def _extract_locations_from_data(data: Any) -> list[str]:
    """Extract location strings from module results."""
    found: set[str] = set()

    def _walk(obj: Any) -> None:
        if isinstance(obj, dict):
            for key in (
                "location",
                "city",
                "country",
                "country_name",
                "region",
                "state",
                "address",
                "gps_address",
            ):
                val = obj.get(key)
                if isinstance(val, str) and val.strip():
                    found.add(val.strip())
            for v in obj.values():
                _walk(v)
        elif isinstance(obj, list):
            for item in obj:
                _walk(item)

    _walk(data)
    return sorted(found)


def _extract_names_from_data(data: Any) -> list[str]:
    """Extract person names from module results."""
    found: set[str] = set()

    def _walk(obj: Any) -> None:
        if isinstance(obj, dict):
            for key in (
                "name",
                "display_name",
                "full_name",
                "real_name",
                "owner",
                "registrant_name",
            ):
                val = obj.get(key)
                if isinstance(val, str) and val.strip() and " " in val.strip():
                    found.add(val.strip())
            for v in obj.values():
                _walk(v)
        elif isinstance(obj, list):
            for item in obj:
                _walk(item)

    _walk(data)
    return sorted(found)


def _username_base(username: str) -> str:
    """Reduce username to a likely base form for pattern matching."""
    u = username.lower()
    # Strip trailing numbers
    u = re.sub(r"\d+$", "", u)
    # Strip common suffixes/prefixes
    u = re.sub(r"[-_.](real|official|the|mr|ms|dr|dev|hq|pro|1|2|3)$", "", u)
    u = re.sub(r"^(the|mr|ms|dr)", "", u)
    # Remove non-alphanumeric
    u = _USERNAME_CLEAN_RE.sub("", u)
    return u


def _score_username_similarity(u1: str, u2: str) -> float:
    """Score similarity between two usernames (0.0-1.0)."""
    if u1 == u2:
        return 1.0
    b1, b2 = _username_base(u1), _username_base(u2)
    if b1 == b2 and b1:
        return 0.9
    # One contains the other
    if b1 and b2:
        if b1 in b2 or b2 in b1:
            overlap = min(len(b1), len(b2)) / max(len(b1), len(b2))
            return 0.6 + (0.3 * overlap)

    # Simple character overlap (Jaccard on character bigrams)
    def bigrams(s: str) -> set[str]:
        return {s[i : i + 2] for i in range(len(s) - 1)} if len(s) > 1 else set()

    bg1, bg2 = bigrams(u1.lower()), bigrams(u2.lower())
    if bg1 and bg2:
        j = len(bg1 & bg2) / len(bg1 | bg2)
        return j * 0.5
    return 0.0


class CorrelationEngine:
    """
    Cross-references all module outputs to build an entity map and find connections.

    Steps:
        1. Load all raw_data/*.json files.
        2. Extract entities: emails, usernames, IPs, names, locations.
        3. Build entity_map: entity_value -> {type, modules_that_found_it}.
        4. Detect connections:
           - Same email on multiple platforms
           - Username base-form matches
           - Geographic consistency/inconsistency
           - Temporal proximity of account creation
        5. Score connections (0.0-1.0 confidence).
        6. Optionally invoke LLM for deeper analysis.
        7. Persist results to session.correlation_dir.
    """

    def correlate(self, module_results: dict[str, Any]) -> list[dict[str, Any]]:
        """Backward-compatible helper used by older tests/code."""
        normalized = self._normalize_module_results(module_results)
        entity_map = self._build_entity_map(normalized)
        return self._find_connections(entity_map, normalized)

    async def run(self, session: ScanSession) -> dict[str, Any]:
        """
        Execute full correlation analysis on a completed (or in-progress) session.

        Args:
            session: The active ScanSession with raw_data populated.

        Returns:
            dict with keys: entity_map, connections, anomalies, summary.
        """
        logger.info("correlation_started", request_id=session.request_id)

        # ── 1. Load raw data files ─────────────────────────────────────
        module_data: dict[str, Any] = self._normalize_module_results(self._load_raw_data(session))

        if not module_data:
            logger.warning("correlation_no_data", request_id=session.request_id)
            return self._empty_result()

        # ── 2. Extract entities ────────────────────────────────────────
        entity_map = self._build_entity_map(module_data)

        # ── 3. Find connections ────────────────────────────────────────
        connections = self._find_connections(entity_map, module_data)

        # ── 4. Detect anomalies ────────────────────────────────────────
        anomalies = self._detect_anomalies(entity_map, module_data)

        # ── 5. Optional LLM analysis ───────────────────────────────────
        llm_insights: dict[str, Any] = {}
        if self._ai_enabled(session) and self._llm_available():
            try:
                llm_insights = await self._run_llm_correlation(
                    session.target,
                    session.target_type.value
                    if hasattr(session.target_type, "value")
                    else str(session.target_type),
                    module_data,
                )
            except Exception as exc:
                logger.warning("correlation_llm_failed", error=str(exc))

        # ── 6. Build summary ──────────────────────────────────────────
        summary = self._build_summary(entity_map, connections, anomalies, llm_insights)

        result: dict[str, Any] = {
            "entity_map": entity_map,
            "connections": connections,
            "anomalies": anomalies,
            "llm_insights": llm_insights,
            "summary": summary,
        }

        # ── 7. Save results ───────────────────────────────────────────
        self._save_results(session, entity_map, connections)

        logger.info(
            "correlation_completed",
            request_id=session.request_id,
            entities=len(entity_map),
            connections=len(connections),
        )
        return result

    # ── Private helpers ────────────────────────────────────────────────

    def _load_raw_data(self, session: ScanSession) -> dict[str, Any]:
        """Load all raw_data/*.json files from the session directory."""
        module_data: dict[str, Any] = {}
        raw_dir: Path = session.raw_data_dir

        if not raw_dir.exists():
            return module_data

        for json_path in sorted(raw_dir.glob("*.json")):
            module_name = json_path.stem
            try:
                with open(json_path) as f:
                    module_data[module_name] = json.load(f)
            except Exception as exc:
                logger.warning(
                    "correlation_load_failed",
                    file=str(json_path),
                    error=str(exc),
                )

        # Also pull from in-memory context if available
        for name, data in session.context.get("module_results", {}).items():
            if name not in module_data and data:
                module_data[name] = data

        return module_data

    @staticmethod
    def _normalize_module_results(module_results: dict[str, Any]) -> dict[str, Any]:
        normalized: dict[str, Any] = {}
        envelope_keys = {
            "success",
            "data",
            "errors",
            "warnings",
            "module_name",
            "target",
            "execution_time_ms",
            "findings_count",
            "error",
        }
        for module_name, data in module_results.items():
            if (
                isinstance(data, dict)
                and "data" in data
                and isinstance(data.get("data"), dict)
                and (
                    set(data.keys()) <= envelope_keys
                    or any(key in data for key in ("success", "errors", "warnings"))
                )
            ):
                normalized[module_name] = data["data"]
            else:
                normalized[module_name] = data
        return normalized

    def _ai_enabled(self, session: ScanSession) -> bool:
        return bool(session.context.get("enable_ai_correlation", settings.enable_ai_correlation))

    def _build_entity_map(self, module_data: dict[str, Any]) -> dict[str, dict[str, Any]]:
        """
        Build a unified entity map: entity_value -> metadata dict.

        Entity metadata includes:
            - type: email/username/ip/name/location
            - modules: list of module names that found this entity
            - count: how many modules found it
        """
        # entity_key -> {type, modules: set, raw_values: list}
        accumulator: dict[str, dict[str, Any]] = {}

        def _add(entity_type: str, value: str, module_name: str) -> None:
            key = f"{entity_type}:{value}"
            if key not in accumulator:
                accumulator[key] = {
                    "type": entity_type,
                    "value": value,
                    "modules": set(),
                    "count": 0,
                }
            accumulator[key]["modules"].add(module_name)
            accumulator[key]["count"] += 1

        for module_name, data in module_data.items():
            for email in _extract_emails_from_data(data):
                _add("email", email, module_name)
            for ip in _extract_ips_from_data(data):
                _add("ip", ip, module_name)
            for uname in _extract_usernames_from_data(data):
                _add("username", uname, module_name)
            for location in _extract_locations_from_data(data):
                _add("location", location, module_name)
            for name in _extract_names_from_data(data):
                _add("name", name, module_name)

        # Convert sets to sorted lists for JSON serialisation
        result: dict[str, dict[str, Any]] = {}
        for key, meta in accumulator.items():
            result[key] = {
                "type": meta["type"],
                "value": meta["value"],
                "modules": sorted(meta["modules"]),
                "count": meta["count"],
            }

        return result

    def _find_connections(
        self,
        entity_map: dict[str, dict[str, Any]],
        module_data: dict[str, Any],
    ) -> list[dict[str, Any]]:
        """
        Discover meaningful connections between entities.

        Connection types produced:
            - same_email_multiple_platforms
            - username_pattern_match
            - location_consistency
            - temporal_proximity
        """
        connections: list[dict[str, Any]] = []

        # Group entities by type
        by_type: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for meta in entity_map.values():
            by_type[meta["type"]].append(meta)

        # ── Same email on multiple modules ─────────────────────────
        for email_meta in by_type.get("email", []):
            if email_meta["count"] >= 2:
                connections.append(
                    {
                        "connection_type": "same_email_multiple_platforms",
                        "entities": [email_meta["value"]],
                        "confidence": min(0.95, 0.6 + 0.1 * email_meta["count"]),
                        "description": (
                            f"Email '{email_meta['value']}' found in "
                            f"{email_meta['count']} modules: "
                            f"{', '.join(email_meta['modules'])}"
                        ),
                        "source_modules": email_meta["modules"],
                        "evidence": [f"Found by: {m}" for m in email_meta["modules"]],
                    }
                )

        # ── Username pattern matching ──────────────────────────────
        usernames = [m["value"] for m in by_type.get("username", [])]
        seen_pairs: set[frozenset] = set()
        for i, u1 in enumerate(usernames):
            for u2 in usernames[i + 1 :]:
                pair = frozenset({u1, u2})
                if pair in seen_pairs:
                    continue
                seen_pairs.add(pair)
                score = _score_username_similarity(u1, u2)
                if score >= 0.6:
                    connections.append(
                        {
                            "connection_type": "username_pattern_match",
                            "entities": [u1, u2],
                            "confidence": round(score, 3),
                            "description": (
                                f"Usernames '{u1}' and '{u2}' share a common base pattern "
                                f"(similarity: {score:.0%})"
                            ),
                            "source_modules": list(
                                set(
                                    entity_map.get(f"username:{u1}", {}).get("modules", [])
                                    + entity_map.get(f"username:{u2}", {}).get("modules", [])
                                )
                            ),
                            "evidence": [
                                f"Base of '{u1}': '{_username_base(u1)}'",
                                f"Base of '{u2}': '{_username_base(u2)}'",
                            ],
                        }
                    )

        # ── Location consistency ───────────────────────────────────
        locations = [m["value"] for m in by_type.get("location", [])]
        location_modules: dict[str, list[str]] = {}
        for lmeta in by_type.get("location", []):
            location_modules[lmeta["value"]] = lmeta["modules"]

        if len(locations) >= 2:
            # Check for contradicting countries
            countries_seen: set[str] = set()
            for loc in locations:
                # Very rough heuristic: check if it looks like a known country
                for country in (
                    "United States",
                    "USA",
                    "UK",
                    "United Kingdom",
                    "Germany",
                    "France",
                    "Russia",
                    "China",
                    "India",
                    "Canada",
                    "Australia",
                    "Brazil",
                ):
                    if country.lower() in loc.lower():
                        countries_seen.add(country)

            if len(countries_seen) >= 2:
                connections.append(
                    {
                        "connection_type": "location_inconsistency",
                        "entities": list(countries_seen),
                        "confidence": 0.5,
                        "description": (
                            f"Target appears in multiple countries: {', '.join(countries_seen)}"
                        ),
                        "source_modules": sorted(
                            set(m for lmods in location_modules.values() for m in lmods)
                        ),
                        "evidence": [f"Location found: {loc}" for loc in locations[:5]],
                    }
                )
            elif len(countries_seen) == 1:
                connections.append(
                    {
                        "connection_type": "location_consistency",
                        "entities": locations,
                        "confidence": 0.75,
                        "description": (
                            f"All location data consistently points to: "
                            f"{next(iter(countries_seen))}"
                        ),
                        "source_modules": sorted(
                            set(m for lmods in location_modules.values() for m in lmods)
                        ),
                        "evidence": [f"Location: {loc}" for loc in locations[:5]],
                    }
                )

        # ── Temporal proximity (account creation dates) ────────────
        creation_dates: list[dict[str, Any]] = self._extract_creation_dates(module_data)
        if len(creation_dates) >= 2:
            # Find accounts created within 7 days of each other
            sorted_dates = sorted(creation_dates, key=lambda x: x["timestamp"])
            for i, d1 in enumerate(sorted_dates):
                for d2 in sorted_dates[i + 1 :]:
                    try:
                        import datetime

                        t1 = datetime.datetime.fromisoformat(d1["timestamp"].replace("Z", "+00:00"))
                        t2 = datetime.datetime.fromisoformat(d2["timestamp"].replace("Z", "+00:00"))
                        diff_days = abs((t2 - t1).days)
                        if diff_days <= 7:
                            connections.append(
                                {
                                    "connection_type": "temporal_proximity",
                                    "entities": [d1["platform"], d2["platform"]],
                                    "confidence": 0.65,
                                    "description": (
                                        f"Accounts on '{d1['platform']}' and "
                                        f"'{d2['platform']}' created within "
                                        f"{diff_days} days of each other"
                                    ),
                                    "source_modules": [d1["module"], d2["module"]],
                                    "evidence": [
                                        f"{d1['platform']} created: {d1['timestamp']}",
                                        f"{d2['platform']} created: {d2['timestamp']}",
                                    ],
                                }
                            )
                    except Exception:
                        pass

        return connections

    def _extract_creation_dates(self, module_data: dict[str, Any]) -> list[dict[str, Any]]:
        """Extract account/domain creation dates from module data."""
        dates: list[dict[str, Any]] = []

        def _walk(obj: Any, module: str, platform: str) -> None:
            if isinstance(obj, dict):
                # Look for creation date keys
                for key in (
                    "created_at",
                    "account_created_at",
                    "creation_date",
                    "registered_at",
                    "registration_date",
                    "joined_at",
                    "member_since",
                ):
                    val = obj.get(key)
                    if isinstance(val, str) and val.strip():
                        plat = obj.get("platform") or obj.get("source") or platform
                        dates.append(
                            {
                                "timestamp": val.strip(),
                                "platform": str(plat),
                                "module": module,
                            }
                        )
                # Recurse
                for v in obj.values():
                    _walk(v, module, platform)
            elif isinstance(obj, list):
                for item in obj:
                    _walk(item, module, platform)

        for module_name, data in module_data.items():
            _walk(data, module_name, module_name)

        return dates

    def _detect_anomalies(
        self,
        entity_map: dict[str, dict[str, Any]],
        module_data: dict[str, Any],
    ) -> list[dict[str, Any]]:
        """
        Detect anomalies and red flags across module results.

        Anomaly types:
            - passwords_exposed: plaintext/hash passwords found in breach data
            - unexpected_face_match: face found on unexpected platform
            - exif_gps_exposure: GPS coordinates in image metadata
            - public_registrant_info: WHOIS with un-redacted registrant data
            - leaked_secrets: API keys or tokens in public repos
        """
        anomalies: list[dict[str, Any]] = []

        for module_name, data in module_data.items():
            if not isinstance(data, dict):
                continue

            all_text = " ".join(_flatten_to_strings(data)).lower()

            # Check for exposed passwords
            password_fields = ["password", "plaintext", "hash", "exposed_password", "exposed_hash"]
            for field in password_fields:
                val = data.get(field)
                if isinstance(val, str) and val.strip() and len(val) > 3:
                    anomalies.append(
                        {
                            "anomaly_type": "passwords_exposed",
                            "description": f"Password/hash data found in breach results ({module_name})",
                            "severity": "critical",
                            "module": module_name,
                            "evidence": [f"Field '{field}' contains non-empty value"],
                        }
                    )
                    break

            # Check for GPS data in EXIF
            if any(k in data for k in ("gps_latitude", "gps_longitude", "has_gps")):
                if data.get("has_gps") or (data.get("gps_latitude") and data.get("gps_longitude")):
                    anomalies.append(
                        {
                            "anomaly_type": "exif_gps_exposure",
                            "description": f"GPS coordinates found in image metadata ({module_name})",
                            "severity": "high",
                            "module": module_name,
                            "evidence": [
                                f"Lat: {data.get('gps_latitude')}, Lon: {data.get('gps_longitude')}"
                            ],
                        }
                    )

            # Check for WHOIS privacy not enabled
            if module_name in ("whois_lookup", "whois") and isinstance(
                data.get("has_whois_privacy"), bool
            ):
                if not data["has_whois_privacy"]:
                    anomalies.append(
                        {
                            "anomaly_type": "public_registrant_info",
                            "description": "Domain WHOIS shows public registrant information",
                            "severity": "medium",
                            "module": module_name,
                            "evidence": [
                                f"Registrant: {data.get('registrant_name', 'unknown')}",
                                f"Email: {data.get('registrant_email', 'unknown')}",
                            ],
                        }
                    )

            # Leaked secrets in code repos
            secret_patterns = [
                r"api[_-]?key\s*[:=]\s*['\"][A-Za-z0-9_\-]{16,}['\"]",
                r"token\s*[:=]\s*['\"][A-Za-z0-9_\-]{16,}['\"]",
                r"secret\s*[:=]\s*['\"][A-Za-z0-9_\-]{16,}['\"]",
                r"password\s*[:=]\s*['\"][^'\"]{6,}['\"]",
            ]
            for pattern in secret_patterns:
                if re.search(pattern, all_text, re.IGNORECASE):
                    anomalies.append(
                        {
                            "anomaly_type": "leaked_secrets",
                            "description": f"Potential API key/secret found in data from {module_name}",
                            "severity": "critical",
                            "module": module_name,
                            "evidence": ["Pattern match for credential-like strings"],
                        }
                    )
                    break

        return anomalies

    def _build_summary(
        self,
        entity_map: dict[str, dict[str, Any]],
        connections: list[dict[str, Any]],
        anomalies: list[dict[str, Any]],
        llm_insights: dict[str, Any],
    ) -> dict[str, Any]:
        """Build a human-readable summary of correlation findings."""
        by_type: dict[str, int] = defaultdict(int)
        for meta in entity_map.values():
            by_type[meta["type"]] += 1

        high_conf_connections = [c for c in connections if c.get("confidence", 0) >= 0.8]
        critical_anomalies = [a for a in anomalies if a.get("severity") == "critical"]

        narrative = (
            f"Correlation analysis found {len(entity_map)} unique entities across all modules. "
            f"Entity breakdown: "
            + ", ".join(f"{v} {k}s" for k, v in sorted(by_type.items()) if v > 0)
            + f". Identified {len(connections)} connections "
            f"({len(high_conf_connections)} high-confidence) "
            f"and {len(anomalies)} anomalies "
            f"({len(critical_anomalies)} critical)."
        )

        if llm_insights.get("summary"):
            llm_summary = llm_insights["summary"]
            if not isinstance(llm_summary, str):
                llm_summary = json.dumps(llm_summary, default=str)[:500]
            narrative += " LLM analysis: " + llm_summary

        return {
            "total_entities": len(entity_map),
            "entity_breakdown": dict(by_type),
            "total_connections": len(connections),
            "high_confidence_connections": len(high_conf_connections),
            "total_anomalies": len(anomalies),
            "critical_anomalies": len(critical_anomalies),
            "narrative": narrative,
        }

    def _llm_available(self) -> bool:
        """Check if any LLM provider is configured."""
        return (
            settings.has_api_key("anthropic_api_key")
            or settings.has_api_key("openai_api_key")
            or settings.has_api_key("openrouter_api_key")
            or bool(settings.ollama_endpoint)
        )

    async def _run_llm_correlation(
        self,
        target: str,
        target_type: str,
        module_data: dict[str, Any],
    ) -> dict[str, Any]:
        """
        Run LLM-based correlation analysis.

        Sends a summarised version of the module data to the configured AI
        provider and parses the JSON response.
        """
        from app.ai.prompts import CORRELATION_PROMPT
        from app.ai.report_generator import ReportGenerator

        # Build a concise data summary (avoid sending megabytes to LLM)
        data_summary = self._build_data_summary(module_data)

        prompt = CORRELATION_PROMPT.format(
            target=target,
            target_type=target_type,
            data_summary=data_summary,
        )

        generator = ReportGenerator()
        raw_text = await generator._call_llm(prompt)

        # Attempt to parse JSON from response
        try:
            # Extract JSON block from markdown code fence if present
            json_match = re.search(r"```(?:json)?\s*([\s\S]+?)```", raw_text)
            json_str = json_match.group(1) if json_match else raw_text
            return json.loads(json_str)
        except json.JSONDecodeError:
            return {"summary": raw_text[:500], "raw_response": raw_text}

    def _build_data_summary(self, module_data: dict[str, Any], max_chars: int = 6000) -> str:
        """Build a concise text summary of module data for LLM input."""
        lines: list[str] = []
        total = 0

        for module_name, data in module_data.items():
            if total >= max_chars:
                break
            line = f"Module: {module_name}\n"
            if isinstance(data, dict):
                # Only include top-level keys with non-null scalar values
                for k, v in list(data.items())[:20]:
                    if isinstance(v, (str, int, float, bool)) and v is not None:
                        line += f"  {k}: {v}\n"
                    elif isinstance(v, list) and v:
                        line += f"  {k}: [{', '.join(str(x) for x in v[:5])}]\n"
            lines.append(line)
            total += len(line)

        return "\n".join(lines)[:max_chars]

    def _empty_result(self) -> dict[str, Any]:
        """Return empty correlation result when no data is available."""
        return {
            "entity_map": {},
            "connections": [],
            "anomalies": [],
            "llm_insights": {},
            "summary": {
                "total_entities": 0,
                "entity_breakdown": {},
                "total_connections": 0,
                "high_confidence_connections": 0,
                "total_anomalies": 0,
                "critical_anomalies": 0,
                "narrative": "No module data available for correlation.",
            },
        }

    def _save_results(
        self,
        session: ScanSession,
        entity_map: dict[str, dict[str, Any]],
        connections: list[dict[str, Any]],
    ) -> None:
        """Persist entity map and connections to disk."""
        corr_dir: Path = session.correlation_dir
        corr_dir.mkdir(parents=True, exist_ok=True)

        entity_path = corr_dir / "entity_map.json"
        conn_path = corr_dir / "connections.json"

        try:
            with open(entity_path, "w") as f:
                json.dump(entity_map, f, indent=2, default=str)

            with open(conn_path, "w") as f:
                json.dump(connections, f, indent=2, default=str)

            logger.info(
                "correlation_saved",
                entity_map=str(entity_path),
                connections=str(conn_path),
            )
        except Exception as exc:
            logger.error("correlation_save_failed", error=str(exc))
