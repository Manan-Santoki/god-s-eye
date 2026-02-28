"""
Chronological event timeline builder for GOD_EYE.

Extracts timestamped events from all module results, sorts them
chronologically, optionally enriches them with an LLM, and saves
the timeline to correlation/timeline.json.

Usage:
    builder = TimelineBuilder()
    events = await builder.run(session)
    # events: list[TimelineEvent] sorted oldest-first
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from app.core.config import settings
from app.core.logging import get_logger
from app.database.models import TimelineEvent
from app.engine.session import ScanSession

logger = get_logger(__name__)

# ── Date parsing helpers ────────────────────────────────────────────

_ISO_RE = re.compile(
    r"\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}(?::\d{2})?(?:[.\d]+)?(?:Z|[+-]\d{2}:?\d{2})?)?"
)
_YEAR_ONLY_RE = re.compile(r"\b(19[6-9]\d|20[0-3]\d)\b")


def _parse_timestamp(raw: str) -> str | None:
    """
    Normalise a raw timestamp string to ISO-8601 format.

    Returns None if the string cannot be parsed.
    """
    if not isinstance(raw, str):
        return None
    raw = raw.strip()

    # Already ISO-8601
    m = _ISO_RE.match(raw)
    if m:
        return m.group(0)

    # Try dateutil for flexible parsing
    try:
        from dateutil import parser as dateutil_parser

        dt = dateutil_parser.parse(raw, fuzzy=False)
        return dt.isoformat()
    except Exception:
        pass

    # Year-only fallback
    m = _YEAR_ONLY_RE.search(raw)
    if m:
        return f"{m.group(0)}-01-01"

    return None


def _sort_key(event: TimelineEvent) -> str:
    """
    Return a sortable string key for a TimelineEvent.

    Falls back to a very old timestamp so unparseable events sort first.
    """
    ts = _parse_timestamp(event.timestamp)
    return ts or "0001-01-01"


# ── Event extraction ────────────────────────────────────────────────


def _extract_account_creations(module_name: str, data: Any) -> list[dict[str, Any]]:
    """Extract account creation date events."""
    events: list[dict[str, Any]] = []

    def _walk(obj: Any) -> None:
        if isinstance(obj, dict):
            for date_key in (
                "created_at",
                "account_created_at",
                "creation_date",
                "registered_at",
                "joined_at",
                "member_since",
            ):
                raw_ts = obj.get(date_key)
                if not isinstance(raw_ts, str) or not raw_ts.strip():
                    continue
                ts = _parse_timestamp(raw_ts)
                if not ts:
                    continue
                platform = (
                    obj.get("platform") or obj.get("source") or obj.get("module") or module_name
                )
                username = obj.get("username") or obj.get("handle") or obj.get("login") or ""
                events.append(
                    {
                        "timestamp": ts,
                        "event_type": "account_created",
                        "description": (
                            f"Account created on {platform}"
                            + (f" (username: {username})" if username else "")
                        ),
                        "platform": str(platform),
                        "source_module": module_name,
                        "confidence": "high",
                    }
                )
            for v in obj.values():
                _walk(v)
        elif isinstance(obj, list):
            for item in obj:
                _walk(item)

    _walk(data)
    return events


def _extract_breach_events(module_name: str, data: Any) -> list[dict[str, Any]]:
    """Extract data breach events from HIBP / DeHashed style data."""
    events: list[dict[str, Any]] = []

    breach_containers = []
    if isinstance(data, dict):
        for key in ("breaches", "breach_records", "results", "entries"):
            val = data.get(key)
            if isinstance(val, list):
                breach_containers.extend(val)
        # Single breach record at top level
        if data.get("breach_date") or data.get("BreachDate"):
            breach_containers.append(data)

    for record in breach_containers:
        if not isinstance(record, dict):
            continue
        raw_ts = (
            record.get("breach_date")
            or record.get("BreachDate")
            or record.get("date")
            or record.get("added_date")
        )
        if not raw_ts:
            continue
        ts = _parse_timestamp(str(raw_ts))
        if not ts:
            continue

        breach_name = (
            record.get("name") or record.get("Name") or record.get("breach") or "Unknown Breach"
        )
        data_classes = record.get("data_classes") or record.get("DataClasses") or []
        if isinstance(data_classes, list):
            classes_str = ", ".join(data_classes[:5])
        else:
            classes_str = str(data_classes)

        events.append(
            {
                "timestamp": ts,
                "event_type": "breach",
                "description": (
                    f"Data breach: {breach_name}"
                    + (f" — exposed: {classes_str}" if classes_str else "")
                ),
                "platform": str(breach_name),
                "source_module": module_name,
                "confidence": "high" if record.get("is_verified") else "medium",
            }
        )

    return events


def _extract_exif_events(module_name: str, data: Any) -> list[dict[str, Any]]:
    """Extract EXIF capture date events from image analysis data."""
    events: list[dict[str, Any]] = []

    def _walk(obj: Any) -> None:
        if isinstance(obj, dict):
            for key in ("captured_at", "DateTimeOriginal", "DateTime", "exif_date", "date_taken"):
                raw_ts = obj.get(key)
                if not isinstance(raw_ts, str) or not raw_ts.strip():
                    continue
                # EXIF dates are often formatted as "YYYY:MM:DD HH:MM:SS"
                normalised = raw_ts.replace(":", "-", 2)
                ts = _parse_timestamp(normalised)
                if not ts:
                    continue
                source = obj.get("original_url") or obj.get("file_path") or "image"
                events.append(
                    {
                        "timestamp": ts,
                        "event_type": "post",
                        "description": f"Photo captured (EXIF): {source}",
                        "platform": "image_exif",
                        "source_module": module_name,
                        "confidence": "high",
                    }
                )
            for v in obj.values():
                _walk(v)
        elif isinstance(obj, list):
            for item in obj:
                _walk(item)

    _walk(data)
    return events


def _extract_domain_events(module_name: str, data: Any) -> list[dict[str, Any]]:
    """Extract domain registration and certificate events."""
    events: list[dict[str, Any]] = []

    if not isinstance(data, dict):
        return events

    domain = data.get("name") or data.get("domain") or data.get("query") or ""

    # WHOIS registration date
    for key in ("registration_date", "creation_date", "created", "registered"):
        raw_ts = data.get(key)
        if isinstance(raw_ts, str) and raw_ts.strip():
            ts = _parse_timestamp(raw_ts)
            if ts:
                events.append(
                    {
                        "timestamp": ts,
                        "event_type": "account_created",
                        "description": f"Domain registered: {domain}",
                        "platform": "domain_registration",
                        "source_module": module_name,
                        "confidence": "high",
                    }
                )

    # Certificate transparency log entries
    certs = data.get("certificates") or data.get("cert_records") or []
    for cert in certs if isinstance(certs, list) else []:
        if not isinstance(cert, dict):
            continue
        raw_ts = cert.get("not_before") or cert.get("issued_at") or cert.get("entry_timestamp")
        if isinstance(raw_ts, str) and raw_ts.strip():
            ts = _parse_timestamp(raw_ts)
            if ts:
                cn = cert.get("common_name") or cert.get("domain") or domain
                events.append(
                    {
                        "timestamp": ts,
                        "event_type": "account_created",
                        "description": f"SSL certificate issued for: {cn}",
                        "platform": "certificate_transparency",
                        "source_module": module_name,
                        "confidence": "high",
                    }
                )

    return events


def _extract_post_events(module_name: str, data: Any) -> list[dict[str, Any]]:
    """Extract post/activity events from social module results."""
    events: list[dict[str, Any]] = []

    def _walk_posts(obj: Any) -> None:
        if isinstance(obj, dict):
            # Reddit submission / Twitter tweet style
            for ts_key in ("created_utc", "created_at", "timestamp", "published_at", "date"):
                raw_ts = obj.get(ts_key)
                # Reddit uses UNIX timestamps
                if isinstance(raw_ts, (int, float)) and raw_ts > 1e8:
                    import datetime

                    try:
                        dt = datetime.datetime.utcfromtimestamp(raw_ts)
                        raw_ts = dt.isoformat()
                    except Exception:
                        raw_ts = None
                if isinstance(raw_ts, str) and raw_ts.strip():
                    ts = _parse_timestamp(raw_ts)
                    if not ts:
                        continue
                    text = (
                        obj.get("title")
                        or obj.get("text")
                        or obj.get("selftext")
                        or obj.get("full_text")
                        or obj.get("body")
                        or ""
                    )
                    platform = obj.get("subreddit_prefixed") or obj.get("platform") or module_name
                    events.append(
                        {
                            "timestamp": ts,
                            "event_type": "post",
                            "description": f"Posted on {platform}: {str(text)[:100]}",
                            "platform": str(platform),
                            "source_module": module_name,
                            "confidence": "high",
                        }
                    )
                    break

    posts = data.get("posts") or data.get("tweets") or data.get("submissions") or []
    if isinstance(posts, list):
        for post in posts[:50]:  # Limit to 50 posts per module
            _walk_posts(post)

    return events


class TimelineBuilder:
    """
    Builds a chronological event timeline from all module results.

    Extracts:
        - Account creation dates (social profiles, domains)
        - Data breach dates (HIBP, DeHashed)
        - Post/activity dates (Reddit, Twitter)
        - EXIF image capture dates
        - Certificate issuance dates
        - Domain registration dates

    Optionally enriches events using an LLM for contextual descriptions.
    """

    def build(self, module_results: dict[str, Any]) -> list[dict[str, Any]]:
        """Backward-compatible helper used by older tests/code."""
        normalized = self._normalize_module_results(module_results)
        raw_events: list[dict[str, Any]] = []
        for module_name, data in normalized.items():
            if not data:
                continue
            raw_events.extend(_extract_account_creations(module_name, data))
            raw_events.extend(_extract_breach_events(module_name, data))
            raw_events.extend(_extract_exif_events(module_name, data))
            raw_events.extend(_extract_domain_events(module_name, data))
            raw_events.extend(_extract_post_events(module_name, data))
        for event in raw_events:
            event.setdefault("event", event.get("event_type", "event"))
            event.setdefault("title", event.get("description", ""))
        raw_events.sort(key=lambda ev: ev.get("timestamp", ""))
        return raw_events

    async def run(self, session: ScanSession) -> list[TimelineEvent]:
        """
        Build and return the timeline for a session.

        Args:
            session: The ScanSession with module results available.

        Returns:
            List of TimelineEvent models sorted chronologically (oldest first).
        """
        logger.info("timeline_building_started", request_id=session.request_id)

        module_results = self._normalize_module_results(self._load_module_results(session))

        raw_events: list[dict[str, Any]] = []

        for module_name, data in module_results.items():
            if not data:
                continue
            raw_events.extend(_extract_account_creations(module_name, data))
            raw_events.extend(_extract_breach_events(module_name, data))
            raw_events.extend(_extract_exif_events(module_name, data))
            raw_events.extend(_extract_domain_events(module_name, data))
            raw_events.extend(_extract_post_events(module_name, data))

        # Deduplicate by (timestamp, event_type, platform)
        seen: set[tuple] = set()
        deduped: list[dict[str, Any]] = []
        for ev in raw_events:
            key = (ev["timestamp"], ev["event_type"], ev.get("platform", ""))
            if key not in seen:
                seen.add(key)
                deduped.append(ev)

        # Optional LLM enrichment
        if self._ai_enabled(session) and self._llm_available() and deduped:
            try:
                deduped = await self._enrich_with_llm(session.target, deduped)
            except Exception as exc:
                logger.warning("timeline_llm_failed", error=str(exc))

        # Convert to TimelineEvent models
        events: list[TimelineEvent] = [
            TimelineEvent(
                timestamp=ev["timestamp"],
                event_type=ev["event_type"],
                description=ev["description"],
                platform=ev.get("platform"),
                source_module=ev.get("source_module", ""),
                data={"confidence": ev.get("confidence", "medium")},
            )
            for ev in deduped
        ]

        # Sort chronologically
        events.sort(key=_sort_key)

        self._save(session, events)

        logger.info(
            "timeline_built",
            request_id=session.request_id,
            event_count=len(events),
        )
        return events

    # ── Private helpers ────────────────────────────────────────────────

    def _load_module_results(self, session: ScanSession) -> dict[str, Any]:
        """Load module results from session context and raw_data directory."""
        results: dict[str, Any] = {}

        for name, data in session.context.get("module_results", {}).items():
            if data:
                results[name] = data

        raw_dir: Path = session.raw_data_dir
        if raw_dir.exists():
            for json_path in sorted(raw_dir.glob("*.json")):
                module_name = json_path.stem
                if module_name not in results:
                    try:
                        with open(json_path) as f:
                            results[module_name] = json.load(f)
                    except Exception as exc:
                        logger.warning(
                            "timeline_load_failed",
                            file=str(json_path),
                            error=str(exc),
                        )

        return results

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

    def _llm_available(self) -> bool:
        return (
            settings.has_api_key("anthropic_api_key")
            or settings.has_api_key("openai_api_key")
            or settings.has_api_key("openrouter_api_key")
            or bool(settings.ollama_endpoint)
        )

    async def _enrich_with_llm(
        self,
        target: str,
        raw_events: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """
        Send the raw event list to the LLM to enrich descriptions and
        add any events the heuristics may have missed.

        The LLM response is expected to be a JSON array of event objects.
        If parsing fails, the original events are returned unchanged.
        """
        from app.ai.prompts import TIMELINE_PROMPT
        from app.ai.report_generator import ReportGenerator

        # Limit to first 100 events to avoid token overflow
        subset = raw_events[:100]
        data_str = json.dumps(subset, indent=2, default=str)

        prompt = TIMELINE_PROMPT.format(target=target, data=data_str)

        generator = ReportGenerator()
        raw_text = await generator._call_llm(prompt)

        # Try to extract JSON array from response
        json_match = re.search(r"```(?:json)?\s*(\[[\s\S]+?\])\s*```", raw_text)
        if not json_match:
            # Try raw JSON array
            json_match = re.search(r"\[[\s\S]+\]", raw_text)

        if json_match:
            try:
                enriched = json.loads(
                    json_match.group(0) if not hasattr(json_match, "group") else json_match.group(0)
                )
                if isinstance(enriched, list) and enriched:
                    # Validate each event has required fields
                    valid = []
                    for ev in enriched:
                        if isinstance(ev, dict) and ev.get("timestamp"):
                            valid.append(
                                {
                                    "timestamp": str(ev.get("timestamp", "")),
                                    "event_type": str(ev.get("event_type", "post")),
                                    "description": str(ev.get("description", "")),
                                    "platform": ev.get("platform") or ev.get("source") or "unknown",
                                    "source_module": ev.get("source_module", "llm"),
                                    "confidence": str(ev.get("confidence", "medium")),
                                }
                            )
                    return valid if valid else raw_events
            except (json.JSONDecodeError, AttributeError):
                pass

        return raw_events

    def _save(self, session: ScanSession, events: list[TimelineEvent]) -> None:
        """Persist timeline to correlation/timeline.json."""
        corr_dir: Path = session.correlation_dir
        corr_dir.mkdir(parents=True, exist_ok=True)
        path = corr_dir / "timeline.json"
        try:
            timeline_data = [e.model_dump() for e in events]
            with open(path, "w") as f:
                json.dump(timeline_data, f, indent=2, default=str)
            logger.info("timeline_saved", path=str(path), events=len(events))
        except Exception as exc:
            logger.error("timeline_save_failed", error=str(exc))
