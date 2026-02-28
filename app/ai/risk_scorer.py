"""
Privacy risk scorer for GOD_EYE.

Calculates a 1-10 risk score based on weighted evidence from module results,
maps the score to a risk level, and optionally uses an LLM to generate
personalised recommendations.

Usage:
    scorer = RiskScorer()
    assessment = await scorer.run(session)
    # assessment: RiskAssessment(score=7.5, level="high", ...)
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from app.core.config import settings
from app.core.constants import RISK_WEIGHTS, RiskLevel
from app.core.logging import get_logger
from app.database.models import RiskAssessment
from app.engine.session import ScanSession

logger = get_logger(__name__)


def _score_to_level(score: float) -> str:
    """Map a numeric risk score to a RiskLevel string."""
    if score <= 4.0:
        return RiskLevel.LOW.value
    elif score <= 6.0:
        return RiskLevel.MEDIUM.value
    elif score <= 8.0:
        return RiskLevel.HIGH.value
    else:
        return RiskLevel.CRITICAL.value


class RiskScorer:
    """
    Calculates a privacy risk score (0-10) from module results.

    Weights defined in app.core.constants.RISK_WEIGHTS:
        - email_breach_each: +2.0 per breach (capped at +4.0)
        - passwords_exposed:  +3.0 (flat if any password/hash found)
        - social_platforms_per_5: +1.0 per 5 public platforms (capped at +3.0)
        - personal_info_each: +1.0 per public phone/address/employer found
        - face_match_unexpected: +2.0 (face found on unexpected platform)
        - exif_gps_data: +2.0 (GPS coordinates in any public image)
        - whois_not_private: +1.0 (WHOIS record not privacy-protected)
        - secret_in_code: +3.0 (API key/credential in public code repo)
        - public_social_per: +0.5 per confirmed public social profile
    """

    def score_to_level(self, score: float) -> str:
        """Backward-compatible helper used by older tests/code."""
        return _score_to_level(score)

    def compute(self, module_results: dict[str, Any]) -> tuple[float, str, list[str]]:
        """Compute a score synchronously from in-memory module results."""
        normalized = self._normalize_module_results(module_results)
        breakdown: dict[str, float] = {}
        raw_score, breakdown = self._score_breach_data(normalized, breakdown)
        raw_score, breakdown = self._score_social_exposure(normalized, raw_score, breakdown)
        raw_score, breakdown = self._score_personal_info(normalized, raw_score, breakdown)
        raw_score, breakdown = self._score_image_risks(normalized, raw_score, breakdown)
        raw_score, breakdown = self._score_domain_risks(normalized, raw_score, breakdown)
        raw_score, breakdown = self._score_code_risks(normalized, raw_score, breakdown)
        final_score = round(max(0.0, min(10.0, raw_score)), 2)
        level = _score_to_level(final_score)
        recommendations = self._default_recommendations(level, breakdown)
        return final_score, level, recommendations

    async def run(self, session: ScanSession) -> RiskAssessment:
        """
        Execute risk scoring for a session.

        Loads module results, applies weights, optionally queries the LLM
        for recommendations, and saves the assessment to disk.

        Args:
            session: The ScanSession to score.

        Returns:
            RiskAssessment model populated with score, level, breakdown, and recommendations.
        """
        logger.info("risk_scoring_started", request_id=session.request_id)

        module_results = self._normalize_module_results(self._load_module_results(session))

        # ── Apply weights ──────────────────────────────────────────
        breakdown: dict[str, float] = {}
        raw_score: float = 0.0

        raw_score, breakdown = self._score_breach_data(module_results, breakdown)
        raw_score, breakdown = self._score_social_exposure(module_results, raw_score, breakdown)
        raw_score, breakdown = self._score_personal_info(module_results, raw_score, breakdown)
        raw_score, breakdown = self._score_image_risks(module_results, raw_score, breakdown)
        raw_score, breakdown = self._score_domain_risks(module_results, raw_score, breakdown)
        raw_score, breakdown = self._score_code_risks(module_results, raw_score, breakdown)

        # ── Clamp and map ──────────────────────────────────────────
        final_score = round(max(0.0, min(10.0, raw_score)), 2)
        level = _score_to_level(final_score)

        # ── Derive top risks ──────────────────────────────────────
        top_risks = self._derive_top_risks(breakdown, module_results)

        # ── LLM recommendations ───────────────────────────────────
        recommendations: list[str] = []
        if self._ai_enabled(session) and self._llm_available():
            try:
                recommendations = await self._generate_recommendations(
                    session.target, final_score, level, breakdown, top_risks
                )
            except Exception as exc:
                logger.warning("risk_scorer_llm_failed", error=str(exc))

        if not recommendations:
            recommendations = self._default_recommendations(level, breakdown)

        assessment = RiskAssessment(
            score=final_score,
            level=level,
            breakdown=breakdown,
            top_risks=top_risks,
            recommendations=recommendations,
        )

        # Update session context
        session.context["risk_score"] = final_score
        session.context["risk_level"] = level

        # Save to disk
        self._save(session, assessment)

        logger.info(
            "risk_scoring_completed",
            request_id=session.request_id,
            score=final_score,
            level=level,
        )
        return assessment

    # ── Scoring sub-methods ────────────────────────────────────────────

    def _score_breach_data(
        self,
        module_results: dict[str, Any],
        breakdown: dict[str, float],
    ) -> tuple[float, dict[str, float]]:
        """Score based on email breach data."""
        score_delta = 0.0
        breach_count = 0
        passwords_exposed = False

        for _module_name, data in module_results.items():
            if not isinstance(data, dict):
                continue

            # Count distinct breaches from HIBP-style results
            breaches = data.get("breaches") or data.get("breach_records") or []
            if isinstance(breaches, list):
                breach_count += len(breaches)

            # Also check top-level breach_count field
            for count_key in ("breach_count", "total_breaches"):
                if count_key in data and isinstance(data[count_key], int):
                    breach_count = max(breach_count, data[count_key])

            # Check for exposed password / hash data
            for field in ("password", "plaintext", "exposed_password", "exposed_hash", "hash"):
                val = data.get(field)
                if isinstance(val, str) and val.strip() and len(val) > 3:
                    passwords_exposed = True

            # Check nested breach records
            for record in breaches if isinstance(breaches, list) else []:
                if isinstance(record, dict):
                    for field in ("exposed_password", "exposed_hash", "password"):
                        val = record.get(field)
                        if isinstance(val, str) and val.strip():
                            passwords_exposed = True

        weight = RISK_WEIGHTS.get("email_breach_each", 2.0)
        max_breach_score = RISK_WEIGHTS.get("email_breach_each", 2.0) * 2  # cap at 2 breaches worth
        breach_score = min(weight * breach_count, max_breach_score)

        if breach_score > 0:
            breakdown["email_breaches"] = round(breach_score, 2)
            score_delta += breach_score

        if passwords_exposed:
            pw_weight = RISK_WEIGHTS.get("passwords_exposed", 3.0)
            breakdown["passwords_exposed"] = pw_weight
            score_delta += pw_weight

        return score_delta, breakdown

    def _score_social_exposure(
        self,
        module_results: dict[str, Any],
        current_score: float,
        breakdown: dict[str, float],
    ) -> tuple[float, dict[str, float]]:
        """Score based on number of public social profiles discovered."""
        social_count = 0
        per_weight = RISK_WEIGHTS.get("public_social_per", 0.5)
        per5_weight = RISK_WEIGHTS.get("social_platforms_per_5", 1.0)
        max_per5 = per5_weight * 3  # cap at 3 groups of 5

        for _module_name, data in module_results.items():
            if not isinstance(data, dict):
                continue

            # Sherlock / social checker style
            platforms = data.get("platforms") or data.get("found_platforms") or []
            if isinstance(platforms, list):
                social_count += len(platforms)

            # Individual profile result
            if data.get("profile_url") and data.get("exists", True):
                social_count += 1

            # Username entity list
            accounts = data.get("accounts") or data.get("social_profiles") or []
            if isinstance(accounts, list):
                social_count += len(accounts)

        if social_count > 0:
            per_score = round(social_count * per_weight, 2)
            per5_score = min(round((social_count // 5) * per5_weight, 2), max_per5)
            total_social_score = round(per_score + per5_score, 2)
            breakdown["public_social_profiles"] = total_social_score
            current_score += total_social_score

        return current_score, breakdown

    def _score_personal_info(
        self,
        module_results: dict[str, Any],
        current_score: float,
        breakdown: dict[str, float],
    ) -> tuple[float, dict[str, float]]:
        """Score based on public personal information (phone, address, employer)."""
        personal_items = 0
        per_weight = RISK_WEIGHTS.get("personal_info_each", 1.0)

        personal_keys = ("phone", "address", "employer", "company", "home_address", "mobile")

        for _module_name, data in module_results.items():
            if not isinstance(data, dict):
                continue
            for key in personal_keys:
                val = data.get(key)
                if val and isinstance(val, (str, list)) and val:
                    personal_items += 1 if isinstance(val, str) else len(val)

        if personal_items > 0:
            info_score = round(per_weight * personal_items, 2)
            breakdown["personal_info_exposed"] = info_score
            current_score += info_score

        return current_score, breakdown

    def _score_image_risks(
        self,
        module_results: dict[str, Any],
        current_score: float,
        breakdown: dict[str, float],
    ) -> tuple[float, dict[str, float]]:
        """Score based on GPS EXIF data and unexpected face matches."""
        exif_weight = RISK_WEIGHTS.get("exif_gps_data", 2.0)
        face_weight = RISK_WEIGHTS.get("face_match_unexpected", 2.0)

        has_gps = False
        has_unexpected_face = False

        for _module_name, data in module_results.items():
            if not isinstance(data, dict):
                continue

            # EXIF GPS check
            if data.get("has_gps") or (data.get("gps_latitude") and data.get("gps_longitude")):
                has_gps = True

            # Check nested image results
            images = data.get("images") or data.get("exif_results") or []
            if isinstance(images, list):
                for img in images:
                    if isinstance(img, dict) and img.get("has_gps"):
                        has_gps = True

            # Unexpected face match
            if data.get("face_match_unexpected") or data.get("unexpected_face_match"):
                has_unexpected_face = True

        if has_gps:
            breakdown["exif_gps_data"] = exif_weight
            current_score += exif_weight

        if has_unexpected_face:
            breakdown["face_match_unexpected"] = face_weight
            current_score += face_weight

        return current_score, breakdown

    def _score_domain_risks(
        self,
        module_results: dict[str, Any],
        current_score: float,
        breakdown: dict[str, float],
    ) -> tuple[float, dict[str, float]]:
        """Score based on WHOIS privacy and domain exposure."""
        whois_weight = RISK_WEIGHTS.get("whois_not_private", 1.0)

        for _module_name, data in module_results.items():
            if not isinstance(data, dict):
                continue
            if isinstance(data.get("has_whois_privacy"), bool) and not data["has_whois_privacy"]:
                breakdown["whois_not_private"] = whois_weight
                current_score += whois_weight
                break  # Only count once

        return current_score, breakdown

    def _score_code_risks(
        self,
        module_results: dict[str, Any],
        current_score: float,
        breakdown: dict[str, float],
    ) -> tuple[float, dict[str, float]]:
        """Score based on secrets found in public code repositories."""
        import re

        secret_weight = RISK_WEIGHTS.get("secret_in_code", 3.0)
        secret_patterns = [
            r"api[_-]?key\s*[:=]\s*['\"][A-Za-z0-9_\-]{16,}['\"]",
            r"token\s*[:=]\s*['\"][A-Za-z0-9_\-]{16,}['\"]",
            r"secret\s*[:=]\s*['\"][A-Za-z0-9_\-]{16,}['\"]",
            r"password\s*[:=]\s*['\"][^'\"]{6,}['\"]",
        ]

        for _module_name, data in module_results.items():
            if not isinstance(data, dict):
                continue
            if data.get("secrets_found") or data.get("leaked_secrets"):
                breakdown["secret_in_code"] = secret_weight
                current_score += secret_weight
                break

            # Scan text for patterns
            all_text = json.dumps(data)
            for pattern in secret_patterns:
                if re.search(pattern, all_text, re.IGNORECASE):
                    breakdown["secret_in_code"] = secret_weight
                    current_score += secret_weight
                    return current_score, breakdown

        return current_score, breakdown

    # ── Helpers ────────────────────────────────────────────────────────

    def _derive_top_risks(
        self,
        breakdown: dict[str, float],
        module_results: dict[str, Any],
    ) -> list[str]:
        """Produce up to 5 top-risk strings sorted by weight."""
        risk_descriptions = {
            "email_breaches": "Email address found in data breach databases",
            "passwords_exposed": "Passwords or password hashes exposed in breach data",
            "public_social_profiles": "Large number of public social media profiles discoverable",
            "personal_info_exposed": "Phone numbers, addresses, or employer information publicly visible",
            "exif_gps_data": "GPS location data embedded in publicly accessible images",
            "face_match_unexpected": "Face match found on unexpected or sensitive platforms",
            "whois_not_private": "Domain WHOIS record exposes real name/email/address",
            "secret_in_code": "API keys or credentials found in public code repositories",
        }

        sorted_risks = sorted(breakdown.items(), key=lambda x: x[1], reverse=True)
        top: list[str] = []
        for key, _score in sorted_risks[:5]:
            desc = risk_descriptions.get(key)
            if desc:
                top.append(desc)

        return top

    def _default_recommendations(self, level: str, breakdown: dict[str, float]) -> list[str]:
        """Generate rule-based recommendations when LLM is unavailable."""
        recs: list[str] = []

        if "email_breaches" in breakdown:
            recs.append(
                "Change passwords on all accounts associated with breached emails immediately."
            )
        if "passwords_exposed" in breakdown:
            recs.append(
                "Your password(s) are publicly exposed. Change them everywhere and enable 2FA."
            )
        if "public_social_profiles" in breakdown:
            recs.append(
                "Review privacy settings on all social media accounts and remove excess personal data."
            )
        if "exif_gps_data" in breakdown:
            recs.append(
                "Strip EXIF metadata from photos before uploading. "
                "Disable location tagging in your camera app."
            )
        if "whois_not_private" in breakdown:
            recs.append(
                "Enable WHOIS privacy protection (domain privacy) on all registered domains."
            )
        if "secret_in_code" in breakdown:
            recs.append(
                "Rotate all exposed API keys immediately. Use secrets managers instead of committing credentials."
            )

        # Generic recommendations based on level
        if level in ("high", "critical"):
            recs.append(
                "Consider submitting opt-out requests to data broker websites (Spokeo, Whitepages, etc.)."
            )
        if level == "critical":
            recs.append(
                "Engage a privacy specialist — your digital footprint poses immediate risks."
            )
        if not recs:
            recs.append(
                "Regularly audit your online presence and review platform privacy settings."
            )

        return recs[:5]

    def _llm_available(self) -> bool:
        """Check whether any LLM provider is configured."""
        return (
            settings.has_api_key("anthropic_api_key")
            or settings.has_api_key("openai_api_key")
            or settings.has_api_key("openrouter_api_key")
            or bool(settings.ollama_endpoint)
        )

    async def _generate_recommendations(
        self,
        target: str,
        score: float,
        level: str,
        breakdown: dict[str, float],
        top_risks: list[str],
    ) -> list[str]:
        """Use LLM to generate personalised privacy recommendations."""
        from app.ai.prompts import RISK_SCORING_PROMPT
        from app.ai.report_generator import ReportGenerator

        findings_text = "\n".join(
            f"- {k}: {v:.1f} risk points" for k, v in sorted(breakdown.items(), key=lambda x: -x[1])
        )
        if top_risks:
            findings_text += "\n\nTop risks identified:\n" + "\n".join(f"- {r}" for r in top_risks)

        prompt = RISK_SCORING_PROMPT.format(
            target=target,
            findings=findings_text,
        )

        generator = ReportGenerator()
        raw_text = await generator._call_llm(prompt)

        # Try to parse JSON from the response
        import json as _json
        import re

        json_match = re.search(r"```(?:json)?\s*([\s\S]+?)```", raw_text)
        json_str = json_match.group(1) if json_match else raw_text

        try:
            parsed = _json.loads(json_str)
            if isinstance(parsed, dict):
                recs = parsed.get("recommendations") or []
                if isinstance(recs, list):
                    return [str(r) for r in recs[:5]]
        except _json.JSONDecodeError:
            pass

        # Fallback: extract bullet points
        lines = [
            line.lstrip("- •*").strip()
            for line in raw_text.split("\n")
            if line.strip().startswith(("-", "•", "*"))
        ]
        return [line for line in lines if len(line) > 10][:5]

    def _load_module_results(self, session: ScanSession) -> dict[str, Any]:
        """Load module results from session context and disk."""
        results: dict[str, Any] = {}

        # From in-memory context (preferred, already loaded)
        for name, data in session.context.get("module_results", {}).items():
            if data:
                results[name] = data

        # Supplement from raw_data directory
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
                            "risk_scorer_load_failed", file=str(json_path), error=str(exc)
                        )

        return results

    def _normalize_module_results(self, module_results: dict[str, Any]) -> dict[str, Any]:
        """Unwrap legacy {success, data} result envelopes into plain data dicts."""
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

    def _save(self, session: ScanSession, assessment: RiskAssessment) -> None:
        """Save the risk assessment to correlation/risk_assessment.json."""
        corr_dir: Path = session.correlation_dir
        corr_dir.mkdir(parents=True, exist_ok=True)
        path = corr_dir / "risk_assessment.json"
        try:
            with open(path, "w") as f:
                json.dump(assessment.model_dump(), f, indent=2, default=str)
            logger.info("risk_assessment_saved", path=str(path))
        except Exception as exc:
            logger.error("risk_assessment_save_failed", error=str(exc))
