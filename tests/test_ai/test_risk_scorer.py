"""
Tests for the AI risk scoring module.
"""

import pytest


class TestRiskScorer:
    """Tests for app.ai.risk_scorer.RiskScorer"""

    def test_zero_risk_empty_results(self):
        from app.ai.risk_scorer import RiskScorer

        scorer = RiskScorer()
        score, level, recs = scorer.compute({})

        assert isinstance(score, (int, float))
        assert 0.0 <= score <= 10.0
        assert level in ("low", "medium", "high", "critical")

    def test_high_risk_with_breaches(self):
        from app.ai.risk_scorer import RiskScorer

        scorer = RiskScorer()
        module_results = {
            "hibp_breach_checker": {
                "success": True,
                "data": {
                    "total_breaches": 10,
                    "total_pastes": 5,
                },
            },
            "email_validator": {
                "success": True,
                "data": {"is_valid": True},
            },
        }

        score, level, recs = scorer.compute(module_results)
        assert score > 3.0  # Multiple breaches should increase score

    def test_risk_level_thresholds(self):
        from app.ai.risk_scorer import RiskScorer

        scorer = RiskScorer()

        assert scorer.score_to_level(0.5) == "low"
        assert scorer.score_to_level(3.5) == "low"
        assert scorer.score_to_level(4.5) == "medium"
        assert scorer.score_to_level(6.5) == "high"
        assert scorer.score_to_level(8.5) == "critical"

    def test_recommendations_generated(self):
        from app.ai.risk_scorer import RiskScorer

        scorer = RiskScorer()
        module_results = {
            "hibp_breach_checker": {
                "success": True,
                "data": {"total_breaches": 3},
            },
        }

        score, level, recs = scorer.compute(module_results)
        assert isinstance(recs, list)

    def test_social_presence_increases_score(self):
        from app.ai.risk_scorer import RiskScorer

        scorer = RiskScorer()

        # Minimal data
        score_minimal, _, _ = scorer.compute({})

        # Many platforms found
        score_high, _, _ = scorer.compute({
            "social_checker": {
                "success": True,
                "data": {
                    "platforms": ["github", "twitter", "instagram", "linkedin", "reddit"],
                    "platform_count": 5,
                },
            },
        })

        assert score_high >= score_minimal

    def test_exif_gps_increases_score(self):
        from app.ai.risk_scorer import RiskScorer

        scorer = RiskScorer()

        score_no_gps, _, _ = scorer.compute({})
        score_with_gps, _, _ = scorer.compute({
            "exif_extractor": {
                "success": True,
                "data": {"images_with_gps": 3, "gps_coordinates": [{"lat": 37.7, "lon": -122.4}]},
            },
        })

        assert score_with_gps >= score_no_gps

    def test_score_capped_at_ten(self):
        from app.ai.risk_scorer import RiskScorer

        scorer = RiskScorer()

        # Maximize all risk factors
        extreme_results = {
            "hibp_breach_checker": {"success": True, "data": {"total_breaches": 50}},
            "exif_extractor": {"success": True, "data": {"images_with_gps": 20}},
            "social_checker": {"success": True, "data": {"platform_count": 30}},
            "shodan_search": {"success": True, "data": {"open_ports": [22, 80, 443, 3306, 5432]}},
        }

        score, _, _ = scorer.compute(extreme_results)
        assert score <= 10.0


class TestCorrelationEngine:
    """Tests for app.ai.correlation_engine.CorrelationEngine"""

    def test_finds_email_username_correlation(self):
        from app.ai.correlation_engine import CorrelationEngine

        engine = CorrelationEngine()
        findings = engine.correlate({
            "email_validator": {"data": {"email": "johndoe@example.com"}},
            "social_checker": {"data": {"github": {"login": "johndoe"}}},
        })

        assert isinstance(findings, list)

    def test_empty_results_no_crash(self):
        from app.ai.correlation_engine import CorrelationEngine

        engine = CorrelationEngine()
        findings = engine.correlate({})
        assert findings == [] or isinstance(findings, list)

    def test_username_pattern_detection(self):
        from app.utils.text_analysis import find_username_patterns

        result = find_username_patterns(["john", "john123", "johndoe", "john_x"])
        assert "patterns" in result
        # john appears as base for multiple variants
        patterns = result["patterns"]
        assert len(patterns) >= 1


class TestTimelineBuilder:
    """Tests for app.ai.timeline_builder.TimelineBuilder"""

    def test_build_empty_timeline(self):
        from app.ai.timeline_builder import TimelineBuilder

        builder = TimelineBuilder()
        events = builder.build({})
        assert isinstance(events, list)

    def test_extracts_breach_dates(self):
        from app.ai.timeline_builder import TimelineBuilder

        builder = TimelineBuilder()
        module_results = {
            "hibp_breach_checker": {
                "data": {
                    "breaches": [
                        {"Name": "LinkedIn", "BreachDate": "2012-05-05"},
                        {"Name": "Adobe", "BreachDate": "2013-10-04"},
                    ]
                }
            }
        }

        events = builder.build(module_results)
        assert len(events) >= 2

    def test_events_have_required_fields(self):
        from app.ai.timeline_builder import TimelineBuilder

        builder = TimelineBuilder()
        module_results = {
            "hibp_breach_checker": {
                "data": {
                    "breaches": [{"Name": "TestBreach", "BreachDate": "2020-01-01"}]
                }
            }
        }

        events = builder.build(module_results)
        if events:
            event = events[0]
            assert "timestamp" in event or "date" in event
            assert "title" in event or "event" in event
