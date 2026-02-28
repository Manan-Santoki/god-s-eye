"""
Tests for utility functions.
"""

import pytest
from pathlib import Path


class TestValidators:
    def test_is_valid_email(self):
        from app.utils.validators import is_valid_email
        assert is_valid_email("user@example.com") is True
        assert is_valid_email("user+tag@sub.domain.co.uk") is True
        assert is_valid_email("not-an-email") is False
        assert is_valid_email("") is False
        assert is_valid_email("@domain.com") is False

    def test_is_valid_domain(self):
        from app.utils.validators import is_valid_domain
        assert is_valid_domain("example.com") is True
        assert is_valid_domain("sub.example.co.uk") is True
        assert is_valid_domain("localhost") is False
        assert is_valid_domain("") is False

    def test_is_valid_ip(self):
        from app.utils.validators import is_valid_ip
        assert is_valid_ip("192.168.1.1") is True
        assert is_valid_ip("8.8.8.8") is True
        assert is_valid_ip("256.0.0.1") is False
        assert is_valid_ip("not-an-ip") is False

    def test_is_valid_phone(self):
        from app.utils.validators import is_valid_phone
        assert is_valid_phone("+12125551234") is True
        assert is_valid_phone("+44 20 7946 0958") is True
        # Very short strings that can't be phones
        assert is_valid_phone("abc") is False

    def test_detect_target_type(self):
        from app.utils.validators import detect_target_type
        from app.core.constants import TargetType

        assert detect_target_type("user@example.com") == TargetType.EMAIL
        assert detect_target_type("8.8.8.8") == TargetType.IP
        assert detect_target_type("example.com") == TargetType.DOMAIN
        assert detect_target_type("+12125551234") == TargetType.PHONE

    def test_normalize_domain(self):
        from app.utils.validators import normalize_domain
        assert normalize_domain("https://www.example.com/path") == "example.com"
        assert normalize_domain("WWW.EXAMPLE.COM") == "example.com"
        assert normalize_domain("example.com") == "example.com"

    def test_normalize_email(self):
        from app.utils.validators import normalize_email
        assert normalize_email("User@Example.COM") == "user@example.com"
        assert normalize_email("  user@example.com  ") == "user@example.com"

    def test_sanitize_target(self):
        from app.utils.validators import sanitize_target
        assert sanitize_target("  test@example.com  ") == "test@example.com"
        result = sanitize_target("<script>alert(1)</script>")
        assert "<script>" not in result


class TestTextAnalysis:
    def test_extract_emails(self):
        from app.utils.text_analysis import extract_emails
        text = "Contact us at admin@example.com or support@test.org for help."
        emails = extract_emails(text)
        assert "admin@example.com" in emails
        assert "support@test.org" in emails

    def test_extract_phones(self):
        from app.utils.text_analysis import extract_phones
        text = "Call us at (212) 555-1234 or +1-800-555-0100"
        phones = extract_phones(text)
        assert len(phones) >= 1

    def test_extract_urls(self):
        from app.utils.text_analysis import extract_urls
        text = "Visit https://example.com and http://test.org/path?q=1"
        urls = extract_urls(text)
        assert "https://example.com" in urls
        assert "http://test.org/path?q=1" in urls

    def test_extract_ips(self):
        from app.utils.text_analysis import extract_ips
        text = "Server IP is 192.168.1.1 and public IP is 8.8.8.8"
        ips = extract_ips(text)
        assert "8.8.8.8" in ips

    def test_find_username_patterns(self):
        from app.utils.text_analysis import find_username_patterns
        result = find_username_patterns(["john", "john123", "johnx", "alice"])
        assert "patterns" in result
        # john should be grouped with john123, johnx
        patterns = result["patterns"]
        assert any("john" in base for base in patterns)

    def test_detect_language_english(self):
        from app.utils.text_analysis import detect_language
        text = "The quick brown fox jumps over the lazy dog and it was a good day"
        assert detect_language(text) == "en"

    def test_summarize_findings_aggregates(self):
        from app.utils.text_analysis import summarize_findings
        results = {
            "email_validator": {"email": "test@example.com", "emails": []},
            "hibp_breach_checker": {"total_breaches": 3},
            "social_checker": {"platforms": ["github", "twitter"]},
        }
        summary = summarize_findings(results)
        assert isinstance(summary, dict)
        assert "breach_count" in summary
        assert summary["breach_count"] == 3


class TestFingerprint:
    def test_fingerprint_target_stable(self):
        from app.utils.fingerprint import fingerprint_target
        fp1 = fingerprint_target("user@example.com", "email")
        fp2 = fingerprint_target("user@example.com", "email")
        assert fp1 == fp2

    def test_fingerprint_target_different_types(self):
        from app.utils.fingerprint import fingerprint_target
        fp_email = fingerprint_target("example.com", "email")
        fp_domain = fingerprint_target("example.com", "domain")
        assert fp_email != fp_domain

    def test_fingerprint_result_stable(self):
        from app.utils.fingerprint import fingerprint_result
        data = {"key": "value", "count": 5, "items": ["a", "b"]}
        fp1 = fingerprint_result(data)
        fp2 = fingerprint_result(data)
        assert fp1 == fp2

    def test_fingerprint_result_changes_with_data(self):
        from app.utils.fingerprint import fingerprint_result
        fp1 = fingerprint_result({"key": "value1"})
        fp2 = fingerprint_result({"key": "value2"})
        assert fp1 != fp2

    def test_extract_username_base(self):
        from app.utils.fingerprint import extract_username_base
        assert extract_username_base("john123") == "john"
        assert extract_username_base("john_doe_official") == "john_doe"
        assert extract_username_base("alice") == "alice"

    def test_compute_similarity_same_profiles(self):
        from app.utils.fingerprint import compute_similarity_score
        profile = {"email": "test@example.com", "username": "testuser"}
        score = compute_similarity_score(profile, profile)
        assert score == 1.0 or score > 0.8

    def test_compute_similarity_different_profiles(self):
        from app.utils.fingerprint import compute_similarity_score
        a = {"email": "alice@example.com", "username": "alice"}
        b = {"email": "bob@example.com", "username": "bob"}
        score = compute_similarity_score(a, b)
        assert score < 0.5

    def test_deduplicate_profiles(self):
        from app.utils.fingerprint import deduplicate_profiles
        profiles = [
            {"email": "test@example.com", "username": "testuser", "name": "Test User"},
            {"email": "test@example.com", "username": "testuser", "location": "NYC"},
            {"email": "other@example.com", "username": "other"},
        ]
        deduped = deduplicate_profiles(profiles, threshold=0.7)
        # First two should be merged
        assert len(deduped) == 2


class TestImageProcessing:
    def test_image_to_base64_invalid_path(self):
        from app.utils.image_processing import image_to_base64
        result = image_to_base64("/nonexistent/path/image.jpg")
        assert result is None

    def test_get_image_metadata_invalid_path(self):
        from app.utils.image_processing import get_image_metadata
        result = get_image_metadata("/nonexistent/image.jpg")
        assert "file_path" in result
        assert result["file_size_bytes"] == 0

    def test_is_image_file_false_for_text(self, tmp_path):
        from app.utils.image_processing import is_image_file
        text_file = tmp_path / "test.txt"
        text_file.write_text("This is not an image")
        assert is_image_file(text_file) is False
