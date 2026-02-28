"""
Tests for email intelligence modules.
"""

from unittest.mock import MagicMock, patch

import pytest

from app.core.constants import TargetType


class TestEmailValidator:
    """Tests for app.modules.email.validator.EmailValidatorModule"""

    @pytest.mark.asyncio
    async def test_validate_valid_email(self):
        from app.modules.email.validator import EmailValidatorModule

        module = EmailValidatorModule()
        assert await module.validate("user@example.com", TargetType.EMAIL) is True

    @pytest.mark.asyncio
    async def test_validate_invalid_email(self):
        from app.modules.email.validator import EmailValidatorModule

        module = EmailValidatorModule()
        assert await module.validate("not-an-email", TargetType.EMAIL) is False
        assert await module.validate("", TargetType.EMAIL) is False
        assert await module.validate("@nodomain.com", TargetType.EMAIL) is False

    @pytest.mark.asyncio
    async def test_metadata(self):
        from app.modules.email.validator import EmailValidatorModule

        module = EmailValidatorModule()
        meta = module.metadata()
        assert meta.name == "email_validator"
        assert TargetType.EMAIL in meta.target_types
        assert meta.requires_api_key is False

    @pytest.mark.asyncio
    async def test_run_with_mocked_dns(self):
        from app.modules.email.validator import EmailValidatorModule

        module = EmailValidatorModule()

        # Mock DNS resolution to avoid network calls
        with patch("dns.resolver.resolve") as mock_resolve:
            mock_mx = MagicMock()
            mock_mx.exchange.to_text.return_value = "mail.example.com"
            mock_resolve.return_value = [mock_mx]

            result = await module.run("test@example.com", TargetType.EMAIL)

        assert result.success is True
        assert result.target == "test@example.com"
        assert result.data["email"] == "test@example.com"

    @pytest.mark.asyncio
    async def test_run_disposable_email(self):
        from app.modules.email.validator import EmailValidatorModule

        module = EmailValidatorModule()

        with patch("dns.resolver.resolve") as mock_resolve:
            mock_resolve.side_effect = Exception("DNS error")
            result = await module.run("user@mailinator.com", TargetType.EMAIL)

        # Should succeed even if DNS fails — just marks as potentially invalid
        assert result is not None
        assert result.module_name == "email_validator"

    @pytest.mark.asyncio
    async def test_run_dns_error_graceful(self):
        from app.modules.email.validator import EmailValidatorModule

        module = EmailValidatorModule()

        with patch("dns.resolver.resolve", side_effect=Exception("Network unreachable")):
            result = await module.run("user@example.com", TargetType.EMAIL)

        # Module should handle DNS errors gracefully
        assert result is not None
        assert result.module_name == "email_validator"


class TestEmailPermutator:
    """Tests for app.modules.email.permutator.EmailPermutatorModule"""

    @pytest.mark.asyncio
    async def test_validate(self):
        from app.modules.email.permutator import EmailPermutatorModule

        module = EmailPermutatorModule()
        assert await module.validate("John Doe", TargetType.PERSON) is True
        assert await module.validate("J", TargetType.PERSON) is False

    @pytest.mark.asyncio
    async def test_run_generates_permutations(self):
        from app.modules.email.permutator import EmailPermutatorModule

        module = EmailPermutatorModule()

        result = await module.run(
            "John Doe",
            TargetType.PERSON,
            target_inputs={"domain": "example.com"},
        )

        assert result.success is True
        permutations = result.data.get("permutations", [])
        assert len(permutations) > 0
        # Should include common formats
        email_list = " ".join(permutations)
        assert "john" in email_list.lower()

    @pytest.mark.asyncio
    async def test_metadata(self):
        from app.modules.email.permutator import EmailPermutatorModule

        module = EmailPermutatorModule()
        meta = module.metadata()
        assert meta.name == "email_permutator"
        assert TargetType.PERSON in meta.target_types


class TestHIBPBreachChecker:
    """Tests for app.modules.email.breach_checker.HIBPBreachCheckerModule"""

    @pytest.mark.asyncio
    async def test_metadata(self):
        from app.modules.email.breach_checker import HIBPBreachCheckerModule

        module = HIBPBreachCheckerModule()
        meta = module.metadata()
        assert meta.name == "hibp_breach_checker"
        assert meta.requires_api_key is True

    @pytest.mark.asyncio
    async def test_skip_without_api_key(self, monkeypatch):
        from app.modules.email.breach_checker import HIBPBreachCheckerModule

        monkeypatch.delenv("HIBP_API_KEY", raising=False)

        module = HIBPBreachCheckerModule()
        result = await module.run("test@example.com", TargetType.EMAIL)

        # Should return a result (not raise) even without API key
        assert result is not None
        assert result.module_name == "hibp_breach_checker"

    @pytest.mark.asyncio
    async def test_run_with_mocked_response(self, mock_aiohttp_response, monkeypatch):
        monkeypatch.setenv("HIBP_API_KEY", "test_key_12345")

        from app.modules.email.breach_checker import HIBPBreachCheckerModule

        module = HIBPBreachCheckerModule()

        breach_data = [
            {"Name": "LinkedIn", "BreachDate": "2012-05-05", "PwnCount": 117000000},
            {"Name": "Adobe", "BreachDate": "2013-10-04", "PwnCount": 152000000},
        ]

        mock_resp = mock_aiohttp_response(breach_data, status=200)

        with patch("aiohttp.ClientSession.get", return_value=mock_resp):
            result = await module.run("test@example.com", TargetType.EMAIL)

        assert result.success is True
        assert result.data.get("total_breaches") == 2


class TestHunterModule:
    """Tests for app.modules.email.hunter.HunterModule"""

    @pytest.mark.asyncio
    async def test_metadata(self):
        from app.modules.email.hunter import HunterModule

        module = HunterModule()
        meta = module.metadata()
        assert meta.name == "hunter_io"
        assert TargetType.DOMAIN in meta.target_types

    @pytest.mark.asyncio
    async def test_validate_domain(self):
        from app.modules.email.hunter import HunterModule

        module = HunterModule()
        assert await module.validate("example.com", TargetType.DOMAIN) is True
        assert await module.validate("", TargetType.DOMAIN) is False

    @pytest.mark.asyncio
    async def test_skip_without_api_key(self, monkeypatch):
        monkeypatch.delenv("HUNTER_API_KEY", raising=False)
        from app.modules.email.hunter import HunterModule

        module = HunterModule()
        result = await module.run("example.com", TargetType.DOMAIN)
        assert result is not None
