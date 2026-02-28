"""
Tests for username intelligence modules.
"""

from unittest.mock import AsyncMock, patch

import pytest

from app.core.constants import TargetType


class TestSocialChecker:
    """Tests for app.modules.username.social_checker.SocialCheckerModule"""

    @pytest.mark.asyncio
    async def test_metadata(self):
        from app.modules.username.social_checker import SocialCheckerModule

        module = SocialCheckerModule()
        meta = module.metadata()
        assert meta.name == "social_checker"
        assert TargetType.USERNAME in meta.target_types
        assert meta.requires_api_key is False

    @pytest.mark.asyncio
    async def test_validate_username(self):
        from app.modules.username.social_checker import SocialCheckerModule

        module = SocialCheckerModule()
        assert await module.validate("johndoe", TargetType.USERNAME) is True
        assert await module.validate("j", TargetType.USERNAME) is False
        assert await module.validate("", TargetType.USERNAME) is False

    @pytest.mark.asyncio
    async def test_run_github_found(self, mock_aiohttp_response):
        from app.modules.username.social_checker import SocialCheckerModule

        module = SocialCheckerModule()

        github_data = {
            "login": "johndoe",
            "name": "John Doe",
            "bio": "Developer",
            "public_repos": 42,
            "followers": 100,
        }

        mock_resp = mock_aiohttp_response(github_data, status=200)

        with patch("aiohttp.ClientSession.get", return_value=mock_resp):
            result = await module.run("johndoe", TargetType.USERNAME)

        assert result is not None
        assert result.module_name == "social_checker"

    @pytest.mark.asyncio
    async def test_run_github_not_found(self, mock_aiohttp_response):
        from app.modules.username.social_checker import SocialCheckerModule

        module = SocialCheckerModule()

        mock_resp = mock_aiohttp_response({"message": "Not Found"}, status=404)

        with patch("aiohttp.ClientSession.get", return_value=mock_resp):
            result = await module.run("zzznobodyhasthisusername999", TargetType.USERNAME)

        assert result is not None


class TestSherlockWrapper:
    """Tests for app.modules.username.sherlock_wrapper.SherlockWrapperModule"""

    @pytest.mark.asyncio
    async def test_metadata(self):
        from app.modules.username.sherlock_wrapper import SherlockWrapperModule

        module = SherlockWrapperModule()
        meta = module.metadata()
        assert meta.name == "sherlock_wrapper"
        assert TargetType.USERNAME in meta.target_types

    @pytest.mark.asyncio
    async def test_validate_username(self):
        from app.modules.username.sherlock_wrapper import SherlockWrapperModule

        module = SherlockWrapperModule()
        assert await module.validate("testuser", TargetType.USERNAME) is True
        assert await module.validate("x", TargetType.USERNAME) is False

    @pytest.mark.asyncio
    async def test_run_sherlock_not_installed(self):
        """When sherlock is not installed, module should return gracefully."""
        from app.modules.username.sherlock_wrapper import SherlockWrapperModule

        module = SherlockWrapperModule()

        with patch("asyncio.create_subprocess_exec") as mock_proc:
            mock_proc.side_effect = FileNotFoundError("sherlock not found")
            result = await module.run("testuser", TargetType.USERNAME)

        assert result is not None
        assert result.module_name == "sherlock_wrapper"

    @pytest.mark.asyncio
    async def test_run_with_mocked_subprocess(self, tmp_path):
        """Test parsing sherlock JSON output."""
        import json as _json

        from app.modules.username.sherlock_wrapper import SherlockWrapperModule

        module = SherlockWrapperModule()

        fake_output = _json.dumps(
            {
                "GitHub": {"url_user": "https://github.com/testuser", "status": "Claimed"},
                "Twitter": {"url_user": "https://twitter.com/testuser", "status": "Claimed"},
            }
        ).encode()

        mock_proc = AsyncMock()
        mock_proc.communicate = AsyncMock(return_value=(fake_output, b""))
        mock_proc.returncode = 0

        with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
            result = await module.run("testuser", TargetType.USERNAME)

        assert result is not None


class TestMaigretWrapper:
    """Tests for app.modules.username.maigret_wrapper.MaigretWrapper"""

    @pytest.mark.asyncio
    async def test_metadata(self):
        from app.modules.username.maigret_wrapper import MaigretWrapper

        module = MaigretWrapper()
        meta = module.metadata()
        assert meta.name == "maigret_wrapper"
        assert TargetType.USERNAME in meta.target_types

    @pytest.mark.asyncio
    async def test_validate_valid_username(self):
        from app.modules.username.maigret_wrapper import MaigretWrapper

        module = MaigretWrapper()
        assert await module.validate("johndoe", TargetType.USERNAME) is True
        assert await module.validate("john_doe-99", TargetType.USERNAME) is True

    @pytest.mark.asyncio
    async def test_validate_invalid_username(self):
        from app.modules.username.maigret_wrapper import MaigretWrapper

        module = MaigretWrapper()
        assert await module.validate("x", TargetType.USERNAME) is False
        assert await module.validate("user name with spaces", TargetType.USERNAME) is False

    @pytest.mark.asyncio
    async def test_run_fallback_when_not_installed(self):
        from app.modules.username.maigret_wrapper import MaigretWrapper

        module = MaigretWrapper()

        with patch.dict("sys.modules", {"maigret": None}):
            with patch("asyncio.create_subprocess_exec") as mock_exec:
                mock_exec.side_effect = FileNotFoundError("maigret not found")
                result = await module.run("testuser", TargetType.USERNAME)

        assert result is not None
        assert result.success is False
        assert "not installed" in result.error.lower()
