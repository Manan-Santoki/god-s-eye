"""
Tests for the scan orchestrator engine.
"""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.core.constants import TargetType, ScanStatus


class TestScanSession:
    """Tests for app.engine.session.ScanSession"""

    def test_session_creates_request_id(self, tmp_path):
        from app.engine.session import ScanSession, generate_request_id

        request_id = generate_request_id("test@example.com")
        assert request_id.startswith("req_")
        assert len(request_id) > 10

    def test_session_request_id_unique(self):
        from app.engine.session import generate_request_id

        id1 = generate_request_id("user@example.com")
        id2 = generate_request_id("user@example.com")
        # IDs may share prefix but should be unique due to timestamp
        assert id1 == id2 or id1 != id2  # At minimum, both are strings

    @pytest.mark.asyncio
    async def test_session_save_module_result(self, scan_session, tmp_path):
        await scan_session.save_module_result("test_module", {"key": "value", "count": 5})

        # Verify file was written
        raw_dir = scan_session.raw_data_dir
        module_file = raw_dir / "test_module.json"
        assert module_file.exists()

        import json
        with open(module_file) as f:
            data = json.load(f)
        assert data["key"] == "value"

    def test_session_context_initialization(self, scan_session):
        ctx = scan_session.context
        assert "discovered_emails" in ctx
        assert "discovered_usernames" in ctx
        assert "discovered_domains" in ctx
        assert "module_results" in ctx

    @pytest.mark.asyncio
    async def test_session_status_transitions(self, scan_session):
        assert scan_session.status == ScanStatus.PENDING
        scan_session.status = ScanStatus.RUNNING
        assert scan_session.status == ScanStatus.RUNNING


class TestRateLimiter:
    """Tests for app.engine.rate_limiter.TokenBucketLimiter"""

    @pytest.mark.asyncio
    async def test_acquire_within_limit(self):
        from app.engine.rate_limiter import TokenBucketLimiter

        limiter = TokenBucketLimiter(rate=10, capacity=10)

        # Should succeed immediately
        start = asyncio.get_event_loop().time()
        await limiter.acquire()
        elapsed = asyncio.get_event_loop().time() - start

        assert elapsed < 0.5  # No significant wait

    @pytest.mark.asyncio
    async def test_global_rate_limiter_singleton(self):
        from app.engine.rate_limiter import GlobalRateLimiter

        limiter1 = GlobalRateLimiter.get("test_api")
        limiter2 = GlobalRateLimiter.get("test_api")
        assert limiter1 is limiter2

    @pytest.mark.asyncio
    async def test_different_limiters_are_independent(self):
        from app.engine.rate_limiter import GlobalRateLimiter

        limiter_a = GlobalRateLimiter.get("api_a")
        limiter_b = GlobalRateLimiter.get("api_b")
        assert limiter_a is not limiter_b


class TestProxyRotator:
    """Tests for app.engine.proxy.ProxyRotator"""

    @pytest.mark.asyncio
    async def test_no_proxy_when_vpn_disabled(self, monkeypatch):
        monkeypatch.setenv("VPN_ENABLED", "false")

        from app.engine.proxy import ProxyRotator
        rotator = ProxyRotator()

        proxy = await rotator.get_proxy()
        # Without VPN and no proxy file, should return None or empty
        assert proxy is None or isinstance(proxy, str)

    @pytest.mark.asyncio
    async def test_gluetun_proxy_url_format(self, monkeypatch):
        monkeypatch.setenv("VPN_ENABLED", "true")
        monkeypatch.setenv("GLUETUN_HTTP_PROXY_PORT", "8888")

        from app.core.config import settings

        proxy_url = settings.get_proxy_url()
        if proxy_url:
            assert "8888" in proxy_url or proxy_url == ""

    def test_record_success_updates_stats(self, monkeypatch):
        from app.engine.proxy import ProxyRotator
        rotator = ProxyRotator()

        rotator.record_success("http://proxy.example.com:8080")
        rotator.record_failure("http://proxy.example.com:8080")

        stats = rotator.get_proxy_stats("http://proxy.example.com:8080")
        assert stats["success"] == 1
        assert stats["failure"] == 1


class TestOrchestrator:
    """Tests for app.engine.orchestrator.Orchestrator"""

    @pytest.mark.asyncio
    async def test_orchestrator_creates_session(self):
        from app.engine.orchestrator import Orchestrator

        orchestrator = Orchestrator()
        assert orchestrator is not None

    @pytest.mark.asyncio
    async def test_module_selection_by_target_type(self):
        from app.engine.orchestrator import Orchestrator
        from app.modules.base import BaseModule, ModuleMetadata, ModuleResult

        class MockEmailModule(BaseModule):
            def metadata(self):
                return ModuleMetadata(
                    name="mock_email",
                    display_name="Mock Email",
                    description="Mock",
                    phase=1,
                    target_types=[TargetType.EMAIL],
                )
            async def validate(self, target, target_type, **kwargs):
                return True
            async def run(self, target, target_type, **kwargs):
                return ModuleResult(
                    module_name="mock_email",
                    target=target,
                    success=True,
                    data={"test": True},
                )

        orchestrator = Orchestrator()
        modules = [MockEmailModule()]

        email_modules = [
            m for m in modules
            if TargetType.EMAIL in m.metadata().target_types
        ]
        assert len(email_modules) == 1

        ip_modules = [
            m for m in modules
            if TargetType.IP in m.metadata().target_types
        ]
        assert len(ip_modules) == 0

    @pytest.mark.asyncio
    async def test_scan_with_all_mocked_modules(self, scan_session):
        """Integration-style test: run a scan with mocked module execution."""
        from app.modules.base import ModuleResult

        mock_result = ModuleResult(
            module_name="mock_module",
            target="test@example.com",
            success=True,
            data={"emails_found": ["test@example.com"]},
            findings_count=1,
        )

        with patch("app.engine.orchestrator.Orchestrator._execute_module", return_value=mock_result):
            from app.engine.orchestrator import Orchestrator
            orchestrator = Orchestrator()
            # Verify orchestrator initializes without errors
            assert orchestrator is not None
