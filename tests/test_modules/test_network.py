"""
Tests for network modules.
"""

from unittest.mock import AsyncMock, patch

import pytest

from app.core.constants import TargetType


class TestIPLookupModule:
    @pytest.mark.asyncio
    async def test_domain_target_resolves_and_scans_ips(self):
        from app.modules.network.ip_lookup import IPLookupModule

        module = IPLookupModule()

        with patch.object(
            module, "_resolve_domain_ips", AsyncMock(return_value=["1.2.3.4", "5.6.7.8"])
        ):
            with patch.object(
                module,
                "_lookup_ip",
                AsyncMock(
                    side_effect=[
                        type(
                            "Lookup", (), {"success": True, "data": {"ip": "1.2.3.4"}, "errors": []}
                        )(),
                        type(
                            "Lookup", (), {"success": True, "data": {"ip": "5.6.7.8"}, "errors": []}
                        )(),
                    ]
                ),
            ):
                result = await module.run("example.com", TargetType.DOMAIN, {})

        assert result.success is True
        assert result.data["resolved_ips"] == ["1.2.3.4", "5.6.7.8"]
        assert result.data["lookups"][0]["ip"] == "1.2.3.4"
