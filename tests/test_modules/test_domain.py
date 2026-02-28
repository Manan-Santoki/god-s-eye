"""
Tests for domain intelligence modules.
"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.core.constants import TargetType


class TestDNSRecon:
    """Tests for app.modules.domain.dns_recon.DNSReconModule"""

    @pytest.mark.asyncio
    async def test_metadata(self):
        from app.modules.domain.dns_recon import DNSReconModule
        module = DNSReconModule()
        meta = module.metadata()
        assert meta.name == "dns_recon"
        assert TargetType.DOMAIN in meta.target_types

    @pytest.mark.asyncio
    async def test_validate_domain(self):
        from app.modules.domain.dns_recon import DNSReconModule
        module = DNSReconModule()
        assert await module.validate("example.com", TargetType.DOMAIN) is True
        assert await module.validate("sub.example.com", TargetType.DOMAIN) is True
        assert await module.validate("not a domain", TargetType.DOMAIN) is False

    @pytest.mark.asyncio
    async def test_run_with_mocked_dns(self):
        from app.modules.domain.dns_recon import DNSReconModule
        module = DNSReconModule()

        with patch("dns.resolver.resolve") as mock_resolve:
            mock_a = MagicMock()
            mock_a.address = "93.184.216.34"
            mock_resolve.return_value = [mock_a]

            result = await module.run("example.com", TargetType.DOMAIN)

        assert result is not None
        assert result.module_name == "dns_recon"

    @pytest.mark.asyncio
    async def test_run_dns_failure_graceful(self):
        from app.modules.domain.dns_recon import DNSReconModule
        module = DNSReconModule()

        with patch("dns.resolver.resolve", side_effect=Exception("DNS resolution failed")):
            result = await module.run("nonexistent-fake-domain-xyz.com", TargetType.DOMAIN)

        assert result is not None
        # Should not raise, just return partial or error result
        assert result.module_name == "dns_recon"


class TestCertificateSearch:
    """Tests for app.modules.domain.certificate_search.CertificateSearchModule"""

    @pytest.mark.asyncio
    async def test_metadata(self):
        from app.modules.domain.certificate_search import CertificateSearchModule
        module = CertificateSearchModule()
        meta = module.metadata()
        assert meta.name == "certificate_search"
        assert TargetType.DOMAIN in meta.target_types

    @pytest.mark.asyncio
    async def test_run_with_mocked_crt_sh(self, mock_aiohttp_response):
        from app.modules.domain.certificate_search import CertificateSearchModule
        module = CertificateSearchModule()

        crt_data = [
            {"name_value": "example.com", "issuer_name": "Let's Encrypt", "not_before": "2024-01-01"},
            {"name_value": "www.example.com", "issuer_name": "Let's Encrypt", "not_before": "2024-01-01"},
            {"name_value": "mail.example.com", "issuer_name": "DigiCert", "not_before": "2023-06-01"},
        ]

        mock_resp = mock_aiohttp_response(crt_data, status=200)

        with patch("aiohttp.ClientSession.get", return_value=mock_resp):
            result = await module.run("example.com", TargetType.DOMAIN)

        assert result is not None
        assert result.module_name == "certificate_search"


class TestSubdomainEnum:
    """Tests for app.modules.domain.subdomain_enum.SubdomainEnumModule"""

    @pytest.mark.asyncio
    async def test_metadata(self):
        from app.modules.domain.subdomain_enum import SubdomainEnumModule
        module = SubdomainEnumModule()
        meta = module.metadata()
        assert meta.name == "subdomain_enum"
        assert TargetType.DOMAIN in meta.target_types

    @pytest.mark.asyncio
    async def test_validate(self):
        from app.modules.domain.subdomain_enum import SubdomainEnumModule
        module = SubdomainEnumModule()
        assert await module.validate("example.com", TargetType.DOMAIN) is True
        assert await module.validate("x", TargetType.DOMAIN) is False

    @pytest.mark.asyncio
    async def test_run_with_mocked_dns(self, mock_aiohttp_response):
        from app.modules.domain.subdomain_enum import SubdomainEnumModule
        module = SubdomainEnumModule()

        # Mock crt.sh response
        crt_data = [
            {"name_value": "www.example.com"},
            {"name_value": "mail.example.com"},
            {"name_value": "*.example.com"},
        ]
        mock_resp = mock_aiohttp_response(crt_data, status=200)

        with patch("aiohttp.ClientSession.get", return_value=mock_resp):
            with patch("dns.resolver.resolve") as mock_dns:
                mock_a = MagicMock()
                mock_a.address = "93.184.216.34"
                mock_dns.return_value = [mock_a]

                result = await module.run("example.com", TargetType.DOMAIN)

        assert result is not None
        assert result.module_name == "subdomain_enum"
