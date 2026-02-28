"""
Tests for domain permutation discovery.
"""

import pytest

from app.core.constants import TargetType


class TestDomainPermutatorModule:
    def test_build_labels_generates_extended_combinations(self):
        from app.modules.domain.permutator import DomainPermutatorModule

        module = DomainPermutatorModule()
        labels = module._build_labels(
            "Roshni Joshi",
            __import__("app.core.constants", fromlist=["TargetType"]).TargetType.PERSON,
            {"target_inputs": {"name": "Roshni Joshi"}},
        )

        assert "roshnijoshi" in labels  # full concat
        assert "rjoshi" in labels  # first initial + last
        assert "roshni-joshi" in labels  # hyphen variant
        assert "joshniroshi" not in labels  # reversed would be "joshiroshni" — not expected
        assert "roshnij" in labels  # first + last initial

    def test_build_labels_from_name_and_email(self):
        from app.modules.domain.permutator import DomainPermutatorModule

        module = DomainPermutatorModule()
        labels = module._build_labels(
            "manansantoki2003@gmail.com",
            TargetType.EMAIL,
            {
                "target_inputs": {
                    "name": "Manan Santoki",
                    "email": "manansantoki2003@gmail.com",
                }
            },
        )

        assert "manansantoki" in labels
        assert "msantoki" in labels

    @pytest.mark.asyncio
    async def test_run_returns_registered_domains(self):
        from app.modules.domain.permutator import DomainPermutatorModule

        module = DomainPermutatorModule()

        async def fake_probe(domain: str, semaphore):
            return {
                "domain": domain,
                "is_registered": domain in {"msantoki.com", "manansantoki.xyz"},
                "a_records": ["1.2.3.4"] if domain == "msantoki.com" else [],
                "aaaa_records": [],
                "nameservers": ["ns1.example.com"],
                "mx_records": [],
                "soa_records": [],
            }

        module._probe_domain = fake_probe  # type: ignore[method-assign]

        result = await module.run(
            "Manan Santoki",
            TargetType.PERSON,
            {"target_inputs": {"name": "Manan Santoki"}},
        )

        assert result.success is True
        assert "msantoki.com" in result.data["discovered_domains"]
        assert "manansantoki.xyz" in result.data["discovered_domains"]
        assert "1.2.3.4" in result.data["discovered_ips"]
