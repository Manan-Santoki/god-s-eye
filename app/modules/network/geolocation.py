"""
IP Geolocation module using multiple providers.

Providers (in order of preference):
  1. MaxMind GeoLite2 (local DB, no API key required)
  2. IPinfo.io (API key optional, 50k/month free)
  3. ip-api.com (no key, 45 req/min free tier)
  4. ipwhois (pure Python, no deps)

Target types: ip, domain
Phase: FAST_API (1)
"""

from typing import Any

from app.modules.base import BaseModule, ModuleMetadata, ModuleResult
from app.core.constants import ModulePhase, TargetType
from app.core.logging import get_logger

logger = get_logger(__name__)


class GeolocationModule(BaseModule):
    """Geolocate IP addresses using multiple providers."""

    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            name="geolocation",
            display_name="IP Geolocation",
            description="Geolocates IP addresses using MaxMind GeoLite2, IPinfo, and ip-api.com",
            phase=ModulePhase.FAST_API,
            target_types=[TargetType.IP, TargetType.DOMAIN],
            requires_browser=False,
            requires_api_key=False,
            rate_limit_per_minute=45,
        )

    async def validate(self, target: str, target_type: TargetType, **kwargs: Any) -> bool:
        import re
        ip_re = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
        domain_re = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$")
        return bool(ip_re.match(target) or domain_re.match(target))

    async def run(
        self,
        target: str,
        target_type: TargetType,
        session: Any = None,
        **kwargs: Any,
    ) -> ModuleResult:
        from app.core.config import settings

        results: dict[str, Any] = {
            "target": target,
            "ip": target,
            "geolocation": {},
            "asn": {},
            "provider": None,
        }

        # Resolve domain to IP if needed
        if target_type == TargetType.DOMAIN:
            resolved = await self._resolve_domain(target)
            if resolved:
                results["ip"] = resolved
                results["resolved_from"] = target
            else:
                return ModuleResult(
                    module_name=self.metadata().name,
                    target=target,
                    success=False,
                    error=f"Could not resolve domain {target} to IP",
                    data=results,
                )

        ip = results["ip"]

        # Validate resolved IP
        if not self._is_public_ip(ip):
            return ModuleResult(
                module_name=self.metadata().name,
                target=target,
                success=True,
                data={**results, "note": f"IP {ip} is private/loopback — no geolocation available"},
                findings_count=0,
            )

        # Try providers in order
        geo = None

        # 1. MaxMind GeoLite2 (local DB)
        geo = await self._maxmind_lookup(ip)
        if geo:
            results["provider"] = "maxmind_geoip2"
            results["geolocation"] = geo

        # 2. IPinfo.io
        if not geo:
            geo = await self._ipinfo_lookup(ip, settings.ipinfo_api_key.get_secret_value() if settings.ipinfo_api_key else None)
            if geo:
                results["provider"] = "ipinfo"
                results["geolocation"] = geo

        # 3. ip-api.com (free, no key)
        if not geo:
            geo = await self._ip_api_lookup(ip)
            if geo:
                results["provider"] = "ip-api.com"
                results["geolocation"] = geo

        # 4. ipwhois fallback
        if not geo:
            geo = await self._ipwhois_lookup(ip)
            if geo:
                results["provider"] = "ipwhois"
                results["geolocation"] = geo

        if not geo:
            return ModuleResult(
                module_name=self.metadata().name,
                target=target,
                success=False,
                error="All geolocation providers failed",
                data=results,
            )

        # Extract ASN separately
        results["asn"] = {
            "asn": geo.pop("asn", None),
            "org": geo.pop("org", None),
            "isp": geo.pop("isp", None),
        }

        logger.info(
            "geolocation_complete",
            ip=ip,
            country=geo.get("country"),
            city=geo.get("city"),
            provider=results["provider"],
        )

        return ModuleResult(
            module_name=self.metadata().name,
            target=target,
            success=True,
            data=results,
            findings_count=1,
        )

    async def _resolve_domain(self, domain: str) -> str | None:
        """Resolve domain to IPv4 using asyncio DNS."""
        import asyncio
        try:
            loop = asyncio.get_event_loop()
            result = await loop.getaddrinfo(domain, None)
            for family, _, _, _, sockaddr in result:
                import socket
                if family == socket.AF_INET:
                    return sockaddr[0]
        except Exception as e:
            logger.debug("domain_resolve_failed", domain=domain, error=str(e))
        return None

    def _is_public_ip(self, ip: str) -> bool:
        """Check if IP is a public routable address."""
        import ipaddress
        try:
            addr = ipaddress.ip_address(ip)
            return not (addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved)
        except ValueError:
            return False

    async def _maxmind_lookup(self, ip: str) -> dict | None:
        """Look up IP using local MaxMind GeoLite2 database."""
        try:
            import geoip2.database
            from pathlib import Path

            db_paths = [
                Path("/usr/share/GeoIP/GeoLite2-City.mmdb"),
                Path("data/GeoLite2-City.mmdb"),
                Path.home() / ".local/share/GeoIP/GeoLite2-City.mmdb",
            ]

            db_path = next((p for p in db_paths if p.exists()), None)
            if not db_path:
                return None

            with geoip2.database.Reader(str(db_path)) as reader:
                response = reader.city(ip)
                return {
                    "country": response.country.name,
                    "country_code": response.country.iso_code,
                    "region": response.subdivisions.most_specific.name if response.subdivisions else None,
                    "city": response.city.name,
                    "postal": response.postal.code,
                    "latitude": float(response.location.latitude or 0),
                    "longitude": float(response.location.longitude or 0),
                    "timezone": response.location.time_zone,
                    "accuracy_radius": response.location.accuracy_radius,
                    "asn": str(response.traits.autonomous_system_number or ""),
                    "org": response.traits.autonomous_system_organization or "",
                }
        except Exception as e:
            logger.debug("maxmind_lookup_failed", ip=ip, error=str(e))
            return None

    async def _ipinfo_lookup(self, ip: str, api_key: str | None) -> dict | None:
        """Look up IP using IPinfo.io API."""
        import aiohttp
        try:
            url = f"https://ipinfo.io/{ip}/json"
            headers = {}
            if api_key:
                headers["Authorization"] = f"Bearer {api_key}"

            async with aiohttp.ClientSession() as session:
                async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    if resp.status != 200:
                        return None
                    data = await resp.json()

            # Parse "lat,lng" from loc field
            lat, lng = 0.0, 0.0
            if loc := data.get("loc"):
                try:
                    lat, lng = map(float, loc.split(","))
                except ValueError:
                    pass

            org_parts = data.get("org", "").split(" ", 1)
            asn = org_parts[0] if org_parts else ""
            org = org_parts[1] if len(org_parts) > 1 else ""

            return {
                "country": data.get("country"),
                "country_code": data.get("country"),
                "region": data.get("region"),
                "city": data.get("city"),
                "postal": data.get("postal"),
                "latitude": lat,
                "longitude": lng,
                "timezone": data.get("timezone"),
                "hostname": data.get("hostname"),
                "asn": asn,
                "org": org,
            }
        except Exception as e:
            logger.debug("ipinfo_lookup_failed", ip=ip, error=str(e))
            return None

    async def _ip_api_lookup(self, ip: str) -> dict | None:
        """Look up IP using ip-api.com (free, no key)."""
        import aiohttp
        try:
            fields = "status,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,query"
            url = f"http://ip-api.com/json/{ip}?fields={fields}"

            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    if resp.status != 200:
                        return None
                    data = await resp.json()

            if data.get("status") != "success":
                return None

            return {
                "country": data.get("country"),
                "country_code": data.get("countryCode"),
                "region": data.get("regionName"),
                "city": data.get("city"),
                "postal": data.get("zip"),
                "latitude": data.get("lat", 0.0),
                "longitude": data.get("lon", 0.0),
                "timezone": data.get("timezone"),
                "asn": data.get("as", "").split(" ")[0],
                "org": data.get("org"),
                "isp": data.get("isp"),
            }
        except Exception as e:
            logger.debug("ip_api_lookup_failed", ip=ip, error=str(e))
            return None

    async def _ipwhois_lookup(self, ip: str) -> dict | None:
        """Look up IP using ipwhois (pure Python, no API)."""
        import asyncio
        try:
            from ipwhois import IPWhois

            loop = asyncio.get_event_loop()

            def _sync_lookup():
                obj = IPWhois(ip)
                return obj.lookup_rdap(depth=1)

            data = await asyncio.wait_for(
                loop.run_in_executor(None, _sync_lookup),
                timeout=15,
            )

            network = data.get("network", {})
            asn_description = data.get("asn_description", "")

            return {
                "country": data.get("asn_country_code"),
                "country_code": data.get("asn_country_code"),
                "region": None,
                "city": None,
                "postal": None,
                "latitude": None,
                "longitude": None,
                "timezone": None,
                "asn": f"AS{data.get('asn', '')}",
                "org": asn_description,
                "network_name": network.get("name"),
                "cidr": network.get("cidr"),
            }
        except Exception as e:
            logger.debug("ipwhois_lookup_failed", ip=ip, error=str(e))
            return None
