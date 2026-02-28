"""
Proxy rotation manager with TOR support and Gluetun VPN integration.

Priority:
1. Gluetun VPN HTTP proxy (if VPN_ENABLED=true in .env)
2. Proxy list file rotation (if USE_PROXY=true)
3. TOR SOCKS proxy (if TOR_ENABLED=true)
4. Direct connection (no proxy)

Usage:
    rotator = ProxyRotator()
    await rotator.initialize()
    proxy_url = await rotator.get_next_proxy()  # Returns None if no proxy
    async with aiohttp.ClientSession() as session:
        async with session.get(url, proxy=proxy_url) as resp:
            ...
"""

import asyncio
import random
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import aiohttp

from app.core.config import settings
from app.core.logging import get_logger

logger = get_logger(__name__)


@dataclass
class ProxyInfo:
    """Information about a single proxy."""

    url: str                         # protocol://user:pass@host:port
    protocol: str = "http"           # http | socks5 | socks4
    host: str = ""
    port: int = 0
    is_healthy: bool = True
    success_count: int = 0
    failure_count: int = 0
    last_used: float = field(default_factory=time.monotonic)
    last_checked: float = field(default_factory=time.monotonic)
    avg_latency_ms: float = 0.0

    @property
    def success_rate(self) -> float:
        total = self.success_count + self.failure_count
        return (self.success_count / total) if total > 0 else 1.0

    def record_success(self, latency_ms: float) -> None:
        self.success_count += 1
        self.last_used = time.monotonic()
        # Exponential moving average of latency
        self.avg_latency_ms = (0.7 * self.avg_latency_ms + 0.3 * latency_ms) if self.avg_latency_ms else latency_ms

    def record_failure(self) -> None:
        self.failure_count += 1
        if self.success_rate < 0.3:
            self.is_healthy = False
            logger.warning("proxy_marked_unhealthy", url=self._safe_url())

    def _safe_url(self) -> str:
        """Return URL without credentials for logging."""
        parts = self.url.split("@")
        if len(parts) > 1:
            protocol_end = parts[0].find("://") + 3
            protocol = parts[0][:protocol_end]
            return f"{protocol}***@{parts[-1]}"
        return self.url


class ProxyRotator:
    """
    Manages proxy rotation for OSINT modules.

    Supports:
    - Gluetun VPN HTTP proxy (highest priority)
    - File-based proxy list with health checking
    - TOR SOCKS5 proxy with circuit rotation
    - Round-robin, random, or least-used rotation strategies
    """

    def __init__(self) -> None:
        self._proxies: list[ProxyInfo] = []
        self._current_index: int = 0
        self._strategy = settings.proxy_rotation_strategy
        self._tor_proxy: ProxyInfo | None = None
        self._gluetun_proxy: ProxyInfo | None = None
        self._initialized = False

    async def initialize(self) -> None:
        """Load and health-check all proxies on startup."""
        if self._initialized:
            return

        # 1. Gluetun VPN proxy (highest priority)
        if settings.vpn_enabled:
            self._gluetun_proxy = ProxyInfo(
                url=settings.gluetun_http_proxy,
                protocol="http",
            )
            logger.info("vpn_proxy_configured", url=settings.gluetun_http_proxy)

        # 2. TOR proxy
        if settings.tor_enabled:
            tor_url = f"socks5://127.0.0.1:{settings.tor_socks_port}"
            self._tor_proxy = ProxyInfo(url=tor_url, protocol="socks5")
            await self._check_tor()

        # 3. File-based proxy list
        if settings.use_proxy:
            await self._load_proxy_file()
            await self._health_check_all()

        self._initialized = True
        total = len(self._proxies)
        healthy = sum(1 for p in self._proxies if p.is_healthy)
        logger.info(
            "proxy_rotator_initialized",
            total=total,
            healthy=healthy,
            vpn=settings.vpn_enabled,
            tor=settings.tor_enabled,
        )

    async def _load_proxy_file(self) -> None:
        """Load proxies from the configured proxy list file."""
        proxy_file = Path(settings.proxy_list_file)
        if not proxy_file.exists():
            logger.warning("proxy_file_not_found", path=str(proxy_file))
            return

        loaded = 0
        with open(proxy_file) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    proxy = self._parse_proxy_url(line)
                    if proxy:
                        self._proxies.append(proxy)
                        loaded += 1

        logger.info("proxies_loaded", count=loaded, file=str(proxy_file))

    def _parse_proxy_url(self, url: str) -> ProxyInfo | None:
        """Parse a proxy URL into a ProxyInfo object."""
        try:
            if "://" not in url:
                url = f"http://{url}"
            protocol = url.split("://")[0].lower()
            # Parse host:port
            netloc = url.split("://")[-1].split("@")[-1]
            host = netloc.split(":")[0]
            port = int(netloc.split(":")[1]) if ":" in netloc else 80
            return ProxyInfo(url=url, protocol=protocol, host=host, port=port)
        except Exception as e:
            logger.warning("proxy_parse_failed", url=url, error=str(e))
            return None

    async def _health_check_all(self) -> None:
        """Health check all proxies concurrently."""
        tasks = [self._check_proxy(proxy) for proxy in self._proxies]
        await asyncio.gather(*tasks, return_exceptions=True)

    async def _check_proxy(self, proxy: ProxyInfo) -> bool:
        """Test if a proxy is working by fetching a test URL."""
        test_url = "https://httpbin.org/ip"
        start = time.monotonic()
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    test_url,
                    proxy=proxy.url,
                    timeout=aiohttp.ClientTimeout(total=10),
                ) as resp:
                    if resp.status == 200:
                        latency = (time.monotonic() - start) * 1000
                        proxy.record_success(latency)
                        proxy.is_healthy = True
                        return True
        except Exception:
            pass
        proxy.is_healthy = False
        return False

    async def _check_tor(self) -> bool:
        """Verify TOR connection is working."""
        if not self._tor_proxy:
            return False
        is_working = await self._check_proxy(self._tor_proxy)
        if is_working:
            logger.info("tor_connected")
        else:
            logger.warning("tor_connection_failed")
            self._tor_proxy = None
        return is_working

    async def rotate_tor_circuit(self) -> bool:
        """
        Request a new TOR circuit (new exit node = new IP).

        Requires TOR control port and password.
        """
        if not settings.tor_enabled or not settings.tor_password:
            return False
        try:
            import socket
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect(("127.0.0.1", settings.tor_control_port))
                password = settings.tor_password.get_secret_value()
                s.send(f'AUTHENTICATE "{password}"\r\n'.encode())
                s.recv(1024)
                s.send(b"SIGNAL NEWNYM\r\n")
                response = s.recv(1024).decode()
                if "250 OK" in response:
                    logger.info("tor_new_circuit_requested")
                    await asyncio.sleep(3)  # Wait for new circuit
                    return True
        except Exception as e:
            logger.error("tor_circuit_rotation_failed", error=str(e))
        return False

    async def get_next_proxy(self) -> str | None:
        """
        Get the next proxy URL based on rotation strategy.

        Returns:
            Proxy URL string, or None for direct connection.
        """
        if not self._initialized:
            await self.initialize()

        # Priority 1: Gluetun VPN
        if settings.vpn_enabled and self._gluetun_proxy:
            return self._gluetun_proxy.url

        # Priority 2: File-based proxies
        healthy = [p for p in self._proxies if p.is_healthy]
        if healthy:
            if self._strategy == "random":
                proxy = random.choice(healthy)
            elif self._strategy == "least_used":
                proxy = min(healthy, key=lambda p: p.last_used)
            else:  # round_robin
                self._current_index = self._current_index % len(healthy)
                proxy = healthy[self._current_index]
                self._current_index += 1
            proxy.last_used = time.monotonic()
            return proxy.url

        # Priority 3: TOR
        if settings.tor_enabled and self._tor_proxy and self._tor_proxy.is_healthy:
            return self._tor_proxy.url

        return None

    def record_success(self, proxy_url: str, latency_ms: float = 0) -> None:
        """Record a successful request for a proxy."""
        for proxy in self._proxies:
            if proxy.url == proxy_url:
                proxy.record_success(latency_ms)
                return

    def record_failure(self, proxy_url: str) -> None:
        """Record a failed request for a proxy."""
        for proxy in self._proxies:
            if proxy.url == proxy_url:
                proxy.record_failure()
                return

    def get_stats(self) -> dict:
        """Return proxy rotation statistics."""
        healthy = [p for p in self._proxies if p.is_healthy]
        return {
            "total_proxies": len(self._proxies),
            "healthy_proxies": len(healthy),
            "vpn_enabled": settings.vpn_enabled,
            "tor_enabled": settings.tor_enabled and self._tor_proxy is not None,
            "strategy": self._strategy,
        }


# ── Singleton ─────────────────────────────────────────────────────
_rotator: ProxyRotator | None = None


async def get_proxy_rotator() -> ProxyRotator:
    """Get the global proxy rotator instance."""
    global _rotator
    if _rotator is None:
        _rotator = ProxyRotator()
        await _rotator.initialize()
    return _rotator
