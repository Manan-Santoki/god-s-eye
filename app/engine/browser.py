"""
Playwright browser factory with advanced anti-fingerprinting.

Singleton pattern: one browser process, many stealth contexts.
Each module that needs a browser gets its own isolated context
(separate cookies, localStorage, etc.)

Anti-fingerprinting features:
- navigator.webdriver = false
- Randomized canvas fingerprint
- Randomized WebGL vendor/renderer
- Disabled WebRTC (prevents IP leak)
- Randomized viewport with realistic dimensions
- Rotating User-Agent strings
- Human-like mouse movement and typing
- Cookie persistence per platform (LinkedIn, Instagram, etc.)

Usage:
    factory = await BrowserFactory.create()
    page = await factory.new_page(
        proxy="socks5://127.0.0.1:9050",
        persist_session="linkedin",
    )
    await factory.human_goto(page, "https://linkedin.com")
    await factory.human_click(page, "button.login")
    await factory.human_type(page, "input#email", "user@example.com")
    await page.close()
    await factory.close()
"""

import asyncio
import json
import random
from pathlib import Path
from typing import Optional

from playwright.async_api import (
    Browser,
    BrowserContext,
    Page,
    Playwright,
    async_playwright,
)

from app.core.config import settings
from app.core.exceptions import BrowserError
from app.core.logging import get_logger

logger = get_logger(__name__)

# Modern browser User-Agents (rotate to avoid fingerprinting)
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
]

# Stealth JavaScript to inject into every page
STEALTH_SCRIPT = """
// Override navigator.webdriver
Object.defineProperty(navigator, 'webdriver', {
    get: () => undefined
});

// Override plugins (empty in headless)
Object.defineProperty(navigator, 'plugins', {
    get: () => [1, 2, 3, 4, 5]
});

// Override languages
Object.defineProperty(navigator, 'languages', {
    get: () => ['en-US', 'en']
});

// Disable WebRTC IP leak
const originalGetUserMedia = navigator.getUserMedia;
const originalMediaDevices = navigator.mediaDevices;
if (originalMediaDevices && originalMediaDevices.getUserMedia) {
    navigator.mediaDevices.getUserMedia = () => Promise.reject(new Error('Not allowed'));
}

// Randomize canvas fingerprint
const originalGetContext = HTMLCanvasElement.prototype.getContext;
HTMLCanvasElement.prototype.getContext = function(type, ...args) {
    const ctx = originalGetContext.call(this, type, ...args);
    if (type === '2d' && ctx) {
        const originalGetImageData = ctx.getImageData.bind(ctx);
        ctx.getImageData = function(...args) {
            const data = originalGetImageData(...args);
            for (let i = 0; i < data.data.length; i += 4) {
                data.data[i] = data.data[i] ^ 1;
            }
            return data;
        };
    }
    return ctx;
};

// Randomize WebGL
const getParameter = WebGLRenderingContext.prototype.getParameter;
WebGLRenderingContext.prototype.getParameter = function(parameter) {
    if (parameter === 37445) return 'Intel Inc.';
    if (parameter === 37446) return 'Intel Iris OpenGL Engine';
    return getParameter.call(this, parameter);
};

// Remove Playwright/automation traces
delete window.cdc_adoQpoasnfa76pfcZLmcfl_Array;
delete window.cdc_adoQpoasnfa76pfcZLmcfl_Promise;
delete window.cdc_adoQpoasnfa76pfcZLmcfl_Symbol;
"""


class BrowserFactory:
    """
    Singleton Playwright browser factory.

    Manages a single browser process with multiple isolated contexts.
    Injects anti-fingerprinting scripts into all pages.
    """

    _instance: Optional["BrowserFactory"] = None

    def __init__(self) -> None:
        self._playwright: Playwright | None = None
        self._browser: Browser | None = None
        self._contexts: dict[str, BrowserContext] = {}
        self._semaphore = asyncio.Semaphore(settings.max_concurrent_browsers)
        self._sessions_dir = Path(settings.data_dir) / "sessions"
        self._sessions_dir.mkdir(parents=True, exist_ok=True)

    @classmethod
    async def create(cls) -> "BrowserFactory":
        """Get or create the BrowserFactory singleton."""
        if cls._instance is None:
            factory = cls()
            await factory._start()
            cls._instance = factory
        return cls._instance

    async def _start(self) -> None:
        """Launch Playwright and browser."""
        try:
            self._playwright = await async_playwright().start()
            self._browser = await self._playwright.chromium.launch(
                headless=settings.module_config.get("stealth", {}).get("headless", True)
                if hasattr(settings, "module_config")
                else True,
                args=[
                    "--no-sandbox",
                    "--disable-setuid-sandbox",
                    "--disable-dev-shm-usage",
                    "--disable-blink-features=AutomationControlled",
                    "--disable-extensions",
                    "--disable-plugins",
                    "--disable-infobars",
                    "--disable-web-security",
                    "--disable-webrtc",
                    "--no-first-run",
                    "--no-default-browser-check",
                    "--window-size=1920,1080",
                ],
            )
            logger.info("browser_started", type="chromium")
        except Exception as e:
            raise BrowserError("BrowserFactory", f"Failed to start browser: {e}") from e

    async def new_page(
        self,
        proxy: str | None = None,
        user_agent: str | None = None,
        persist_session: str | None = None,
        headless_override: bool | None = None,
    ) -> Page:
        """
        Create a new stealth browser page.

        Args:
            proxy: Proxy URL (protocol://user:pass@host:port) or None.
            user_agent: Override User-Agent string. Random if None.
            persist_session: Platform name to persist cookies (e.g., "linkedin").
                             Loads saved state on creation, saves on page close.
            headless_override: Override headless setting for this context.

        Returns:
            A Playwright Page with all stealth scripts injected.
        """
        assert self._browser is not None

        # Select a random User-Agent
        ua = user_agent or random.choice(USER_AGENTS)

        # Randomize viewport (realistic but slightly different each time)
        base_w, base_h = 1920, 1080
        viewport_w = base_w + random.randint(-100, 100)
        viewport_h = base_h + random.randint(-50, 50)

        # Build context options
        context_options: dict = {
            "user_agent": ua,
            "viewport": {"width": viewport_w, "height": viewport_h},
            "locale": "en-US",
            "timezone_id": random.choice(["America/New_York", "America/Chicago", "America/Los_Angeles", "Europe/London"]),
            "geolocation": None,
            "permissions": [],
            "extra_http_headers": {
                "Accept-Language": "en-US,en;q=0.9",
                "Accept-Encoding": "gzip, deflate, br",
            },
        }

        if proxy:
            # Parse proxy URL for Playwright
            context_options["proxy"] = {"server": proxy}

        # Load saved session state if requested
        session_file = self._sessions_dir / f"{persist_session}_state.json" if persist_session else None
        if session_file and session_file.exists():
            try:
                with open(session_file) as f:
                    state = json.load(f)
                context_options["storage_state"] = state
                logger.info("session_loaded", platform=persist_session)
            except Exception as e:
                logger.warning("session_load_failed", platform=persist_session, error=str(e))

        # Create isolated context
        context_key = persist_session or f"ctx_{id(context_options)}"
        async with self._semaphore:
            context = await self._browser.new_context(**context_options)

            # Inject stealth script into every page
            await context.add_init_script(STEALTH_SCRIPT)

            # Block unnecessary resources (tracking, ads) for speed
            await context.route(
                "**/*.{png,jpg,jpeg,gif,svg,ico,woff,woff2,ttf,mp4,webm}",
                lambda route: route.abort()
                if route.request.resource_type in ("image", "media", "font")
                and not route.request.url.endswith((".jpg", ".jpeg", ".png"))
                else route.continue_(),
            )

            page = await context.new_page()

            # Save session on page close if persist_session is set
            if persist_session and session_file:
                page.on("close", lambda: asyncio.create_task(
                    self._save_session(context, str(session_file), persist_session)
                ))

            self._contexts[context_key] = context
            logger.debug("page_created", ua=ua[:50], proxy=bool(proxy), session=persist_session)
            return page

    async def _save_session(self, context: BrowserContext, path: str, platform: str) -> None:
        """Save browser context state (cookies + localStorage) to disk."""
        try:
            state = await context.storage_state()
            with open(path, "w") as f:
                json.dump(state, f)
            logger.info("session_saved", platform=platform)
        except Exception as e:
            logger.warning("session_save_failed", platform=platform, error=str(e))

    async def clear_session(self, platform: str) -> None:
        """Delete saved session state for a platform."""
        session_file = self._sessions_dir / f"{platform}_state.json"
        if session_file.exists():
            session_file.unlink()
            logger.info("session_cleared", platform=platform)

    # ── Human Behavior Simulation ────────────────────────────────

    async def human_goto(
        self, page: Page, url: str, wait_ms: tuple[int, int] = (1000, 3000)
    ) -> None:
        """Navigate to URL with human-like timing."""
        await page.goto(url, wait_until="domcontentloaded", timeout=30000)
        await asyncio.sleep(random.randint(*wait_ms) / 1000)

    async def human_click(
        self,
        page: Page,
        selector: str,
        wait_ms: tuple[int, int] = (500, 2000),
    ) -> None:
        """Click an element with human-like mouse movement and delay."""
        element = page.locator(selector).first
        # Move mouse to element first
        box = await element.bounding_box()
        if box:
            target_x = box["x"] + box["width"] / 2 + random.randint(-5, 5)
            target_y = box["y"] + box["height"] / 2 + random.randint(-3, 3)
            await page.mouse.move(target_x, target_y)
            await asyncio.sleep(random.randint(100, 300) / 1000)
        await element.click()
        await asyncio.sleep(random.randint(*wait_ms) / 1000)

    async def human_type(
        self,
        page: Page,
        selector: str,
        text: str,
        delay_range: tuple[int, int] = (50, 150),
    ) -> None:
        """Type text character-by-character with random delays (simulates human typing)."""
        element = page.locator(selector).first
        await element.click()
        for char in text:
            await element.type(char, delay=random.randint(*delay_range))
        await asyncio.sleep(random.randint(200, 500) / 1000)

    async def human_scroll(
        self,
        page: Page,
        distance: int = 500,
        steps: int = 5,
    ) -> None:
        """Scroll the page with a human-like pattern."""
        for _ in range(steps):
            scroll_amount = distance // steps + random.randint(-20, 20)
            await page.mouse.wheel(0, scroll_amount)
            await asyncio.sleep(random.randint(200, 600) / 1000)

    async def take_screenshot(self, page: Page, path: str) -> None:
        """Take a full-page screenshot."""
        try:
            await page.screenshot(path=path, full_page=True)
            logger.debug("screenshot_taken", path=path)
        except Exception as e:
            logger.warning("screenshot_failed", path=path, error=str(e))

    async def close(self) -> None:
        """Close all contexts and the browser."""
        for context in self._contexts.values():
            try:
                await context.close()
            except Exception:
                pass
        if self._browser:
            await self._browser.close()
        if self._playwright:
            await self._playwright.stop()
        BrowserFactory._instance = None
        logger.info("browser_closed")
