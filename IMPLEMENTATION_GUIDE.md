# IMPLEMENTATION_GUIDE.md — Step-by-Step Build Instructions

> **For AI Agents:** Read this document fully before writing any code. Execute steps in order. Do not skip steps. Do not hallucinate APIs or libraries not listed here.

---

## STRICT RULES FOR CODE GENERATION

1. **Type Hints everywhere** — use `typing` module, Pydantic models for all data structures
2. **Async/await for all I/O** — network calls, file I/O, database operations
3. **Never let the app crash** — wrap all external calls in try/except, log errors, continue
4. **Pydantic for validation** — all inputs, API responses, and module outputs must be validated
5. **Structured logging** — use `structlog` with JSON output; never use `print()`
6. **No hardcoded secrets** — all API keys, passwords, URLs from environment variables
7. **Docstrings on every class and public method** — Google style
8. **Tests for every module** — pytest + pytest-asyncio

---

## STEP 1: Project Skeleton + Dependencies

### 1.1 Create `pyproject.toml`

```toml
[project]
name = "god_eye"
version = "1.0.0"
description = "Open Source Intelligence Platform"
requires-python = ">=3.11"
dependencies = [
    # CLI & UI
    "typer[all]>=0.9.0",
    "rich>=13.0",
    "prompt-toolkit>=3.0",
    
    # Web Framework
    "fastapi>=0.104.0",
    "uvicorn[standard]>=0.24.0",
    
    # Async HTTP
    "aiohttp>=3.9.0",
    "aiofiles>=23.0",
    
    # Browser Automation
    "playwright>=1.40.0",
    
    # Databases
    "neo4j>=5.14.0",
    "redis[hiredis]>=5.0.0",
    "aiosqlite>=0.19.0",
    
    # Data Validation
    "pydantic>=2.5.0",
    "pydantic-settings>=2.1.0",
    
    # DNS & Network
    "dnspython>=2.4.0",
    "python-whois>=0.9.0",
    
    # Phone
    "phonenumbers>=8.13.0",
    
    # Image Processing
    "Pillow>=10.0.0",
    "exifread>=3.0.0",
    "imagehash>=4.3.0",
    
    # AI & NLP
    "anthropic>=0.40.0",
    "openai>=1.6.0",
    "spacy>=3.7.0",
    
    # Face Recognition
    "insightface>=0.7.3",
    "onnxruntime>=1.16.0",
    "numpy>=1.26.0",
    
    # Export
    "jinja2>=3.1.0",
    "markdown>=3.5.0",
    "weasyprint>=60.0",
    
    # Utilities
    "python-dotenv>=1.0.0",
    "pyyaml>=6.0.0",
    "structlog>=23.2.0",
    "tenacity>=8.2.0",
    "beautifulsoup4>=4.12.0",
    "lxml>=4.9.0",
]

[project.optional-dependencies]
dev = [
    "pytest>=7.4.0",
    "pytest-asyncio>=0.23.0",
    "pytest-cov>=4.1.0",
    "pytest-mock>=3.12.0",
    "ruff>=0.1.0",
    "mypy>=1.7.0",
]

[project.scripts]
god_eye = "app.cli:app"
```

### 1.2 Create `docker-compose.yml`

```yaml
version: '3.8'

services:
  neo4j:
    image: neo4j:5-community
    ports:
      - "7474:7474"   # Browser UI
      - "7687:7687"   # Bolt protocol
    environment:
      NEO4J_AUTH: neo4j/god_eye_password
      NEO4J_PLUGINS: '["apoc"]'
    volumes:
      - neo4j_data:/data
    healthcheck:
      test: ["CMD", "neo4j", "status"]
      interval: 10s
      timeout: 5s
      retries: 5

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    volumes:
      - redis_data:/data
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 5s
      timeout: 3s
      retries: 5

  app:
    build: .
    depends_on:
      neo4j:
        condition: service_healthy
      redis:
        condition: service_healthy
    env_file: .env
    volumes:
      - ./data:/app/data
    ports:
      - "8000:8000"

volumes:
  neo4j_data:
  redis_data:
```

### 1.3 Create `.env.example`

```ini
# ═══════════════════════════════════════════════
# GOD_EYE Configuration
# Copy to .env and fill in your values
# ═══════════════════════════════════════════════

# ── Infrastructure ──
NEO4J_URI=bolt://localhost:7687
NEO4J_USER=neo4j
NEO4J_PASSWORD=god_eye_password
REDIS_URL=redis://localhost:6379

# ── Email Intelligence APIs ──
HIBP_API_KEY=                          # https://haveibeenpwned.com/API/Key (free)
HUNTER_IO_API_KEY=                     # https://hunter.io (free: 25 req/month)
DEHASHED_API_KEY=                      # https://dehashed.com (pay-per-query)
EMAILREP_API_KEY=                      # https://emailrep.io (optional)
INTELX_API_KEY=                        # https://intelx.io (free tier)

# ── Search Engine APIs ──
GOOGLE_CSE_API_KEY=                    # Google Cloud Console
GOOGLE_CSE_ENGINE_ID=                  # Custom Search Engine ID
BING_API_KEY=                          # Azure Cognitive Services
SHODAN_API_KEY=                        # https://shodan.io ($59 lifetime)

# ── Social Media APIs ──
TWITTER_BEARER_TOKEN=                  # Twitter Developer Portal
GITHUB_TOKEN=                          # GitHub Personal Access Token (free)
REDDIT_CLIENT_ID=                      # Reddit App credentials
REDDIT_CLIENT_SECRET=
YOUTUBE_API_KEY=                       # Google Cloud Console

# ── Domain & Network APIs ──
WHOISXML_API_KEY=                      # https://whoisxmlapi.com (free: 500/month)
SECURITYTRAILS_API_KEY=                # https://securitytrails.com (free: 50/month)
VIRUSTOTAL_API_KEY=                    # https://virustotal.com (free: 4 req/min)
IPINFO_TOKEN=                          # https://ipinfo.io (free: 50k/month)
ABUSEIPDB_API_KEY=                     # https://abuseipdb.com (free: 1k/day)
CENSYS_API_ID=                         # https://censys.io (free: 250/month)
CENSYS_API_SECRET=

# ── Phone Intelligence ──
NUMVERIFY_API_KEY=                     # https://numverify.com (free: 100/month)
TWILIO_ACCOUNT_SID=                    # https://twilio.com
TWILIO_AUTH_TOKEN=

# ── Image Intelligence ──
TINEYE_API_KEY=                        # https://tineye.com ($200/year)
GOOGLE_VISION_API_KEY=                 # Google Cloud Vision

# ── Business Intelligence ──
OPENCORPORATES_API_TOKEN=              # https://opencorporates.com (free: 500/month)
CLEARBIT_API_KEY=                      # https://clearbit.com

# ── Browser Automation Credentials ──
# WARNING: Use dedicated accounts, not personal ones
LINKEDIN_EMAIL=
LINKEDIN_PASSWORD=
INSTAGRAM_USERNAME=
INSTAGRAM_PASSWORD=
FACEBOOK_EMAIL=
FACEBOOK_PASSWORD=

# ── Proxy Configuration ──
USE_PROXY=false
PROXY_LIST_FILE=proxies.txt            # One proxy per line: protocol://user:pass@host:port
PROXY_ROTATION_STRATEGY=round_robin    # round_robin | random | least_used
TOR_ENABLED=false
TOR_SOCKS_PORT=9050
TOR_CONTROL_PORT=9051
TOR_PASSWORD=

# ── AI Configuration ──
AI_PROVIDER=anthropic                  # anthropic | openai | ollama
ANTHROPIC_API_KEY=
OPENAI_API_KEY=
OLLAMA_ENDPOINT=http://localhost:11434
OLLAMA_MODEL=llama3
AI_MODEL=claude-sonnet-4-20250514
AI_MAX_TOKENS=4000
ENABLE_AI_CORRELATION=true
ENABLE_AI_REPORTS=true

# ── Application Settings ──
LOG_LEVEL=INFO
LOG_FORMAT=json                        # json | text
DATA_DIR=./data
DATA_RETENTION_DAYS=90
MAX_CONCURRENT_MODULES=10
MAX_CONCURRENT_BROWSERS=3
REQUEST_TIMEOUT_SECONDS=30
RESPECT_ROBOTS_TXT=true
AUDIT_LOG_ENABLED=true
CONSENT_REQUIRED=true
```

### 1.4 Create `config.yaml`

```yaml
# Module configuration — override .env defaults
modules:
  email:
    validator: { enabled: true }
    breach_checker: { enabled: true, providers: [hibp, dehashed, intelx] }
    hunter: { enabled: true }
    reputation: { enabled: true }
    permutator: { enabled: true }

  username:
    sherlock: { enabled: true, timeout: 120 }
    maigret: { enabled: false }  # Slower but more thorough
    social_checker: { enabled: true }
    permutator: { enabled: true }

  phone:
    validator: { enabled: true }
    lookup: { enabled: true, providers: [numverify] }
    voip_detector: { enabled: true }

  web:
    google_cse: { enabled: true, max_results: 20 }
    bing: { enabled: true, max_results: 20 }
    duckduckgo: { enabled: true, max_results: 20 }
    wayback: { enabled: true, max_snapshots: 10 }
    google_dorker: { enabled: true, max_queries: 10 }

  social:
    github: { enabled: true }
    reddit: { enabled: true }
    twitter: { enabled: true }
    linkedin: { enabled: true, require_auth: true }
    instagram: { enabled: true, require_auth: true, max_posts: 50 }
    facebook: { enabled: true, require_auth: true }
    tiktok: { enabled: false }
    youtube: { enabled: true }
    medium: { enabled: true }

  domain:
    whois: { enabled: true }
    dns: { enabled: true }
    subdomains: { enabled: true }
    certificates: { enabled: true }
    tech_stack: { enabled: true }

  network:
    ip_lookup: { enabled: true }
    shodan: { enabled: true }
    censys: { enabled: false }
    geolocation: { enabled: true }

  visual:
    face_recognition: { enabled: true, similarity_threshold: 0.6 }
    reverse_image: { enabled: true, engines: [google, tineye, yandex] }
    exif: { enabled: true }
    downloader: { enabled: true, max_images: 100 }

  breach:
    hibp: { enabled: true }
    dehashed: { enabled: true }
    intelx: { enabled: true }
    paste_monitor: { enabled: true }

  business:
    opencorporates: { enabled: true }
    clearbit: { enabled: false }
    professional: { enabled: false }

# Stealth settings
stealth:
  user_agent_rotation: true
  random_delays:
    min_ms: 1000
    max_ms: 5000
  headless: false  # Some sites detect headless mode
  disable_webrtc: true
  randomize_canvas: true
  randomize_webgl: true

# Output settings
output:
  formats: [json, markdown, html]
  include_raw_data: true
  include_screenshots: true
  redact_sensitive: false

# AI settings (supplements .env)
ai:
  auto_generate_report: true
  correlation_analysis: true
  risk_scoring: true
  summarization: true
```

---

## STEP 2: Core Layer

### 2.1 `app/core/config.py`

```python
"""
Centralized configuration management.
Loads from .env file and config.yaml, validates all settings.
"""
from pathlib import Path
from pydantic import SecretStr, field_validator
from pydantic_settings import BaseSettings
import yaml

class Settings(BaseSettings):
    """Application settings loaded from environment variables."""
    
    # Infrastructure
    neo4j_uri: str = "bolt://localhost:7687"
    neo4j_user: str = "neo4j"
    neo4j_password: SecretStr = SecretStr("password")
    redis_url: str = "redis://localhost:6379"
    
    # API Keys (all optional — modules check availability at runtime)
    hibp_api_key: SecretStr | None = None
    hunter_io_api_key: SecretStr | None = None
    dehashed_api_key: SecretStr | None = None
    google_cse_api_key: SecretStr | None = None
    google_cse_engine_id: str | None = None
    shodan_api_key: SecretStr | None = None
    github_token: SecretStr | None = None
    twitter_bearer_token: SecretStr | None = None
    # ... all other keys follow same pattern
    
    # Application
    log_level: str = "INFO"
    data_dir: Path = Path("./data")
    max_concurrent_modules: int = 10
    max_concurrent_browsers: int = 3
    request_timeout_seconds: int = 30
    respect_robots_txt: bool = True
    audit_log_enabled: bool = True
    consent_required: bool = True
    
    # AI
    ai_provider: str = "anthropic"  # anthropic | openai | ollama
    ai_model: str = "claude-sonnet-4-20250514"
    ai_max_tokens: int = 4000
    enable_ai_correlation: bool = True
    enable_ai_reports: bool = True
    
    # Proxy
    use_proxy: bool = False
    proxy_list_file: str = "proxies.txt"
    tor_enabled: bool = False

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8"}

    @classmethod
    def load_module_config(cls) -> dict:
        """Load config.yaml for module-specific settings."""
        config_path = Path("config.yaml")
        if config_path.exists():
            with open(config_path) as f:
                return yaml.safe_load(f)
        return {}

settings = Settings()
module_config = Settings.load_module_config()
```

### 2.2 `app/core/exceptions.py`

```python
"""Custom exception hierarchy. Catch specific exceptions for retry logic."""

class GodEyeError(Exception):
    """Base exception for all GOD_EYE errors."""
    pass

class ModuleError(GodEyeError):
    """A module failed during execution."""
    def __init__(self, module_name: str, message: str):
        self.module_name = module_name
        super().__init__(f"[{module_name}] {message}")

class APIError(GodEyeError):
    """An external API returned an error."""
    def __init__(self, api_name: str, status_code: int, message: str):
        self.api_name = api_name
        self.status_code = status_code
        super().__init__(f"[{api_name}] HTTP {status_code}: {message}")

class RateLimitError(APIError):
    """Rate limit exceeded. Should trigger backoff/retry."""
    def __init__(self, api_name: str, retry_after: int | None = None):
        self.retry_after = retry_after
        super().__init__(api_name, 429, f"Rate limited. Retry after: {retry_after}s")

class AuthenticationError(GodEyeError):
    """Authentication failed (bad credentials, expired token)."""
    pass

class BrowserError(GodEyeError):
    """Browser automation error (page load, element not found, CAPTCHA)."""
    pass

class ValidationError(GodEyeError):
    """Input validation failed."""
    pass

class CacheError(GodEyeError):
    """Cache read/write failed. Non-fatal — continue without cache."""
    pass
```

### 2.3 `app/core/logging.py`

```python
"""Structured logging setup with structlog."""
import structlog
from app.core.config import settings

def setup_logging() -> None:
    """Configure structured logging. Call once at startup."""
    processors = [
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
    ]
    
    if settings.log_format == "json":
        processors.append(structlog.processors.JSONRenderer())
    else:
        processors.append(structlog.dev.ConsoleRenderer())

    structlog.configure(
        processors=processors,
        wrapper_class=structlog.make_filtering_bound_logger(
            getattr(structlog, settings.log_level.upper(), structlog.INFO)
        ),
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )

def get_logger(name: str) -> structlog.BoundLogger:
    """Get a logger bound with the given name."""
    return structlog.get_logger(name)
```

### 2.4 `app/core/constants.py`

```python
"""Enums and constants used throughout the application."""
from enum import Enum

class TargetType(str, Enum):
    PERSON = "person"
    EMAIL = "email"
    USERNAME = "username"
    PHONE = "phone"
    DOMAIN = "domain"
    IP = "ip"
    COMPANY = "company"

class ScanStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"

class RiskLevel(str, Enum):
    LOW = "low"           # 1-3
    MEDIUM = "medium"     # 4-6
    HIGH = "high"         # 7-8
    CRITICAL = "critical" # 9-10

class ModulePhase(int, Enum):
    FAST_API = 1          # No auth, quick API calls
    BREACH_DB = 2         # Breach database lookups
    SEARCH_ENGINE = 3     # Web search queries
    BROWSER_AUTH = 4      # Browser automation with login
    IMAGE_PROCESSING = 5  # Image download and analysis
    DEEP_ANALYSIS = 6     # Infrastructure recon
    AI_CORRELATION = 7    # AI-powered analysis
    REPORT_GEN = 8        # Final report generation
```

---

## STEP 3: Database Layer

### 3.1 `app/database/neo4j_client.py`

Implement an async Neo4j client with these operations:

```python
"""
Async Neo4j client for graph operations.

Must implement:
- connect() / disconnect()
- create_person(name, metadata) -> node_id
- create_username(handle, platform) -> node_id
- create_email(address, is_breached) -> node_id
- create_image(hash, file_path, has_faces) -> node_id
- create_location(lat, long, address) -> node_id
- create_ip(address, isp) -> node_id
- link_nodes(from_id, to_id, relationship_type, properties)
- query_target_graph(target_name) -> full graph dict
- query_connections(node_id, depth=2) -> connected nodes

All operations use async neo4j driver.
All Cypher queries use parameterized queries (never string interpolation).
"""
```

### 3.2 `app/database/sqlite_cache.py`

```python
"""
SQLite cache for deduplication and rate limit tracking.

Tables:
- api_cache: key (str PK), value (json), created_at, expires_at
- rate_limits: domain (str PK), requests_count (int), window_start (datetime)
- scan_history: request_id (str PK), target, status, started_at, completed_at

Must implement:
- get(key) -> value or None
- set(key, value, ttl_seconds=3600)
- has_fresh_result(key, max_age_seconds) -> bool
- increment_rate_counter(domain) -> current_count
- save_scan(request_id, metadata)
- list_scans(limit=20) -> list
"""
```

---

## STEP 4: Engine Layer

### 4.1 `app/engine/browser.py` — BrowserFactory

```python
"""
Playwright browser factory with anti-fingerprinting.

Implementation requirements:
1. Singleton pattern (one browser process)
2. Context pool (reuse contexts for same platform)
3. Stealth injection:
   - Override navigator.webdriver to false
   - Randomize canvas fingerprint
   - Randomize WebGL vendor/renderer strings  
   - Disable WebRTC (prevents IP leak)
   - Set realistic viewport (1920x1080 ± random offset)
   - Set realistic language headers
4. User-Agent rotation from curated list of modern browsers
5. Proxy injection per-context
6. Cookie persistence: save/load storage state per platform
   - data/sessions/linkedin_state.json
   - data/sessions/instagram_state.json
7. Human behavior simulation:
   - Random mouse movements before clicks
   - Typing with random inter-key delay (50-150ms)
   - Random scroll patterns
   - Random delays between actions (1-5s)
8. Screenshot on error for debugging

Usage:
    factory = await BrowserFactory.create()
    page = await factory.new_page(
        proxy="http://user:pass@proxy:8080",
        persist_session="linkedin"
    )
    await page.goto("https://linkedin.com")
    await factory.human_click(page, selector="button.login")
    await factory.human_type(page, selector="input#email", text="user@example.com")
"""
```

### 4.2 `app/engine/proxy.py` — ProxyRotator

```python
"""
Proxy rotation manager.

Implementation requirements:
1. Load proxies from:
   - PROXY_LIST_FILE (one per line: protocol://user:pass@host:port)
   - Environment variable (single proxy)
   - TOR SOCKS proxy
2. Health check: test each proxy on startup, remove dead ones
3. Rotation strategies:
   - round_robin: cycle through list
   - random: pick random proxy
   - least_used: track usage count per proxy
4. Automatic failover: if proxy fails, mark as unhealthy, try next
5. TOR support: new identity via control port for circuit rotation
6. Metrics: track success rate, latency, ban rate per proxy
"""
```

### 4.3 `app/engine/orchestrator.py` — Main Workflow

```python
"""
Main scan orchestrator. Manages the entire scan lifecycle.

Implementation requirements:
1. Accept scan parameters (target, target_type, options)
2. Generate unique request_id: req_{YYYYMMDD}_{HHMMSS}_{target_hash}
3. Create data directory: data/requests/{request_id}/
4. Save metadata.json with scan parameters
5. Discover available modules via module registry
6. Filter modules by:
   - Target type compatibility
   - Enabled status in config.yaml
   - API key availability
7. Group modules by phase (see ModulePhase enum)
8. Execute phases sequentially:
   - Within each phase, run all modules in parallel (asyncio.gather)
   - Collect ModuleResult from each module
   - Save each result to raw_data/{module_name}.json
   - Create Neo4j nodes from results
   - Update progress (Rich progress bar)
   - Pass accumulated context to next phase
9. After all phases:
   - Run AI correlation (if enabled)
   - Generate reports (if enabled)
   - Update metadata.json with final status
10. Handle interrupts gracefully (Ctrl+C pauses, second Ctrl+C stops)

The context dict passed between phases:
{
    "request_id": "req_...",
    "target": "...",
    "target_type": "person",
    "discovered_emails": ["a@b.com"],
    "discovered_usernames": ["user123"],
    "discovered_domains": ["example.com"],
    "discovered_ips": ["1.2.3.4"],
    "discovered_images": ["/path/to/img.jpg"],
    "discovered_names": ["John Doe"],
    "module_results": {"module_name": ModuleResult, ...},
}
```

---

## STEP 5: Module Implementation

### Pattern for Every Module

Every module follows this exact pattern:

```python
# app/modules/{category}/{module_name}.py

import aiohttp
import structlog
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type

from app.modules.base import BaseModule, ModuleMetadata, ModuleResult
from app.core.constants import TargetType, ModulePhase
from app.core.config import settings
from app.core.exceptions import APIError, RateLimitError

logger = structlog.get_logger(__name__)

class ExampleModule(BaseModule):
    """Docstring explaining what this module does."""

    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            name="example_module",
            display_name="Example Module",
            description="Does X by querying Y API",
            supported_targets=[TargetType.EMAIL, TargetType.USERNAME],
            requires_auth=False,
            requires_proxy=False,
            requires_browser=False,
            rate_limit_rpm=60,
            timeout_seconds=30,
            priority=1,
            phase=ModulePhase.FAST_API,
            enabled_by_default=True,
        )

    async def validate(self, target: str, target_type: TargetType) -> bool:
        """Validate target format."""
        if target_type == TargetType.EMAIL:
            return "@" in target and "." in target.split("@")[1]
        return bool(target.strip())

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=30),
        retry=retry_if_exception_type((aiohttp.ClientError, RateLimitError)),
        before_sleep=lambda retry_state: logger.warning(
            "retrying", attempt=retry_state.attempt_number
        ),
    )
    async def run(self, target: str, target_type: TargetType, context: dict) -> ModuleResult:
        """Execute the module."""
        import time
        start = time.monotonic()
        
        try:
            # 1. Check if API key is available
            api_key = settings.example_api_key
            if not api_key:
                return ModuleResult(
                    module_name=self.metadata().name,
                    target=target,
                    success=False,
                    errors=["API key not configured"],
                )
            
            # 2. Make async API call
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"https://api.example.com/v1/search",
                    params={"q": target},
                    headers={"Authorization": f"Bearer {api_key.get_secret_value()}"},
                    timeout=aiohttp.ClientTimeout(total=self.metadata().timeout_seconds),
                ) as resp:
                    if resp.status == 429:
                        raise RateLimitError("example_api", retry_after=int(resp.headers.get("Retry-After", 60)))
                    if resp.status != 200:
                        raise APIError("example_api", resp.status, await resp.text())
                    data = await resp.json()
            
            # 3. Parse and structure the response
            findings = self._parse_response(data)
            
            # 4. Return structured result
            elapsed = int((time.monotonic() - start) * 1000)
            return ModuleResult(
                module_name=self.metadata().name,
                target=target,
                success=True,
                data=findings,
                execution_time_ms=elapsed,
            )
            
        except (APIError, RateLimitError):
            raise  # Let tenacity handle retries
        except Exception as e:
            logger.error("module_failed", module=self.metadata().name, error=str(e))
            elapsed = int((time.monotonic() - start) * 1000)
            return ModuleResult(
                module_name=self.metadata().name,
                target=target,
                success=False,
                errors=[str(e)],
                execution_time_ms=elapsed,
            )

    def _parse_response(self, data: dict) -> dict:
        """Parse raw API response into structured findings."""
        # Module-specific parsing logic
        return data
```

### Implementation Order for Modules

Build modules in this exact order (each builds on patterns from the previous):

1. `modules/email/validator.py` — Pure logic, no API calls (validates email format + MX records via dnspython)
2. `modules/breach/hibp.py` — Simple REST API pattern (GET with API key header)
3. `modules/username/social_checker.py` — Multiple API calls in parallel (GitHub, Reddit)
4. `modules/web/google_cse.py` — Paginated API results
5. `modules/web/duckduckgo.py` — No-auth API call
6. `modules/domain/dns_recon.py` — DNS library usage (dnspython)
7. `modules/domain/certificate_search.py` — crt.sh free API
8. `modules/network/ip_lookup.py` — Multiple providers with fallback
9. `modules/social/github_api.py` — OAuth token, pagination, nested resources
10. `modules/social/reddit_api.py` — OAuth flow, rate limiting
11. `modules/username/sherlock_wrapper.py` — Wrapping external CLI tool
12. `modules/social/linkedin_scraper.py` — Full Playwright browser automation with login
13. `modules/social/instagram_scraper.py` — Playwright with login + scrolling
14. `modules/visual/exif_extractor.py` — Image file processing
15. `modules/visual/reverse_image.py` — Browser-based reverse image search
16. `modules/visual/face_recognition.py` — InsightFace ML model
17. `modules/breach/dehashed.py` — Paid API with auth
18. `modules/web/wayback.py` — Wayback Machine API
19. `modules/network/shodan_search.py` — Shodan API
20. `modules/business/opencorporates.py` — Business registry API

---

## STEP 6: AI Layer

### 6.1 `app/ai/correlation_engine.py`

```python
"""
Cross-references all module outputs to find patterns and connections.

Implementation:
1. Load all raw_data/*.json files for a scan
2. Extract entities: emails, usernames, names, locations, dates, IPs
3. Build an entity map: which modules found which entities
4. Find connections:
   - Same email across multiple platforms
   - Username patterns (john, john123, john_doe, johndoe)
   - Location consistency (all geolocated to same city)
   - Temporal patterns (account creation dates)
   - Network patterns (follows/followers overlap)
5. Score each connection with confidence (0.0-1.0)
6. Output: correlation.json with all discovered connections
"""
```

### 6.2 `app/ai/risk_scorer.py`

```python
"""
Calculates a privacy risk score (1-10) based on data exposure.

Scoring factors:
- Number of platforms with public profiles (+1 per 5 platforms, max +3)
- Email in breach databases (+2 per breach, max +4)
- Passwords found in breaches (+3)
- Public personal information (phone, address, employer) (+1 each)
- Facial recognition matches on unexpected platforms (+2)
- EXIF data with GPS in public images (+2)
- Domain registration with personal info (no WHOIS privacy) (+1)
- Public code repos with sensitive data (API keys, passwords) (+3)
- Social media privacy settings (public vs private) (+1 per public)

Output:
{
    "score": 8.5,
    "level": "high",
    "breakdown": {
        "breach_exposure": 4,
        "social_exposure": 2,
        "data_leakage": 1.5,
        "identity_exposure": 1
    },
    "top_risks": [
        "Email found in 3 data breaches including passwords",
        "Home address visible in Instagram photo EXIF data",
        "GitHub repo contains AWS access key"
    ],
    "recommendations": [
        "Change passwords for all breached accounts",
        "Enable 2FA on all platforms",
        "Strip EXIF data from photos before posting"
    ]
}
```

### 6.3 `app/ai/report_generator.py`

```python
"""
Generates human-readable reports using LLM.

Supports three providers:
1. Anthropic Claude (preferred): uses anthropic SDK
2. OpenAI GPT: uses openai SDK  
3. Ollama (self-hosted): uses HTTP API to localhost

The LLM receives:
- Structured JSON of all findings
- Correlation analysis results
- Risk score breakdown

And generates:
- Executive summary (2-3 paragraphs)
- Key findings (organized by category)
- Risk assessment with justification
- Data exposure analysis
- Actionable recommendations

Reports are rendered via Jinja2 templates into:
- Markdown (.md)
- HTML (.html) with embedded CSS
- PDF (.pdf) via weasyprint
- JSON (.json) structured data
"""
```

---

## STEP 7: CLI Layer

### 7.1 `app/cli.py`

```python
"""
Typer CLI application with Rich UI.

Commands to implement:
- scan: Main scan command with all target options
- interactive: Launch interactive shell
- resume: Resume a paused/failed scan
- list: List all previous scans
- view: View a specific scan's results
- report: Generate report from existing scan data
- settings: View/modify configuration
- modules: List/enable/disable modules
- cache: View stats / clear cache
- export: Export scan data
- monitor: Start monitoring mode
- setup: First-time configuration wizard
- health-check: Verify all services are running

Every command must:
- Use Rich console for output (tables, panels, progress bars)
- Handle KeyboardInterrupt gracefully
- Log all actions to audit log
- Validate all inputs before proceeding
"""
```

---

## STEP 8: Testing

### Test every module with:

```python
# tests/test_modules/test_email.py
import pytest
from unittest.mock import AsyncMock, patch
from app.modules.email.validator import EmailValidator
from app.core.constants import TargetType

@pytest.mark.asyncio
async def test_email_validator_valid():
    module = EmailValidator()
    assert await module.validate("user@example.com", TargetType.EMAIL) is True

@pytest.mark.asyncio
async def test_email_validator_invalid():
    module = EmailValidator()
    assert await module.validate("not-an-email", TargetType.EMAIL) is False

@pytest.mark.asyncio
async def test_email_validator_run():
    module = EmailValidator()
    result = await module.run("user@example.com", TargetType.EMAIL, {})
    assert result.success is True
    assert "is_valid" in result.data

# Mock external API calls
@pytest.mark.asyncio
@patch("aiohttp.ClientSession.get")
async def test_hibp_breach_check(mock_get):
    mock_get.return_value.__aenter__.return_value.status = 200
    mock_get.return_value.__aenter__.return_value.json = AsyncMock(
        return_value=[{"Name": "TestBreach", "BreachDate": "2023-01-01"}]
    )
    # ... test module
```

---

## Build Order Summary

| Step | What to Build | Depends On |
|------|--------------|------------|
| 1 | Project skeleton, pyproject.toml, docker-compose, .env | Nothing |
| 2 | core/config.py, core/exceptions.py, core/logging.py, core/constants.py | Step 1 |
| 3 | database/neo4j_client.py, database/sqlite_cache.py, database/redis_client.py | Step 2 |
| 4 | engine/browser.py, engine/proxy.py, engine/rate_limiter.py, engine/session.py | Step 2 |
| 5 | engine/orchestrator.py | Steps 3 + 4 |
| 6 | modules/base.py + module registry | Step 2 |
| 7 | All modules (in order listed above) | Steps 5 + 6 |
| 8 | ai/correlation_engine.py, ai/risk_scorer.py, ai/report_generator.py | Step 7 |
| 9 | cli.py (all commands) | Steps 5 + 8 |
| 10 | main.py (FastAPI routes) | Steps 5 + 8 |
| 11 | Tests for everything | All steps |
| 12 | Dockerfile, deployment configs | Step 11 |
