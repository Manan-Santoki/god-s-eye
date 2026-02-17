# ARCHITECTURE.md — System Architecture

## 1. High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                     USER INTERFACE LAYER                            │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────────┐  │
│  │  Typer CLI   │  │  FastAPI     │  │  Interactive Shell       │  │
│  │  (commands)  │  │  (REST API)  │  │  (prompt_toolkit + Rich) │  │
│  └──────┬───────┘  └──────┬───────┘  └────────────┬─────────────┘  │
└─────────┼──────────────────┼──────────────────────┼────────────────┘
          │                  │                      │
          └──────────────────┼──────────────────────┘
                             ▼
┌─────────────────────────────────────────────────────────────────────┐
│                     ORCHESTRATOR ENGINE                             │
│  ┌────────────────┐  ┌───────────────┐  ┌───────────────────────┐  │
│  │ Task Scheduler │  │ Progress Mgr  │  │ Error Recovery        │  │
│  │ (Redis Queue)  │  │ (Rich Live)   │  │ (retry + fallback)    │  │
│  └────────┬───────┘  └───────────────┘  └───────────────────────┘  │
└───────────┼────────────────────────────────────────────────────────┘
            │
    ┌───────┴───────┬──────────────┬──────────────┬──────────────┐
    ▼               ▼              ▼              ▼              ▼
┌─────────┐  ┌───────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐
│   API   │  │  Browser  │  │ Storage  │  │    AI    │  │  Proxy   │
│ Modules │  │  Automtn  │  │ Manager  │  │  Engine  │  │ Rotator  │
│ (REST)  │  │(Playwright)│ │(Neo4j/   │  │(Reports/ │  │(TOR/     │
│         │  │           │  │ SQLite)  │  │ Correltn)│  │ Rotating)│
└─────────┘  └───────────┘  └──────────┘  └──────────┘  └──────────┘
```

---

## 2. Complete Directory Structure

Every file is listed below with its purpose. AI agents MUST create this exact structure.

```
god_eye/
│
├── .env.example                        # Template for all secrets and config
├── .gitignore                          # Standard Python + data/ exclusions
├── docker-compose.yml                  # Neo4j + Redis + App orchestration
├── Dockerfile                          # App container definition
├── pyproject.toml                      # Poetry/pip dependencies + metadata
├── LICENSE                             # MIT License
├── README.md                           # Project overview
│
├── app/
│   ├── __init__.py                     # Package init, version string
│   ├── main.py                         # FastAPI app factory + routes
│   ├── cli.py                          # Typer CLI: all commands defined here
│   │
│   ├── core/
│   │   ├── __init__.py
│   │   ├── config.py                   # Pydantic BaseSettings: loads .env + config.yaml
│   │   ├── logging.py                  # Structured JSON logging with structlog
│   │   ├── exceptions.py              # Custom exceptions: ModuleError, APIError, AuthError, RateLimitError
│   │   └── constants.py               # Enums: TargetType, ModuleName, ScanStatus, RiskLevel
│   │
│   ├── database/
│   │   ├── __init__.py
│   │   ├── neo4j_client.py            # Async Neo4j driver wrapper: create/query nodes+relationships
│   │   ├── redis_client.py            # Async Redis: job queue, pub/sub, caching
│   │   ├── sqlite_cache.py            # aiosqlite: request cache, dedup, rate limit tracking
│   │   └── models.py                  # Pydantic models for all DB entities
│   │
│   ├── engine/
│   │   ├── __init__.py
│   │   ├── orchestrator.py            # Main workflow: schedules modules, tracks progress, handles phases
│   │   ├── browser.py                 # BrowserFactory singleton: Playwright + stealth + context pool
│   │   ├── proxy.py                   # ProxyRotator: manages proxy list, health checks, rotation
│   │   ├── rate_limiter.py            # Token bucket rate limiter per domain/API
│   │   └── session.py                 # ScanSession: tracks request_id, state, timing
│   │
│   ├── modules/
│   │   ├── __init__.py                # Module registry: auto-discovers all modules
│   │   ├── base.py                    # BaseModule ABC: run(), validate(), metadata
│   │   │
│   │   ├── email/
│   │   │   ├── __init__.py
│   │   │   ├── validator.py           # Email format validation (regex + DNS MX check)
│   │   │   ├── breach_checker.py      # HIBP, DeHashed, LeakCheck, IntelX
│   │   │   ├── hunter.py             # Hunter.io: find associated emails, verify deliverability
│   │   │   ├── reputation.py         # EmailRep.io: reputation scoring
│   │   │   └── permutator.py         # Generate email permutations from name patterns
│   │   │
│   │   ├── username/
│   │   │   ├── __init__.py
│   │   │   ├── sherlock_wrapper.py    # Wraps sherlock-project CLI, parses output
│   │   │   ├── maigret_wrapper.py     # Wraps maigret for deeper username search
│   │   │   ├── social_checker.py      # Direct API checks: GitHub, Reddit, Twitter, etc.
│   │   │   └── permutator.py         # Generate username variations from known data
│   │   │
│   │   ├── phone/
│   │   │   ├── __init__.py
│   │   │   ├── validator.py           # libphonenumber: format, country, carrier type
│   │   │   ├── lookup.py             # Numverify, Twilio Lookup, Abstract API
│   │   │   └── voip_detector.py      # Detect VoIP vs landline vs mobile
│   │   │
│   │   ├── web/
│   │   │   ├── __init__.py
│   │   │   ├── google_cse.py         # Google Custom Search Engine API
│   │   │   ├── bing_search.py        # Bing Web Search API
│   │   │   ├── duckduckgo.py         # DuckDuckGo Instant Answer (no key needed)
│   │   │   ├── wayback.py            # Wayback Machine API: historical snapshots
│   │   │   └── google_dorker.py      # Automated Google dork queries
│   │   │
│   │   ├── social/
│   │   │   ├── __init__.py
│   │   │   ├── github_api.py         # GitHub REST API: profile, repos, commits, gists
│   │   │   ├── reddit_api.py         # Reddit OAuth API: posts, comments, karma
│   │   │   ├── twitter_api.py        # Twitter/X API v2: tweets, followers, profile
│   │   │   ├── linkedin_scraper.py   # Playwright-based: profile, posts, experience
│   │   │   ├── instagram_scraper.py  # Playwright-based: posts, stories, followers
│   │   │   ├── facebook_scraper.py   # Playwright-based: profile, posts, friends
│   │   │   ├── tiktok_scraper.py     # Playwright-based: profile, videos
│   │   │   ├── youtube_api.py        # YouTube Data API: channels, videos, comments
│   │   │   └── medium_scraper.py     # Medium: articles, claps, followers
│   │   │
│   │   ├── domain/
│   │   │   ├── __init__.py
│   │   │   ├── whois_lookup.py       # WhoisXML API + python-whois fallback
│   │   │   ├── dns_recon.py          # dnspython: A, AAAA, MX, TXT, SPF, DMARC, NS
│   │   │   ├── subdomain_enum.py     # SecurityTrails API + crt.sh + brute-force
│   │   │   ├── certificate_search.py # crt.sh certificate transparency logs
│   │   │   └── tech_stack.py         # Wappalyzer-style tech detection via headers
│   │   │
│   │   ├── network/
│   │   │   ├── __init__.py
│   │   │   ├── ip_lookup.py          # IPinfo.io, AbuseIPDB, MaxMind GeoLite2
│   │   │   ├── shodan_search.py      # Shodan API: open ports, services, vulns
│   │   │   ├── censys_search.py      # Censys API: certificates, hosts
│   │   │   └── geolocation.py        # IP to lat/long/city/country
│   │   │
│   │   ├── visual/
│   │   │   ├── __init__.py
│   │   │   ├── face_recognition.py   # InsightFace: detect, embed, compare faces
│   │   │   ├── reverse_image.py      # Google Images, TinEye, Yandex reverse search
│   │   │   ├── exif_extractor.py     # Extract EXIF/GPS metadata from images
│   │   │   └── image_downloader.py   # Async image download + dedup by hash
│   │   │
│   │   ├── breach/
│   │   │   ├── __init__.py
│   │   │   ├── hibp.py               # Have I Been Pwned API v3
│   │   │   ├── dehashed.py           # DeHashed API
│   │   │   ├── intelx.py            # Intelligence X API
│   │   │   └── paste_monitor.py      # Pastebin dump monitoring
│   │   │
│   │   └── business/
│   │       ├── __init__.py
│   │       ├── opencorporates.py     # OpenCorporates company search
│   │       ├── clearbit.py           # Clearbit company/person enrichment
│   │       └── professional.py       # Professional license databases
│   │
│   ├── ai/
│   │   ├── __init__.py
│   │   ├── report_generator.py       # LLM-powered report writing (Claude/GPT/Ollama)
│   │   ├── correlation_engine.py     # Cross-reference data, find patterns
│   │   ├── risk_scorer.py            # Calculate privacy risk score (1-10)
│   │   ├── timeline_builder.py       # Build chronological event timeline
│   │   └── prompts.py               # All LLM prompt templates
│   │
│   └── utils/
│       ├── __init__.py
│       ├── validators.py             # Input validation: email, phone, domain, IP, username
│       ├── exporters.py              # Export to JSON, Markdown, HTML, PDF, CSV
│       ├── image_processing.py       # Hash, crop, resize, format conversion
│       ├── text_analysis.py          # Regex patterns, entity extraction
│       └── fingerprint.py            # Browser fingerprint randomization helpers
│
├── tests/
│   ├── __init__.py
│   ├── conftest.py                   # Pytest fixtures: mock APIs, test DB
│   ├── test_modules/
│   │   ├── test_email.py
│   │   ├── test_username.py
│   │   ├── test_phone.py
│   │   └── test_web.py
│   ├── test_engine/
│   │   ├── test_orchestrator.py
│   │   ├── test_browser.py
│   │   └── test_proxy.py
│   └── test_ai/
│       ├── test_correlation.py
│       └── test_report.py
│
├── data/
│   ├── requests/                     # All scan outputs (by request_id)
│   │   └── {request_id}/
│   │       ├── metadata.json         # Scan metadata + status
│   │       ├── raw_data/             # Per-module JSON outputs
│   │       ├── images/               # Downloaded images
│   │       ├── screenshots/          # Browser screenshots
│   │       ├── correlation/          # AI analysis results
│   │       └── reports/              # Final exports
│   │
│   ├── cache/
│   │   └── osint_cache.db           # SQLite cache
│   │
│   ├── logs/
│   │   ├── app.log                  # Application log
│   │   └── audit.log               # Audit trail (who searched what)
│   │
│   └── templates/
│       ├── report.md.jinja2         # Markdown report template
│       ├── report.html.jinja2       # HTML dashboard template
│       └── executive_summary.jinja2 # Short summary template
│
└── scripts/
    ├── setup_apis.py               # Interactive API key configuration wizard
    ├── health_check.py             # Verify all services are running
    └── seed_test_data.py           # Create test data for development
```

---

## 3. Design Patterns

### 3.1 BaseModule Pattern (Plugin Architecture)

Every intelligence module inherits from `BaseModule`. This allows the orchestrator to discover, validate, and run modules uniformly.

```python
# app/modules/base.py
from abc import ABC, abstractmethod
from typing import Any
from pydantic import BaseModel
from enum import Enum

class TargetType(str, Enum):
    PERSON = "person"
    EMAIL = "email"
    USERNAME = "username"
    PHONE = "phone"
    DOMAIN = "domain"
    IP = "ip"
    COMPANY = "company"

class ModuleMetadata(BaseModel):
    name: str                              # Unique module name e.g. "hibp_breach_check"
    display_name: str                      # Human-readable e.g. "Have I Been Pwned"
    description: str                       # What this module does
    supported_targets: list[TargetType]    # Which target types this module accepts
    requires_auth: bool = False            # Does it need stored credentials?
    requires_proxy: bool = False           # Should it use proxy rotation?
    requires_browser: bool = False         # Does it need Playwright?
    rate_limit_rpm: int = 60               # Max requests per minute
    timeout_seconds: int = 30              # Per-request timeout
    priority: int = 1                      # Execution priority (1=highest)
    enabled_by_default: bool = True        # Is it on by default?

class ModuleResult(BaseModel):
    module_name: str
    target: str
    success: bool
    data: dict[str, Any] = {}
    errors: list[str] = []
    execution_time_ms: int = 0
    confidence_score: float = 1.0          # 0.0-1.0 how reliable is this data

class BaseModule(ABC):
    """All intelligence modules MUST inherit from this class."""

    @abstractmethod
    def metadata(self) -> ModuleMetadata:
        """Return module metadata. Called by orchestrator for discovery."""
        ...

    @abstractmethod
    async def validate(self, target: str, target_type: TargetType) -> bool:
        """Validate that the target format is correct for this module."""
        ...

    @abstractmethod
    async def run(self, target: str, target_type: TargetType, context: dict) -> ModuleResult:
        """
        Execute the module's intelligence gathering.
        
        Args:
            target: The search target string
            target_type: What kind of target this is
            context: Shared context dict with data from other modules
            
        Returns:
            ModuleResult with gathered data
        """
        ...

    async def cleanup(self) -> None:
        """Optional: cleanup resources after run."""
        pass
```

### 3.2 BrowserFactory (Singleton + Context Pool)

One browser instance, multiple stealth contexts.

```python
# app/engine/browser.py — Conceptual Design
class BrowserFactory:
    """
    Singleton that manages Playwright browser lifecycle.
    
    Features:
    - Creates browser once, reuses across modules
    - Each module gets its own BrowserContext (isolated cookies, storage)
    - Injects stealth scripts (playwright-stealth or camoufox)
    - Rotates user agents per context
    - Supports proxy injection per context
    - Persists cookies to disk for session reuse (e.g., LinkedIn login)
    
    Usage:
        factory = BrowserFactory.get_instance()
        page = await factory.new_page(proxy=proxy_url, persist_session="linkedin")
        # ... use page ...
        await page.close()
    """
    _instance = None

    @classmethod
    def get_instance(cls) -> "BrowserFactory":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    async def new_page(
        self,
        proxy: str | None = None,
        user_agent: str | None = None,
        persist_session: str | None = None,
        headless: bool = True,
    ) -> Page:
        """Create a new stealth page with anti-fingerprinting."""
        ...
```

### 3.3 Orchestrator (Phase-Based Execution)

The orchestrator runs modules in dependency-ordered phases:

```
Phase 1 (Fast, No Auth)     → Email validation, username format, DNS, GitHub/Reddit APIs
Phase 2 (Breach DBs)        → HIBP, DeHashed, IntelX, paste sites
Phase 3 (Search Engines)    → Google CSE, Bing, DuckDuckGo, Wayback
Phase 4 (Browser + Auth)    → LinkedIn, Instagram, Facebook, TikTok (Playwright)
Phase 5 (Image Processing)  → Download images, reverse search, EXIF, face recognition
Phase 6 (Deep Analysis)     → Subdomain enum, cert transparency, Shodan, Censys
Phase 7 (AI Correlation)    → Cross-reference, timeline, risk scoring
Phase 8 (Report Generation) → Generate exports in all formats
```

Each phase runs its modules in **parallel** (within the phase). Phases run **sequentially** because later phases depend on earlier results.

### 3.4 Error Handling Strategy

```
Error Occurs in Module
        │
        ▼
  ┌─ Is it retryable? (timeout, rate limit, network error)
  │     YES → Retry with exponential backoff (max 3 attempts)
  │              │
  │              ├─ Still failing? → Log error, mark module as FAILED
  │              │                    Continue with other modules
  │              └─ Success → Continue normally
  │
  └─ Is it permanent? (auth error, invalid target, API removed)
        YES → Log error, mark module as SKIPPED
               Continue with other modules

NEVER crash the application. Always continue the scan.
Every error is logged to both app.log and the ModuleResult.errors list.
```

### 3.5 Rate Limiting (Token Bucket)

```python
# Each external API gets its own rate limiter instance
# Configured via module metadata (rate_limit_rpm)
# Implemented as async token bucket:
#   - Tokens refill at (rate_limit_rpm / 60) per second
#   - Each request consumes 1 token
#   - If no tokens available, await until refilled
#   - Global fallback: max 100 requests/second across all modules
```

---

## 4. Data Flow

```
User Input (CLI/API/Interactive)
        │
        ▼
┌─── Input Validator ───┐
│  • Detect target type  │
│  • Normalize format    │
│  • Generate request_id │
└───────────┬────────────┘
            │
            ▼
┌─── Module Registry ───────────────────┐
│  • Filter modules by target_type      │
│  • Check enabled status (config.yaml) │
│  • Sort by phase + priority           │
│  • Check API key availability         │
└───────────┬───────────────────────────┘
            │
            ▼
┌─── Orchestrator ──────────────────────┐
│  For each phase:                      │
│    • Distribute modules to asyncio    │
│    • Each module:                     │
│      1. Check cache (skip if fresh)   │
│      2. Acquire rate limit token      │
│      3. Make API call / scrape page   │
│      4. Parse + validate response     │
│      5. Save to raw_data/{module}.json│
│      6. Create Neo4j nodes/edges      │
│      7. Return ModuleResult           │
│    • Collect all results              │
│    • Update progress bar              │
│    • Pass results as context to next  │
└───────────┬───────────────────────────┘
            │
            ▼
┌─── AI Correlation Engine ─────────────┐
│  • Load all raw_data/*.json           │
│  • Cross-reference findings           │
│  • Build relationship graph           │
│  • Generate timeline                  │
│  • Calculate risk score               │
└───────────┬───────────────────────────┘
            │
            ▼
┌─── Report Generator ─────────────────┐
│  • Render Jinja2 templates            │
│  • LLM executive summary             │
│  • Export: JSON, MD, HTML, PDF, CSV   │
│  • Save to reports/                   │
└───────────────────────────────────────┘
```

---

## 5. Concurrency Model

```python
# The app uses asyncio throughout. Key patterns:

# 1. Module execution: asyncio.gather() within each phase
results = await asyncio.gather(
    *[module.run(target, target_type, context) for module in phase_modules],
    return_exceptions=True  # Never let one failure kill the phase
)

# 2. Browser automation: Semaphore limits concurrent browser contexts
browser_semaphore = asyncio.Semaphore(3)  # Max 3 browser tabs at once

# 3. API calls: Per-domain rate limiters (see rate_limiter.py)
# 4. Redis queue: For distributed mode (multiple workers)
# 5. Neo4j writes: Batched with async driver (neo4j[async])
```

---

## 6. Security Architecture

```
┌─────────────────────────────────────────────┐
│              SECURITY LAYERS                 │
├─────────────────────────────────────────────┤
│                                             │
│  1. Secrets Management                      │
│     • .env file (never committed)           │
│     • Pydantic SecretStr for passwords      │
│     • Optional: HashiCorp Vault integration │
│                                             │
│  2. Network Stealth                         │
│     • Proxy rotation (residential/datacenter)│
│     • TOR integration (optional)            │
│     • User-Agent rotation                   │
│     • WebRTC disabled                       │
│     • Canvas/WebGL fingerprint randomized   │
│     • Human-like delays (1-5s random)       │
│                                             │
│  3. Data Protection                         │
│     • SQLite cache: optional AES encryption │
│     • Neo4j: auth required                  │
│     • Audit log: immutable, append-only     │
│     • Auto-cleanup after retention period   │
│                                             │
│  4. Legal Compliance                        │
│     • Consent banner on first run           │
│     • robots.txt respected (configurable)   │
│     • Rate limiting enforced                │
│     • Legal disclaimer in all reports       │
│     • Audit trail for all searches          │
│                                             │
└─────────────────────────────────────────────┘
```
