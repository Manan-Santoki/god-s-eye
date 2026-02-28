# GOD_EYE — Open Source OSINT Intelligence Platform

> A modular, self-hosted OSINT platform for digital footprint analysis, privacy auditing, and security research.
> Aggregates publicly available data from 50+ sources into a unified intelligence report.

**⚠ This tool must only be used with proper authorization. See [SECURITY_AND_ETHICS.md](./SECURITY_AND_ETHICS.md).**

---

## What It Does

GOD_EYE takes a target (email, username, person name, phone, domain, IP, or company) and:

1. Runs 50+ intelligence modules in parallel across 8 phases
2. Checks breach databases, social platforms, DNS, WHOIS, search engines, and images
3. Builds a Neo4j entity graph linking all discovered relationships
4. Scores risk level (0–10) using weighted signals
5. Generates HTML / PDF / Markdown / CSV / JSON reports via AI or template

---

## Architecture at a Glance

```
CLI (god-eye scan) / REST API (uvicorn app.main:app)
          │
          ▼
  Orchestrator — 8 parallel phases
          │
    ┌─────┴──────────────────────────────────────────────┐
    │  50+ Modules (email · username · social · domain · │
    │   network · breach · visual · business · web)      │
    └─────────────────────────────────────────────────────┘
          │
    ┌─────┴─────────────────┐
    │  Neo4j  │ Redis │ SQLite │
    └───────────────────────┘
          │
    AI layer (Claude / GPT / Ollama)
          │
    Reports: HTML · PDF · MD · JSON · CSV
```

---

## Quick Start (5 minutes)

### 1 — Prerequisites

| Requirement | Minimum | Notes |
|-------------|---------|-------|
| Python | 3.11+ | `python3 --version` |
| Docker | 24+ | For Neo4j and Redis |
| Docker Compose | v2 | Bundled with Docker Desktop |
| RAM | 4 GB | 8 GB+ for face recognition |
| Disk | 10 GB | More for large scan datasets |

### 2 — Install

```bash
git clone https://github.com/yourorg/god_eye.git
cd god_eye

# Create virtual environment
python3 -m venv venv
source venv/bin/activate          # Linux / macOS
# venv\Scripts\activate           # Windows

# Install all dependencies
pip install -e ".[dev]"

# Install Playwright browser (used for social scraping)
playwright install chromium
playwright install-deps           # Linux only — installs system libs
```

### 3 — Start Infrastructure

```bash
# Start Neo4j (graph DB) and Redis (queue/cache)
docker compose up -d neo4j redis

# Verify they are healthy (wait ~30s for Neo4j to start)
docker compose ps
```

Expected output:
```
NAME                STATUS
god_eye_neo4j       Up (healthy)
god_eye_redis       Up (healthy)
```

### 4 — Configure Environment

```bash
cp .env.example .env
```

At minimum, set these in `.env`:
```ini
NEO4J_PASSWORD=your_strong_password    # Change from default
NEO4J_URI=bolt://localhost:7687
REDIS_URL=redis://localhost:6379
```

All API keys are **optional** — modules skip themselves gracefully when keys are missing.
To configure API keys interactively:

```bash
python scripts/setup_apis.py
```

### 5 — Verify Setup

```bash
python scripts/health_check.py
```

You should see all critical services as `✓ ok`. Warnings for optional APIs are expected.

### 6 — Seed Demo Data (Optional)

To explore the UI without making real API calls, generate synthetic scan results:

```bash
# Seed 3 fake email scans
python scripts/seed_test_data.py --target-type email --count 3

# Seed all target types
python scripts/seed_test_data.py --target-type email   --count 2
python scripts/seed_test_data.py --target-type username --count 2
python scripts/seed_test_data.py --target-type domain  --count 2
python scripts/seed_test_data.py --target-type ip      --count 2
```

### 7 — Run Your First Scan

```bash
# Scan an email address
god-eye scan --email you@example.com

# Scan a username across 400+ platforms
god-eye scan --username johndoe

# Scan a domain
god-eye scan --domain example.com

# Multi-input scan (most thorough)
god-eye scan --name "John Doe" --email john@example.com --username johndoe

# Auto-detect target type
god-eye scan --target you@example.com
```

---

## CLI Reference

### `scan` — Run an OSINT scan

```bash
god-eye scan [OPTIONS]

Options:
  --email,    -e TEXT   Target email address
  --username, -u TEXT   Target username
  --name,     -n TEXT   Target full name
  --phone,    -p TEXT   Target phone number (E.164 format: +12125551234)
  --domain,   -d TEXT   Target domain (example.com)
  --ip            TEXT  Target IP address
  --company,  -c TEXT   Target company name
  --target,   -t TEXT   Generic target (type auto-detected)
  --phases        TEXT  Comma-separated phases to run: 1,2,3 (default: all)
  --modules,  -m TEXT   Comma-separated module names to run
  --no-ai             Skip AI correlation and report generation
  --no-progress       Suppress progress bars (useful for CI/logs)
  --output-dir,-o TEXT Custom output directory for results
```

**Phase numbers:**
| Phase | Name | What runs |
|-------|------|-----------|
| 1 | FAST_API | Email validation, username checks, DNS, phone lookup |
| 2 | BREACH_DB | HIBP, DeHashed, IntelX, paste monitoring |
| 3 | SEARCH_ENGINE | Google CSE, Bing, DuckDuckGo, Wayback Machine |
| 4 | BROWSER_AUTH | LinkedIn, Instagram, Facebook (Playwright) |
| 5 | IMAGE_PROC | EXIF extraction, face recognition, reverse image |
| 6 | DEEP_ANALYSIS | Subdomain enum, WHOIS, Shodan, certificates |
| 7 | AI_CORR | Cross-module correlation, entity linking |
| 8 | REPORT_GEN | AI summary, HTML/PDF/CSV export |

### `list` — List past scans

```bash
god-eye list                    # Last 20 scans
god-eye list --limit 50         # More results
god-eye list --status completed # Filter by status
```

### `view` — View scan results

```bash
god-eye view req_20240101_120000_abc123de           # By request ID
god-eye view req_20240101_120000_abc123de --full    # Full module output
```

### `report` — Re-generate reports

```bash
god-eye report req_20240101_120000_abc123de         # All formats
god-eye report req_20240101_120000_abc123de --html  # HTML only
god-eye report req_20240101_120000_abc123de --pdf   # PDF only
```

### `modules` — List loaded modules

```bash
god-eye modules                 # All modules with status
god-eye modules --phase 1       # Only phase 1 modules
god-eye modules --enabled       # Only enabled modules
```

### `health` — Check service health

```bash
god-eye health                  # Quick check
```

### `setup` — First-time wizard

```bash
god-eye setup                   # Interactive setup
```

### `cache` — Manage API cache

```bash
god-eye cache stats             # Show cache statistics
god-eye cache clear             # Clear all cached responses
god-eye cache clear --older 7   # Clear entries older than 7 days
```

---

## REST API

Start the API server:

```bash
# Development (with hot reload)
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload

# Production
uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers 4
```

Open **http://localhost:8000/docs** for the interactive Swagger UI.

### Key Endpoints

```
GET  /                          Platform info
GET  /health                    Service health check
GET  /modules                   List all intelligence modules

POST /scan                      Start background scan → returns request_id
GET  /scan/{request_id}         Scan status and metadata
GET  /scan/{request_id}/results Full module results
GET  /scan/{request_id}/report  Download report (?format=html|pdf|json|markdown|csv)
DEL  /scan/{request_id}         Delete scan data
GET  /scans                     List scans (?limit=20&status=completed)
POST /scan/{request_id}/cancel  Cancel running scan

WS   /ws/{request_id}           Real-time progress (WebSocket)
```

### Example: Start a scan via API

```bash
curl -X POST http://localhost:8000/scan \
  -H "Content-Type: application/json" \
  -d '{
    "target": "john@example.com",
    "target_type": "email",
    "enable_ai": true
  }'
```

Response:
```json
{
  "request_id": "req_20240101_120000_abc123de",
  "status": "started",
  "message": "Scan started. Poll GET /scan/req_20240101_120000_abc123de for status."
}
```

---

## Databases

GOD_EYE uses **three databases** — no PostgreSQL required:

| Database | Role | Connection |
|----------|------|------------|
| **Neo4j** | Graph relationships between entities | `bolt://localhost:7687` |
| **Redis** | Scan progress, job queues, pub/sub | `redis://localhost:6379` |
| **SQLite** | API response cache, audit log, scan history | `data/cache/god_eye.db` (auto-created) |

Neo4j Browser UI: **http://localhost:7474** (login: `neo4j` / your password)

---

## Makefile Shortcuts

```bash
make install          # Install production deps
make install-dev      # Install all deps (dev + test)
make install-browsers # Install Playwright Chromium
make setup            # Full setup: deps + browsers + dirs

make run-api          # Start FastAPI server
make run-dev          # Start with hot-reload
make run TARGET=user@example.com   # CLI scan

make test             # Full test suite
make test-fast        # Skip slow/network tests
make test-cov         # With HTML coverage report
make lint             # ruff check
make format           # ruff format

make docker-up        # Start all Docker services
make docker-up-vpn    # Start with Gluetun VPN
make docker-down      # Stop all services

make seed-data        # Generate synthetic test scans
make seed-data-all    # Seed all target types
make health           # System health check (alias)

make env-check        # Full env + API key validation
make clean            # Remove __pycache__, .pytest_cache
```

---

## VPN Support (Gluetun)

GOD_EYE integrates [Gluetun](https://github.com/qdm12/gluetun) to route all scan traffic through a VPN:

```bash
# Enable in .env
VPN_ENABLED=true
VPN_PROVIDER=nordvpn       # or: protonvpn | mullvad | expressvpn | surfshark
VPN_TYPE=wireguard         # or: openvpn
WIREGUARD_PRIVATE_KEY=your_key
WIREGUARD_ADDRESSES=10.5.0.2/32

# Start with VPN profile
docker compose --profile vpn up -d
```

When `VPN_ENABLED=true`, all `aiohttp` requests, Playwright browser traffic, and proxy rotations use the Gluetun HTTP proxy at `http://gluetun:8888`.

---

## Project Structure

```
god_eye/
├── app/
│   ├── cli.py                    # Typer CLI (all commands)
│   ├── main.py                   # FastAPI REST server
│   ├── core/
│   │   ├── config.py             # Settings (pydantic-settings + .env)
│   │   ├── constants.py          # TargetType, ScanStatus, ModulePhase enums
│   │   ├── exceptions.py         # Full exception hierarchy
│   │   └── logging.py            # structlog setup
│   ├── database/
│   │   ├── models.py             # Pydantic v2 entity models
│   │   ├── neo4j_client.py       # Async Neo4j (graph entities)
│   │   ├── redis_client.py       # Async Redis (queues, progress)
│   │   └── sqlite_cache.py       # aiosqlite (cache, audit log)
│   ├── engine/
│   │   ├── orchestrator.py       # 8-phase parallel scan engine
│   │   ├── session.py            # ScanSession (request_id, file I/O)
│   │   ├── browser.py            # Playwright stealth browser factory
│   │   ├── proxy.py              # Proxy rotation (VPN/TOR/file)
│   │   └── rate_limiter.py       # Token bucket per-API rate limiter
│   ├── modules/                  # 50+ intelligence modules
│   │   ├── email/                # validator, breach_checker, hunter, permutator
│   │   ├── username/             # social_checker, sherlock_wrapper, maigret_wrapper
│   │   ├── phone/                # validator, lookup
│   │   ├── web/                  # google_cse, duckduckgo, bing_search, wayback
│   │   ├── social/               # github_api, twitter_api, reddit_api, youtube_api,
│   │   │                         #   linkedin_scraper, instagram_scraper, facebook_scraper
│   │   ├── domain/               # dns_recon, whois_lookup, certificate_search, subdomain_enum
│   │   ├── network/              # ip_lookup, shodan_search, geolocation
│   │   ├── breach/               # hibp, dehashed, intelx, paste_monitor
│   │   ├── business/             # opencorporates
│   │   └── visual/               # exif_extractor, image_downloader, face_recognition, reverse_image
│   ├── ai/
│   │   ├── correlation_engine.py # Cross-module entity linking
│   │   ├── risk_scorer.py        # Weighted 0–10 risk scoring
│   │   ├── timeline_builder.py   # Chronological event extraction
│   │   ├── report_generator.py   # Claude / GPT / Ollama report generation
│   │   └── prompts.py            # LLM system prompts
│   └── utils/
│       ├── validators.py         # Email/IP/domain/phone validation
│       ├── text_analysis.py      # NER, regex entity extraction
│       ├── exporters.py          # JSON/HTML/PDF/CSV/Markdown export
│       ├── image_processing.py   # Hash, resize, metadata
│       └── fingerprint.py        # Target fingerprinting, deduplication
├── data/
│   ├── requests/                 # Scan output (per request_id/)
│   ├── cache/                    # SQLite DB + API caches
│   ├── logs/                     # Structured JSON logs
│   ├── sessions/                 # Browser session persistence
│   └── templates/                # Jinja2 report templates
├── tests/                        # pytest test suite (60+ tests)
├── scripts/
│   ├── setup_apis.py             # Interactive API key wizard
│   ├── health_check.py           # System health check
│   └── seed_test_data.py         # Generate synthetic scan data
├── .github/workflows/ci.yml      # CI: lint + test + Docker build + security scan
├── docker-compose.yml            # Neo4j + Redis + Gluetun VPN + app
├── Dockerfile                    # Multi-stage production image
├── Makefile                      # All common tasks
├── pyproject.toml                # Deps, build config, pytest/ruff/mypy settings
└── .env.example                  # All environment variables documented
```

---

## Documentation Index

| Document | Description |
|----------|-------------|
| **[QUICKSTART.md](./QUICKSTART.md)** | Step-by-step setup and first scan |
| [DEPLOYMENT.md](./DEPLOYMENT.md) | Docker, production config, VPN, proxy, backup |
| [ARCHITECTURE.md](./ARCHITECTURE.md) | System design, data flow, design patterns |
| [MODULE_SPECS.md](./MODULE_SPECS.md) | Every module: inputs, outputs, API requirements |
| [API_REFERENCE.md](./API_REFERENCE.md) | All external API keys, pricing, free tiers |
| [DATABASE_SCHEMA.md](./DATABASE_SCHEMA.md) | Neo4j graph model, SQLite schema, file layout |
| [CLI_REFERENCE.md](./CLI_REFERENCE.md) | Full CLI command reference |
| [SECURITY_AND_ETHICS.md](./SECURITY_AND_ETHICS.md) | Legal safeguards, consent, responsible use |
| [CONTRIBUTING.md](./CONTRIBUTING.md) | How to add modules, code standards |

---

## License

MIT — see [LICENSE](./LICENSE)

> This tool is provided for authorized security research and personal privacy auditing only.
> The authors are not responsible for misuse. Users must comply with all applicable laws.
