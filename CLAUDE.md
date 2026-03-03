# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

GOD_EYE is an open-source OSINT (Open Source Intelligence) platform for digital footprint analysis and privacy auditing. Python 3.11+, ~24,800 lines across 85 source files.

## Common Commands

```bash
# Install & setup
make setup                    # Full dev setup (deps + browsers + env)
pip install -e ".[dev]"       # Manual install with dev deps
playwright install chromium   # Browser for scraping modules

# Run
make run TARGET=user@example.com   # CLI scan
make run-api                       # FastAPI server on :8000
make run-dev                       # FastAPI with hot-reload
make run-cli                       # Interactive shell

# Test
make test                          # Full test suite
make test-fast                     # Skip slow/network tests
make test-one T=tests/test_modules/test_email.py  # Single test file
make test-cov                      # Coverage report → data/coverage/

# Code quality
make lint                          # ruff check
make format                        # ruff format
make typecheck                     # mypy
make check                         # All three above

# Docker
make docker-up                     # Start neo4j + redis + app
make docker-down                   # Stop all
```

## Architecture

### Layer Structure

```
CLI (app/cli.py, Typer) / REST API (app/main.py, FastAPI)
    ↓
Orchestrator (app/engine/orchestrator.py)
    ↓
50+ Intelligence Modules (app/modules/**/*, all inherit BaseModule)
    ↓
Storage: Neo4j (graph) + Redis (queue/cache) + SQLite (request cache)
    ↓
AI Analysis (app/ai/*) → Reports (JSON/MD/HTML/PDF/CSV)
```

### Phase-Based Execution

The orchestrator runs 8 sequential phases. Modules within each phase run in parallel via `asyncio.gather()`:

| Phase | Name | Examples |
|-------|------|---------|
| 1 | FAST_API | Email validator, GitHub API, phone lookup |
| 2 | BREACH_DB | HIBP, DeHashed, IntelX |
| 3 | SEARCH_ENGINE | Google CSE, Bing, Wayback, Google dorks |
| 4 | BROWSER_AUTH | LinkedIn, Instagram, Facebook scrapers |
| 5 | IMAGE_PROCESSING | Reverse image, EXIF, face recognition |
| 6 | DEEP_ANALYSIS | Subdomain enum, Shodan, Censys, WHOIS |
| 7 | AI_CORRELATION | Cross-reference, timeline, risk scoring |
| 8 | REPORT_GEN | Generate reports in all formats |

### Module Plugin System

All modules inherit from `BaseModule` (`app/modules/base.py`). Key contract:

- `metadata() -> ModuleMetadata` — name, phase, supported target types, auth requirements, rate limits
- `run(target, target_type, context) -> ModuleResult` — execute gathering; never raise exceptions
- `cleanup()` — optional resource cleanup

`ModuleResult.ok(data)` / `ModuleResult.fail(*errors)` factory methods for results.

Modules are organized into 11 categories under `app/modules/`: email, username, phone, web, social, domain, network, visual, breach, business.

### Context Passing

A shared `context` dict flows between phases. Modules read/write keys like `discovered_emails`, `discovered_usernames`, `discovered_domains`, `discovered_ips`, `discovered_images`, `discovered_names` to chain data across phases.

### Error Resilience

Modules never crash the scan. Errors are caught via `asyncio.gather(return_exceptions=True)`, logged, and stored in `ModuleResult.errors`. Transient failures retry with exponential backoff (tenacity).

## Key Directories

- `app/core/` — Config (Pydantic settings from `.env` + `config.yaml`), constants (enums), logging (structlog), exceptions
- `app/database/` — Neo4j async client, Redis client, SQLite cache, Pydantic models
- `app/engine/` — Orchestrator, Playwright browser factory, proxy rotator, rate limiter, scan session
- `app/modules/` — 50+ intelligence modules with auto-discovery registry
- `app/ai/` — Report generator (Jinja2), correlation engine, risk scorer, timeline builder, LLM prompts
- `app/utils/` — Validators, exporters, text analysis, image processing
- `scripts/` — Setup wizard, health check, test data seeder
- `data/` — Runtime output (scans, cache, logs, reports)

## Code Conventions

- **Async/await** for all I/O operations
- **Pydantic** models for data validation
- **structlog** for logging (never `print()`)
- **Ruff** for linting and formatting (line length 100, target Python 3.11)
- **Type hints** on all functions
- Ruff rules: E, F, I, N, W, B, UP (ignores E501, B008, B904)
- pytest with `asyncio_mode = "auto"` — async test functions auto-detected
- All API keys are optional; modules auto-skip when their key is missing

## Configuration

- `.env` — Secrets and infrastructure (API keys, database URIs, VPN settings). All keys optional.
- `config.yaml` — Module enable/disable toggles, stealth settings, output formats, rate limits
- `app/core/config.py` — Pydantic `BaseSettings` loads both; uses `SecretStr` for sensitive values

## CI/CD

GitHub Actions (`ci.yml`): lint → test (Python 3.11 + 3.12 matrix) → smoke test → security scan (bandit) → Docker build → PyPI publish → GitHub release. AI features disabled in CI (no API keys).
