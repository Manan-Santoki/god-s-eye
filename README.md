# PROJECT GOD_EYE — Open Source OSINT Intelligence Platform

> A modular, self-hosted, terminal-based Open Source Intelligence (OSINT) platform for digital footprint analysis, privacy auditing, and security research.

---

## Purpose

GOD_EYE aggregates publicly available data from across the internet to build a comprehensive digital profile of a target (person, email, username, domain, phone number, IP address, or company). It is designed for:

- **Personal security auditing** — understand your own digital exposure
- **Authorized penetration testing** — assess client attack surfaces
- **Academic research** — study digital privacy at scale
- **Journalism** — verify identities and connections

**This tool must only be used with proper authorization. See [SECURITY_AND_ETHICS.md](./SECURITY_AND_ETHICS.md).**

---

## Key Features

| Feature | Description |
|---|---|
| **Multi-target input** | Person, email, username, phone, domain, IP, company |
| **40+ data modules** | Social media, breaches, DNS, images, public records |
| **Browser automation** | Playwright with anti-fingerprinting and stealth |
| **Face recognition** | Self-hosted InsightFace (buffalo_l model) |
| **Graph database** | Neo4j for relationship mapping |
| **AI-powered reports** | Claude/GPT/Ollama for correlation and report generation |
| **Rich terminal UI** | Progress bars, tables, color-coded output via Rich |
| **Proxy & VPN support** | Rotating proxies, TOR integration, anti-ban |
| **Export formats** | JSON, Markdown, HTML, PDF, CSV, Neo4j graph |
| **Monitoring mode** | Scheduled scans with change detection alerts |

---

## Tech Stack

| Layer | Technology |
|---|---|
| Language | Python 3.11+ |
| CLI Framework | Typer + Rich |
| Async Engine | asyncio + aiohttp |
| Web Server (optional) | FastAPI |
| Browser Automation | Playwright + playwright-stealth / camoufox |
| Graph Database | Neo4j |
| Cache / Queue | Redis |
| Local Database | SQLite |
| Face Recognition | InsightFace (buffalo_l) |
| NLP | spaCy / Ollama (local LLM) |
| AI Reports | Anthropic Claude / OpenAI GPT / Ollama |
| Containerization | Docker + Docker Compose |

---

## Quick Start

### Prerequisites

- Python 3.11+
- Docker & Docker Compose
- Node.js 18+ (optional, for web dashboard)
- 8GB+ RAM recommended (for InsightFace models)

### Installation

```bash
# Clone the repository
git clone https://github.com/yourorg/god_eye.git
cd god_eye

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
# venv\Scripts\activate   # Windows

# Install dependencies
pip install -e ".[dev]"

# Install Playwright browsers
playwright install chromium firefox

# Start infrastructure (Neo4j + Redis)
docker-compose up -d neo4j redis

# Copy and configure environment
cp .env.example .env
# Edit .env with your API keys

# Run first-time setup
god_eye --setup

# Verify installation
god_eye --health-check
```

### First Scan

```bash
# Quick email scan
god_eye scan --email user@example.com

# Full person investigation
god_eye scan --target "John Doe" --email john@example.com --username johndoe

# Interactive mode
god_eye interactive
```

---

## Documentation Index

| Document | Description |
|---|---|
| [ARCHITECTURE.md](./ARCHITECTURE.md) | System architecture, design patterns, data flow |
| [IMPLEMENTATION_GUIDE.md](./IMPLEMENTATION_GUIDE.md) | Step-by-step build instructions for AI agents |
| [MODULE_SPECS.md](./MODULE_SPECS.md) | Detailed specification for every intelligence module |
| [API_REFERENCE.md](./API_REFERENCE.md) | All external APIs, keys, endpoints, pricing |
| [DATABASE_SCHEMA.md](./DATABASE_SCHEMA.md) | Neo4j graph model, SQLite cache, file storage |
| [CLI_REFERENCE.md](./CLI_REFERENCE.md) | All commands, flags, interactive mode |
| [DEPLOYMENT.md](./DEPLOYMENT.md) | Docker, self-hosting, production config |
| [SECURITY_AND_ETHICS.md](./SECURITY_AND_ETHICS.md) | Legal safeguards, consent, audit logging |
| [CONTRIBUTING.md](./CONTRIBUTING.md) | How to add new modules, code standards |

---

## Project Structure (Summary)

```
god_eye/
├── app/
│   ├── main.py                 # FastAPI entry point
│   ├── cli.py                  # Typer CLI entry point
│   ├── core/                   # Config, logging, exceptions
│   ├── database/               # Neo4j, Redis, SQLite
│   ├── engine/                 # Orchestrator, browser, proxy
│   ├── modules/                # All intelligence modules
│   ├── ai/                     # Report generation, correlation
│   └── utils/                  # Validators, rate limiter, helpers
├── tests/                      # Pytest suite
├── data/                       # Scan results, cache, templates
├── docker-compose.yml
├── pyproject.toml
└── .env.example
```

See [ARCHITECTURE.md](./ARCHITECTURE.md) for the full directory tree with every file explained.

---

## License

MIT License — see [LICENSE](./LICENSE) for details.

**Disclaimer:** This tool is provided for authorized security research and personal privacy auditing only. The authors are not responsible for misuse. Users must comply with all applicable laws and regulations in their jurisdiction.
