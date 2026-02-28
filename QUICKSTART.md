# QUICKSTART — GOD_EYE Setup & First Scan

This guide gets you from zero to running your first scan in under 10 minutes.

---

## Step 1 — Install Python Dependencies

```bash
# Clone the repo
git clone https://github.com/yourorg/god_eye.git
cd god_eye

# Create and activate a virtual environment
python3 -m venv .venv
source .venv/bin/activate        # Linux / macOS
# .venv\Scripts\activate         # Windows PowerShell

# Install the package and all dependencies
pip install -e ".[dev]"

# Verify the CLI is available
god-eye --version
```

---

## Step 2 — Install Playwright Browser

GOD_EYE uses Playwright Chromium for scraping LinkedIn, Instagram, Facebook, and reverse image search.

```bash
playwright install chromium
```

**On Linux / WSL2**, also install system dependencies:
```bash
# If you hit apt GPG errors (common on WSL2 with Docker repos), fix them first:
sudo apt-get update --fix-missing 2>/dev/null || true
playwright install-deps chromium

# If install-deps fails due to repository signing issues, try:
sudo apt-get install -y \
    libnss3 libatk1.0-0 libatk-bridge2.0-0 libcups2 libdrm2 \
    libdbus-1-3 libxkbcommon0 libatspi2.0-0 libxcomposite1 \
    libxdamage1 libxfixes3 libxrandr2 libgbm1 libpango-1.0-0 \
    libcairo2 libasound2 libxss1 2>/dev/null || true
```

> **WSL2 note:** If `install-deps` fails, just proceed — WSL2 usually has sufficient system libs already installed.

---

## Step 3 — Start Infrastructure (Neo4j + Redis)

GOD_EYE requires Neo4j (graph database) and Redis (job queue/cache). Start them via Docker:

```bash
# Start Neo4j and Redis in the background
docker compose up -d neo4j redis

# Check they are healthy (wait ~30s for Neo4j to initialize)
docker compose ps
```

Expected output:
```
NAME                STATUS
god_eye_neo4j       Up (healthy)
god_eye_redis       Up (healthy)
```

If Neo4j is still starting, watch the log:
```bash
docker compose logs -f neo4j
# Wait until you see: "Remote interface available at http://localhost:7474/"
```

**Neo4j Browser** (optional visual explorer): http://localhost:7474
- Username: `neo4j`
- Password: whatever you set in `.env` (default: `god_eye_password`)

---

## Step 4 — Configure Environment

```bash
cp .env.example .env
```

Open `.env` and set the required infrastructure values:

```ini
# ── Required ──────────────────────────────────────────
NEO4J_URI=bolt://localhost:7687
NEO4J_USER=neo4j
NEO4J_PASSWORD=god_eye_password     # ← change this

REDIS_URL=redis://localhost:6379

# ── Optional but highly recommended ───────────────────
HIBP_API_KEY=                       # haveibeenpwned.com — breach data
GITHUB_TOKEN=                       # github.com/settings/tokens — social
ANTHROPIC_API_KEY=                  # console.anthropic.com — AI reports
```

All other keys are optional. Modules auto-skip when their key is missing.

---

## Step 5 — Interactive API Key Setup (Recommended)

The setup wizard walks through every API key, validates format, and writes to `.env`:

```bash
python scripts/setup_apis.py
```

Follow the prompts. Skip any service you don't have an account for — the scan still runs, just without that module's data.

---

## Step 6 — Verify Everything Works

```bash
python scripts/health_check.py
```

Sample output:
```
Check                          Status    Detail              Fix
Python Version                 ✓ ok      3.11.8
pkg:fastapi                    ✓ ok      0.109.2
pkg:playwright                 ✓ ok      1.41.0
.env file                      ✓ ok      1842 bytes
dir:data/requests              ✓ ok      ok
Jinja2 templates               ✓ ok      3 templates present
Playwright browsers            ✓ ok      installed
SQLite (aiosqlite)             ✓ ok      working
Neo4j                          ✓ ok      connected
Redis                          ✓ ok      connected
Module registry                ✓ ok      52 modules loaded
api:HIBP                       ✓ ok      configured
api:GitHub                     ✓ ok      configured
api:Anthropic Claude           ○ warn    not set
```

Warnings on API keys are fine — those modules simply skip. Only `fail` entries need fixing.

---

## Step 7 — Seed Demo Data (Try Before Scanning Real Targets)

Generate synthetic scan results so you can explore reports and the UI without touching any real APIs:

```bash
# Seed 3 fake email scans
python scripts/seed_test_data.py --target-type email --count 3

# Seed across all target types
python scripts/seed_test_data.py --target-type email    --count 2
python scripts/seed_test_data.py --target-type username --count 2
python scripts/seed_test_data.py --target-type domain   --count 2
python scripts/seed_test_data.py --target-type ip       --count 2
```

Then explore the seeded data:
```bash
god-eye list              # View all seeded scans
god-eye view <request_id> # View a specific scan
```

---

## Step 8 — Run Your First Real Scan

```bash
# Scan your own email (recommended first test)
god-eye scan --email you@example.com

# Scan a username across 400+ platforms
god-eye scan --username yourusername

# Scan a domain
god-eye scan --domain example.com

# Combine multiple inputs (most thorough)
god-eye scan --name "Your Name" --email you@example.com --username yourusername

# Skip AI report generation (faster, no API key needed)
god-eye scan --email you@example.com --no-ai

# Run only fast phases (1–3), skip browser automation
god-eye scan --email you@example.com --phases 1,2,3
```

The scan shows a live progress bar per phase. When complete, you'll see a summary table and the output directory path.

---

## Step 9 — View Results

```bash
# List all scans
god-eye list

# View summary of a specific scan
god-eye view req_20240101_120000_abc123de

# View with full module output
god-eye view req_20240101_120000_abc123de --full

# Open the HTML report in your browser
xdg-open data/requests/req_20240101_120000_abc123de/reports/full_report.html
# macOS: open data/requests/.../reports/full_report.html
# Windows: start data/requests/.../reports/full_report.html
```

Reports are saved to:
```
data/requests/<request_id>/
├── metadata.json          # Scan metadata, risk score
├── raw_data/              # Per-module JSON results
│   ├── email_validator.json
│   ├── hibp_breach_checker.json
│   └── ...
└── reports/
    ├── full_report.html   # Dark-theme HTML report
    ├── full_report.md     # Markdown report (if AI enabled)
    ├── full_report.pdf    # PDF (requires weasyprint)
    ├── technical_data.json
    └── export.csv
```

---

## Step 10 — Start the REST API (Optional)

If you prefer a web interface or want to integrate with other tools:

```bash
# Start the API server
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload

# Open the interactive docs
# → http://localhost:8000/docs
```

Start a scan via API:
```bash
curl -X POST http://localhost:8000/scan \
  -H "Content-Type: application/json" \
  -d '{"target": "you@example.com", "target_type": "email", "enable_ai": false}'
```

---

## Common Issues & Fixes

### "No module named 'app'" when running god-eye

```bash
# Make sure your virtualenv is active
source .venv/bin/activate
# Re-install
pip install -e "."
```

### Neo4j connection failed

```bash
# Check if container is running
docker compose ps
# View startup logs
docker compose logs neo4j
# Restart if needed
docker compose restart neo4j
```

### Redis connection failed

```bash
docker compose restart redis
redis-cli ping     # Should return PONG
```

### Playwright browser not found

```bash
# Reinstall the browser
playwright install chromium
# Check install location
python -c "from playwright.sync_api import sync_playwright; p = sync_playwright().start(); b = p.chromium.launch(); print('OK'); b.close(); p.stop()"
```

### `install-deps` fails with apt GPG error (WSL2)

```bash
# Fix Docker repository signing key
sudo apt-key adv --fetch-keys https://download.docker.com/linux/ubuntu/gpg 2>/dev/null || true
sudo apt-get update
playwright install-deps chromium

# If that still fails, install deps manually:
sudo apt-get install -y libnss3 libatk1.0-0 libatk-bridge2.0-0 \
    libcups2 libdrm2 libxkbcommon0 libgbm1 libpango-1.0-0 libcairo2 libasound2
```

### "0 modules loaded" from god-eye modules

```bash
# Check for import errors
python -c "from app.modules import get_registry; r = get_registry(); print(len(r))"
# If you see an ImportError, install missing deps:
pip install -e ".[dev]"
```

### Port 7474 or 7687 already in use

```bash
# Check what's using the port
sudo lsof -i :7474
# Change the port in docker-compose.yml if needed
```

---

## Next Steps

- **Add more API keys**: Run `python scripts/setup_apis.py` again to add keys you skipped
- **Enable VPN**: See [DEPLOYMENT.md](./DEPLOYMENT.md#vpn-gluetun) for Gluetun setup
- **Add a module**: See [CONTRIBUTING.md](./CONTRIBUTING.md)
- **Production deployment**: See [DEPLOYMENT.md](./DEPLOYMENT.md)
- **Full CLI reference**: See [CLI_REFERENCE.md](./CLI_REFERENCE.md)
