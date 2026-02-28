# DEPLOYMENT.md — Deployment & Infrastructure Guide

---

## Table of Contents

1. [Local Development](#1-local-development)
2. [Docker Compose (Recommended)](#2-docker-compose-recommended)
3. [Running with VPN (Gluetun)](#3-running-with-vpn-gluetun)
4. [Production Checklist](#4-production-checklist)
5. [Database Reference](#5-database-reference)
6. [Proxy Configuration](#6-proxy-configuration)
7. [System Requirements](#7-system-requirements)
8. [Backup & Recovery](#8-backup--recovery)

---

## 1. Local Development

### Prerequisites

| Requirement | Version | Install |
|-------------|---------|---------|
| Python | 3.11+ | [python.org](https://www.python.org/downloads/) |
| Docker | 24+ | [docs.docker.com](https://docs.docker.com/get-docker/) |
| Docker Compose | v2 | Bundled with Docker Desktop |

### Full Setup

```bash
# 1. Clone and enter the repo
git clone https://github.com/yourorg/god_eye.git
cd god_eye

# 2. Create virtual environment
python3 -m venv .venv
source .venv/bin/activate          # Linux / macOS
# .venv\Scripts\activate           # Windows

# 3. Install all dependencies
pip install -e ".[dev]"

# 4. Install Playwright browser
playwright install chromium

# 5. Install Playwright system dependencies (Linux only)
#    If this fails due to apt GPG errors (common on WSL2), see note below.
playwright install-deps chromium

# 6. Start Neo4j and Redis
docker compose up -d neo4j redis

# 7. Configure environment
cp .env.example .env
# Edit .env — at minimum set NEO4J_PASSWORD

# 8. Run interactive API key setup
python scripts/setup_apis.py

# 9. Verify everything
python scripts/health_check.py

# 10. Seed demo data (optional)
python scripts/seed_test_data.py --target-type email --count 3
```

### WSL2 — playwright install-deps Fix

If `playwright install-deps` fails with a Docker apt GPG error:

```bash
# Option A: Fix the Docker apt key (recommended)
sudo apt-key adv --fetch-keys https://download.docker.com/linux/ubuntu/gpg 2>/dev/null || true
sudo apt-get update
playwright install-deps chromium

# Option B: Install browser dependencies manually
sudo apt-get install -y \
    libnss3 libatk1.0-0 libatk-bridge2.0-0 libcups2 libdrm2 libdbus-1-3 \
    libxkbcommon0 libatspi2.0-0 libxcomposite1 libxdamage1 libxfixes3 \
    libxrandr2 libgbm1 libpango-1.0-0 libcairo2 libasound2 libxss1

# Option C: Skip install-deps entirely
#   WSL2 usually has sufficient system libraries. Try running a scan
#   first — Chromium often works without the explicit dep install.
```

---

## 2. Docker Compose (Recommended)

The `docker-compose.yml` defines five services with Docker profiles so you only start what you need.

### Services and Profiles

| Service | Profile | Description |
|---------|---------|-------------|
| `neo4j` | *(always)* | Neo4j 5 graph database |
| `redis` | *(always)* | Redis 7 cache/queue |
| `gluetun` | `vpn` | Gluetun VPN gateway |
| `app` | `app` | GOD_EYE CLI/API app |
| `app_via_vpn` | `vpn` | App with all traffic routed through VPN |
| `neo4j_bloom` | `ui` | Neo4j Bloom graph visualizer |

### Common Compose Commands

```bash
# ── Infrastructure only (most common for dev) ──
docker compose up -d neo4j redis

# ── Full stack (infra + app) ──
docker compose --profile app up -d

# ── Full stack with VPN ──
docker compose --profile vpn up -d

# ── Full stack with Neo4j Bloom UI ──
docker compose --profile app --profile ui up -d

# ── View logs ──
docker compose logs -f                  # All services
docker compose logs -f neo4j            # Neo4j only
docker compose logs -f app              # App only

# ── Restart a service ──
docker compose restart neo4j

# ── Stop all services ──
docker compose down

# ── Stop and wipe all data (DESTRUCTIVE) ──
docker compose down -v

# ── Run a scan inside Docker ──
docker compose run --rm app scan --email user@example.com

# ── Open a shell in the app container ──
docker compose exec app bash
```

### Building the App Image

```bash
docker compose build app

# Or with no cache
docker compose build --no-cache app
```

### Environment Variables in Docker

When running with `docker compose`, the app container reads `.env` via `env_file: .env`.
Infrastructure URIs are overridden automatically:

```yaml
environment:
  NEO4J_URI: bolt://neo4j:7687      # Use service name, not localhost
  REDIS_URL: redis://redis:6379
```

You do **not** need to change `NEO4J_URI` in `.env` for Docker — the compose file overrides it.

---

## 3. Running with VPN (Gluetun)

[Gluetun](https://github.com/qdm12/gluetun) routes all app traffic through a VPN tunnel.
Supports NordVPN, ProtonVPN, Mullvad, ExpressVPN, Surfshark, Private Internet Access, and more.

### Configure in `.env`

```ini
VPN_ENABLED=true
VPN_PROVIDER=nordvpn               # nordvpn | protonvpn | mullvad | expressvpn
                                   # surfshark | privateinternetaccess | windscribe | ipvanish

# ── WireGuard (recommended) ──
VPN_TYPE=wireguard
WIREGUARD_PRIVATE_KEY=your_wg_private_key
WIREGUARD_ADDRESSES=10.5.0.2/32

# ── OpenVPN (alternative) ──
# VPN_TYPE=openvpn
# VPN_USERNAME=your_vpn_user
# VPN_PASSWORD=your_vpn_pass

# ── Server selection (optional) ──
VPN_COUNTRIES=United States
VPN_CITIES=New York
```

### Start with VPN

```bash
docker compose --profile vpn up -d

# Check VPN is connected
docker compose logs gluetun | grep "VPN is up"
# Expected: "VPN is up"

# Verify your VPN IP
docker compose exec app_via_vpn curl -s https://ipinfo.io/ip
```

### How It Works

- The `gluetun` container establishes the VPN tunnel and exposes an HTTP proxy on port `8888`
- `app_via_vpn` uses `network_mode: "service:gluetun"` — all traffic goes through the VPN
- `settings.get_proxy_url()` returns `http://gluetun:8888` when `VPN_ENABLED=true`
- All `aiohttp` requests and Playwright browser sessions use this proxy

### Getting WireGuard Keys

**NordVPN:**
```bash
# Using NordVPN CLI
nordvpn set technology NordLynx
nordvpn set killswitch on
# Get private key from NordVPN WireGuard config generator in account portal
```

**ProtonVPN:**
```
1. Log in to proton.me/vpn
2. Download → WireGuard configuration
3. Copy PrivateKey and Address from the .conf file
```

**Mullvad:**
```bash
# Using Mullvad CLI
mullvad tunnel wireguard key generate
mullvad tunnel wireguard key check
# Get key from account.mullvad.net → WireGuard keys
```

---

## 4. Production Checklist

### Security

- [ ] Change `NEO4J_PASSWORD` from the default `god_eye_password`
- [ ] Set strong, unique passwords for all infrastructure
- [ ] Never commit `.env` to version control (it's in `.gitignore`)
- [ ] Run app as a non-root user (Docker image already does this)
- [ ] Keep `AUDIT_LOG_ENABLED=true` for accountability
- [ ] Place FastAPI behind a reverse proxy (nginx / Caddy) with TLS
- [ ] Restrict Neo4j and Redis ports to internal network only (remove public port mappings)
- [ ] Set `APP_ENV=production` in `.env`
- [ ] Set `CONSENT_REQUIRED=true` to enforce ethics consent per scan

### Performance Tuning

```ini
# .env — performance settings
MAX_CONCURRENT_MODULES=15          # Increase if CPU/network allows
MAX_CONCURRENT_BROWSERS=5          # Increase RAM if you raise this
REQUEST_TIMEOUT_SECONDS=45         # Increase for slow APIs
```

```yaml
# docker-compose.yml — resource limits for app
deploy:
  resources:
    limits:
      memory: 8G
      cpus: '4'
```

Neo4j memory (in `docker-compose.yml`):
```yaml
NEO4J_dbms_memory_heap_initial__size: "1g"
NEO4J_dbms_memory_heap_max__size: "2g"
NEO4J_dbms_memory_pagecache_size: "1g"
```

### Nginx Reverse Proxy (HTTPS)

```nginx
server {
    listen 443 ssl http2;
    server_name osint.yourcompany.com;

    ssl_certificate     /etc/ssl/certs/fullchain.pem;
    ssl_certificate_key /etc/ssl/private/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # WebSocket support (for /ws/* endpoints)
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
```

---

## 5. Database Reference

### Neo4j — Graph Database

| Setting | Default | Notes |
|---------|---------|-------|
| `NEO4J_URI` | `bolt://localhost:7687` | Use `bolt://neo4j:7687` in Docker |
| `NEO4J_USER` | `neo4j` | Default admin user |
| `NEO4J_PASSWORD` | `god_eye_password` | **Change this!** |

**Web UI:** http://localhost:7474

GOD_EYE creates these node labels in Neo4j:
`Person`, `Email`, `Username`, `Domain`, `IP`, `Phone`, `Location`, `Image`, `Breach`, `Company`

All nodes are created with `MERGE` (no duplicates) and linked via `RELATED_TO`, `HAS_EMAIL`, `FOUND_ON`, `BREACHED_IN`, and other relationship types.

```cypher
-- Example Cypher queries in Neo4j Browser
MATCH (p:Person)-[:HAS_EMAIL]->(e:Email) RETURN p, e LIMIT 25
MATCH (e:Email)-[:BREACHED_IN]->(b:Breach) RETURN e, b ORDER BY b.date DESC
MATCH path = (p:Person)-[*1..3]-(n) WHERE p.name = "John Doe" RETURN path
```

### Redis — Cache & Queue

| Setting | Default |
|---------|---------|
| `REDIS_URL` | `redis://localhost:6379` |

Keys used by GOD_EYE:
- `god_eye:progress:{request_id}` — scan progress (JSON)
- `god_eye:session:{session_id}` — browser session state
- `god_eye:rate:{api_name}` — distributed rate limit counters
- `god_eye:queue:scans` — scan job queue (LPUSH/BRPOP)

### SQLite — Local Cache

Location: `data/cache/god_eye.db` (auto-created on first run)

| Table | Purpose |
|-------|---------|
| `api_cache` | Cached API responses with TTL |
| `rate_limits` | Per-API rate limit counters |
| `scans` | Scan history and metadata |
| `audit_log` | Immutable audit trail of all searches |

No configuration needed — SQLite is embedded and requires no server.

---

## 6. Proxy Configuration

### Option A — Gluetun VPN (Recommended)

See [Section 3](#3-running-with-vpn-gluetun) above.

### Option B — Proxy File (Static List)

```ini
# .env
USE_PROXY=true
PROXY_LIST_FILE=proxies.txt
PROXY_ROTATION_STRATEGY=round_robin   # round_robin | random | least_used
```

```
# proxies.txt — one proxy per line
http://user:pass@gate.smartproxy.com:7777
http://user:pass@gate.smartproxy.com:7778
socks5://user:pass@socks-proxy.example.com:1080
```

Recommended residential proxy providers: Smartproxy, BrightData, IPRoyal

### Option C — TOR Network

```ini
# .env
TOR_ENABLED=true
TOR_SOCKS_PORT=9050
TOR_CONTROL_PORT=9051
TOR_PASSWORD=your_control_password
```

```bash
# Start with TOR (using optional TOR service in docker-compose.yml)
# Add the tor service to docker-compose.yml from DEPLOYMENT.md extras
docker compose --profile tor up -d tor
```

TOR circuits are rotated automatically every 30 requests via the control port.

---

## 7. System Requirements

| Deployment Mode | CPU | RAM | Disk |
|----------------|-----|-----|------|
| API keys only (no browser, no AI) | 2 cores | 2 GB | 10 GB |
| Standard (browser automation) | 4 cores | 4 GB | 50 GB |
| With face recognition (InsightFace) | 4 cores | 8 GB | 100 GB |
| Full production server | 8 cores | 16 GB | 500 GB |

**WSL2 on Windows:** Allocate at least 6 GB RAM to WSL2 in `.wslconfig`:
```ini
# %USERPROFILE%\.wslconfig
[wsl2]
memory=8GB
processors=4
```

---

## 8. Backup & Recovery

### Backup Neo4j

```bash
# Create a database dump
docker compose exec neo4j neo4j-admin database dump neo4j --to-path=/var/lib/neo4j/dumps

# Copy dump to host
docker cp god_eye_neo4j:/var/lib/neo4j/dumps/neo4j.dump ./backups/neo4j_$(date +%Y%m%d).dump
```

### Backup Scan Data

```bash
# All scan results, reports, and logs
tar -czf god_eye_data_$(date +%Y%m%d).tar.gz data/
```

### Backup Redis (if using persistence)

```bash
docker compose exec redis redis-cli BGSAVE
docker cp god_eye_redis:/data/dump.rdb ./backups/redis_$(date +%Y%m%d).rdb
```

### Restore Neo4j

```bash
# Stop the app first
docker compose stop app

# Restore
docker cp ./backups/neo4j_backup.dump god_eye_neo4j:/var/lib/neo4j/dumps/
docker compose exec neo4j neo4j-admin database load neo4j \
    --from-path=/var/lib/neo4j/dumps --overwrite-destination

docker compose start app
```

### Clear All Data (Fresh Start)

```bash
# Remove scan results only (keep config)
python scripts/seed_test_data.py --clear

# Remove Docker volumes (Neo4j + Redis data)
docker compose down -v

# Remove all data dirs
rm -rf data/requests/ data/cache/ data/logs/ data/sessions/
mkdir -p data/requests data/cache data/logs data/sessions data/templates
```
