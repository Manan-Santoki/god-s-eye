# DEPLOYMENT.md — Deployment & Infrastructure Guide

---

## 1. Local Development Setup

### Prerequisites

| Requirement | Version | Purpose |
|---|---|---|
| Python | 3.11+ | Core runtime |
| Docker | 24+ | Neo4j, Redis containers |
| Docker Compose | 2.20+ | Service orchestration |
| Node.js | 18+ | Optional: web dashboard |
| Git | 2.40+ | Version control |

### Step-by-Step Local Setup

```bash
# 1. Clone and enter project
git clone https://github.com/yourorg/god_eye.git
cd god_eye

# 2. Python environment
python -m venv venv
source venv/bin/activate
pip install -e ".[dev]"

# 3. Install Playwright browsers
playwright install chromium firefox
playwright install-deps  # System dependencies for Linux

# 4. Start infrastructure
docker-compose up -d neo4j redis

# 5. Wait for services to be ready
docker-compose logs -f neo4j  # Wait for "Started"
# Or use health check:
god_eye health-check

# 6. Configure environment
cp .env.example .env
# Edit .env with your API keys

# 7. Run setup wizard
god_eye setup

# 8. Verify everything works
god_eye health-check
god_eye scan -e test@example.com --fast --verbose
```

---

## 2. Docker Deployment

### Dockerfile

```dockerfile
FROM python:3.11-slim AS base

# System dependencies for Playwright and image processing
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Playwright browser dependencies
    libnss3 libnspr4 libatk1.0-0 libatk-bridge2.0-0 \
    libcups2 libdrm2 libdbus-1-3 libxkbcommon0 \
    libatspi2.0-0 libxcomposite1 libxdamage1 libxfixes3 \
    libxrandr2 libgbm1 libpango-1.0-0 libcairo2 libasound2 \
    # WeasyPrint (PDF generation)
    libpango1.0-dev libcairo2-dev libgdk-pixbuf2.0-dev \
    # Image processing
    libjpeg62-turbo-dev libpng-dev \
    # General utilities
    wget curl git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies
COPY pyproject.toml .
RUN pip install --no-cache-dir -e "."

# Install Playwright browsers
RUN playwright install chromium firefox
RUN playwright install-deps

# Download InsightFace models (cached in image)
RUN python -c "from insightface.app import FaceAnalysis; app = FaceAnalysis(name='buffalo_l'); app.prepare(ctx_id=-1)"

# Copy application code
COPY . .

# Create data directories
RUN mkdir -p /app/data/requests /app/data/cache /app/data/logs /app/data/sessions

# Non-root user for security
RUN useradd -m -s /bin/bash godeye && chown -R godeye:godeye /app
USER godeye

ENTRYPOINT ["python", "-m", "app.cli"]
```

### docker-compose.yml (Full Production)

```yaml
version: '3.8'

services:
  # ── Application ──
  god_eye:
    build:
      context: .
      dockerfile: Dockerfile
    depends_on:
      neo4j:
        condition: service_healthy
      redis:
        condition: service_healthy
    env_file: .env
    volumes:
      - ./data:/app/data            # Persistent scan data
      - ./config.yaml:/app/config.yaml:ro
    networks:
      - god_eye_net
    restart: unless-stopped
    deploy:
      resources:
        limits:
          memory: 4G                 # InsightFace needs RAM
          cpus: '2'

  # ── FastAPI Server (optional) ──
  god_eye_api:
    build:
      context: .
      dockerfile: Dockerfile
    command: uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers 2
    depends_on:
      neo4j:
        condition: service_healthy
      redis:
        condition: service_healthy
    env_file: .env
    ports:
      - "8000:8000"
    volumes:
      - ./data:/app/data
      - ./config.yaml:/app/config.yaml:ro
    networks:
      - god_eye_net
    restart: unless-stopped

  # ── Neo4j Graph Database ──
  neo4j:
    image: neo4j:5-community
    ports:
      - "7474:7474"                  # Browser UI
      - "7687:7687"                  # Bolt protocol
    environment:
      NEO4J_AUTH: neo4j/${NEO4J_PASSWORD:-god_eye_password}
      NEO4J_PLUGINS: '["apoc"]'
      NEO4J_server_memory_heap_initial__size: 512m
      NEO4J_server_memory_heap_max__size: 1G
      NEO4J_server_memory_pagecache_size: 512m
    volumes:
      - neo4j_data:/data
      - neo4j_logs:/logs
    networks:
      - god_eye_net
    healthcheck:
      test: ["CMD-SHELL", "wget --no-verbose --tries=1 --spider http://localhost:7474 || exit 1"]
      interval: 10s
      timeout: 10s
      retries: 5
      start_period: 30s
    restart: unless-stopped

  # ── Redis Cache & Queue ──
  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    command: redis-server --appendonly yes --maxmemory 256mb --maxmemory-policy allkeys-lru
    volumes:
      - redis_data:/data
    networks:
      - god_eye_net
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 5s
      timeout: 3s
      retries: 5
    restart: unless-stopped

  # ── Ollama (Self-Hosted LLM, optional) ──
  ollama:
    image: ollama/ollama:latest
    ports:
      - "11434:11434"
    volumes:
      - ollama_data:/root/.ollama
    networks:
      - god_eye_net
    restart: unless-stopped
    deploy:
      resources:
        limits:
          memory: 8G
    # After first start, pull a model:
    # docker exec -it god_eye-ollama-1 ollama pull llama3

  # ── TOR Proxy (optional) ──
  tor:
    image: dperson/torproxy:latest
    ports:
      - "9050:9050"                  # SOCKS proxy
      - "9051:9051"                  # Control port
    environment:
      PASSWORD: ${TOR_PASSWORD:-}
    networks:
      - god_eye_net
    restart: unless-stopped
    profiles:
      - tor                          # Only start with: docker-compose --profile tor up

volumes:
  neo4j_data:
  neo4j_logs:
  redis_data:
  ollama_data:

networks:
  god_eye_net:
    driver: bridge
```

### Running with Docker

```bash
# Start all services
docker-compose up -d

# Start with TOR proxy
docker-compose --profile tor up -d

# Run a scan
docker-compose run --rm god_eye scan -t "John Doe" -e john@example.com

# View logs
docker-compose logs -f god_eye

# Enter interactive mode
docker-compose run --rm -it god_eye interactive

# Pull Ollama model (if using self-hosted LLM)
docker-compose exec ollama ollama pull llama3

# Stop all services
docker-compose down

# Stop and remove volumes (WARNING: deletes all data)
docker-compose down -v
```

---

## 3. Production Checklist

### Security

- [ ] Change default Neo4j password in `.env`
- [ ] Use strong, unique passwords for all credentials
- [ ] Never commit `.env` to version control
- [ ] Run application as non-root user
- [ ] Enable audit logging (`AUDIT_LOG_ENABLED=true`)
- [ ] Restrict network access (firewall rules)
- [ ] Use HTTPS for FastAPI (reverse proxy with nginx/Caddy)
- [ ] Regular security updates for Docker images

### Performance

- [ ] Allocate sufficient RAM (min 4GB, 8GB+ recommended)
- [ ] SSD storage for Neo4j and scan data
- [ ] Adjust `MAX_CONCURRENT_MODULES` based on available resources
- [ ] Configure Neo4j memory (`heap` and `pagecache`)
- [ ] Monitor Redis memory usage
- [ ] Set up log rotation for `data/logs/`

### Backup

```bash
# Backup Neo4j
docker-compose exec neo4j neo4j-admin database dump neo4j --to-path=/dumps
docker cp $(docker-compose ps -q neo4j):/dumps ./backups/

# Backup scan data
tar -czf backup_$(date +%Y%m%d).tar.gz data/

# Backup Redis
docker-compose exec redis redis-cli BGSAVE
```

### Monitoring

- [ ] Set up log aggregation (ELK stack, Loki, etc.)
- [ ] Monitor container health via Docker healthchecks
- [ ] Set up disk space alerts (scans can generate lots of data)
- [ ] Monitor API rate limit consumption

---

## 4. Proxy Infrastructure

### Option A: Residential Proxy Service

Recommended providers: Smartproxy, BrightData, IPRoyal

```ini
# .env
USE_PROXY=true
PROXY_LIST_FILE=proxies.txt
PROXY_ROTATION_STRATEGY=round_robin
```

```
# proxies.txt (one per line)
http://user:pass@gate.smartproxy.com:7777
http://user:pass@gate.smartproxy.com:7778
http://user:pass@gate.smartproxy.com:7779
```

### Option B: TOR Network

```ini
# .env
TOR_ENABLED=true
TOR_SOCKS_PORT=9050
TOR_CONTROL_PORT=9051
TOR_PASSWORD=your_tor_password
```

```bash
# Start with TOR profile
docker-compose --profile tor up -d
```

### Option C: Self-Hosted Proxy Pool

For advanced users: set up multiple VPS instances as proxies using Squid or 3proxy.

---

## 5. System Requirements

| Deployment | CPU | RAM | Storage | Network |
|---|---|---|---|---|
| Minimal (API only) | 2 cores | 2 GB | 10 GB | Broadband |
| Standard (with browser) | 4 cores | 4 GB | 50 GB | Broadband |
| Full (with InsightFace) | 4 cores | 8 GB | 100 GB | Broadband |
| Production server | 8 cores | 16 GB | 500 GB | Dedicated |
