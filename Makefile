# ╔══════════════════════════════════════════════════════════════════╗
# ║              GOD_EYE OSINT Platform — Makefile                  ║
# ║   Usage: make <target>   (e.g. make install, make test)         ║
# ╚══════════════════════════════════════════════════════════════════╝

.DEFAULT_GOAL := help
.PHONY: help install install-dev install-browsers setup env-check \
        run run-dev run-api run-docker docker-up docker-down docker-logs \
        test test-fast test-cov lint format typecheck \
        health seed-data clean clean-cache clean-logs clean-all \
        build-docker reports

PYTHON     ?= python3
PIP        ?= pip
UVICORN    ?= uvicorn
PYTEST     ?= pytest
RUFF       ?= ruff
MYPY       ?= mypy
PORT       ?= 8000
HOST       ?= 0.0.0.0
DATA_DIR   ?= data
LOG_LEVEL  ?= INFO

# ── Colors ────────────────────────────────────────────────────────────────────
BOLD   := \033[1m
CYAN   := \033[1;36m
GREEN  := \033[1;32m
YELLOW := \033[1;33m
RED    := \033[1;31m
RESET  := \033[0m

## Show this help message
help:
	@echo ""
	@echo "$(CYAN)GOD_EYE OSINT Platform$(RESET)"
	@echo "$(BOLD)Usage:$(RESET) make [target]"
	@echo ""
	@echo "$(BOLD)Setup:$(RESET)"
	@grep -E '^##[^#]' $(MAKEFILE_LIST) | head -30 | sed 's/## /  /'
	@echo ""
	@echo "$(BOLD)Targets:$(RESET)"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  $(CYAN)%-20s$(RESET) %s\n", $$1, $$2}'
	@echo ""

# ── Installation ──────────────────────────────────────────────────────────────

install: ## Install production dependencies
	@echo "$(GREEN)Installing production dependencies...$(RESET)"
	$(PIP) install -e ".[prod]"
	@echo "$(GREEN)✓ Production dependencies installed$(RESET)"

install-dev: ## Install all dependencies including dev/test
	@echo "$(GREEN)Installing all dependencies (dev + prod)...$(RESET)"
	$(PIP) install -e ".[dev,test,ml,nlp]"
	@echo "$(GREEN)✓ All dependencies installed$(RESET)"

install-browsers: ## Install Playwright browsers (Chromium)
	@echo "$(GREEN)Installing Playwright Chromium browser...$(RESET)"
	$(PYTHON) -m playwright install chromium
	@echo "$(GREEN)Installing Playwright system dependencies...$(RESET)"
	@$(PYTHON) -m playwright install-deps chromium 2>&1 || \
		(echo "$(YELLOW)⚠  install-deps failed (common on WSL2 with Docker repos).$(RESET)" && \
		 echo "$(YELLOW)   Trying manual dep install via apt-get...$(RESET)" && \
		 sudo apt-get install -y libnss3 libatk1.0-0 libatk-bridge2.0-0 libcups2 \
		     libdrm2 libdbus-1-3 libxkbcommon0 libatspi2.0-0 libxcomposite1 \
		     libxdamage1 libxfixes3 libxrandr2 libgbm1 libpango-1.0-0 libcairo2 \
		     libasound2 libxss1 2>/dev/null || \
		 echo "$(YELLOW)   Skipping system deps — Chromium may still work on WSL2.$(RESET)")
	@echo "$(GREEN)✓ Playwright Chromium ready$(RESET)"

setup: install-dev install-browsers ## Full development setup (install + browsers + env)
	@echo "$(GREEN)Setting up environment...$(RESET)"
	@[ -f .env ] || cp .env.example .env
	@mkdir -p $(DATA_DIR)/logs $(DATA_DIR)/requests $(DATA_DIR)/cache $(DATA_DIR)/sessions
	@echo "$(GREEN)✓ Setup complete!$(RESET)"
	@echo ""
	@echo "  Next: $(CYAN)make setup-apis$(RESET) to configure API keys"

setup-apis: ## Interactive API key configuration wizard
	$(PYTHON) scripts/setup_apis.py

env-check: ## Validate environment and service health
	$(PYTHON) scripts/health_check.py

env-check-json: ## Output health check as JSON
	$(PYTHON) scripts/health_check.py --json

# ── Running ───────────────────────────────────────────────────────────────────

run: ## Run a scan via CLI (usage: make run TARGET=user@example.com)
	@[ -n "$(TARGET)" ] || (echo "$(RED)Error: TARGET is required$(RESET)\n  make run TARGET=user@example.com" && exit 1)
	$(PYTHON) -m app.cli scan --target "$(TARGET)"

run-api: ## Start the FastAPI REST server
	@echo "$(GREEN)Starting GOD_EYE REST API on http://$(HOST):$(PORT)$(RESET)"
	$(UVICORN) app.main:app --host $(HOST) --port $(PORT) --log-level $(LOG_LEVEL)

run-dev: ## Start the FastAPI server with hot-reload
	@echo "$(GREEN)Starting GOD_EYE REST API (dev mode) on http://$(HOST):$(PORT)$(RESET)"
	$(UVICORN) app.main:app --host $(HOST) --port $(PORT) --reload --log-level debug

run-cli: ## Launch the interactive CLI
	$(PYTHON) -m app.cli

# ── Docker ────────────────────────────────────────────────────────────────────

docker-up: ## Start all Docker services (neo4j, redis, app)
	docker compose up -d
	@echo "$(GREEN)✓ Services started$(RESET)"
	@echo "  API:    http://localhost:8000/docs"
	@echo "  Neo4j:  http://localhost:7474"
	@echo "  Redis:  localhost:6379"

docker-up-vpn: ## Start services with VPN (gluetun)
	docker compose --profile vpn up -d
	@echo "$(GREEN)✓ Services started with VPN$(RESET)"

docker-down: ## Stop all Docker services
	docker compose down
	@echo "$(GREEN)✓ Services stopped$(RESET)"

docker-logs: ## Follow Docker service logs
	docker compose logs -f

docker-shell: ## Open shell in the app container
	docker compose exec app bash

build-docker: ## Build the Docker image
	docker compose build app
	@echo "$(GREEN)✓ Docker image built$(RESET)"

# ── Testing ───────────────────────────────────────────────────────────────────

test: ## Run full test suite
	@echo "$(GREEN)Running tests...$(RESET)"
	$(PYTEST) tests/ -v --tb=short

test-fast: ## Run tests excluding slow/network tests
	$(PYTEST) tests/ -v --tb=short -m "not slow and not network"

test-cov: ## Run tests with coverage report
	$(PYTEST) tests/ --cov=app --cov-report=term-missing --cov-report=html:data/coverage
	@echo "$(GREEN)✓ Coverage report: data/coverage/index.html$(RESET)"

test-modules: ## Test only intelligence modules
	$(PYTEST) tests/test_modules/ -v --tb=short

test-engine: ## Test only engine layer
	$(PYTEST) tests/test_engine/ -v --tb=short

test-ai: ## Test only AI layer
	$(PYTEST) tests/test_ai/ -v --tb=short

test-one: ## Run a specific test (usage: make test-one T=tests/test_modules/test_email.py)
	$(PYTEST) $(T) -v --tb=long

# ── Code Quality ──────────────────────────────────────────────────────────────

lint: ## Lint with ruff
	$(RUFF) check app/ tests/ scripts/

format: ## Auto-format with ruff
	$(RUFF) format app/ tests/ scripts/

format-check: ## Check formatting without modifying files
	$(RUFF) format --check app/ tests/ scripts/

typecheck: ## Run mypy type checking
	$(MYPY) app/ --ignore-missing-imports

check: lint format-check typecheck ## Run all code quality checks

# ── Data Management ───────────────────────────────────────────────────────────

seed-data: ## Seed synthetic test data (email scans)
	$(PYTHON) scripts/seed_test_data.py --target-type email --count 3

seed-data-all: ## Seed synthetic test data for all target types
	$(PYTHON) scripts/seed_test_data.py --target-type email --count 2
	$(PYTHON) scripts/seed_test_data.py --target-type username --count 2
	$(PYTHON) scripts/seed_test_data.py --target-type domain --count 2
	$(PYTHON) scripts/seed_test_data.py --target-type ip --count 2

clear-data: ## Remove all scan data (DESTRUCTIVE)
	@echo "$(RED)This will delete all scan data in $(DATA_DIR)/requests$(RESET)"
	@read -p "Continue? [y/N] " yn; [ "$$yn" = "y" ] || exit 1
	$(PYTHON) scripts/seed_test_data.py --clear
	@echo "$(GREEN)✓ Scan data cleared$(RESET)"

clean-cache: ## Clear Python and data caches
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -name "*.pyc" -delete 2>/dev/null || true
	find . -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null || true
	find . -name ".ruff_cache" -exec rm -rf {} + 2>/dev/null || true
	@echo "$(GREEN)✓ Caches cleared$(RESET)"

clean-logs: ## Clear application logs
	find $(DATA_DIR)/logs -name "*.log" -delete 2>/dev/null || true
	@echo "$(GREEN)✓ Logs cleared$(RESET)"

clean: clean-cache ## Clean build artifacts and caches

clean-all: clean clean-logs ## Clean everything (but preserve scan data and .env)
	@echo "$(GREEN)✓ All artifacts cleaned$(RESET)"

# ── Reports ───────────────────────────────────────────────────────────────────

reports: ## List all generated reports
	@find $(DATA_DIR)/requests -name "full_report.html" 2>/dev/null | \
		sed 's|$(DATA_DIR)/requests/||' | sed 's|/reports/.*||' | sort || \
		echo "No reports found. Run a scan first."

# ── Utilities ─────────────────────────────────────────────────────────────────

list-scans: ## List all scans in the data directory
	$(PYTHON) -m app.cli list

version: ## Show GOD_EYE version
	$(PYTHON) -c "print('GOD_EYE OSINT Platform v1.0.0')"

modules: ## List all loaded intelligence modules
	$(PYTHON) -m app.cli modules
