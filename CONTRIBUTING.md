# CONTRIBUTING.md — How to Add Modules & Code Standards

---

## Code Standards

### Mandatory for All Code

1. **Python 3.11+** — use modern syntax (match/case, `X | Y` union types, etc.)
2. **Type hints on every function** — parameters and return types
3. **Pydantic models** for all data structures (inputs, outputs, configs)
4. **Async/await** for all I/O operations (network, file, database)
5. **structlog** for all logging — never use `print()` or stdlib `logging`
6. **Docstrings** on every class, public method, and module (Google style)
7. **Error handling** — never let exceptions propagate uncaught; log and continue
8. **No hardcoded values** — all configuration from `.env` or `config.yaml`

### Code Style

```bash
# Linting
ruff check app/ tests/

# Formatting
ruff format app/ tests/

# Type checking
mypy app/ --strict

# Testing
pytest tests/ -v --cov=app --cov-report=term-missing
```

### File Conventions

- File names: `snake_case.py`
- Class names: `PascalCase`
- Function names: `snake_case`
- Constants: `UPPER_SNAKE_CASE`
- Private methods: `_prefixed_with_underscore`
- Max line length: 100 characters
- Imports: stdlib → third-party → local (separated by blank lines)

---

## Adding a New Module

### Step 1: Create the Module File

```
app/modules/{category}/{module_name}.py
```

Choose the appropriate category: `email`, `username`, `phone`, `web`, `social`, `domain`, `network`, `visual`, `breach`, `business`

### Step 2: Implement the BaseModule Interface

```python
"""
Module: {Module Name}
Description: {What this module does}
API: {API name and URL, or "None (local)"}
Auth: {API key required? Which env var?}
Rate Limit: {Requests per minute/day}
Phase: {1-6}
"""
import aiohttp
import structlog
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type

from app.modules.base import BaseModule, ModuleMetadata, ModuleResult
from app.core.constants import TargetType, ModulePhase
from app.core.config import settings
from app.core.exceptions import APIError, RateLimitError

logger = structlog.get_logger(__name__)


class MyNewModule(BaseModule):
    """One-line description of what this module does."""

    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            name="my_new_module",              # Unique, snake_case
            display_name="My New Module",       # Human-readable
            description="Does X by querying Y",
            supported_targets=[TargetType.EMAIL],  # Which target types work
            requires_auth=False,
            requires_proxy=False,
            requires_browser=False,
            rate_limit_rpm=60,
            timeout_seconds=30,
            priority=5,                         # 1=highest priority within phase
            phase=ModulePhase.FAST_API,         # Which phase to run in
            enabled_by_default=True,
        )

    async def validate(self, target: str, target_type: TargetType) -> bool:
        """Return True if this module can process this target."""
        if target_type == TargetType.EMAIL:
            return "@" in target and "." in target.split("@")[-1]
        return False

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=30),
        retry=retry_if_exception_type((aiohttp.ClientError, RateLimitError)),
    )
    async def run(self, target: str, target_type: TargetType, context: dict) -> ModuleResult:
        """Main execution logic."""
        import time
        start = time.monotonic()
        errors: list[str] = []

        try:
            # 1. Check prerequisites (API key, etc.)
            # 2. Make API call or scrape
            # 3. Parse response
            # 4. Return structured result
            
            data = {"example": "result"}
            
            return ModuleResult(
                module_name=self.metadata().name,
                target=target,
                success=True,
                data=data,
                execution_time_ms=int((time.monotonic() - start) * 1000),
            )

        except Exception as e:
            logger.error("module_error", module=self.metadata().name, error=str(e))
            return ModuleResult(
                module_name=self.metadata().name,
                target=target,
                success=False,
                errors=[str(e)],
                execution_time_ms=int((time.monotonic() - start) * 1000),
            )
```

### Step 3: Add Config Entry

Add to `config.yaml`:
```yaml
modules:
  {category}:
    my_new_module: { enabled: true, custom_param: "value" }
```

### Step 4: Add Environment Variables (if needed)

Add to `.env.example`:
```ini
MY_NEW_MODULE_API_KEY=                    # https://api.example.com
```

Add to `app/core/config.py`:
```python
my_new_module_api_key: SecretStr | None = None
```

### Step 5: Write Tests

```python
# tests/test_modules/test_my_new_module.py
import pytest
from unittest.mock import AsyncMock, patch
from app.modules.{category}.my_new_module import MyNewModule
from app.core.constants import TargetType

@pytest.mark.asyncio
async def test_validate_valid_input():
    module = MyNewModule()
    assert await module.validate("user@example.com", TargetType.EMAIL) is True

@pytest.mark.asyncio
async def test_validate_invalid_input():
    module = MyNewModule()
    assert await module.validate("not-valid", TargetType.EMAIL) is False

@pytest.mark.asyncio
async def test_run_success():
    module = MyNewModule()
    result = await module.run("user@example.com", TargetType.EMAIL, {})
    assert result.success is True
    assert result.module_name == "my_new_module"

@pytest.mark.asyncio
async def test_run_api_failure():
    """Module should return success=False, never raise."""
    module = MyNewModule()
    with patch("aiohttp.ClientSession.get", side_effect=Exception("Network error")):
        result = await module.run("user@example.com", TargetType.EMAIL, {})
        assert result.success is False
        assert len(result.errors) > 0
```

### Step 6: Register the Module

The module registry auto-discovers all `BaseModule` subclasses. Just ensure:
1. The file is in `app/modules/{category}/`
2. The class inherits from `BaseModule`
3. The `__init__.py` file in the category folder imports the class

---

## Adding a Browser-Based Scraper

For modules that require Playwright:

```python
class MyScraper(BaseModule):
    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            name="my_scraper",
            requires_browser=True,     # Orchestrator will provide browser context
            requires_proxy=True,       # Route through proxy rotator
            phase=ModulePhase.BROWSER_AUTH,
            # ...
        )

    async def run(self, target: str, target_type: TargetType, context: dict) -> ModuleResult:
        from app.engine.browser import BrowserFactory
        
        factory = await BrowserFactory.create()
        page = await factory.new_page(
            persist_session="my_platform",  # Reuse cookies
        )
        
        try:
            # Navigate with human-like behavior
            await page.goto(f"https://platform.com/{target}")
            await factory.human_delay(1, 3)  # Random 1-3 second wait
            
            # Extract data
            name = await page.text_content("h1.profile-name")
            
            # Take screenshot for evidence
            screenshot_path = f"data/requests/{context['request_id']}/screenshots/my_platform.png"
            await page.screenshot(path=screenshot_path)
            
            return ModuleResult(
                module_name=self.metadata().name,
                target=target,
                success=True,
                data={"name": name, "screenshot": screenshot_path},
            )
        finally:
            await page.close()
```

---

## Neo4j Integration Pattern

Modules should create graph nodes/relationships when appropriate:

```python
from app.database.neo4j_client import Neo4jClient

async def run(self, target, target_type, context):
    # ... gather data ...
    
    # Create nodes in graph
    db = Neo4jClient()
    await db.create_node("Username", {
        "handle": username,
        "platform": "github",
        "profile_url": url,
        "follower_count": followers,
    })
    
    # Link to person if known
    if "person_id" in context:
        await db.create_relationship(
            context["person_id"], "Person",
            node_id, "Username",
            "HAS_ACCOUNT"
        )
```

---

## Pull Request Checklist

Before submitting a new module:

- [ ] Module inherits from `BaseModule` and implements all required methods
- [ ] `metadata()` returns complete, accurate `ModuleMetadata`
- [ ] `validate()` correctly checks all supported target types
- [ ] `run()` never raises exceptions — always returns `ModuleResult`
- [ ] Retry logic with `tenacity` for transient failures
- [ ] Rate limiting respected (via module metadata)
- [ ] API keys read from `settings` (never hardcoded)
- [ ] Structured logging with `structlog` (no `print()`)
- [ ] Type hints on all functions
- [ ] Docstrings on class and public methods
- [ ] Config entry added to `config.yaml`
- [ ] Env vars added to `.env.example` (if needed)
- [ ] Tests written and passing (min 80% coverage for new code)
- [ ] `ruff check` and `mypy` pass clean
- [ ] Documentation updated (MODULE_SPECS.md, API_REFERENCE.md if new API)
