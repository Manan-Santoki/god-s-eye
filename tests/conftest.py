"""
Pytest configuration and shared fixtures for GOD_EYE test suite.
"""

import asyncio
import json
import os
import tempfile
from pathlib import Path
from typing import Any, AsyncGenerator, Generator
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import pytest_asyncio

# ── Event loop ───────────────────────────────────────────────────────────────

@pytest.fixture(scope="session")
def event_loop_policy():
    return asyncio.DefaultEventLoopPolicy()


# ── Env setup ────────────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def set_test_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Set environment variables for tests to avoid polluting real data dirs."""
    monkeypatch.setenv("DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("LOG_LEVEL", "DEBUG")
    monkeypatch.setenv("LOG_FORMAT", "console")
    monkeypatch.setenv("ENABLE_AI_CORRELATION", "false")
    monkeypatch.setenv("ENABLE_AI_REPORTS", "false")
    # Unset real API keys so tests don't accidentally make live calls
    for key in [
        "HIBP_API_KEY", "HUNTER_API_KEY", "SHODAN_API_KEY", "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY", "VIRUSTOTAL_API_KEY", "ABUSEIPDB_API_KEY",
    ]:
        monkeypatch.delenv(key, raising=False)


@pytest.fixture
def data_dir(tmp_path: Path) -> Path:
    """Temporary data directory for a single test."""
    d = tmp_path / "data"
    d.mkdir(parents=True)
    return d


# ── Sample data fixtures ─────────────────────────────────────────────────────

@pytest.fixture
def sample_email() -> str:
    return "john.doe@example.com"


@pytest.fixture
def sample_username() -> str:
    return "johndoe"


@pytest.fixture
def sample_phone() -> str:
    return "+12125551234"


@pytest.fixture
def sample_domain() -> str:
    return "example.com"


@pytest.fixture
def sample_ip() -> str:
    return "8.8.8.8"


@pytest.fixture
def sample_person() -> str:
    return "John Doe"


@pytest.fixture
def sample_scan_result() -> dict[str, Any]:
    return {
        "request_id": "req_20240101_120000_abc123de",
        "target": "john.doe@example.com",
        "target_type": "email",
        "status": "completed",
        "total_findings": 5,
        "risk_score": 6.5,
        "risk_level": "high",
        "started_at": "2024-01-01T12:00:00",
        "completed_at": "2024-01-01T12:02:30",
        "scan_duration_seconds": 150.0,
        "modules_run": 8,
        "modules_failed": 1,
        "module_results": {
            "email_validator": {
                "success": True,
                "data": {
                    "email": "john.doe@example.com",
                    "is_valid": True,
                    "mx_records": ["mail.example.com"],
                    "is_disposable": False,
                },
            },
            "hibp_breach_checker": {
                "success": True,
                "data": {
                    "email": "john.doe@example.com",
                    "total_breaches": 2,
                    "breaches": [
                        {"Name": "LinkedIn", "BreachDate": "2012-05-05"},
                        {"Name": "Adobe", "BreachDate": "2013-10-04"},
                    ],
                },
            },
        },
    }


@pytest.fixture
def mock_aiohttp_response():
    """Factory for mocking aiohttp responses."""
    def _make_response(json_data: dict, status: int = 200):
        mock = AsyncMock()
        mock.status = status
        mock.json = AsyncMock(return_value=json_data)
        mock.text = AsyncMock(return_value=json.dumps(json_data))
        mock.__aenter__ = AsyncMock(return_value=mock)
        mock.__aexit__ = AsyncMock(return_value=None)
        return mock
    return _make_response


# ── Session fixture ──────────────────────────────────────────────────────────

@pytest_asyncio.fixture
async def scan_session(tmp_path: Path):
    """Create a real ScanSession backed by a temp directory."""
    import sys
    sys.path.insert(0, str(Path(__file__).parent.parent))

    from app.core.constants import TargetType
    from app.core.config import settings
    from app.engine.session import ScanSession

    # Point settings to temp data dir
    object.__setattr__(settings, "data_dir", tmp_path / "data")

    session = ScanSession(
        target="john.doe@example.com",
        target_type=TargetType.EMAIL,
        target_inputs={},
    )
    yield session


# ── Module base fixture ──────────────────────────────────────────────────────

@pytest.fixture
def mock_module_result():
    """Factory for creating ModuleResult objects."""
    def _make(
        module_name: str = "test_module",
        target: str = "test@example.com",
        success: bool = True,
        data: dict | None = None,
        error: str | None = None,
        findings_count: int = 0,
    ):
        from app.modules.base import ModuleResult
        return ModuleResult(
            module_name=module_name,
            target=target,
            success=success,
            data=data or {},
            error=error,
            findings_count=findings_count,
        )
    return _make


# ── Database fixtures ────────────────────────────────────────────────────────

@pytest_asyncio.fixture
async def sqlite_cache(tmp_path: Path):
    """Initialize an in-memory SQLite cache for testing."""
    from app.database.sqlite_cache import SQLiteCache

    db_path = tmp_path / "test_cache.db"
    cache = SQLiteCache(db_path=db_path)
    await cache.initialize()
    yield cache
    await cache.close()
