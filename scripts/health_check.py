#!/usr/bin/env python3
"""
GOD_EYE system health check.

Verifies all services, APIs, dependencies, and configuration.
Prints a Rich status table with actionable remediation hints.

Usage:
  python scripts/health_check.py
  python scripts/health_check.py --json
  python scripts/health_check.py --fix-perms
"""

import argparse
import asyncio
import json
import os
import subprocess
import sys
from pathlib import Path

project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))


def parse_args():
    parser = argparse.ArgumentParser(description="GOD_EYE health check")
    parser.add_argument("--json", action="store_true", help="Output JSON instead of table")
    parser.add_argument("--fix-perms", action="store_true", help="Fix data directory permissions")
    parser.add_argument("--quiet", "-q", action="store_true", help="Only print failures")
    return parser.parse_args()


def try_rich():
    try:
        from rich.console import Console
        from rich.table import Table
        from rich.text import Text

        return Console(), Table, Text
    except ImportError:
        return None, None, None


console, RichTable, RichText = try_rich()


async def check_python_version() -> dict:
    version = sys.version_info
    ok = version >= (3, 11)
    return {
        "name": "Python Version",
        "status": "ok" if ok else "fail",
        "detail": f"{version.major}.{version.minor}.{version.micro}",
        "fix": "Install Python 3.11+" if not ok else None,
    }


async def check_python_dependencies() -> list[dict]:
    results = []
    packages = [
        ("fastapi", "fastapi"),
        ("pydantic", "pydantic"),
        ("typer", "typer"),
        ("rich", "rich"),
        ("aiohttp", "aiohttp"),
        ("aiosqlite", "aiosqlite"),
        ("structlog", "structlog"),
        ("tenacity", "tenacity"),
        ("playwright", "playwright"),
        ("dnspython", "dns"),
        ("jinja2", "jinja2"),
        ("pillow", "PIL"),
        ("phonenumbers", "phonenumbers"),
        ("exifread", "exifread"),
        ("neo4j", "neo4j"),
        ("redis", "redis"),
    ]
    optional = {
        ("insightface", "insightface"),
        ("weasyprint", "weasyprint"),
        ("spacy", "spacy"),
        ("imagehash", "imagehash"),
        ("maigret", "maigret"),
        ("geoip2", "geoip2"),
        ("ipwhois", "ipwhois"),
    }

    for pkg_name, import_name in packages + list(optional):
        is_optional = (pkg_name, import_name) in optional
        try:
            mod = __import__(import_name)
            version = getattr(mod, "__version__", "installed")
            results.append(
                {
                    "name": f"pkg:{pkg_name}",
                    "status": "ok",
                    "detail": version,
                    "optional": is_optional,
                }
            )
        except ImportError:
            results.append(
                {
                    "name": f"pkg:{pkg_name}",
                    "status": "warn" if is_optional else "fail",
                    "detail": "not installed",
                    "optional": is_optional,
                    "fix": f"pip install {pkg_name}",
                }
            )

    return results


async def check_neo4j() -> dict:
    try:
        from app.database.neo4j_client import Neo4jClient

        client = Neo4jClient()
        await client.connect()
        healthy = await client.health_check()
        await client.disconnect()
        return {"name": "Neo4j", "status": "ok" if healthy else "warn", "detail": "connected"}
    except Exception as e:
        return {
            "name": "Neo4j",
            "status": "warn",
            "detail": str(e)[:80],
            "fix": "Start Neo4j: docker compose up neo4j -d",
        }


async def check_redis() -> dict:
    try:
        from app.database.redis_client import RedisClient

        redis = RedisClient()
        await redis.connect()
        healthy = await redis.health_check()
        await redis.disconnect()
        return {"name": "Redis", "status": "ok" if healthy else "warn", "detail": "connected"}
    except Exception as e:
        return {
            "name": "Redis",
            "status": "warn",
            "detail": str(e)[:80],
            "fix": "Start Redis: docker compose up redis -d",
        }


async def check_sqlite() -> dict:
    try:
        import tempfile
        from pathlib import Path

        from app.database.sqlite_cache import SQLiteCache

        with tempfile.TemporaryDirectory() as tmp:
            cache = SQLiteCache(db_path=Path(tmp) / "test.db")
            await cache.initialize()
            await cache.close()
        return {"name": "SQLite (aiosqlite)", "status": "ok", "detail": "working"}
    except Exception as e:
        return {
            "name": "SQLite (aiosqlite)",
            "status": "fail",
            "detail": str(e)[:80],
            "fix": "pip install aiosqlite",
        }


async def check_env_file() -> dict:
    env_file = project_root / ".env"
    if not env_file.exists():
        return {
            "name": ".env file",
            "status": "warn",
            "detail": "missing",
            "fix": "cp .env.example .env && python scripts/setup_apis.py",
        }
    size = env_file.stat().st_size
    return {"name": ".env file", "status": "ok", "detail": f"{size} bytes"}


async def check_data_dirs() -> list[dict]:
    results = []
    dirs = [
        project_root / "data",
        project_root / "data" / "logs",
        project_root / "data" / "requests",
        project_root / "data" / "cache",
        project_root / "data" / "templates",
    ]
    for d in dirs:
        exists = d.exists()
        writable = exists and os.access(d, os.W_OK)
        results.append(
            {
                "name": f"dir:{d.relative_to(project_root)}",
                "status": "ok" if (exists and writable) else ("warn" if exists else "fail"),
                "detail": "ok"
                if (exists and writable)
                else ("not writable" if exists else "missing"),
                "fix": f"mkdir -p {d}" if not exists else f"chmod 755 {d}",
            }
        )
    return results


async def check_templates() -> dict:
    templates_dir = project_root / "data" / "templates"
    required = ["report.html.jinja2", "report.md.jinja2", "executive_summary.jinja2"]
    missing = [t for t in required if not (templates_dir / t).exists()]
    if missing:
        return {
            "name": "Jinja2 templates",
            "status": "warn",
            "detail": f"missing: {', '.join(missing)}",
            "fix": "Templates should be in data/templates/",
        }
    return {
        "name": "Jinja2 templates",
        "status": "ok",
        "detail": f"{len(required)} templates present",
    }


async def check_playwright() -> dict:
    try:
        subprocess.run(
            ["python", "-m", "playwright", "install", "--dry-run"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        # Check if chromium browser is installed
        browser_path_candidates = [
            Path.home() / ".cache/ms-playwright",
            Path("/root/.cache/ms-playwright"),
        ]
        installed = any(p.exists() for p in browser_path_candidates)
        return {
            "name": "Playwright browsers",
            "status": "ok" if installed else "warn",
            "detail": "installed" if installed else "browsers not installed",
            "fix": "playwright install chromium" if not installed else None,
        }
    except Exception as e:
        return {
            "name": "Playwright browsers",
            "status": "warn",
            "detail": str(e)[:80],
            "fix": "playwright install chromium",
        }


async def check_api_keys() -> list[dict]:
    results = []
    api_keys = {
        "HIBP_API_KEY": ("HIBP", True),
        "HUNTER_API_KEY": ("Hunter.io", False),
        "GITHUB_TOKEN": ("GitHub", False),
        "TWITTER_BEARER_TOKEN": ("Twitter/X", False),
        "SHODAN_API_KEY": ("Shodan", False),
        "SERPAPI_API_KEY": ("SerpApi", False),
        "ABUSEIPDB_API_KEY": ("AbuseIPDB", False),
        "VIRUSTOTAL_API_KEY": ("VirusTotal", False),
        "ANTHROPIC_API_KEY": ("Anthropic Claude", False),
        "OPENAI_API_KEY": ("OpenAI", False),
        "OPENROUTER_API_KEY": ("OpenRouter", False),
        "DEHASHED_API_KEY": ("DeHashed", False),
        "INTELX_API_KEY": ("IntelX", False),
    }

    # Load from .env if exists
    env_file = project_root / ".env"
    env_values: dict[str, str] = {}
    if env_file.exists():
        with open(env_file) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, _, v = line.partition("=")
                    env_values[k.strip()] = v.strip().strip('"').strip("'")

    for env_var, (display_name, required) in api_keys.items():
        value = env_values.get(env_var) or os.environ.get(env_var, "")
        configured = bool(value and len(value) > 5)
        results.append(
            {
                "name": f"api:{display_name}",
                "status": "ok" if configured else ("warn" if not required else "fail"),
                "detail": "configured" if configured else "not set",
                "optional": not required,
                "fix": "python scripts/setup_apis.py" if not configured else None,
            }
        )

    return results


async def check_modules() -> dict:
    try:
        from app.modules import get_registry

        registry = get_registry()
        count = len(registry)
        return {
            "name": "Module registry",
            "status": "ok" if count > 0 else "fail",
            "detail": f"{count} modules loaded",
        }
    except Exception as e:
        return {
            "name": "Module registry",
            "status": "fail",
            "detail": str(e)[:80],
        }


def print_table(checks: list[dict], quiet: bool = False) -> int:
    """Print results as a Rich table. Returns exit code."""
    failures = [c for c in checks if c["status"] == "fail"]
    warnings = [c for c in checks if c["status"] == "warn"]

    if console:
        table = RichTable(show_header=True, header_style="bold cyan", box=None)
        table.add_column("Check", style="bold", min_width=30)
        table.add_column("Status", min_width=8)
        table.add_column("Detail", style="dim")
        table.add_column("Fix", style="yellow dim")

        for check in checks:
            if quiet and check["status"] == "ok":
                continue
            status = check["status"]
            icon = {
                "ok": "[green]✓ ok[/green]",
                "warn": "[yellow]⚠ warn[/yellow]",
                "fail": "[red]✗ fail[/red]",
            }.get(status, status)
            table.add_row(
                check["name"],
                icon,
                check.get("detail", ""),
                check.get("fix", "") or "",
            )

        console.print(table)
        console.print(
            f"\n[green]{len(checks) - len(failures) - len(warnings)} passed[/green] | "
            f"[yellow]{len(warnings)} warnings[/yellow] | "
            f"[red]{len(failures)} failures[/red]"
        )
    else:
        for check in checks:
            if quiet and check["status"] == "ok":
                continue
            status = check["status"].upper()
            fix = f" → {check['fix']}" if check.get("fix") else ""
            print(f"[{status}] {check['name']}: {check.get('detail', '')}{fix}")
        print(
            f"\nPassed: {len(checks) - len(failures) - len(warnings)} | Warnings: {len(warnings)} | Failures: {len(failures)}"
        )

    return 1 if failures else 0


async def main_async(args) -> int:
    checks: list[dict] = []

    # Run all checks
    checks.append(await check_python_version())
    checks.extend(await check_python_dependencies())
    checks.append(await check_env_file())
    checks.extend(await check_data_dirs())
    checks.append(await check_templates())
    checks.append(await check_playwright())
    checks.append(await check_sqlite())
    checks.append(await check_neo4j())
    checks.append(await check_redis())
    checks.append(await check_modules())
    checks.extend(await check_api_keys())

    if args.json:
        print(json.dumps(checks, indent=2))
        failures = [c for c in checks if c["status"] == "fail"]
        return 1 if failures else 0

    return print_table(checks, quiet=args.quiet)


def main():
    args = parse_args()

    if args.fix_perms:
        for d in ["data", "data/logs", "data/requests", "data/cache", "data/templates"]:
            path = project_root / d
            path.mkdir(parents=True, exist_ok=True)
            os.chmod(path, 0o755)
        print("Directory permissions fixed.")

    exit_code = asyncio.run(main_async(args))
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
