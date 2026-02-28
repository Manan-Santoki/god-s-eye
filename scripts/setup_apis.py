#!/usr/bin/env python3
"""
GOD_EYE API Key Setup Assistant.

Interactive guided setup that validates API keys and writes them to .env.
Run: python scripts/setup_apis.py
"""

import os
import re
import sys
from pathlib import Path

# Ensure project root is on the path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))


def _try_rich():
    try:
        from rich.console import Console
        from rich.table import Table
        from rich.prompt import Prompt, Confirm
        from rich.panel import Panel
        from rich.text import Text
        return Console(), Prompt, Confirm, Panel, Table, Text
    except ImportError:
        return None, None, None, None, None, None


console, Prompt, Confirm, Panel, Table, Text = _try_rich()


def print_header():
    if console:
        console.print(Panel.fit(
            "[bold cyan]GOD_EYE API Key Setup[/bold cyan]\n"
            "[dim]Interactive configuration wizard[/dim]",
            border_style="cyan",
        ))
    else:
        print("\n=== GOD_EYE API Key Setup ===\n")


def ask(prompt: str, default: str = "", password: bool = False) -> str:
    if Prompt:
        return Prompt.ask(prompt, default=default, password=password)
    val = input(f"{prompt} [{default}]: ").strip()
    return val or default


def confirm(prompt: str, default: bool = False) -> bool:
    if Confirm:
        return Confirm.ask(prompt, default=default)
    ans = input(f"{prompt} [{'Y/n' if default else 'y/N'}]: ").strip().lower()
    if not ans:
        return default
    return ans in ("y", "yes")


def print_section(title: str):
    if console:
        console.print(f"\n[bold yellow]── {title} ──[/bold yellow]")
    else:
        print(f"\n--- {title} ---")


def print_success(msg: str):
    if console:
        console.print(f"[green]✓[/green] {msg}")
    else:
        print(f"[OK] {msg}")


def print_skip(msg: str):
    if console:
        console.print(f"[dim]○ {msg} (skipped)[/dim]")
    else:
        print(f"[ ] {msg} (skipped)")


def print_warning(msg: str):
    if console:
        console.print(f"[yellow]⚠[/yellow] {msg}")
    else:
        print(f"[!] {msg}")


# ── API definitions ───────────────────────────────────────────────────────────

APIS = [
    {
        "section": "Core Intelligence (Highly Recommended)",
        "apis": [
            {
                "name": "Have I Been Pwned (HIBP)",
                "env": "HIBP_API_KEY",
                "url": "https://haveibeenpwned.com/API/Key",
                "description": "Breach database — checks if email appears in data breaches",
                "required": True,
                "validate": lambda k: len(k) >= 20,
            },
            {
                "name": "Hunter.io",
                "env": "HUNTER_API_KEY",
                "url": "https://hunter.io/users/sign_up",
                "description": "Email discovery and verification for domains",
                "required": False,
                "validate": lambda k: len(k) >= 20,
            },
            {
                "name": "Shodan",
                "env": "SHODAN_API_KEY",
                "url": "https://account.shodan.io",
                "description": "Internet-connected device and network intelligence",
                "required": False,
                "validate": lambda k: len(k) >= 20,
            },
        ],
    },
    {
        "section": "Search & Web Intelligence",
        "apis": [
            {
                "name": "SerpApi",
                "env": "SERPAPI_API_KEY",
                "url": "https://serpapi.com/search-api",
                "description": "Google search results and dorking via SerpApi",
                "required": False,
                "validate": lambda k: len(k) >= 20,
            },
            {
                "name": "Bing Search API",
                "env": "BING_API_KEY",
                "url": "https://azure.microsoft.com/en-us/services/cognitive-services/bing-web-search-api/",
                "description": "Microsoft Bing web search",
                "required": False,
                "validate": lambda k: len(k) >= 20,
            },
        ],
    },
    {
        "section": "Social Media APIs",
        "apis": [
            {
                "name": "GitHub Personal Access Token",
                "env": "GITHUB_TOKEN",
                "url": "https://github.com/settings/tokens",
                "description": "GitHub profile, repos, commit history (5000 req/hr auth vs 60 unauth)",
                "required": False,
                "validate": lambda k: k.startswith(("ghp_", "github_pat_")) and len(k) >= 20,
            },
            {
                "name": "Twitter/X Bearer Token",
                "env": "TWITTER_BEARER_TOKEN",
                "url": "https://developer.twitter.com/en/portal/dashboard",
                "description": "Twitter/X user and tweet data",
                "required": False,
                "validate": lambda k: k.startswith("AAAA") and len(k) >= 50,
            },
            {
                "name": "Reddit Client ID",
                "env": "REDDIT_CLIENT_ID",
                "url": "https://www.reddit.com/prefs/apps",
                "description": "Reddit user profile and post history",
                "required": False,
                "validate": lambda k: len(k) >= 10,
            },
            {
                "name": "Reddit Client Secret",
                "env": "REDDIT_CLIENT_SECRET",
                "url": "https://www.reddit.com/prefs/apps",
                "description": "Reddit OAuth secret",
                "required": False,
                "validate": lambda k: len(k) >= 20,
            },
            {
                "name": "YouTube Data API v3",
                "env": "YOUTUBE_API_KEY",
                "url": "https://console.cloud.google.com",
                "description": "YouTube channel and video data",
                "required": False,
                "validate": lambda k: k.startswith("AIza") and len(k) >= 30,
            },
        ],
    },
    {
        "section": "Network & Domain Intelligence",
        "apis": [
            {
                "name": "AbuseIPDB",
                "env": "ABUSEIPDB_API_KEY",
                "url": "https://www.abuseipdb.com/register",
                "description": "IP abuse reports and reputation scoring",
                "required": False,
                "validate": lambda k: len(k) >= 20,
            },
            {
                "name": "VirusTotal",
                "env": "VIRUSTOTAL_API_KEY",
                "url": "https://www.virustotal.com/gui/join-us",
                "description": "Domain/IP/file malware scanning",
                "required": False,
                "validate": lambda k: len(k) == 64,
            },
            {
                "name": "WhoisXML API",
                "env": "WHOISXML_API_KEY",
                "url": "https://whois.whoisxmlapi.com/signup",
                "description": "WHOIS domain registration data",
                "required": False,
                "validate": lambda k: k.startswith("at_") and len(k) >= 20,
            },
            {
                "name": "SecurityTrails",
                "env": "SECURITYTRAILS_API_KEY",
                "url": "https://securitytrails.com/app/account",
                "description": "DNS history and subdomain enumeration",
                "required": False,
                "validate": lambda k: len(k) >= 20,
            },
            {
                "name": "IPinfo.io",
                "env": "IPINFO_API_KEY",
                "url": "https://ipinfo.io/signup",
                "description": "IP geolocation (50k/month free)",
                "required": False,
                "validate": lambda k: len(k) >= 10,
            },
        ],
    },
    {
        "section": "Breach Intelligence",
        "apis": [
            {
                "name": "DeHashed",
                "env": "DEHASHED_API_KEY",
                "url": "https://dehashed.com/pricing",
                "description": "Leaked credentials database search",
                "required": False,
                "validate": lambda k: len(k) >= 10,
            },
            {
                "name": "IntelligenceX (IntelX)",
                "env": "INTELX_API_KEY",
                "url": "https://intelx.io/signup",
                "description": "Dark web and paste site search",
                "required": False,
                "validate": lambda k: len(k) >= 20,
            },
        ],
    },
    {
        "section": "AI Report Generation & Vision Analysis",
        "apis": [
            {
                "name": "OpenRouter (Recommended)",
                "env": "OPENROUTER_API_KEY",
                "url": "https://openrouter.ai/keys",
                "description": "Unified AI API — access Claude, GPT-4, Llama and 200+ models. Used for reports AND vision analysis of screenshots. Recommended over direct Anthropic/OpenAI keys.",
                "required": False,
                "validate": lambda k: k.startswith("sk-or-") and len(k) >= 20,
            },
            {
                "name": "Anthropic Claude API",
                "env": "ANTHROPIC_API_KEY",
                "url": "https://console.anthropic.com",
                "description": "Direct Anthropic API (use OpenRouter instead if you have that key)",
                "required": False,
                "validate": lambda k: k.startswith("sk-ant-") and len(k) >= 40,
            },
            {
                "name": "OpenAI API",
                "env": "OPENAI_API_KEY",
                "url": "https://platform.openai.com/api-keys",
                "description": "Direct OpenAI API (use OpenRouter instead if you have that key)",
                "required": False,
                "validate": lambda k: k.startswith("sk-") and len(k) >= 40,
            },
        ],
    },
    {
        "section": "LinkedIn (Optional)",
        "apis": [
            {
                "name": "LinkedIn Email",
                "env": "LINKEDIN_EMAIL",
                "url": "https://www.linkedin.com",
                "description": "Your LinkedIn account email (for profile scraping)",
                "required": False,
                "validate": lambda k: "@" in k,
            },
            {
                "name": "LinkedIn Password",
                "env": "LINKEDIN_PASSWORD",
                "url": "https://www.linkedin.com",
                "description": "Your LinkedIn account password",
                "required": False,
                "validate": lambda k: len(k) >= 6,
                "password": True,
            },
        ],
    },
]


def validate_key(api: dict, value: str) -> bool:
    validator = api.get("validate")
    if validator:
        return validator(value)
    return bool(value)


def setup_apis() -> dict[str, str]:
    """Run interactive setup wizard. Returns dict of env_var: value."""
    env_values: dict[str, str] = {}

    # Load existing .env if present
    env_file = project_root / ".env"
    existing: dict[str, str] = {}
    if env_file.exists():
        with open(env_file) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, _, v = line.partition("=")
                    existing[k.strip()] = v.strip().strip('"').strip("'")

    for group in APIS:
        print_section(group["section"])

        for api in group["apis"]:
            env_key = api["env"]
            current = existing.get(env_key, "")

            if console:
                console.print(
                    f"\n[bold]{api['name']}[/bold]\n"
                    f"  [dim]{api['description']}[/dim]\n"
                    f"  Get key: {api['url']}"
                )
            else:
                print(f"\n{api['name']}: {api['description']}")
                print(f"  Get key: {api['url']}")

            if current:
                masked = current[:4] + "..." + current[-4:] if len(current) > 8 else "****"
                use_existing = confirm(f"  Use existing key ({masked})?", default=True)
                if use_existing:
                    env_values[env_key] = current
                    print_success(f"{api['name']}: using existing key")
                    continue

            skip = not confirm(f"  Configure {api['name']}?", default=api.get("required", False))
            if skip:
                print_skip(api["name"])
                continue

            while True:
                value = ask(
                    f"  Enter {api['name']} key",
                    password=api.get("password", False),
                )
                if not value:
                    print_skip(api["name"])
                    break
                if validate_key(api, value):
                    env_values[env_key] = value
                    print_success(f"{api['name']}: key saved")
                    break
                else:
                    print_warning(f"Key format looks incorrect for {api['name']}. Try again or press Enter to skip.")

    return env_values


def write_env_file(values: dict[str, str], env_file: Path) -> None:
    """Write validated API keys to .env file."""
    # Load existing .env template
    template_file = project_root / ".env.example"
    if template_file.exists():
        with open(template_file) as f:
            template = f.read()
    else:
        template = ""

    # Update values in template
    for key, value in values.items():
        pattern = re.compile(rf"^{re.escape(key)}=.*$", re.MULTILINE)
        replacement = f'{key}="{value}"'
        if pattern.search(template):
            template = pattern.sub(replacement, template)
        else:
            template += f'\n{key}="{value}"\n'

    with open(env_file, "w") as f:
        f.write(template)

    print_success(f".env file written to {env_file}")


def test_connections(values: dict[str, str]) -> None:
    """Quick connectivity test for configured APIs."""
    print_section("Testing API Connections")

    import asyncio

    async def _test():
        if "HIBP_API_KEY" in values:
            try:
                import aiohttp
                headers = {"hibp-api-key": values["HIBP_API_KEY"], "user-agent": "god-eye-setup"}
                async with aiohttp.ClientSession() as session:
                    async with session.get(
                        "https://haveibeenpwned.com/api/v3/breachedaccount/test%40test.com",
                        headers=headers,
                        timeout=aiohttp.ClientTimeout(total=10),
                    ) as resp:
                        if resp.status in (200, 404):
                            print_success("HIBP API: connected")
                        else:
                            print_warning(f"HIBP API: unexpected status {resp.status}")
            except Exception as e:
                print_warning(f"HIBP API: {e}")

        if "GITHUB_TOKEN" in values:
            try:
                import aiohttp
                headers = {
                    "Authorization": f"token {values['GITHUB_TOKEN']}",
                    "User-Agent": "god-eye-setup",
                }
                async with aiohttp.ClientSession() as session:
                    async with session.get(
                        "https://api.github.com/user",
                        headers=headers,
                        timeout=aiohttp.ClientTimeout(total=10),
                    ) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            print_success(f"GitHub API: authenticated as @{data.get('login')}")
                        else:
                            print_warning(f"GitHub API: status {resp.status}")
            except Exception as e:
                print_warning(f"GitHub API: {e}")

    asyncio.run(_test())


def main():
    print_header()

    if console:
        console.print(
            "\n[dim]This wizard helps you configure API keys for GOD_EYE modules.\n"
            "All keys are stored locally in your .env file and never transmitted.\n"
            "Free tier keys are sufficient for most use cases.[/dim]\n"
        )

    env_file = project_root / ".env"
    backup_file = project_root / ".env.backup"

    # Backup existing .env
    if env_file.exists():
        import shutil
        shutil.copy2(env_file, backup_file)
        print_success(f"Backed up existing .env to {backup_file}")

    try:
        values = setup_apis()

        if not values:
            print_warning("No API keys configured. Run setup again when ready.")
            return

        write_env_file(values, env_file)

        if confirm("\nTest API connections now?", default=True):
            test_connections(values)

        if console:
            console.print(
                Panel.fit(
                    f"[bold green]Setup complete![/bold green]\n"
                    f"[dim]Configured {len(values)} API key(s).[/dim]\n\n"
                    "Start GOD_EYE:\n"
                    "  [cyan]python -m app.cli scan --target your@email.com[/cyan]\n"
                    "  [cyan]uvicorn app.main:app --host 0.0.0.0 --port 8000[/cyan]",
                    border_style="green",
                )
            )
        else:
            print(f"\nSetup complete! Configured {len(values)} API key(s).")
            print("Start: python -m app.cli scan --target your@email.com")

    except KeyboardInterrupt:
        print("\n\nSetup interrupted. Partial configuration saved.")


if __name__ == "__main__":
    main()
