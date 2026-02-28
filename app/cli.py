"""
GOD_EYE — Command Line Interface

All commands are defined here using Typer + Rich.
Entry point: god_eye (defined in pyproject.toml [project.scripts])

Commands:
  scan        — Run an OSINT scan
  interactive — Interactive shell
  list        — List previous scans
  view        — View scan results
  modules     — List/manage modules
  health      — Check service health
  setup       — First-time configuration wizard
  report      — Generate/re-generate reports
  cache       — Manage cache

Usage:
  god_eye scan --email user@example.com
  god_eye scan --name "John Doe" --username johndoe
  god_eye interactive
  god_eye list
  god_eye health
"""

import asyncio
import json
import sys
from pathlib import Path

import typer
from rich import box
from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.table import Table

from app import __version__

app = typer.Typer(
    name="god_eye",
    help="[bold cyan]GOD_EYE[/bold cyan] — Open Source Intelligence Platform",
    rich_markup_mode="rich",
    add_completion=True,
    no_args_is_help=True,
)
console = Console()

BANNER = f"""
[bold cyan]
  ██████╗  ██████╗ ██████╗      ███████╗██╗   ██╗███████╗
 ██╔════╝ ██╔═══██╗██╔══██╗     ██╔════╝╚██╗ ██╔╝██╔════╝
 ██║  ███╗██║   ██║██║  ██║     █████╗   ╚████╔╝ █████╗
 ██║   ██║██║   ██║██║  ██║     ██╔══╝    ╚██╔╝  ██╔══╝
 ╚██████╔╝╚██████╔╝██████╔╝     ███████╗   ██║   ███████╗
  ╚═════╝  ╚═════╝ ╚═════╝      ╚══════╝   ╚═╝   ╚══════╝
[/bold cyan]
[dim]Open Source Intelligence Platform v{__version__}[/dim]
[red]⚠  For authorized security research and personal privacy auditing ONLY.[/red]
"""


def show_banner() -> None:
    console.print(BANNER)


def show_consent_banner() -> bool:
    """Show ethics/legal consent banner. Return True if user consents."""
    console.print(
        Panel(
            "[bold yellow]⚖  LEGAL & ETHICAL NOTICE[/bold yellow]\n\n"
            "GOD_EYE collects publicly available information for:\n"
            "  • Personal privacy auditing (your own data)\n"
            "  • Authorized security research\n"
            "  • Journalism and academic research\n\n"
            "[red bold]This tool must NOT be used without authorization.[/red bold]\n"
            "Unauthorized OSINT may violate the CFAA, GDPR, CCPA, and local laws.\n\n"
            "An audit log of all searches is maintained for accountability.\n"
            "See SECURITY_AND_ETHICS.md for full usage policy.",
            border_style="yellow",
            title="[bold yellow]GOD_EYE Ethics Consent[/bold yellow]",
        )
    )
    return Confirm.ask(
        "[bold]Do you confirm you have authorization to investigate this target?[/bold]"
    )


def _run_async(coro):
    """Run an async coroutine from a sync Typer command."""
    try:
        loop = asyncio.get_event_loop()
        if loop.is_closed():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
        return loop.run_until_complete(coro)
    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted by user.[/yellow]")
        sys.exit(0)


# ── Commands ────────────────────────────────────────────────────


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    version: bool = typer.Option(False, "--version", "-v", help="Show version"),
) -> None:
    """GOD_EYE — Open Source Intelligence Platform"""
    if version:
        console.print(f"[bold cyan]GOD_EYE[/bold cyan] v{__version__}")
        raise typer.Exit()
    if ctx.invoked_subcommand is None:
        show_banner()
        console.print("Run [bold cyan]god_eye --help[/bold cyan] to see available commands.\n")


@app.command()
def scan(
    # Target inputs
    email: str | None = typer.Option(None, "--email", "-e", help="Target email address"),
    username: str | None = typer.Option(None, "--username", "-u", help="Target username"),
    name: str | None = typer.Option(None, "--name", "-n", help="Target full name"),
    phone: str | None = typer.Option(None, "--phone", "-p", help="Target phone number"),
    domain: str | None = typer.Option(None, "--domain", "-d", help="Target domain"),
    ip: str | None = typer.Option(None, "--ip", help="Target IP address"),
    company: str | None = typer.Option(None, "--company", "-c", help="Target company name"),
    target: str | None = typer.Option(
        None, "--target", "-t", help="Generic target (auto-detected type)"
    ),
    # Narrowing filters (improves precision for common names)
    work: str | None = typer.Option(
        None,
        "--work",
        "-w",
        help="Target's employer/workplace (narrows searches for common names, e.g. --work 'BlackRock')",
    ),
    location: str | None = typer.Option(
        None,
        "--location",
        "-l",
        help="Target's city/country (narrows searches, e.g. --location 'Mumbai')",
    ),
    # Scan options
    phases: str | None = typer.Option(
        None, "--phases", help="Comma-separated phase numbers (e.g., 1,2,3)"
    ),
    modules: str | None = typer.Option(
        None, "--modules", "-m", help="Comma-separated module names"
    ),
    no_ai: bool = typer.Option(False, "--no-ai", help="Skip AI correlation and reports"),
    no_progress: bool = typer.Option(False, "--no-progress", help="Suppress progress bars"),
    output_dir: str | None = typer.Option(
        None, "--output-dir", "-o", help="Custom output directory"
    ),
) -> None:
    """
    [bold]Run an OSINT scan[/bold] against a target.

    Examples:
      god_eye scan --email john@example.com
      god_eye scan --name "John Doe" --username johndoe --email john@example.com
      god_eye scan --name "Roshni Joshi" --work "BlackRock" --location "Mumbai"
      god_eye scan --domain example.com --phases 1,3,6
    """
    from app.core.config import settings

    # Show consent banner
    if settings.consent_required:
        if not show_consent_banner():
            console.print("[red]Scan aborted. Consent not given.[/red]")
            raise typer.Exit(1)

    # Determine primary target and type
    from app.core.constants import TargetType
    from app.utils.validators import detect_target_type

    target_inputs: dict[str, str] = {}
    primary_target: str | None = None
    primary_type: TargetType | None = None

    # Auto-detect from provided options
    if email:
        target_inputs["email"] = email
        primary_target = primary_target or email
        primary_type = primary_type or TargetType.EMAIL
    if username:
        target_inputs["username"] = username
        primary_target = primary_target or username
        primary_type = primary_type or TargetType.USERNAME
    if name:
        target_inputs["name"] = name
        primary_target = primary_target or name
        primary_type = primary_type or TargetType.PERSON
    if phone:
        target_inputs["phone"] = phone
        primary_target = primary_target or phone
        primary_type = primary_type or TargetType.PHONE
    if domain:
        target_inputs["domain"] = domain
        primary_target = primary_target or domain
        primary_type = primary_type or TargetType.DOMAIN
    if ip:
        target_inputs["ip"] = ip
        primary_target = primary_target or ip
        primary_type = primary_type or TargetType.IP
    if company:
        target_inputs["company"] = company
        primary_target = primary_target or company
        primary_type = primary_type or TargetType.COMPANY
    # Narrowing filters — injected into target_inputs for all modules
    if work:
        target_inputs["work"] = work
    if location:
        target_inputs["location"] = location
    if target:
        detected = detect_target_type(target)
        target_inputs[detected] = target
        primary_target = primary_target or target
        primary_type = primary_type or TargetType(detected)

    if not primary_target or not primary_type:
        console.print("[red]Error: Please specify at least one target option.[/red]")
        console.print("Run [bold]god_eye scan --help[/bold] for usage.")
        raise typer.Exit(1)

    # Parse phases
    phase_list = [int(p.strip()) for p in phases.split(",")] if phases else None
    module_list = [m.strip() for m in modules.split(",")] if modules else None

    show_banner()
    console.print("[bold cyan]Starting scan...[/bold cyan]")
    console.print(f"Target: [bold]{escape(primary_target)}[/bold] | Type: {primary_type.value}\n")

    _run_async(
        _async_scan(
            primary_target,
            primary_type,
            target_inputs,
            phase_list,
            module_list,
            not no_ai,
            not no_progress,
        )
    )


async def _async_scan(
    target: str,
    target_type,
    target_inputs: dict,
    phases: list | None,
    module_list: list | None,
    enable_ai: bool,
    show_progress: bool,
) -> None:
    """Execute the scan asynchronously."""
    from app.engine.orchestrator import Orchestrator

    orchestrator = Orchestrator()
    session = await orchestrator.run_scan(
        target=target,
        target_type=target_type,
        target_inputs=target_inputs,
        phases=phases,
        module_filter=module_list,
        show_progress=show_progress,
        enable_ai_correlation=enable_ai,
        enable_ai_reports=enable_ai,
    )

    # Display results summary
    _display_scan_results(session)


def _display_scan_results(session) -> None:
    """Display a Rich summary of scan results."""
    meta = session.to_metadata()

    # Status panel
    status_color = "green" if meta.status == "completed" else "red"
    console.print(
        Panel(
            f"[bold]Status:[/bold] [{status_color}]{meta.status.upper()}[/{status_color}]\n"
            f"[bold]Request ID:[/bold] {meta.request_id}\n"
            f"[bold]Target:[/bold] {escape(meta.target)}\n"
            f"[bold]Duration:[/bold] {meta.execution_time_seconds}s\n"
            f"[bold]Findings:[/bold] {meta.total_findings}\n"
            f"[bold]Modules:[/bold] {len(meta.modules_executed)} executed, {len(meta.modules_failed)} failed\n"
            + (
                f"[bold]Risk Score:[/bold] {meta.risk_score}/10 ({meta.risk_level})\n"
                if meta.risk_score
                else ""
            ),
            title="[bold cyan]Scan Complete[/bold cyan]",
            border_style=status_color,
        )
    )

    console.print(f"\nResults saved to: [dim]data/requests/{meta.request_id}/[/dim]")
    console.print(f"View details: [bold cyan]god_eye view {meta.request_id}[/bold cyan]")


@app.command("list")
def list_scans(
    limit: int = typer.Option(20, "--limit", "-l", help="Number of scans to show"),
    status: str | None = typer.Option(None, "--status", "-s", help="Filter by status"),
) -> None:
    """List previous OSINT scans."""
    _run_async(_async_list_scans(limit, status))


async def _async_list_scans(limit: int, status: str | None) -> None:
    from app.database.sqlite_cache import get_cache

    cache = await get_cache()
    scans = await cache.list_scans(limit=limit, status=status)

    if not scans:
        console.print("[dim]No scans found.[/dim]")
        return

    table = Table(title="[bold cyan]Previous Scans[/bold cyan]", box=box.ROUNDED)
    table.add_column("Request ID", style="cyan", no_wrap=True)
    table.add_column("Target", style="white")
    table.add_column("Type", style="dim")
    table.add_column("Status", style="green")
    table.add_column("Date", style="dim")
    table.add_column("Findings", justify="right")
    table.add_column("Risk", justify="center")

    for scan in scans:
        status_str = scan.get("status", "unknown")
        status_color = {"completed": "green", "failed": "red", "running": "yellow"}.get(
            status_str, "white"
        )
        risk = scan.get("risk_score")
        risk_str = f"{risk:.1f}" if risk else "—"
        date = scan.get("started_at", "")[:16] if scan.get("started_at") else "—"

        table.add_row(
            scan.get("request_id", "")[:30],
            escape(scan.get("target", ""))[:40],
            scan.get("target_type", ""),
            f"[{status_color}]{status_str}[/{status_color}]",
            date,
            str(scan.get("total_findings", 0)),
            risk_str,
        )

    console.print(table)


@app.command()
def view(
    request_id: str = typer.Argument(..., help="Scan request ID"),
    module: str | None = typer.Option(None, "--module", "-m", help="Show only this module's data"),
) -> None:
    """View results of a previous scan."""
    _run_async(_async_view(request_id, module))


async def _async_view(request_id: str, module: str | None) -> None:
    from app.core.config import settings

    scan_dir = Path(settings.data_dir) / "requests" / request_id

    if not scan_dir.exists():
        console.print(f"[red]Scan not found: {request_id}[/red]")
        raise typer.Exit(1)

    meta_file = scan_dir / "metadata.json"
    if meta_file.exists():
        with open(meta_file) as f:
            meta = json.load(f)
        console.print(
            Panel(
                json.dumps(meta, indent=2, default=str),
                title=f"[bold cyan]{request_id} — Metadata[/bold cyan]",
            )
        )

    raw_dir = scan_dir / "raw_data"
    if raw_dir.exists():
        for result_file in sorted(raw_dir.glob("*.json")):
            mod_name = result_file.stem
            if module and module != mod_name:
                continue
            with open(result_file) as f:
                data = json.load(f)
            console.print(
                Panel(
                    json.dumps(data, indent=2, default=str)[:3000],
                    title=f"[bold green]{mod_name}[/bold green]",
                )
            )


@app.command()
def modules() -> None:
    """List all available intelligence modules."""
    from app.modules import list_modules

    mods = list_modules()
    table = Table(title="[bold cyan]Available Modules[/bold cyan]", box=box.ROUNDED)
    table.add_column("Name", style="cyan")
    table.add_column("Display Name", style="white")
    table.add_column("Phase", justify="center")
    table.add_column("Auth", justify="center")
    table.add_column("Browser", justify="center")
    table.add_column("Targets", style="dim")

    for mod in mods:
        table.add_row(
            mod["name"],
            mod["display_name"],
            str(mod["phase"]),
            "✓" if mod["requires_auth"] else "✗",
            "✓" if mod["requires_browser"] else "✗",
            ", ".join(mod["supported_targets"]),
        )

    console.print(table)
    console.print(f"\n[dim]Total: {len(mods)} modules[/dim]")


@app.command()
def health() -> None:
    """Check health of all services."""
    _run_async(_async_health())


async def _async_health() -> None:
    from app.core.config import settings

    console.print(Panel("[bold cyan]GOD_EYE Health Check[/bold cyan]", border_style="cyan"))

    checks = []

    # Neo4j
    try:
        from app.database.neo4j_client import Neo4jClient

        client = Neo4jClient()
        await client.connect()
        ok = await client.health_check()
        await client.disconnect()
        checks.append(("Neo4j", "✓ Connected" if ok else "✗ Failed", ok))
    except Exception as e:
        checks.append(("Neo4j", f"✗ {str(e)[:50]}", False))

    # Redis
    try:
        from app.database.redis_client import RedisClient

        redis = RedisClient()
        await redis.connect()
        ok = await redis.health_check()
        await redis.disconnect()
        checks.append(("Redis", "✓ Connected" if ok else "✗ Failed", ok))
    except Exception as e:
        checks.append(("Redis", f"✗ {str(e)[:50]}", False))

    # Playwright
    try:
        from playwright.async_api import async_playwright

        async with async_playwright() as p:
            browser = await p.chromium.launch()
            await browser.close()
        checks.append(("Playwright", "✓ Browser OK", True))
    except Exception as e:
        checks.append(("Playwright", f"✗ {str(e)[:50]}", False))

    # VPN
    if settings.vpn_enabled:
        try:
            import aiohttp

            async with aiohttp.ClientSession() as session:
                async with session.get(
                    settings.gluetun_http_proxy.replace("http://", "http://") + "/v1/publicip/ip",
                    timeout=aiohttp.ClientTimeout(total=5),
                ) as resp:
                    ok = resp.status == 200
            checks.append(("Gluetun VPN", "✓ Active" if ok else "✗ Unreachable", ok))
        except Exception as e:
            checks.append(("Gluetun VPN", f"✗ {str(e)[:50]}", False))

    # Module count
    try:
        from app.modules import get_registry

        count = len(get_registry())
        checks.append(("Modules", f"✓ {count} registered", True))
    except Exception as e:
        checks.append(("Modules", f"✗ {str(e)[:50]}", False))

    table = Table(box=box.SIMPLE)
    table.add_column("Service", style="white", width=20)
    table.add_column("Status")

    for name, status, ok in checks:
        color = "green" if ok else "red"
        table.add_row(name, f"[{color}]{status}[/{color}]")

    console.print(table)


@app.command()
def setup() -> None:
    """Interactive first-time configuration wizard."""
    show_banner()
    console.print("[bold cyan]GOD_EYE Setup Wizard[/bold cyan]\n")
    console.print("This wizard will guide you through configuring API keys.\n")

    env_lines: list[str] = []

    def ask_key(display_name: str, env_var: str, docs_url: str = "") -> str:
        hint = f" ({docs_url})" if docs_url else ""
        key = Prompt.ask(f"  [cyan]{display_name}[/cyan]{hint}", default="", show_default=False)
        if key:
            env_lines.append(f"{env_var}={key}")
        return key

    console.print("[bold]Essential Keys (highly recommended):[/bold]")
    ask_key("GitHub Token (free)", "GITHUB_TOKEN", "https://github.com/settings/tokens")
    ask_key("HIBP API Key", "HIBP_API_KEY", "https://haveibeenpwned.com/API/Key")
    ask_key(
        "Anthropic API Key (for AI reports)", "ANTHROPIC_API_KEY", "https://console.anthropic.com/"
    )
    ask_key(
        "OpenRouter API Key (for AI reports)", "OPENROUTER_API_KEY", "https://openrouter.ai/keys"
    )

    console.print("\n[bold]Search Engine APIs:[/bold]")
    ask_key("SerpApi Key", "SERPAPI_API_KEY", "https://serpapi.com/manage-api-key")
    ask_key("Shodan API Key", "SHODAN_API_KEY", "https://account.shodan.io/")

    console.print("\n[bold]Social Media APIs:[/bold]")
    ask_key("Twitter Bearer Token", "TWITTER_BEARER_TOKEN")
    ask_key("Reddit Client ID", "REDDIT_CLIENT_ID")
    ask_key("Reddit Client Secret", "REDDIT_CLIENT_SECRET")

    if env_lines:
        env_path = Path(".env")
        # Append to existing .env
        with open(env_path, "a") as f:
            f.write("\n# Added by god_eye setup\n")
            for line in env_lines:
                f.write(f"{line}\n")
        console.print(f"\n[green]✓ API keys saved to {env_path}[/green]")
    else:
        console.print("\n[dim]No keys entered.[/dim]")

    console.print(
        "\n[bold green]Setup complete![/bold green] Run [bold cyan]god_eye health[/bold cyan] to verify services."
    )


@app.command()
def report(
    request_id: str = typer.Argument(..., help="Scan request ID to generate report for"),
    format: str = typer.Option(
        "all", "--format", "-f", help="Output format: json|markdown|html|pdf|all"
    ),
) -> None:
    """Generate or re-generate a report for an existing scan."""
    _run_async(_async_report(request_id, format))


async def _async_report(request_id: str, format: str) -> None:
    from app.engine.session import ScanSession

    session = ScanSession.load_from_disk(request_id)
    if not session:
        console.print(f"[red]Scan not found: {request_id}[/red]")
        raise typer.Exit(1)

    console.print(f"[cyan]Generating report for {request_id}...[/cyan]")

    try:
        from app.ai.report_generator import ReportGenerator

        generator = ReportGenerator()
        selected_formats = None if format == "all" else [format]
        paths = await generator.generate_all(session, formats=selected_formats)
        console.print("[green]✓ Report generated:[/green]")
        for fmt, path in paths.items():
            console.print(f"  {fmt}: [dim]{path}[/dim]")
    except Exception as e:
        console.print(f"[red]Report generation failed: {e}[/red]")


cache_app = typer.Typer(help="Manage API response cache")
app.add_typer(cache_app, name="cache")


@cache_app.command("stats")
def cache_stats() -> None:
    """Show cache statistics."""
    _run_async(_async_cache_stats())


async def _async_cache_stats() -> None:
    from app.database.sqlite_cache import get_cache

    cache = await get_cache()
    stats = await cache.get_stats()
    console.print(
        Panel(
            f"Active entries: [bold]{stats['active_entries']}[/bold]\n"
            f"Total cache hits: [bold]{stats['total_hits']}[/bold]",
            title="[bold cyan]Cache Statistics[/bold cyan]",
        )
    )


@cache_app.command("clear")
def cache_clear() -> None:
    """Clear expired cache entries."""
    _run_async(_async_cache_clear())


async def _async_cache_clear() -> None:
    from app.database.sqlite_cache import get_cache

    cache = await get_cache()
    count = await cache.clear_expired()
    console.print(f"[green]✓ Cleared {count} expired cache entries.[/green]")


if __name__ == "__main__":
    app()
