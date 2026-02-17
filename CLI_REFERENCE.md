# CLI_REFERENCE.md — Command Line Interface

---

## Entry Point

```bash
god_eye [COMMAND] [OPTIONS]
```

The CLI is built with **Typer** and uses **Rich** for terminal UI (progress bars, tables, panels, colored output).

---

## Commands

### `scan` — Run a New Investigation

```bash
god_eye scan [OPTIONS]

Options:
  --target, -t TEXT          Person name or general search term
  --email, -e TEXT           Email address(es) (can be repeated)
  --username, -u TEXT        Username(s) to search (can be repeated)
  --phone, -p TEXT           Phone number(s) in E.164 format
  --domain, -d TEXT          Domain name(s)
  --ip TEXT                  IP address(es)
  --company, -c TEXT         Company name
  --image PATH               Reference image for face recognition
  --modules TEXT             Comma-separated module list (e.g. "hibp,sherlock,github")
  --exclude-modules TEXT     Modules to skip
  --output-dir PATH          Custom output directory (default: data/requests/)
  --format TEXT              Output format: json,markdown,html,pdf,csv (default: json,markdown)
  --no-ai                    Disable AI correlation and report generation
  --no-browser               Skip all browser-based modules
  --fast                     Run only Phase 1 (fast API checks)
  --deep                     Run all phases including deep analysis
  --stealth                  Enable maximum stealth (slower but safer)
  --proxy TEXT               Override proxy for this scan
  --timeout INT              Global timeout in minutes (default: 30)
  --verbose, -v              Show detailed module output
  --quiet, -q                Minimal output (just final summary)

Examples:
  god_eye scan -t "John Doe" -e john@example.com -u johndoe
  god_eye scan -e user@company.com --fast
  god_eye scan -d example.com --modules "dns,whois,subdomains,shodan"
  god_eye scan -t "John Doe" --image ./john_photo.jpg --deep --stealth
  god_eye scan -u manan123 --exclude-modules "linkedin,facebook" --format json,html,pdf
```

**Terminal UI during scan:**
```
╔═══════════════════════════════════════════════════════════════════╗
║  🔍 GOD_EYE Intelligence Scan v1.0                               ║
╠═══════════════════════════════════════════════════════════════════╣
║  Target: John Doe (john@example.com, @johndoe)                    ║
║  Request ID: req_20260120_143052_abc123                           ║
║  Started: 2026-01-20 14:30:52                                     ║
╚═══════════════════════════════════════════════════════════════════╝

 Phase 1: Fast Reconnaissance
  [1/6] 📧 Email Validation         ████████████████████ 100% ✓  (0.8s)
  [2/6] 🔐 Breach Check (HIBP)      ████████████████████ 100% ✓  (1.2s)
  [3/6] 👤 Username Search           ████████████████████ 100% ✓  (12.4s)
  [4/6] 🐙 GitHub Profile            ████████████████████ 100% ✓  (0.5s)
  [5/6] 🤖 Reddit Profile            ████████████████████ 100% ✓  (0.7s)
  [6/6] 📱 Phone Validation          ████████████████████ 100% ✓  (0.3s)

 Phase 2: Search Engines
  [1/3] 🔎 Google Search             ████████████████████ 100% ✓  (2.1s)
  [2/3] 🦆 DuckDuckGo                ████████████████████ 100% ✓  (1.8s)
  [3/3] 📚 Wayback Machine           ████████████████████ 100% ✓  (3.2s)

 Phase 3: Social Media Deep Dive
  [1/3] 💼 LinkedIn                   ████████████░░░░░░░░  60% ⟳  (scraping...)
  [2/3] 📸 Instagram                  ░░░░░░░░░░░░░░░░░░░░   0% ⏸
  [3/3] 📘 Facebook                   ░░░░░░░░░░░░░░░░░░░░   0% ⏸

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 Status: Running │ Progress: 52% │ ETA: 6m 20s │ Findings: 87
 [Ctrl+C] Pause  │ [Ctrl+C×2] Stop
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

---

### `interactive` — Launch Interactive Shell

```bash
god_eye interactive
```

Launches a `prompt_toolkit`-based interactive shell with auto-completion.

**Interactive commands:**
```
god_eye> help                              # Show all commands
god_eye> set-target john@example.com       # Set primary target
god_eye> add-email jane@example.com        # Add another email
god_eye> add-username johndoe              # Add username
god_eye> add-phone +12025551234            # Add phone number
god_eye> set-image ./photo.jpg             # Set reference image
god_eye> show-config                       # Display current config
god_eye> enable email,username,github      # Enable specific modules
god_eye> disable linkedin,facebook         # Disable modules
god_eye> run                               # Start scan
god_eye> run --fast                        # Quick scan only
god_eye> status                            # Check scan progress
god_eye> pause                             # Pause running scan
god_eye> resume                            # Resume paused scan
god_eye> stop                              # Stop scan gracefully
god_eye> results                           # View current findings
god_eye> results --module hibp             # View specific module output
god_eye> report                            # Generate report
god_eye> report --format pdf               # Generate specific format
god_eye> export --format csv               # Export data
god_eye> graph                             # Open Neo4j browser
god_eye> clear                             # Clear screen
god_eye> history                           # Show scan history
god_eye> exit                              # Exit shell
```

---

### `list` — List Previous Scans

```bash
god_eye list [OPTIONS]

Options:
  --limit INT        Number of scans to show (default: 20)
  --status TEXT       Filter by status: completed, failed, paused
  --target TEXT       Filter by target name
  --format TEXT       Output format: table (default), json

Example output:
┌──────────────────────────────┬────────────┬──────────┬──────────┬──────┐
│ Request ID                   │ Target     │ Status   │ Date     │ Risk │
├──────────────────────────────┼────────────┼──────────┼──────────┼──────┤
│ req_20260120_143052_abc123   │ John Doe   │ ✓ Done   │ Jan 20   │ 8.5  │
│ req_20260119_091500_def456   │ jane@co.com│ ✓ Done   │ Jan 19   │ 3.2  │
│ req_20260118_220000_ghi789   │ example.com│ ✗ Failed │ Jan 18   │ —    │
└──────────────────────────────┴────────────┴──────────┴──────────┴──────┘
```

---

### `view` — View Scan Results

```bash
god_eye view REQUEST_ID [OPTIONS]

Options:
  --module TEXT       Show specific module output
  --summary           Show executive summary only
  --raw                Show raw JSON data
  --graph             Open relationship graph in Neo4j browser

Example:
  god_eye view req_20260120_143052_abc123
  god_eye view req_20260120_143052_abc123 --module hibp
  god_eye view req_20260120_143052_abc123 --summary
```

---

### `resume` — Resume Paused/Failed Scan

```bash
god_eye resume REQUEST_ID [OPTIONS]

Options:
  --skip-failed       Skip previously failed modules
  --retry-failed      Retry failed modules only
```

---

### `report` — Generate Report from Existing Data

```bash
god_eye report REQUEST_ID [OPTIONS]

Options:
  --format TEXT       Formats: markdown, html, pdf, json, csv (can combine with commas)
  --output PATH       Custom output path
  --no-ai             Skip AI-generated summary
  --template PATH     Custom Jinja2 template
```

---

### `modules` — Module Management

```bash
god_eye modules [OPTIONS]

Options:
  --list              Show all modules with status
  --enable TEXT       Enable modules (comma-separated)
  --disable TEXT      Disable modules (comma-separated)
  --info TEXT         Show detailed info about a module

Example output (--list):
┌────────────────────┬──────────────┬─────────┬───────┬─────────┐
│ Module             │ Category     │ Status  │ API   │ Phase   │
├────────────────────┼──────────────┼─────────┼───────┼─────────┤
│ email_validator    │ email        │ ✓ ON    │ None  │ 1       │
│ hibp               │ breach       │ ✓ ON    │ ✓ Key │ 2       │
│ dehashed           │ breach       │ ✗ OFF   │ ✗ Key │ 2       │
│ sherlock           │ username     │ ✓ ON    │ None  │ 1       │
│ github_api         │ social       │ ✓ ON    │ ✓ Key │ 1       │
│ linkedin_scraper   │ social       │ ✓ ON    │ ✓ Auth│ 4       │
│ face_recognition   │ visual       │ ✓ ON    │ None  │ 5       │
└────────────────────┴──────────────┴─────────┴───────┴─────────┘
```

---

### `settings` — Configuration Management

```bash
god_eye settings [OPTIONS]

Options:
  --list              Show all current settings
  --set KEY=VALUE     Set a configuration value
  --api-keys          Interactive API key setup wizard
  --reset             Reset to defaults
  --validate          Check all API keys are valid

Example:
  god_eye settings --list
  god_eye settings --set stealth.headless=false
  god_eye settings --api-keys    # Launches interactive wizard
```

---

### `setup` — First-Time Setup Wizard

```bash
god_eye setup
```

Interactive wizard that:
1. Checks Python version
2. Verifies Docker is running
3. Starts Neo4j + Redis containers
4. Walks through API key configuration
5. Tests each configured API
6. Installs Playwright browsers
7. Runs health check
8. Creates initial config.yaml

---

### `health-check` — Verify Services

```bash
god_eye health-check

Output:
┌───────────────────┬──────────┬─────────────────────────────┐
│ Service           │ Status   │ Details                     │
├───────────────────┼──────────┼─────────────────────────────┤
│ Python            │ ✓ OK     │ 3.11.6                      │
│ Neo4j             │ ✓ OK     │ bolt://localhost:7687       │
│ Redis             │ ✓ OK     │ redis://localhost:6379      │
│ Playwright        │ ✓ OK     │ Chromium + Firefox installed │
│ InsightFace       │ ✓ OK     │ buffalo_l model loaded       │
│ HIBP API          │ ✓ OK     │ Key valid, 847 credits      │
│ GitHub API        │ ✓ OK     │ 4,923 requests remaining     │
│ Shodan API        │ ✗ FAIL   │ Key not configured           │
│ DeHashed API      │ ✗ FAIL   │ Key not configured           │
└───────────────────┴──────────┴─────────────────────────────┘
```

---

### `cache` — Cache Management

```bash
god_eye cache [OPTIONS]

Options:
  --stats             Show cache statistics
  --clear             Clear all cached data
  --clear-expired     Clear only expired entries
```

---

### `monitor` — Continuous Monitoring Mode

```bash
god_eye monitor [OPTIONS]

Options:
  --target, -t TEXT        Target to monitor
  --interval TEXT          Check interval: "1h", "6h", "12h", "24h", "7d"
  --alert-on TEXT          Alert triggers: "new_breach", "new_account", "any_change"
  --notify TEXT            Notification: "terminal", "email:you@example.com", "webhook:url"

Example:
  god_eye monitor -t "john@example.com" --interval 24h --alert-on new_breach
```

---

### `privacy-audit` — Self-Audit Mode

```bash
god_eye privacy-audit [OPTIONS]

Options:
  --email TEXT             Your email address
  --username TEXT          Your username
  --phone TEXT             Your phone number
  --full-scan              Run all available modules
  --recommendations        Include detailed remediation steps

Special mode that scans your own digital footprint and generates
a privacy report with actionable recommendations.
```

---

## Global Options

```bash
god_eye [COMMAND] [GLOBAL OPTIONS]

  --version, -V            Show version and exit
  --help, -h               Show help and exit
  --config PATH            Custom config.yaml path
  --env PATH               Custom .env path
  --log-level TEXT         Override log level: DEBUG, INFO, WARNING, ERROR
  --no-color               Disable colored output
  --json                   Output results as JSON (for piping)
```

---

## Exit Codes

| Code | Meaning |
|---|---|
| 0 | Success |
| 1 | General error |
| 2 | Configuration error (missing .env, bad config) |
| 3 | Infrastructure error (Neo4j/Redis down) |
| 4 | Authentication error (bad credentials) |
| 5 | Scan interrupted (user cancelled) |
| 130 | Ctrl+C (SIGINT) |
