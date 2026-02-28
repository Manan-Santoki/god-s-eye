# CLI_REFERENCE.md

## Entry Point

```bash
god_eye [OPTIONS] COMMAND [ARGS]...
```

The CLI is built with Typer and Rich.

## Commands

### `scan`

Run an OSINT scan against a target.

```bash
god_eye scan [OPTIONS]
```

Options:

```text
--email, -e TEXT        Target email address
--username, -u TEXT     Target username
--name, -n TEXT         Target full name
--phone, -p TEXT        Target phone number
--domain, -d TEXT       Target domain
--ip TEXT               Target IP address
--company, -c TEXT      Target company name
--target, -t TEXT       Generic target (auto-detected type)
--phases TEXT           Comma-separated phase numbers
--modules, -m TEXT      Comma-separated module names
--no-ai                 Disable LLM-assisted correlation/report generation
--no-progress           Suppress Rich progress bars
--output-dir, -o TEXT   Reserved for future custom output routing
```

Examples:

```bash
god_eye scan --email john@example.com
god_eye scan --name "John Doe" --username johndoe --email john@example.com
god_eye scan --domain example.com --phases 1,3,6
god_eye scan --target 8.8.8.8
```

### `list`

List previous scans from the SQLite scan history.

```bash
god_eye list [OPTIONS]
```

Options:

```text
--limit, -l INTEGER     Number of scans to show (default: 20)
--status, -s TEXT       Optional status filter
```

### `view`

View stored scan metadata and raw module output for a request ID.

```bash
god_eye view REQUEST_ID [OPTIONS]
```

Options:

```text
--module, -m TEXT       Show only one module's saved output
```

### `modules`

List all currently discovered modules with phase, auth, browser, and supported target information.

```bash
god_eye modules
```

### `health`

Run service health checks for Neo4j, Redis, Playwright, VPN (if enabled), and module discovery.

```bash
god_eye health
```

### `setup`

Interactive setup wizard for writing API keys into `.env`.

```bash
god_eye setup
```

### `report`

Generate or re-generate report artifacts for an existing request.

```bash
god_eye report REQUEST_ID [OPTIONS]
```

Options:

```text
--format, -f TEXT       all | markdown | html | pdf | json | csv
```

Generated filenames:

```text
full_report.md
full_report.html
full_report.pdf
technical_data.json
export.csv
```

### `cache stats`

Show cache statistics from SQLite.

```bash
god_eye cache stats
```

### `cache clear`

Clear expired cache entries.

```bash
god_eye cache clear
```

## Global Options

```text
--version, -v           Show version
--help                  Show help
```

## Notes

- The CLI command set currently exposed by `app/cli.py` is: `scan`, `list`, `view`, `modules`, `health`, `setup`, `report`, and `cache`.
- AI-related flags disable LLM-assisted enrichment, but heuristic correlation, timeline, risk scoring, and fallback report generation still run when the corresponding scan phases are enabled.
