"""
Export scan results to multiple formats: JSON, Markdown, HTML, PDF, CSV.
All exports use Jinja2 templates from data/templates/.
"""

import csv
import json
from datetime import datetime
from io import StringIO
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from app.core.logging import get_logger

logger = get_logger(__name__)

TEMPLATES_DIR = Path("data/templates")


def _get_jinja_env() -> Environment:
    return Environment(
        loader=FileSystemLoader(str(TEMPLATES_DIR)),
        autoescape=select_autoescape(["html", "xml"]),
    )


def export_json(data: dict[str, Any], output_path: Path) -> Path:
    """Export scan data as pretty-printed JSON."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, default=str, ensure_ascii=False)
    logger.info("exported_json", path=str(output_path))
    return output_path


def export_markdown(content: str, output_path: Path) -> Path:
    """Write Markdown content to file."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(content)
    logger.info("exported_markdown", path=str(output_path))
    return output_path


def export_html(data: dict[str, Any], output_path: Path) -> Path:
    """Render HTML report using Jinja2 template."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    template_path = TEMPLATES_DIR / "report.html.jinja2"

    if template_path.exists():
        env = _get_jinja_env()
        template = env.get_template("report.html.jinja2")
        html = template.render(**data, generated_at=datetime.utcnow().isoformat())
    else:
        # Fallback: basic HTML
        html = _basic_html_report(data)

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)
    logger.info("exported_html", path=str(output_path))
    return output_path


def export_pdf(html_path: Path, output_path: Path) -> Path:
    """Convert HTML report to PDF using WeasyPrint."""
    try:
        from weasyprint import HTML
        output_path.parent.mkdir(parents=True, exist_ok=True)
        HTML(filename=str(html_path)).write_pdf(str(output_path))
        logger.info("exported_pdf", path=str(output_path))
        return output_path
    except ImportError:
        logger.warning("weasyprint_not_installed", msg="PDF export requires: pip install weasyprint")
        raise
    except Exception as e:
        logger.error("pdf_export_failed", error=str(e))
        raise


def export_csv(data: dict[str, Any], output_path: Path) -> Path:
    """Export key findings as CSV spreadsheet."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    rows: list[dict] = []

    # Flatten module results into rows
    for module_name, result in data.get("module_results", {}).items():
        if isinstance(result, dict):
            row = {"module": module_name}
            for k, v in result.items():
                if isinstance(v, (str, int, float, bool)):
                    row[k] = v
                elif isinstance(v, list) and v and isinstance(v[0], str):
                    row[k] = "; ".join(v[:5])
            rows.append(row)

    if not rows:
        rows = [{"target": data.get("target", ""), "status": "no_module_data"}]

    # Get all columns
    all_keys = list({k for row in rows for k in row.keys()})
    all_keys.sort()

    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=all_keys, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)

    logger.info("exported_csv", path=str(output_path), rows=len(rows))
    return output_path


def _basic_html_report(data: dict[str, Any]) -> str:
    """Generate a basic HTML report without a template file."""
    target = data.get("target", "Unknown")
    risk_score = data.get("risk_score", "N/A")
    risk_level = data.get("risk_level", "unknown")
    timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

    color_map = {"low": "#2ecc71", "medium": "#f39c12", "high": "#e74c3c", "critical": "#8e44ad"}
    risk_color = color_map.get(str(risk_level).lower(), "#95a5a6")

    sections_html = ""
    for module, result in data.get("module_results", {}).items():
        if isinstance(result, dict):
            content = json.dumps(result, indent=2, default=str)
            sections_html += f"""
            <div class="module-card">
                <h3>{module.replace("_", " ").title()}</h3>
                <pre>{content[:2000]}</pre>
            </div>"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>GOD_EYE OSINT Report — {target}</title>
<style>
  body {{ font-family: 'Segoe UI', Arial, sans-serif; background: #0d1117; color: #c9d1d9; margin: 0; padding: 20px; }}
  .header {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 24px; margin-bottom: 24px; }}
  .header h1 {{ margin: 0; font-size: 24px; color: #58a6ff; }}
  .risk-badge {{ display: inline-block; background: {risk_color}; color: white; padding: 4px 12px; border-radius: 4px; font-weight: bold; }}
  .module-card {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 16px; margin-bottom: 16px; }}
  .module-card h3 {{ margin: 0 0 12px 0; color: #58a6ff; font-size: 16px; }}
  pre {{ background: #0d1117; padding: 12px; border-radius: 4px; overflow-x: auto; font-size: 12px; color: #8b949e; white-space: pre-wrap; }}
  .meta {{ color: #8b949e; font-size: 13px; margin-top: 8px; }}
  .disclaimer {{ background: #21262d; border: 1px solid #f85149; border-radius: 8px; padding: 16px; margin-top: 24px; font-size: 13px; color: #f85149; }}
</style>
</head>
<body>
<div class="header">
  <h1>🔍 GOD_EYE OSINT Report</h1>
  <p>Target: <strong>{target}</strong></p>
  <p>Risk Level: <span class="risk-badge">{str(risk_level).upper()} ({risk_score}/10)</span></p>
  <p class="meta">Generated: {timestamp} | Request ID: {data.get("request_id", "N/A")}</p>
</div>
{sections_html}
<div class="disclaimer">
  ⚠️ This report is for authorized security research and personal privacy auditing only.
  Unauthorized use may violate applicable laws. See SECURITY_AND_ETHICS.md for guidelines.
</div>
</body>
</html>"""


async def export_all(session, ai_content: str | None = None) -> dict[str, Path]:
    """Export scan in all configured formats. Returns dict of format: Path."""
    from app.core.config import settings

    reports_dir = session.reports_dir
    results: dict[str, Path] = {}

    # Build unified data dict
    metadata = session.to_metadata().model_dump(mode="json")
    export_data = {
        **metadata,
        "module_results": session.context.get("module_results", {}),
        "risk_score": session.context.get("risk_score"),
        "risk_level": session.context.get("risk_level"),
        "ai_summary": ai_content,
    }

    # JSON
    results["json"] = export_json(export_data, reports_dir / "technical_data.json")

    # Markdown
    if ai_content:
        results["markdown"] = export_markdown(ai_content, reports_dir / "full_report.md")

    # HTML
    html_path = reports_dir / "full_report.html"
    results["html"] = export_html(export_data, html_path)

    # PDF
    try:
        results["pdf"] = export_pdf(html_path, reports_dir / "full_report.pdf")
    except Exception as e:
        logger.warning("pdf_export_skipped", error=str(e))

    # CSV
    results["csv"] = export_csv(export_data, reports_dir / "export.csv")

    return results
