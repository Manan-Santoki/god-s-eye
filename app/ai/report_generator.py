"""
AI-powered report generator for GOD_EYE.

Supports three LLM providers:
    - Anthropic Claude (default)
    - OpenAI GPT-4
    - Ollama (self-hosted)

Export formats:
    - Markdown (.md)
    - HTML (via Jinja2 template)
    - PDF  (via weasyprint)
    - JSON (structured data dump)
    - CSV  (tabular summary)

Usage:
    generator = ReportGenerator()
    full_report = await generator.generate_full_report(session)
    paths = await generator.generate_all(session)
"""

from __future__ import annotations

import csv
import json
import traceback
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.core.config import settings
from app.core.logging import get_logger
from app.engine.session import ScanSession

logger = get_logger(__name__)

# ── Jinja2 HTML Template ───────────────────────────────────────────

_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>GOD_EYE OSINT Report — {{ title }}</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: 'Segoe UI', Arial, sans-serif; background: #0d1117; color: #c9d1d9; line-height: 1.6; }
    .header { background: linear-gradient(135deg, #161b22 0%, #0d1117 100%); padding: 40px; border-bottom: 2px solid #21262d; }
    .header h1 { font-size: 2.2rem; color: #58a6ff; letter-spacing: 2px; }
    .header .subtitle { color: #8b949e; margin-top: 8px; font-size: 1rem; }
    .header .meta { display: flex; gap: 24px; margin-top: 20px; flex-wrap: wrap; }
    .meta-item { background: #161b22; border: 1px solid #21262d; border-radius: 6px; padding: 8px 16px; }
    .meta-item .label { font-size: 0.75rem; color: #8b949e; text-transform: uppercase; letter-spacing: 1px; }
    .meta-item .value { font-size: 1rem; color: #e6edf3; font-weight: 600; }
    .risk-badge { display: inline-block; padding: 4px 12px; border-radius: 20px; font-weight: 700; font-size: 0.9rem; }
    .risk-low { background: #1a4d2e; color: #3fb950; }
    .risk-medium { background: #4d3f0d; color: #e3b341; }
    .risk-high { background: #4d1a0d; color: #f0883e; }
    .risk-critical { background: #4d0d1a; color: #ff7b72; }
    .container { max-width: 1100px; margin: 0 auto; padding: 32px 24px; }
    .section { background: #161b22; border: 1px solid #21262d; border-radius: 10px; margin-bottom: 24px; overflow: hidden; }
    .section-header { background: #0d1117; padding: 16px 24px; border-bottom: 1px solid #21262d; }
    .section-header h2 { color: #58a6ff; font-size: 1.2rem; }
    .section-body { padding: 24px; }
    .section-body pre { background: #0d1117; border: 1px solid #21262d; border-radius: 6px; padding: 16px;
                         overflow-x: auto; font-size: 0.85rem; color: #c9d1d9; white-space: pre-wrap; }
    .timeline-item { display: flex; gap: 16px; margin-bottom: 16px; padding-bottom: 16px; border-bottom: 1px solid #21262d; }
    .timeline-item:last-child { border-bottom: none; margin-bottom: 0; padding-bottom: 0; }
    .timeline-dot { width: 12px; height: 12px; border-radius: 50%; background: #58a6ff; margin-top: 6px; flex-shrink: 0; }
    .timeline-ts { font-size: 0.8rem; color: #8b949e; font-family: monospace; min-width: 180px; }
    .timeline-desc { color: #c9d1d9; }
    .timeline-platform { font-size: 0.8rem; color: #58a6ff; margin-top: 2px; }
    .risk-breakdown { display: grid; grid-template-columns: repeat(auto-fill, minmax(200px, 1fr)); gap: 12px; }
    .risk-item { background: #0d1117; border: 1px solid #21262d; border-radius: 6px; padding: 12px; }
    .risk-item .name { font-size: 0.8rem; color: #8b949e; }
    .risk-item .score { font-size: 1.4rem; font-weight: 700; color: #f0883e; }
    .recommendations li { margin: 8px 0; padding-left: 16px; }
    .top-risks li { margin: 8px 0; padding-left: 16px; color: #ff7b72; }
    footer { text-align: center; padding: 32px; color: #484f58; font-size: 0.85rem; border-top: 1px solid #21262d; margin-top: 32px; }
  </style>
</head>
<body>
  <div class="header">
    <h1>GOD_EYE OSINT REPORT</h1>
    <div class="subtitle">Open Source Intelligence Analysis</div>
    <div class="meta">
      <div class="meta-item"><div class="label">Target</div><div class="value">{{ title }}</div></div>
      <div class="meta-item"><div class="label">Request ID</div><div class="value">{{ request_id }}</div></div>
      <div class="meta-item"><div class="label">Date</div><div class="value">{{ date }}</div></div>
      {% if risk_score is not none %}
      <div class="meta-item">
        <div class="label">Risk Score</div>
        <div class="value">{{ "%.1f"|format(risk_score) }}/10
          <span class="risk-badge risk-{{ risk_level }}">{{ risk_level | upper }}</span>
        </div>
      </div>
      {% endif %}
      <div class="meta-item"><div class="label">Modules Run</div><div class="value">{{ modules_executed }}</div></div>
      <div class="meta-item"><div class="label">Total Findings</div><div class="value">{{ total_findings }}</div></div>
    </div>
  </div>

  <div class="container">

    {% if executive_summary %}
    <div class="section">
      <div class="section-header"><h2>Executive Summary</h2></div>
      <div class="section-body">
        <p style="white-space: pre-wrap">{{ executive_summary }}</p>
      </div>
    </div>
    {% endif %}

    {% if risk_assessment %}
    <div class="section">
      <div class="section-header"><h2>Risk Assessment</h2></div>
      <div class="section-body">
        {% if risk_assessment.breakdown %}
        <h3 style="color:#8b949e; margin-bottom:12px;">Score Breakdown</h3>
        <div class="risk-breakdown">
          {% for key, val in risk_assessment.breakdown.items() %}
          <div class="risk-item">
            <div class="name">{{ key | replace("_", " ") | title }}</div>
            <div class="score">+{{ "%.1f"|format(val) }}</div>
          </div>
          {% endfor %}
        </div>
        {% endif %}

        {% if risk_assessment.top_risks %}
        <h3 style="color:#8b949e; margin-top:20px; margin-bottom:8px;">Top Risks</h3>
        <ul class="top-risks">
          {% for risk in risk_assessment.top_risks %}
          <li>{{ risk }}</li>
          {% endfor %}
        </ul>
        {% endif %}

        {% if risk_assessment.recommendations %}
        <h3 style="color:#8b949e; margin-top:20px; margin-bottom:8px;">Recommendations</h3>
        <ol class="recommendations">
          {% for rec in risk_assessment.recommendations %}
          <li>{{ rec }}</li>
          {% endfor %}
        </ol>
        {% endif %}
      </div>
    </div>
    {% endif %}

    {% if timeline %}
    <div class="section">
      <div class="section-header"><h2>Timeline ({{ timeline | length }} events)</h2></div>
      <div class="section-body">
        {% for event in timeline %}
        <div class="timeline-item">
          <div class="timeline-dot"></div>
          <div>
            <div class="timeline-ts">{{ event.timestamp }}</div>
            <div class="timeline-desc">{{ event.description }}</div>
            {% if event.platform %}
            <div class="timeline-platform">{{ event.platform }}</div>
            {% endif %}
          </div>
        </div>
        {% endfor %}
      </div>
    </div>
    {% endif %}

    {% if full_report %}
    <div class="section">
      <div class="section-header"><h2>Full Intelligence Report</h2></div>
      <div class="section-body">
        <pre>{{ full_report }}</pre>
      </div>
    </div>
    {% endif %}

    {% for module_name, module_data in module_results.items() %}
    <div class="section">
      <div class="section-header"><h2>{{ module_name | replace("_", " ") | title }}</h2></div>
      <div class="section-body">
        <pre>{{ module_data | tojson(indent=2) }}</pre>
      </div>
    </div>
    {% endfor %}

  </div>
  <footer>
    Generated by GOD_EYE OSINT Platform &bull; {{ date }} &bull; For authorized research use only
  </footer>
</body>
</html>
"""


class ReportGenerator:
    """
    Generates intelligence reports using an LLM and exports them in multiple formats.

    Provider selection priority (configured via settings.ai_provider):
        1. anthropic — Claude API
        2. openai    — GPT-4 API
        3. openrouter — OpenRouter chat completions API
        4. ollama    — Local Ollama server
    """

    # ── LLM Interface ──────────────────────────────────────────────────

    async def _call_llm(self, prompt: str) -> str:
        """
        Route a prompt to the configured LLM provider.

        Returns the plain text response content.
        Raises on failure (caller should catch).
        """
        provider = settings.ai_provider.lower()

        if provider == "anthropic":
            return await self._call_anthropic(prompt)
        elif provider == "openai":
            return await self._call_openai(prompt)
        elif provider == "openrouter":
            return await self._call_openrouter(prompt)
        elif provider == "ollama":
            return await self._call_ollama(prompt)
        else:
            raise ValueError(f"Unsupported AI provider: {provider}")

    async def _call_anthropic(self, prompt: str) -> str:
        """Call Anthropic Claude API."""
        from anthropic import AsyncAnthropic

        if not settings.anthropic_api_key:
            raise RuntimeError("Anthropic API key not configured")

        client = AsyncAnthropic(api_key=settings.anthropic_api_key.get_secret_value())
        response = await client.messages.create(
            model=settings.ai_model,
            max_tokens=settings.ai_max_tokens,
            messages=[{"role": "user", "content": prompt}],
        )
        content = response.content[0]
        return content.text if hasattr(content, "text") else str(content)

    async def _call_openai(self, prompt: str) -> str:
        """Call OpenAI GPT-4 API."""
        from openai import AsyncOpenAI

        if not settings.openai_api_key:
            raise RuntimeError("OpenAI API key not configured")

        client = AsyncOpenAI(api_key=settings.openai_api_key.get_secret_value())
        response = await client.chat.completions.create(
            model=settings.ai_model,
            messages=[{"role": "user", "content": prompt}],
            max_tokens=settings.ai_max_tokens,
        )
        return response.choices[0].message.content or ""

    async def _call_openrouter(self, prompt: str) -> str:
        """Call OpenRouter using its OpenAI-compatible chat completions API."""
        from openai import AsyncOpenAI

        if not settings.openrouter_api_key:
            raise RuntimeError("OpenRouter API key not configured")

        headers: dict[str, str] = {}
        if settings.openrouter_site_url:
            headers["HTTP-Referer"] = settings.openrouter_site_url
        if settings.openrouter_app_name:
            headers["X-Title"] = settings.openrouter_app_name

        client = AsyncOpenAI(
            api_key=settings.openrouter_api_key.get_secret_value(),
            base_url=settings.openrouter_base_url.rstrip("/"),
            default_headers=headers or None,
        )
        response = await client.chat.completions.create(
            model=settings.ai_model,
            messages=[{"role": "user", "content": prompt}],
            max_tokens=settings.ai_max_tokens,
        )
        return response.choices[0].message.content or ""

    async def _call_ollama(self, prompt: str) -> str:
        """Call local Ollama server."""
        import aiohttp

        endpoint = settings.ollama_endpoint.rstrip("/")
        url = f"{endpoint}/api/generate"
        payload = {
            "model": settings.ollama_model,
            "prompt": prompt,
            "stream": False,
        }

        async with aiohttp.ClientSession() as session:
            r = await session.post(url, json=payload, timeout=aiohttp.ClientTimeout(total=120))
            r.raise_for_status()
            data = await r.json()
            return data.get("response", "")

    # ── Report Generation ──────────────────────────────────────────────

    async def generate_executive_summary(self, session: ScanSession) -> str:
        """
        Generate a 2-3 paragraph executive summary for the scan.

        Returns the summary as plain text.
        """
        from app.ai.prompts import EXECUTIVE_SUMMARY_PROMPT

        findings = self._build_findings_text(session)
        risk_score = session.context.get("risk_score", 0.0)
        risk_level = session.context.get("risk_level", "unknown")

        prompt = EXECUTIVE_SUMMARY_PROMPT.format(
            target=session.target,
            date=datetime.now(timezone.utc).strftime("%Y-%m-%d"),
            risk_score=risk_score,
            risk_level=risk_level,
            findings=findings,
        )

        try:
            summary = await self._call_llm(prompt)
            logger.info("executive_summary_generated", request_id=session.request_id)
            return summary
        except Exception as exc:
            logger.error("executive_summary_failed", error=str(exc))
            return self._fallback_summary(session)

    async def generate_full_report(self, session: ScanSession) -> str:
        """
        Generate a comprehensive full-text intelligence report.

        Returns the report as plain text / Markdown.
        """
        from app.ai.prompts import FULL_REPORT_PROMPT

        all_data = self._build_full_data_text(session)
        module_count = len(session.modules_executed)

        prompt = FULL_REPORT_PROMPT.format(
            target=session.target,
            date=datetime.now(timezone.utc).strftime("%Y-%m-%d"),
            request_id=session.request_id,
            risk_score=session.context.get("risk_score", 0.0),
            module_count=module_count,
            execution_summary=self._build_execution_summary_text(session),
            search_activity=self._build_search_activity_text(session),
            image_activity=self._build_image_activity_text(session),
            all_data=all_data,
        )

        try:
            report = await self._call_llm(prompt)
            logger.info("full_report_generated", request_id=session.request_id)
            return report
        except Exception as exc:
            logger.error("full_report_failed", error=str(exc))
            return self._fallback_full_report(session)

    # ── Export Methods ─────────────────────────────────────────────────

    async def export_markdown(self, session: ScanSession, content: str) -> Path:
        """
        Write the report content to a Markdown file.

        Returns the path to the written file.
        """
        session.reports_dir.mkdir(parents=True, exist_ok=True)
        path = session.reports_dir / "full_report.md"

        header = (
            f"# GOD_EYE OSINT Report\n\n"
            f"**Target:** {session.target}  \n"
            f"**Request ID:** {session.request_id}  \n"
            f"**Date:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}  \n"
            f"**Risk Score:** {session.context.get('risk_score', 'N/A')}/10 "
            f"({session.context.get('risk_level', 'N/A')})  \n\n"
            f"---\n\n"
        )

        with open(path, "w", encoding="utf-8") as f:
            f.write(header + content)

        logger.info("markdown_exported", path=str(path))
        return path

    async def export_html(self, session: ScanSession, content: str) -> Path:
        """
        Render the report to HTML using the embedded Jinja2 template.

        Returns the path to the HTML file.
        """
        try:
            from jinja2 import Environment, BaseLoader, select_autoescape
        except ImportError as exc:
            raise RuntimeError("jinja2 is required for HTML export. Install it with: pip install jinja2") from exc

        session.reports_dir.mkdir(parents=True, exist_ok=True)
        path = session.reports_dir / "full_report.html"

        # Load supporting data
        risk_assessment = self._load_json(session.correlation_dir / "risk_assessment.json")
        timeline_data = self._load_json(session.correlation_dir / "timeline.json")

        env = Environment(
            loader=BaseLoader(),
            autoescape=select_autoescape(["html"]),
        )
        # Allow tojson filter
        import json as _json
        env.filters["tojson"] = lambda obj, **kw: _json.dumps(obj, default=str, **kw)

        template = env.from_string(_HTML_TEMPLATE)
        html_content = template.render(
            title=session.target,
            request_id=session.request_id,
            date=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
            risk_score=session.context.get("risk_score"),
            risk_level=session.context.get("risk_level", "unknown"),
            modules_executed=len(session.modules_executed),
            total_findings=session.total_findings,
            executive_summary=self._fallback_summary(session),
            full_report=content,
            risk_assessment=risk_assessment,
            timeline=timeline_data if isinstance(timeline_data, list) else [],
            module_results=session.context.get("module_results", {}),
        )

        with open(path, "w", encoding="utf-8") as f:
            f.write(html_content)

        logger.info("html_exported", path=str(path))
        return path

    async def export_pdf(self, session: ScanSession, html_path: Path) -> Path:
        """
        Convert the HTML report to PDF using weasyprint.

        Args:
            session:   The ScanSession (used for output path).
            html_path: Path to the previously generated HTML file.

        Returns:
            Path to the generated PDF file.
        """
        try:
            import weasyprint
        except ImportError as exc:
            raise RuntimeError(
                "weasyprint is required for PDF export. Install it with: pip install weasyprint"
            ) from exc

        session.reports_dir.mkdir(parents=True, exist_ok=True)
        pdf_path = session.reports_dir / "full_report.pdf"

        try:
            wp = weasyprint.HTML(filename=str(html_path))
            wp.write_pdf(str(pdf_path))
            logger.info("pdf_exported", path=str(pdf_path))
        except Exception as exc:
            logger.error("pdf_export_failed", error=str(exc))
            raise

        return pdf_path

    async def export_json(self, session: ScanSession) -> Path:
        """
        Export a structured JSON bundle with all scan data.

        Includes: metadata, module results, risk assessment, timeline, connections.
        """
        session.reports_dir.mkdir(parents=True, exist_ok=True)
        path = session.reports_dir / "technical_data.json"

        bundle: dict[str, Any] = {
            "metadata": {
                "request_id": session.request_id,
                "target": session.target,
                "target_type": session.target_type.value
                    if hasattr(session.target_type, "value")
                    else str(session.target_type),
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "risk_score": session.context.get("risk_score"),
                "risk_level": session.context.get("risk_level"),
                "modules_executed": session.modules_executed,
                "modules_failed": session.modules_failed,
                "total_findings": session.total_findings,
            },
            "module_results": self._load_all_module_results(session),
            "risk_assessment": self._load_json(session.correlation_dir / "risk_assessment.json"),
            "timeline": self._load_json(session.correlation_dir / "timeline.json"),
            "entity_map": self._load_json(session.correlation_dir / "entity_map.json"),
            "connections": self._load_json(session.correlation_dir / "connections.json"),
        }

        with open(path, "w", encoding="utf-8") as f:
            json.dump(bundle, f, indent=2, default=str)

        logger.info("json_exported", path=str(path))
        return path

    async def export_csv(self, session: ScanSession) -> Path:
        """
        Export a tabular CSV summary of the scan findings.

        Columns: module, finding_type, value, platform, confidence
        """
        session.reports_dir.mkdir(parents=True, exist_ok=True)
        path = session.reports_dir / "export.csv"

        rows: list[dict[str, Any]] = []

        # Risk assessment rows
        risk_data = self._load_json(session.correlation_dir / "risk_assessment.json")
        if isinstance(risk_data, dict):
            for category, score in (risk_data.get("breakdown") or {}).items():
                rows.append({
                    "module": "risk_scorer",
                    "finding_type": "risk_factor",
                    "value": f"{score:.1f}",
                    "platform": category,
                    "confidence": "high",
                    "timestamp": "",
                    "description": category.replace("_", " ").title(),
                })

        # Timeline rows
        timeline = self._load_json(session.correlation_dir / "timeline.json")
        if isinstance(timeline, list):
            for ev in timeline:
                if isinstance(ev, dict):
                    rows.append({
                        "module": ev.get("source_module", ""),
                        "finding_type": ev.get("event_type", ""),
                        "value": ev.get("description", ""),
                        "platform": ev.get("platform", ""),
                        "confidence": (ev.get("data") or {}).get("confidence", ""),
                        "timestamp": ev.get("timestamp", ""),
                        "description": ev.get("description", ""),
                    })

        # Connection rows
        connections = self._load_json(session.correlation_dir / "connections.json")
        if isinstance(connections, list):
            for conn in connections:
                if isinstance(conn, dict):
                    rows.append({
                        "module": ", ".join(conn.get("source_modules") or []),
                        "finding_type": conn.get("connection_type", ""),
                        "value": "; ".join(conn.get("entities") or []),
                        "platform": "",
                        "confidence": str(conn.get("confidence", "")),
                        "timestamp": "",
                        "description": conn.get("description", ""),
                    })

        fieldnames = ["module", "finding_type", "value", "platform", "confidence", "timestamp", "description"]

        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
            writer.writeheader()
            writer.writerows(rows)

        logger.info("csv_exported", path=str(path), rows=len(rows))
        return path

    async def generate_all(
        self,
        session: ScanSession,
        formats: list[str] | None = None,
    ) -> dict[str, Path]:
        """
        Generate the full report and export in all supported formats.

        Returns a dict mapping format name to file path:
            {
                "markdown": Path(...),
                "html":     Path(...),
                "pdf":      Path(...),  # only if weasyprint available
                "json":     Path(...),
                "csv":      Path(...),
            }
        """
        results: dict[str, Path] = {}
        errors: dict[str, str] = {}
        selected = set(formats or ["markdown", "html", "pdf", "json", "csv"])
        if "all" in selected:
            selected = {"markdown", "html", "pdf", "json", "csv"}

        # Generate LLM report text
        full_report_text = ""
        if self._reports_enabled(session) and self._llm_available():
            try:
                full_report_text = await self.generate_full_report(session)
            except Exception as exc:
                logger.warning("generate_all_full_report_failed", error=str(exc))
                full_report_text = self._fallback_full_report(session)
        else:
            full_report_text = self._fallback_full_report(session)

        # Markdown
        if "markdown" in selected:
            try:
                results["markdown"] = await self.export_markdown(session, full_report_text)
            except Exception as exc:
                errors["markdown"] = str(exc)
                logger.error("export_markdown_failed", error=str(exc))

        # HTML
        html_path: Path | None = None
        if "html" in selected or "pdf" in selected:
            try:
                html_path = await self.export_html(session, full_report_text)
                if "html" in selected:
                    results["html"] = html_path
            except Exception as exc:
                errors["html"] = str(exc)
                logger.error("export_html_failed", error=str(exc))

        # PDF
        if html_path and "pdf" in selected:
            try:
                results["pdf"] = await self.export_pdf(session, html_path)
            except ImportError:
                logger.info("pdf_skipped_no_weasyprint")
            except Exception as exc:
                errors["pdf"] = str(exc)
                logger.error("export_pdf_failed", error=str(exc))

        # JSON
        if "json" in selected:
            try:
                results["json"] = await self.export_json(session)
            except Exception as exc:
                errors["json"] = str(exc)
                logger.error("export_json_failed", error=str(exc))

        # CSV
        if "csv" in selected:
            try:
                results["csv"] = await self.export_csv(session)
            except Exception as exc:
                errors["csv"] = str(exc)
                logger.error("export_csv_failed", error=str(exc))

        if errors:
            logger.warning("generate_all_partial_errors", errors=errors)

        logger.info(
            "generate_all_completed",
            request_id=session.request_id,
            formats=list(results.keys()),
        )
        return results

    def _reports_enabled(self, session: ScanSession) -> bool:
        return bool(session.context.get("enable_ai_reports", settings.enable_ai_reports))

    # ── Internal helpers ───────────────────────────────────────────────

    def _llm_available(self) -> bool:
        """Check whether any LLM provider is configured."""
        return (
            settings.has_api_key("anthropic_api_key")
            or settings.has_api_key("openai_api_key")
            or settings.has_api_key("openrouter_api_key")
            or bool(settings.ollama_endpoint)
        )

    def _build_findings_text(self, session: ScanSession, max_chars: int = 4000) -> str:
        """Build a concise findings text for LLM prompts."""
        lines: list[str] = []
        total = 0

        for module_name, data in (session.context.get("module_results") or {}).items():
            if total >= max_chars:
                break
            if not isinstance(data, dict):
                continue
            line = f"\n[{module_name}]\n"
            for k, v in list(data.items())[:10]:
                if v is None:
                    continue
                if isinstance(v, (str, int, float, bool)):
                    line += f"  {k}: {v}\n"
                elif isinstance(v, list) and v:
                    line += f"  {k}: {', '.join(str(x) for x in v[:5])}\n"
            lines.append(line)
            total += len(line)

        if not lines:
            return "No module results available."
        return "".join(lines)[:max_chars]

    def _build_full_data_text(self, session: ScanSession, max_chars: int = 8000) -> str:
        """Build full data text for the comprehensive report prompt."""
        lines: list[str] = []
        total = 0

        results = self._load_all_module_results(session)
        for module_name, data in results.items():
            if total >= max_chars:
                break
            try:
                chunk = f"\n=== {module_name.upper()} ===\n{json.dumps(data, indent=2, default=str)}\n"
            except Exception:
                chunk = f"\n=== {module_name.upper()} ===\n[unparseable data]\n"
            lines.append(chunk[:2000])  # cap individual module
            total += len(chunk)

        return "".join(lines)[:max_chars] or "No data available."

    def _build_execution_summary_text(self, session: ScanSession) -> str:
        """Summarize which modules actually ran, failed, or were skipped."""
        lines = [
            f"Executed modules ({len(session.modules_executed)}): {', '.join(session.modules_executed) or 'none'}",
            f"Failed modules ({len(session.modules_failed)}): {', '.join(session.modules_failed) or 'none'}",
            f"Skipped modules ({len(session.modules_skipped)}): {', '.join(session.modules_skipped) or 'none'}",
            f"Target inputs: {json.dumps(session.target_inputs, default=str)}",
        ]
        return "\n".join(lines)

    def _build_search_activity_text(self, session: ScanSession, max_lines: int = 30) -> str:
        """Summarize actual search module activity for the report prompt."""
        results = self._load_all_module_results(session)
        lines: list[str] = []

        serpapi = results.get("serpapi_search")
        if isinstance(serpapi, dict):
            query_reports = serpapi.get("query_reports", [])
            if isinstance(query_reports, list) and query_reports:
                for report in query_reports[:12]:
                    if not isinstance(report, dict):
                        continue
                    lines.append(
                        "serpapi_search "
                        f"type={report.get('query_type', 'unknown')} "
                        f"query={report.get('query', '')!r} "
                        f"results_returned={report.get('results_returned', 0)} "
                        f"reported_total_results={report.get('reported_total_results', 0)}"
                    )
                inline_images = serpapi.get("inline_images", [])
                if isinstance(inline_images, list):
                    lines.append(
                        f"serpapi_search inline_images={len(inline_images)}"
                    )
            else:
                lines.append(
                    f"serpapi_search ran with total_results={serpapi.get('total_results', 0)}"
                )

        duckduckgo = results.get("duckduckgo")
        if isinstance(duckduckgo, dict):
            lines.append(
                "duckduckgo "
                f"web_results={len(duckduckgo.get('web_results', []) or [])} "
                f"related_topics={len(duckduckgo.get('related_topics', []) or [])}"
            )

        bing = results.get("bing_search")
        if isinstance(bing, dict):
            lines.append(
                f"bing_search total_results={bing.get('total_results', len(bing.get('results', []) or []))}"
            )

        paste_monitor = results.get("paste_monitor")
        if isinstance(paste_monitor, dict):
            lines.append(
                f"paste_monitor total_found={paste_monitor.get('total_found', 0)}"
            )

        wayback = results.get("wayback")
        if isinstance(wayback, dict):
            lines.append(
                "wayback "
                f"has_archives={wayback.get('has_archives', False)} "
                f"total_snapshots={wayback.get('total_snapshots', 0)}"
            )

        if session.request_log_path.exists():
            try:
                tail = session.request_log_path.read_text(encoding="utf-8").splitlines()[-10:]
                if tail:
                    lines.append("request_log_tail:")
                    lines.extend(tail)
            except Exception:
                pass

        if not lines:
            return "No search activity data available."
        return "\n".join(lines[:max_lines])

    def _build_image_activity_text(self, session: ScanSession) -> str:
        """Summarize image-processing execution and findings."""
        results = self._load_all_module_results(session)
        downloader = results.get("image_downloader")
        exif = results.get("exif_extractor")
        face = results.get("face_recognition")
        reverse = results.get("reverse_image_search")

        lines: list[str] = []
        if isinstance(downloader, dict):
            lines.append(
                "image_downloader "
                f"downloaded={downloader.get('downloaded_count', downloader.get('images_downloaded', 0))} "
                f"duplicates_skipped={downloader.get('duplicates_skipped', 0)}"
            )
        if isinstance(exif, dict):
            lines.append(
                "exif_extractor "
                f"processed={exif.get('images_processed', 0)} "
                f"gps_hits={exif.get('gps_count', exif.get('images_with_gps', 0))}"
            )
        if isinstance(face, dict):
            lines.append(
                f"face_recognition matches={face.get('match_count', 0)}"
            )
        if isinstance(reverse, dict):
            lines.append(
                f"reverse_image_search matches={reverse.get('match_count', 0)}"
            )

        if not lines:
            executed_image_modules = [
                name
                for name in session.modules_executed
                if name in {"image_downloader", "exif_extractor", "face_recognition", "reverse_image_search"}
            ]
            if executed_image_modules:
                return (
                    "Image modules executed but produced no image evidence: "
                    + ", ".join(executed_image_modules)
                )
            return "No image modules executed and no image evidence collected."

        return "\n".join(lines)

    def _load_all_module_results(self, session: ScanSession) -> dict[str, Any]:
        """Load all module results from context and disk."""
        results: dict[str, Any] = {}

        for name, data in (session.context.get("module_results") or {}).items():
            if data:
                results[name] = data

        if session.raw_data_dir.exists():
            for json_path in sorted(session.raw_data_dir.glob("*.json")):
                name = json_path.stem
                if name not in results:
                    try:
                        with open(json_path) as f:
                            results[name] = json.load(f)
                    except Exception:
                        pass

        return results

    @staticmethod
    def _load_json(path: Path) -> Any:
        """Load a JSON file; return None on any error."""
        if not path.exists():
            return None
        try:
            with open(path) as f:
                return json.load(f)
        except Exception:
            return None

    def _fallback_summary(self, session: ScanSession) -> str:
        """Generate a basic summary when LLM is unavailable."""
        risk_score = session.context.get("risk_score", "N/A")
        risk_level = session.context.get("risk_level", "unknown")
        executed = len(session.modules_executed)
        failed = len(session.modules_failed)
        findings = session.total_findings

        return (
            f"OSINT investigation for target '{session.target}' "
            f"(type: {session.target_type.value if hasattr(session.target_type, 'value') else session.target_type}) "
            f"completed on {datetime.now(timezone.utc).strftime('%Y-%m-%d')}. "
            f"\n\n"
            f"The scan executed {executed} intelligence modules "
            f"({failed} failed/skipped) and discovered {findings} findings. "
            f"The automated risk assessment assigned a risk score of "
            f"{risk_score}/10 ({risk_level.upper()} level). "
            f"\n\n"
            f"See the full module results below for detailed findings. "
            f"AI-generated analysis is disabled (no LLM provider configured)."
        )

    def _fallback_full_report(self, session: ScanSession) -> str:
        """Generate a Markdown report without LLM when AI is disabled."""
        lines: list[str] = []
        lines.append(f"# GOD_EYE Intelligence Report\n")
        lines.append(f"**Target:** {session.target}")
        lines.append(f"**Request ID:** {session.request_id}")
        lines.append(f"**Date:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}")
        lines.append(f"**Risk Score:** {session.context.get('risk_score', 'N/A')}/10 ({session.context.get('risk_level', 'N/A')})")
        lines.append(f"**Modules Executed:** {len(session.modules_executed)}")
        lines.append(f"**Total Findings:** {session.total_findings}")
        lines.append("\n---\n")
        lines.append("## Module Results\n")

        results = self._load_all_module_results(session)
        for module_name, data in results.items():
            lines.append(f"### {module_name.replace('_', ' ').title()}\n")
            try:
                lines.append(f"```json\n{json.dumps(data, indent=2, default=str)}\n```\n")
            except Exception:
                lines.append(f"*[Data could not be serialized]*\n")

        if not results:
            lines.append("*No module results available.*\n")

        return "\n".join(lines)
